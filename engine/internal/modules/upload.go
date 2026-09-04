package modules

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/safemutation"
	"github.com/akha-security/akca/engine/internal/verification"
)

func (r *Runner) runFileUpload(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("file_upload", target); !ok {
		r.emitSkip("file_upload", target, reason)
		return nil
	}
	if r.client == nil {
		return nil
	}
	cleanupPolicy, policyOK := r.fileUploadPolicy(target)
	if !policyOK {
		r.emitStatefulProofGap("file_upload", target, "explicit cleanup policy is required for automatic upload proof")
		r.emitSkip("file_upload", target, "explicit cleanup policy is required for automatic upload proof")
		return nil
	}
	var out []ModuleFinding
	for _, probe := range []struct {
		extension, contentType, prefix, signal string
		customFilename                         string
	}{
		{extension: ".php", contentType: "image/png", prefix: "", signal: "extension_bypass"},
		{extension: ".phtml", contentType: "image/jpeg", prefix: "<?php //", signal: "phtml_extension_bypass"},
		{extension: ".php5", contentType: "application/octet-stream", prefix: "<?php //", signal: "php5_extension_bypass"},
		{extension: ".phar", contentType: "application/octet-stream", prefix: "<?php //", signal: "phar_extension_bypass"},
		{extension: ".pHP", contentType: "image/png", prefix: "<?php //", signal: "case_extension_bypass"},
		{extension: ".php;.png", contentType: "image/png", prefix: "<?php //", signal: "semicolon_extension_bypass"},
		{extension: ".php.jpg", contentType: "image/jpeg", prefix: "<?php //", signal: "double_extension_bypass"},
		{extension: ".php%00.jpg", contentType: "image/jpeg", prefix: "<?php //", signal: "null_byte_extension_bypass"},
		{extension: ".jsp", contentType: "text/plain", prefix: "<% out.print(\"AKCA_JSP\"); %>", signal: "jsp_upload"},
		{extension: ".jspx", contentType: "text/xml", prefix: "<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\" version=\"2.0\"><jsp:text>AKCA_JSPX</jsp:text></jsp:root>", signal: "jspx_upload"},
		{extension: ".aspx", contentType: "text/plain", prefix: "<%@ Page Language=\"C#\" %><% Response.Write(\"AKCA_ASPX\"); %>", signal: "aspx_upload"},
		{extension: ".shtml", contentType: "text/html", prefix: "<!--#echo var=\"DOCUMENT_ROOT\" -->", signal: "ssi_upload"},
		{extension: ".jpg", contentType: "application/x-php", prefix: "", signal: "content_type_mismatch"},
		{extension: ".gif", contentType: "image/gif", prefix: "GIF89a<?php //", signal: "polyglot_gif_php"},
		{extension: ".jpg", contentType: "image/jpeg", prefix: "\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00", signal: "polyglot_jpeg_php"},
		{extension: ".svg", contentType: "image/svg+xml", prefix: "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script>", signal: "svg_stored_xss"},
		{extension: ".html", contentType: "text/html", prefix: "<iframe src=\"http://169.254.169.254/latest/meta-data/\"></iframe>", signal: "html_pdf_ssrf"},
		{extension: "", contentType: "application/octet-stream", prefix: "AddType application/x-httpd-php .png\n", signal: "htaccess_override", customFilename: ".htaccess"},
		{extension: "", contentType: "text/plain", prefix: "auto_prepend_file=none\n", signal: "user_ini_override", customFilename: ".user.ini"},
		{extension: "", contentType: "text/xml", prefix: "<configuration><system.webServer><handlers><add name=\"akca\" path=\"*.png\" verb=\"*\" type=\"System.Web.UI.PageHandlerFactory\" /></handlers></system.webServer></configuration>", signal: "web_config_override", customFilename: "web.config"},
	} {
		token := randomToken(12)
		filename := "akca-upload-" + token + probe.extension
		if probe.customFilename != "" {
			filename = probe.customFilename
		}
		marker := "AKCA_UPLOAD_" + token
		expectedContent := []byte(probe.prefix + marker)
		body, contentType, err := buildUploadBody(filename, probe.contentType, expectedContent)
		if err != nil {
			continue
		}
		cleanupURL := strings.ReplaceAll(cleanupPolicy.CleanupURL, "{{filename}}", url.PathEscape(filename))
		if strings.Contains(cleanupURL, "{{") || !r.scope.IsInScope(cleanupURL) {
			r.emitSkip("file_upload", target, "cleanup URL must be fully resolvable and in scope before upload")
			return out
		}
		before, err := r.client.Do(ctx, http.MethodGet, target.EndpointURL, nil, nil)
		if err != nil || before.Response.StatusCode == 0 {
			continue
		}
		guard := r.safeMutationGuard()
		tx, guardErr := guard.Begin(safemutation.Operation{
			ID:         "file_upload:" + cleanupPolicy.ID + ":" + filename,
			ResourceID: target.EndpointURL + "#" + filename,
			Risk:       safemutation.ReversibleWrite, CleanupDefined: true,
		}, resourceFingerprint(before.Response.Body))
		if guardErr != nil {
			continue
		}
		method := strings.ToUpper(strings.TrimSpace(target.Method))
		if method != http.MethodPost && method != http.MethodPut && method != http.MethodPatch {
			method = http.MethodPost
		}
		uploadRR, err := r.client.Do(ctx, method, target.EndpointURL, body, map[string]string{
			"Content-Type": contentType, "X-Akca-Canary": tx.Canary,
		})
		uploadAccepted := err == nil && uploadRR.Response.StatusCode >= 200 && uploadRR.Response.StatusCode < 300
		var retrieval httpclient.RequestResponse
		verifiedLocation := ""
		locations := uploadLocations(target.EndpointURL, filename, uploadRR.Response.Headers, uploadRR.Response.Body)
		for _, location := range locations {
			if !r.scope.IsInScope(location) {
				continue
			}
			candidate, getErr := r.client.Do(ctx, http.MethodGet, location, nil, nil)
			if getErr != nil || candidate.Response.StatusCode != http.StatusOK ||
				contentDigest([]byte(candidate.Response.Body)) != contentDigest(expectedContent) {
				continue
			}
			retrieval = candidate
			verifiedLocation = location
			break
		}

		// Cleanup is attempted after every upload request, including transport
		// errors and non-2xx responses: the server may have persisted the body
		// before returning an error.
		cleanupRequest, cleanupErr := r.client.Do(ctx, strings.ToUpper(cleanupPolicy.CleanupMethod), cleanupURL, nil, nil)
		afterCleanup, stateErr := r.client.Do(ctx, http.MethodGet, target.EndpointURL, nil, nil)
		cleanupOK := cleanupErr == nil && cleanupRequest.Response.StatusCode >= 200 &&
			cleanupRequest.Response.StatusCode < 300
		cleanupControl := afterCleanup
		if verifiedLocation != "" {
			locationControl, locationErr := r.client.Do(ctx, http.MethodGet, verifiedLocation, nil, nil)
			cleanupControl = locationControl
			cleanupOK = cleanupOK && locationErr == nil &&
				(locationControl.Response.StatusCode == http.StatusNotFound || locationControl.Response.StatusCode == http.StatusGone ||
					!strings.Contains(locationControl.Response.Body, marker))
		} else {
			cleanupOK = cleanupOK && stateErr == nil &&
				sameResourceFingerprint(before.Response.Body, afterCleanup.Response.Body)
		}
		afterHash := ""
		if verifiedLocation != "" {
			afterHash = contentDigest(expectedContent)
		}
		if _, finishErr := guard.Finish(tx.ID, afterHash, cleanupOK); finishErr != nil {
			return out
		}
		if !uploadAccepted || verifiedLocation == "" {
			continue
		}
		p := defaultPayload("file_upload", probe.signal, marker, "retrieved_hash_confirmed")
		finding := r.verifyAndBuildWithCandidate(ctx, "file_upload", target, p, uploadRR, retrieval,
			"retrieved_hash_confirmed", false, false, "", "", func(candidate *verification.Candidate) {
				candidate.RequestedProofType = verification.ProofFileRetrieval
				candidate.NegativeControlSet = true
				candidate.NegativeControlOK = true
				candidate.Observations = append(candidate.Observations,
					r.observation("file_upload", target, verification.RoleStateAfter, 1, retrieval),
					r.observation("file_upload", target, verification.RoleNegativeControl, 1, cleanupControl),
				)
			})
		if finding != nil {
			finding.Title = "Unrestricted file upload (retrieval and cleanup confirmed)"
			finding.Description = "A harmless " + probe.signal + " canary was uploaded, retrieved from the server-provided location with an exact content hash, then deleted and independently confirmed absent. Server-side execution was not attempted."
			finding.Evidence.ResponseMarkers = append(finding.Evidence.ResponseMarkers, filename, verifiedLocation, contentDigest(expectedContent))
			r.recordFinding(ctx, &out, finding, "file_upload", "retrieved_hash_confirmed")
			return out
		}
	}
	return out
}

func (r *Runner) fileUploadPolicy(target ScanTarget) (config.FileUploadProofPolicy, bool) {
	for _, policy := range r.cfg.FileUploadProofPolicies {
		if strings.Contains(target.EndpointURL, policy.URLContains) {
			return policy, true
		}
	}
	return config.FileUploadProofPolicy{}, false
}

func contentDigest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func buildUploadBody(filename, contentType string, content []byte) ([]byte, string, error) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	header := make(textproto.MIMEHeader)
	header.Set("Content-Disposition", `form-data; name="file"; filename="`+strings.ReplaceAll(filename, `"`, "")+`"`)
	header.Set("Content-Type", contentType)
	part, err := writer.CreatePart(header)
	if err != nil {
		return nil, "", err
	}
	if _, err := part.Write(content); err != nil {
		return nil, "", err
	}
	if err := writer.Close(); err != nil {
		return nil, "", err
	}
	return body.Bytes(), writer.FormDataContentType(), nil
}

var uploadURLPattern = regexp.MustCompile(`https?://[^\s"'<>]+|/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+`)

func uploadLocations(endpoint, filename string, headers map[string]string, responseBody string) []string {
	base, err := url.Parse(endpoint)
	if err != nil {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	add := func(raw string) {
		raw = strings.TrimRight(strings.TrimSpace(raw), ").,;]")
		if raw == "" || !strings.Contains(raw, filename) {
			return
		}
		candidate, parseErr := url.Parse(raw)
		if parseErr != nil {
			return
		}
		candidate = base.ResolveReference(candidate)
		candidate.Fragment = ""
		value := candidate.String()
		if _, exists := seen[value]; exists {
			return
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	for name, value := range headers {
		if strings.EqualFold(name, "Location") || strings.EqualFold(name, "Content-Location") {
			add(value)
		}
	}
	var decoded interface{}
	if json.Unmarshal([]byte(responseBody), &decoded) == nil {
		walkUploadJSON(decoded, add)
	}
	for _, match := range uploadURLPattern.FindAllString(responseBody, -1) {
		add(match)
	}
	// Some upload APIs return only the filename. Resolve it beside the upload
	// endpoint, but never guess unrelated /uploads or /files directories.
	if strings.Contains(responseBody, filename) {
		baseCopy := *base
		baseCopy.Path = path.Join(path.Dir(base.Path), filename)
		baseCopy.RawQuery = ""
		add(baseCopy.String())
	}
	return out
}

func walkUploadJSON(value interface{}, add func(string)) {
	switch typed := value.(type) {
	case map[string]interface{}:
		for key, child := range typed {
			switch strings.ToLower(key) {
			case "url", "location", "path", "download_url", "file_url":
				if raw, ok := child.(string); ok {
					add(raw)
				}
			}
			walkUploadJSON(child, add)
		}
	case []interface{}:
		for _, child := range typed {
			walkUploadJSON(child, add)
		}
	}
}
