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
		r.emitSkip("file_upload", target, "explicit cleanup policy is required for automatic upload proof")
		return nil
	}
	var out []ModuleFinding
	for _, probe := range []struct {
		extension, contentType, prefix, signal string
	}{
		{".php", "image/png", "", "extension_bypass"},
		{".jpg", "application/x-php", "", "content_type_mismatch"},
		{".gif", "image/gif", "GIF89a", "polyglot"},
	} {
		token := randomToken(12)
		filename := "akca-upload-" + token + probe.extension
		marker := "AKCA_UPLOAD_" + token
		expectedContent := []byte(probe.prefix + marker)
		body, contentType, err := buildUploadBody(filename, probe.contentType, expectedContent)
		if err != nil {
			continue
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
		if err != nil || uploadRR.Response.StatusCode < 200 || uploadRR.Response.StatusCode >= 300 {
			_, _ = guard.Finish(tx.ID, "", false)
			continue
		}
		finished := false
		locations := uploadLocations(target.EndpointURL, filename, uploadRR.Response.Headers, uploadRR.Response.Body)
		for _, location := range locations {
			if !r.scope.IsInScope(location) {
				continue
			}
			retrieval, getErr := r.client.Do(ctx, http.MethodGet, location, nil, nil)
			if getErr != nil || retrieval.Response.StatusCode != http.StatusOK ||
				contentDigest([]byte(retrieval.Response.Body)) != contentDigest(expectedContent) {
				continue
			}
			cleanupURL := strings.ReplaceAll(cleanupPolicy.CleanupURL, "{{location}}", location)
			cleanupURL = strings.ReplaceAll(cleanupURL, "{{filename}}", url.PathEscape(filename))
			if !r.scope.IsInScope(cleanupURL) {
				_, _ = guard.Finish(tx.ID, "", false)
				continue
			}
			cleanupRequest, cleanupErr := r.client.Do(ctx, strings.ToUpper(cleanupPolicy.CleanupMethod), cleanupURL, nil, nil)
			if cleanupErr != nil || cleanupRequest.Response.StatusCode < 200 || cleanupRequest.Response.StatusCode >= 300 {
				_, _ = guard.Finish(tx.ID, "", false)
				continue
			}
			cleanupControl, cleanupGetErr := r.client.Do(ctx, http.MethodGet, location, nil, nil)
			cleanupOK := cleanupGetErr == nil &&
				(cleanupControl.Response.StatusCode == http.StatusNotFound ||
					cleanupControl.Response.StatusCode == http.StatusGone)
			if _, finishErr := guard.Finish(tx.ID, contentDigest(expectedContent), cleanupOK); finishErr != nil {
				return out
			}
			finished = true
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
			if finding == nil {
				continue
			}
			finding.Title = "Unrestricted file upload (retrieval and cleanup confirmed)"
			finding.Description = "A harmless " + probe.signal + " canary was uploaded, retrieved from the server-provided location with an exact content hash, then deleted and independently confirmed absent. Server-side execution was not attempted."
			finding.Evidence.ResponseMarkers = append(finding.Evidence.ResponseMarkers, filename, location, contentDigest(expectedContent))
			r.recordFinding(&out, finding, "file_upload", "retrieved_hash_confirmed")
			break
		}
		if !finished {
			_, _ = guard.Finish(tx.ID, "", false)
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
