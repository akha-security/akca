package modules

import (
	"context"
	"net/url"
	"regexp"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

var cloudStorageURLPattern = regexp.MustCompile(`https?://[^\s"'<>]+`)

func (r *Runner) runCloudStorage(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("cloud_storage", target); !ok {
		r.emitSkip("cloud_storage", target, reason)
		return nil
	}
	baselineResponse, err := r.cachedEmptyProbe(ctx, target)
	if err != nil {
		return nil
	}
	baseline := httpclient.RequestResponse{Response: httpclient.ResponseRecord{StatusCode: 403, Body: "access denied"}}
	var out []ModuleFinding
	for _, rawURL := range cloudStorageCandidates(target.EndpointURL, baselineResponse.Response.Body) {
		if !r.scope.IsInScope(rawURL) {
			r.emitOnce("cloud-scope:"+rawURL, "module_notice", "Discovered cloud storage asset was not actively tested because it is outside scope", map[string]interface{}{
				"module": "cloud_storage", "asset": rawURL,
			})
			continue
		}
		rr, err := r.client.Do(ctx, "GET", rawURL, nil, nil)
		if err != nil {
			continue
		}
		if !cloudStorageSignal(rr.Response.StatusCode, rr.Response.Body) {
			continue
		}
		signal := cloudStorageProvider(rawURL)
		p := defaultPayload("cloud_storage", signal, rawURL, signal)
		f := r.verifyAndBuild(ctx, "cloud_storage", target, p, baseline, rr, signal, false, false, "", "")
		r.recordFinding(&out, f, "cloud_storage", signal)
	}
	return out
}

func cloudStorageCandidates(targetURL, body string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(raw string) {
		raw = strings.TrimRight(strings.TrimSpace(raw), ").,;]")
		if raw == "" || cloudStorageProvider(raw) == "" {
			return
		}
		if _, ok := seen[raw]; ok {
			return
		}
		seen[raw] = struct{}{}
		out = append(out, raw)
	}
	add(targetURL)
	for _, raw := range cloudStorageURLPattern.FindAllString(body, -1) {
		add(raw)
	}
	return out
}

func cloudStorageProvider(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	switch {
	case host == "s3.amazonaws.com" || strings.HasSuffix(host, ".s3.amazonaws.com"):
		return "aws_s3"
	case host == "storage.googleapis.com" || strings.HasSuffix(host, ".storage.googleapis.com"):
		return "gcs"
	case strings.HasSuffix(host, ".blob.core.windows.net"):
		return "azure_blob"
	case strings.HasSuffix(host, ".digitaloceanspaces.com"):
		return "do_spaces"
	default:
		return ""
	}
}

func cloudStorageSignal(status int, body string) bool {
	if status == 403 || status == 404 {
		return false
	}
	lower := strings.ToLower(body)
	return status == 200 && (strings.Contains(lower, "<listbucketresult") ||
		strings.Contains(lower, "<enumerationresults") && strings.Contains(lower, "<blobs") ||
		strings.Contains(lower, `"kind"`) && strings.Contains(lower, "storage#objects") ||
		strings.Contains(lower, "<contents>") && strings.Contains(lower, "<key>"))
}
