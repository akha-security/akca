package modules

import (
	"context"
	"net/url"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/secretscan"
	"github.com/akha-security/akca/engine/internal/sensitivedata"
)

var cicdPaths = []string{
	"/.git/HEAD", "/.env", "/.gitlab-ci.yml", "/Jenkinsfile",
	"/.github/workflows/main.yml", "/docker-compose.yml", "/.aws/credentials",
}

func (r *Runner) runSensitiveData(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("sensitive_data", target); !ok {
		r.emitSkip("sensitive_data", target, reason)
		return nil
	}
	baselineRR, err := r.probe(ctx, target, "akca-sensitive-base")
	if err != nil {
		return nil
	}
	rr, err := r.cachedEmptyProbe(ctx, target)
	if err != nil {
		return nil
	}
	findings := sensitivedata.Analyze(rr.Response.Body)
	if len(findings) == 0 {
		return nil
	}
	baseFindings := sensitivedata.Analyze(baselineRR.Response.Body)
	baseKinds := map[string]bool{}
	for _, bh := range baseFindings {
		baseKinds[bh.Kind] = true
	}
	var out []ModuleFinding
	for _, hit := range findings {
		if len(out) >= 3 {
			break
		}
		if baseKinds[hit.Kind] {
			continue
		}
		p := defaultPayload("sensitive_data", hit.Kind, hit.Redacted, hit.Kind)
		f := r.verifyAndBuild(ctx, "sensitive_data", target, p, baselineRR, rr, hit.Kind, false, false, "", "")
		if f == nil {
			continue
		}
		f.Title = "Sensitive data exposure (" + hit.Kind + ")"
		f.Severity = hit.Severity
		f.Description = hit.Kind + " detected in response body"
		r.recordFinding(&out, f, "sensitive_data", hit.Kind)
	}
	return out
}

func (r *Runner) runSecretExposure(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("secret_exposure", target); !ok {
		r.emitSkip("secret_exposure", target, reason)
		return nil
	}
	baselineRR, err := r.probe(ctx, target, "akca-secret-base")
	if err != nil {
		return nil
	}
	rr, err := r.cachedEmptyProbe(ctx, target)
	if err != nil {
		return nil
	}
	matches := secretscan.Detect(rr.Response.Body)
	if len(matches) == 0 {
		return nil
	}
	baseMatches := secretscan.Detect(baselineRR.Response.Body)
	var out []ModuleFinding
	for _, m := range matches {
		if len(out) >= 3 {
			break
		}
		if secretMatchInBaseline(m, baseMatches) {
			continue
		}
		p := defaultPayload("secret_exposure", m.Kind, m.Redacted, m.Kind)
		f := r.verifyAndBuild(ctx, "secret_exposure", target, p, baselineRR, rr, m.Kind, false, false, "", "")
		if f == nil {
			continue
		}
		r.recordFinding(&out, f, "secret_exposure", m.Kind)
	}
	return out
}

func secretMatchInBaseline(match secretscan.Match, baseline []secretscan.Match) bool {
	for _, bm := range baseline {
		if bm.Kind == match.Kind && bm.Value == match.Value {
			return true
		}
	}
	return false
}

func (r *Runner) runCICDExposure(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("cicd_exposure", target); !ok {
		r.emitSkip("cicd_exposure", target, reason)
		return nil
	}
	u, err := url.Parse(target.EndpointURL)
	if err != nil {
		return nil
	}
	base := u.Scheme + "://" + u.Host
	baseline := httpclient.RequestResponse{Response: httpclient.ResponseRecord{StatusCode: 404, Body: "not found"}}
	var out []ModuleFinding
	for _, path := range cicdPaths {
		rawURL := base + path
		if !r.scope.IsInScope(rawURL) {
			continue
		}
		rr, err := r.client.Do(ctx, "GET", rawURL, nil, nil)
		if err != nil || rr.Response.StatusCode != 200 {
			continue
		}
		if !cicdExposureSignal(path, rr.Response.Body) {
			continue
		}
		p := defaultPayload("cicd_exposure", "exposed_artifact", path, "exposed_artifact")
		f := r.verifyAndBuild(ctx, "cicd_exposure", target, p, baseline, rr, "exposed_artifact", false, false, "", "")
		r.recordFinding(&out, f, "cicd_exposure", "exposed_artifact")
	}
	return out
}

func cicdExposureSignal(path, body string) bool {
	lower := strings.ToLower(body)
	switch {
	case strings.Contains(path, ".git"):
		return strings.HasPrefix(strings.TrimSpace(body), "ref:")
	case strings.Contains(path, ".env"):
		return envFileSignal(body)
	case strings.Contains(path, "workflow") || strings.Contains(path, "Jenkinsfile"):
		return strings.Contains(lower, "steps") || strings.Contains(lower, "pipeline") ||
			strings.Contains(lower, "on:") || strings.Contains(lower, "stage")
	default:
		return false
	}
}

func envFileSignal(body string) bool {
	lines := strings.Split(body, "\n")
	hits := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, "=") {
			continue
		}
		lower := strings.ToLower(line)
		if strings.Contains(lower, "secret") || strings.Contains(lower, "password") ||
			strings.Contains(lower, "api_key") || strings.Contains(lower, "token") {
			hits++
		}
	}
	return hits >= 1
}
