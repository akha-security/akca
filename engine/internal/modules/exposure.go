package modules

import (
	"context"
	"crypto/sha1"
	"fmt"
	"net/http"
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
	rr, err := r.cachedEmptyProbe(ctx, target)
	if err != nil {
		return nil
	}
	if rr.Response.Redirected && isRedirectedAway(rr, target.EndpointURL) {
		return nil
	}
	baselineRR := httpclient.RequestResponse{Response: httpclient.ResponseRecord{StatusCode: 200, Headers: map[string]string{}}}
	findings := sensitivedata.Analyze(rr.Response.Body)
	if len(findings) == 0 {
		return nil
	}
	// Directory indexes are passive, typed content evidence. Mutating a query
	// parameter is neither a meaningful negative control nor safe proof here;
	// for parameterless paths it simply fetched the same listing and suppressed
	// a genuine finding as a baseline match.
	needsDifferentialBaseline := false
	for _, hit := range findings {
		if hit.Kind != "directory_listing" {
			needsDifferentialBaseline = true
			break
		}
	}
	differentialBaselineReady := r.cfg.PassiveMode || !needsDifferentialBaseline
	if !r.cfg.PassiveMode && needsDifferentialBaseline {
		candidateBaseline, baselineErr := r.probe(ctx, target, "akca-sensitive-base")
		if baselineErr == nil && candidateBaseline.Response.StatusCode == rr.Response.StatusCode &&
			candidateBaseline.Response.Redirected == rr.Response.Redirected {
			baselineRR = candidateBaseline
			differentialBaselineReady = true
		}
	}
	baseFindings := sensitivedata.Analyze(baselineRR.Response.Body)
	var out []ModuleFinding
	for _, hit := range findings {
		if len(out) >= 3 {
			break
		}
		if hit.Kind == "directory_listing" && rr.Response.StatusCode != http.StatusOK {
			continue
		}
		proofBaseline := baselineRR
		if hit.Kind == "directory_listing" {
			proofBaseline = httpclient.RequestResponse{Response: httpclient.ResponseRecord{StatusCode: 200, Headers: map[string]string{}}}
		} else if !differentialBaselineReady {
			continue
		}
		if hit.Kind != "directory_listing" && sensitiveDataFindingExists(baseFindings, hit.Kind, hit.Match) {
			continue
		}
		p := defaultPayload("sensitive_data", hit.Kind, hit.Match, hit.Kind)
		f := r.verifyAndBuild(ctx, "sensitive_data", target, p, proofBaseline, rr, hit.Kind, false, false, "", "")
		if f == nil {
			continue
		}
		f.Title = "Sensitive data exposure (" + hit.Kind + ")"
		f.Severity = hit.Severity
		f.Description = hit.Kind + " detected in response body"
		if hit.Kind == "directory_listing" {
			f.Title = "Directory listing enabled"
			f.Description = "The web server exposes the contents of this directory (CWE-548). Disable directory indexing or restrict access to prevent unintended file and path disclosure."
		}
		r.recordFinding(ctx, &out, f, "sensitive_data", hit.Kind)
	}
	return out
}

func sensitiveDataFindingExists(findings []sensitivedata.Finding, kind, match string) bool {
	for _, finding := range findings {
		if finding.Kind == kind && finding.Match == match {
			return true
		}
	}
	return false
}

func sensitiveDataSignalConfirmed(body, baseline, kind, match string) bool {
	if body == baseline {
		return false
	}
	hits := sensitivedata.Analyze(body)
	if !sensitiveDataFindingExists(hits, kind, match) {
		return false
	}
	return !sensitiveDataFindingExists(sensitivedata.Analyze(baseline), kind, match)
}

func (r *Runner) runSecretExposure(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("secret_exposure", target); !ok {
		r.emitSkip("secret_exposure", target, reason)
		return nil
	}
	rr, err := r.cachedPassiveContentProbe(ctx, "secret_exposure", target)
	if err != nil {
		return nil
	}
	baselineRR := httpclient.RequestResponse{Response: httpclient.ResponseRecord{StatusCode: 200, Headers: map[string]string{}}}
	matches := r.cachedSecretMatches(rr.Response.Body)
	if len(matches) == 0 {
		return nil
	}
	var out []ModuleFinding
	for _, m := range matches {
		if len(out) >= 3 {
			break
		}
		if !secretscan.IsReportable(m) {
			continue
		}
		p := defaultPayload("secret_exposure", m.Kind, m.Value, m.Kind)
		f := r.verifyAndBuild(ctx, "secret_exposure", target, p, baselineRR, rr, m.Kind, false, false, "", "")
		if f == nil {
			continue
		}
		f.Title = "Secret exposure (" + strings.ReplaceAll(m.Kind, "_", " ") + ")"
		f.Description = m.Kind + " detected in response body"
		f.Evidence.Response.Body = secretEvidenceSnippet(rr.Response.Body, m.Value)
		switch {
		case strings.Contains(m.Kind, "private_key") || strings.Contains(m.Kind, "secret_access_key") ||
			strings.Contains(m.Kind, "stripe_secret") || strings.Contains(m.Kind, "db_connection") ||
			strings.Contains(m.Kind, "vault_token") || strings.Contains(m.Kind, "snowflake") ||
			strings.Contains(m.Kind, "github_token") || strings.Contains(m.Kind, "gitlab_pat"):
			f.Severity = "critical"
		case strings.Contains(m.Kind, "token") || strings.Contains(m.Kind, "key") || strings.Contains(m.Kind, "secret"):
			f.Severity = "high"
		default:
			f.Severity = "medium"
		}
		r.recordFinding(ctx, &out, f, "secret_exposure", m.Kind)
	}
	return out
}

func secretEvidenceSnippet(body, secret string) string {
	const contextWindow = 80
	if body == "" || secret == "" {
		return truncateCloud(body, contextWindow*2)
	}
	idx := strings.Index(body, secret)
	if idx < 0 {
		return truncateCloud(body, contextWindow*2)
	}
	start := idx - contextWindow
	if start < 0 {
		start = 0
	}
	end := idx + len(secret) + contextWindow
	if end > len(body) {
		end = len(body)
	}
	prefix := ""
	if start > 0 {
		prefix = "... "
	}
	suffix := ""
	if end < len(body) {
		suffix = " ..."
	}
	return prefix + body[start:end] + suffix
}

func (r *Runner) cachedPassiveContentProbe(ctx context.Context, module string, target ScanTarget) (httpclient.RequestResponse, error) {
	key := passiveContentProbeKey(module, target)
	r.baselineMu.Lock()
	if rr, ok := r.baselineCache[key]; ok {
		r.baselineMu.Unlock()
		return rr, nil
	}
	r.baselineMu.Unlock()

	rr, err := r.probeWithoutInjectedPayload(ctx, module, target)
	if err != nil {
		return httpclient.RequestResponse{}, err
	}
	r.baselineMu.Lock()
	r.baselineCache[key] = rr
	r.baselineMu.Unlock()
	return rr, nil
}

func passiveContentProbeKey(module string, target ScanTarget) string {
	return fmt.Sprintf("passive-content|%s|%s|%s|%s", module, strings.ToUpper(target.Method), target.EndpointURL, target.Profile.ContentType)
}

func (r *Runner) cachedSecretMatches(content string) []secretscan.Match {
	sum := sha1.Sum([]byte(content))
	key := fmt.Sprintf("%x|%d", sum, len(content))
	r.secretScanMu.Lock()
	if matches, ok := r.secretScanCache[key]; ok {
		r.secretScanMu.Unlock()
		return matches
	}
	r.secretScanMu.Unlock()

	matches := secretscan.Detect(content)
	r.secretScanMu.Lock()
	r.secretScanCache[key] = matches
	r.secretScanMu.Unlock()
	return matches
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
		if rr.Response.Redirected && isRedirectedAway(rr, rawURL) {
			continue
		}
		if isHTMLResponse(rr.Response) {
			continue
		}
		if !cicdExposureSignal(path, rr.Response.Body) {
			continue
		}
		p := defaultPayload("cicd_exposure", "exposed_artifact", path, "exposed_artifact")
		f := r.verifyAndBuild(ctx, "cicd_exposure", target, p, baseline, rr, "exposed_artifact", false, false, "", "")
		r.recordFinding(ctx, &out, f, "cicd_exposure", "exposed_artifact")
	}
	return out
}

func cicdExposureSignal(path, body string) bool {
	lower := strings.ToLower(body)
	if strings.Contains(lower, "<html") || strings.Contains(lower, "<!doctype") || strings.Contains(lower, "<head") {
		return false
	}
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
	lower := strings.ToLower(body)
	if strings.Contains(lower, "<html") || strings.Contains(lower, "<!doctype") || strings.Contains(lower, "<head") {
		return false
	}
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
		eqIdx := strings.Index(line, "=")
		key := strings.TrimSpace(line[:eqIdx])
		if strings.ContainsAny(key, " <>\t\"'/\\") {
			continue
		}
		lowerLine := strings.ToLower(line)
		if strings.Contains(lowerLine, "secret") || strings.Contains(lowerLine, "password") ||
			strings.Contains(lowerLine, "api_key") || strings.Contains(lowerLine, "token") ||
			strings.Contains(lowerLine, "app_key") || strings.Contains(lowerLine, "database_url") {
			hits++
		}
	}
	return hits >= 1
}
