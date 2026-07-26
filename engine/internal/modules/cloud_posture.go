package modules

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/akha-security/akca/engine/internal/cloudposture"
	"github.com/akha-security/akca/engine/internal/httpclient"
)

func (r *Runner) runCloudPosture(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("cloud_posture", target); !ok {
		r.emitSkip("cloud_posture", target, reason)
		return nil
	}
	var out []ModuleFinding
	baseline := httpclient.RequestResponse{Response: httpclient.ResponseRecord{StatusCode: 403, Body: "denied"}}

	contents := r.gatherClientSideContent(ctx, target)
	seenCreds := map[string]struct{}{}
	for _, content := range contents {
		creds := cloudposture.ExtractCredentials(content)
		key := creds.CognitoUserPoolID + creds.FirebaseAPIKey + creds.CognitoIdentityPoolID + creds.Auth0Domain
		if key == "" {
			continue
		}
		if _, ok := seenCreds[key]; ok {
			continue
		}
		seenCreds[key] = struct{}{}
		out = append(out, r.runAuthProviderAbuse(ctx, target, baseline, creds)...)
	}

	out = append(out, r.runTFStateExposure(ctx, target, baseline, contents)...)
	return out
}

func (r *Runner) gatherClientSideContent(ctx context.Context, target ScanTarget) []string {
	var bodies []string
	rr, err := r.cachedEmptyProbe(ctx, target)
	if err == nil && len(rr.Response.Body) > 0 {
		bodies = append(bodies, rr.Response.Body)
	}
	u, err := url.Parse(target.EndpointURL)
	if err != nil {
		return bodies
	}
	base := u.Scheme + "://" + u.Host
	for _, path := range []string{"/main.js", "/app.js", "/static/js/main.js", "/assets/index.js", "/env.js", "/config.js"} {
		rawURL := strings.TrimRight(base, "/") + path
		if !r.scope.IsInScope(rawURL) {
			continue
		}
		jsRR, err := r.client.Do(ctx, http.MethodGet, rawURL, nil, nil)
		if err != nil || jsRR.Response.StatusCode != 200 || len(jsRR.Response.Body) < 50 {
			continue
		}
		bodies = append(bodies, jsRR.Response.Body)
	}
	return bodies
}

func (r *Runner) runAuthProviderAbuse(ctx context.Context, target ScanTarget, baseline httpclient.RequestResponse, creds cloudposture.Credentials) []ModuleFinding {
	client := &http.Client{Timeout: 12 * time.Second}
	var out []ModuleFinding
	probes := cloudposture.BuildProbes(creds)
	for _, probe := range probes {
		if ctx.Err() != nil {
			break
		}
		status, body, err := cloudposture.ExecuteProbe(client, probe)
		if err != nil {
			continue
		}
		ok, signal := cloudposture.InterpretAbuseResponse(probe, status, body)
		if !ok {
			continue
		}
		if probe.Signal == "cognito_identity_pool_access" && signal == "cognito_guest_identity" {
			if id := cloudposture.ExtractIdentityIDFromGetId(body); id != "" && creds.HasIdentityPool() {
				credProbe := cloudposture.BuildCognitoCredentialsProbe(creds, id)
				st2, b2, err2 := cloudposture.ExecuteProbe(client, credProbe)
				if err2 == nil {
					if ok2, sig2 := cloudposture.InterpretAbuseResponse(credProbe, st2, b2); ok2 {
						out = append(out, r.recordCloudPostureFinding(ctx, target, baseline, credProbe, st2, b2, sig2, creds)...)
					}
				}
			}
		}
		out = append(out, r.recordCloudPostureFinding(ctx, target, baseline, probe, status, body, signal, creds)...)
		if len(out) >= 3 {
			break
		}
	}
	return out
}

func (r *Runner) recordCloudPostureFinding(ctx context.Context, target ScanTarget, baseline httpclient.RequestResponse,
	probe cloudposture.AbuseProbe, status int, body, signal string, creds cloudposture.Credentials) []ModuleFinding {
	p := defaultPayload("cloud_posture", probe.Name, probe.URL, signal)
	probeRR := httpclient.RequestResponse{
		Request: httpclient.RequestRecord{
			Method: probe.Method, URL: probe.URL, Headers: probe.Headers, Body: probe.Body,
		},
		Response: httpclient.ResponseRecord{
			StatusCode: status, Body: truncateCloud(body, 4000),
		},
	}
	f := r.verifyAndBuild(ctx, "cloud_posture", target, p, baseline, probeRR, signal, false, false, "", "")
	if f == nil {
		return nil
	}
	severity := "high"
	if strings.Contains(signal, "sts") || strings.Contains(signal, "credentials") {
		severity = "critical"
	}
	f.Title = "Cloud auth provider abuse (" + signal + ")"
	f.Severity = severity
	f.VulnClass = "cloud_posture"
	f.Description = probe.Description + " — " + signal
	// Preserve the verifier's score, reasons, and proof metadata. Only replace
	// the external cloud exchange fields on the existing evidence object.
	f.Evidence.Module = "cloud_posture"
	f.Evidence.Signal = signal
	f.Evidence.Payload = p
	f.Evidence.Request = probeRR.Request
	f.Evidence.Response = probeRR.Response
	var out []ModuleFinding
	r.recordFinding(&out, f, "cloud_posture", signal)
	return out
}

func (r *Runner) runTFStateExposure(ctx context.Context, target ScanTarget, baseline httpclient.RequestResponse, contents []string) []ModuleFinding {
	var out []ModuleFinding
	seenBases := map[string]struct{}{}
	var bases []string
	addBase := func(raw string) {
		base := cloudAssetBase(raw)
		if base == "" {
			return
		}
		if _, exists := seenBases[base]; exists {
			return
		}
		seenBases[base] = struct{}{}
		bases = append(bases, base)
	}
	addBase(target.EndpointURL)
	for _, content := range contents {
		for _, raw := range cloudStorageURLPattern.FindAllString(content, -1) {
			addBase(raw)
		}
	}
	for _, base := range bases {
		for _, path := range cloudposture.TFStatePaths {
			rawURL := strings.TrimRight(base, "/") + path
			if !r.scope.IsInScope(rawURL) {
				continue
			}
			rr, err := r.client.Do(ctx, http.MethodGet, rawURL, nil, nil)
			if err != nil || rr.Response.StatusCode != 200 {
				continue
			}
			if !cloudposture.IsTFState(rr.Response.Body) {
				continue
			}
			findings := cloudposture.AnalyzeTFState(rr.Response.Body)
			if len(findings) == 0 {
				p := defaultPayload("cloud_posture", "tfstate_exposed", rawURL, "tfstate_exposed")
				subTarget := target
				subTarget.EndpointURL = rawURL
				f := r.verifyAndBuild(ctx, "cloud_posture", subTarget, p, baseline, rr, "tfstate_exposed", false, false, "", "")
				if f != nil {
					f.Title = "Exposed Terraform state " + rawURL
					f.Severity = "critical"
					f.VulnClass = "cloud_posture"
					r.recordFinding(&out, f, "cloud_posture", "tfstate_exposed")
				}
				continue
			}
			for _, tf := range findings {
				if len(out) >= 5 {
					break
				}
				p := defaultPayload("cloud_posture", tf.Field, tf.Redacted, "tfstate_secret")
				subTarget := target
				subTarget.EndpointURL = rawURL
				f := r.verifyAndBuild(ctx, "cloud_posture", subTarget, p, baseline, rr, "tfstate_secret", false, false, "", "")
				if f == nil {
					continue
				}
				f.Title = fmt.Sprintf("Terraform state leak (%s) in %s", tf.Field, tf.ResourceType)
				f.Severity = tf.Severity
				f.VulnClass = "cloud_posture"
				f.Description = fmt.Sprintf("Cleartext %s in exposed tfstate at %s", tf.Field, rawURL)
				r.recordFinding(&out, f, "cloud_posture", "tfstate_secret")
			}
		}
	}
	return out
}

func cloudAssetBase(rawURL string) string {
	if cloudStorageProvider(rawURL) == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	base := u.Scheme + "://" + u.Host
	if strings.EqualFold(u.Hostname(), "storage.googleapis.com") {
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(parts) > 0 && parts[0] != "" {
			base += "/" + parts[0]
		}
	} else if strings.HasSuffix(strings.ToLower(u.Hostname()), ".blob.core.windows.net") {
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(parts) > 0 && parts[0] != "" {
			base += "/" + parts[0]
		}
	}
	return strings.TrimRight(base, "/")
}

func truncateCloud(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
