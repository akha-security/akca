package modules

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/reflection"
)

// runLogicalAuthorization runs session cross-over IDOR and method swimming probes.
func (r *Runner) runLogicalAuthorization(ctx context.Context, target ScanTarget) []ModuleFinding {
	var out []ModuleFinding
	out = append(out, r.runSessionCrossOverIDOR(ctx, target)...)
	out = append(out, r.runMethodSwimming(ctx, target)...)
	return out
}

func (r *Runner) runSessionCrossOverIDOR(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, _ := r.shouldRunModule("idor", target); !ok {
		return nil
	}
	if len(r.cfg.RoleProfiles) < 2 {
		return nil
	}

	roleA, okA := r.resolveAuthProfile(r.cfg.RoleProfiles[0].AuthProfileID)
	roleB, okB := r.resolveAuthProfile(r.cfg.RoleProfiles[1].AuthProfileID)
	if !okA || !okB {
		return nil
	}

	candidates := extractIDCandidates(target.EndpointURL, target.Parameter)
	if len(candidates) == 0 && target.Parameter != "" {
		candidates = []IDCandidate{{Name: target.Parameter, Value: "1", Kind: "numeric"}}
	}
	if len(candidates) == 0 {
		return nil
	}

	var out []ModuleFinding
	for _, cand := range candidates {
		ownBaseline, err := r.probeAsProfile(ctx, roleA, target, cand.Value)
		if err != nil {
			continue
		}
		for _, swap := range idSwapValues(cand.Kind, cand.Value) {
			if swap == cand.Value {
				continue
			}
			for _, pair := range []struct {
				profile config.AuthProfile
				label   string
			}{{roleA, "session_a_on_foreign_id"}, {roleB, "session_b_on_foreign_id"}} {
				rr, err := r.probeAsProfileWithValue(ctx, pair.profile, target, cand.Name, swap)
				if err != nil {
					continue
				}
				if !crossAccountSignal(ownBaseline.Response, rr.Response, pair.profile.Name) {
					continue
				}
				for _, method := range crossAccountMethods(target.Method) {
					if method != strings.ToUpper(target.Method) {
						rrM, err := r.probeAsProfileWithMethod(ctx, pair.profile, target, cand.Name, swap, method)
						if err != nil || !crossAccountWriteSignal(rrM.Response) {
							continue
						}
						p := defaultPayload("idor", pair.label+"_"+strings.ToLower(method), swap, "cross_account_"+strings.ToLower(method))
						f := r.verifyAndBuild(ctx, "idor", target, p, ownBaseline, rrM, "cross_account_"+strings.ToLower(method), false, false, "", "")
						if f != nil {
							f.Title = "IDOR cross-session (" + pair.label + ") " + strings.ToUpper(method) + " on " + cand.Name
							r.recordFinding(&out, f, "idor", pair.label)
						}
						continue
					}
					p := defaultPayload("idor", pair.label, swap, "cross_account_access")
					f := r.verifyAndBuild(ctx, "idor", target, p, ownBaseline, rr, "cross_account_access", false, false, "", "")
					if f != nil {
						f.Title = "IDOR cross-session (" + pair.label + ") on " + cand.Name
						r.recordFinding(&out, f, "idor", pair.label)
					}
					break
				}
			}
		}
	}
	return out
}

func crossAccountMethods(current string) []string {
	current = strings.ToUpper(current)
	if current == "" {
		current = http.MethodGet
	}
	methods := []string{current}
	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		if m != current {
			methods = append(methods, m)
		}
	}
	return methods
}

func crossAccountSignal(own, foreign httpclient.ResponseRecord, _ string) bool {
	if foreign.StatusCode < 200 || foreign.StatusCode >= 400 {
		return false
	}
	if foreign.Body == own.Body {
		return false
	}
	lower := strings.ToLower(foreign.Body)
	if strings.Contains(lower, "unauthorized") || strings.Contains(lower, "forbidden") || strings.Contains(lower, "not found") {
		return false
	}
	sensitive := []string{"email", "account", "user", "invoice", "order", "balance", "ssn", "phone", "address"}
	for _, kw := range sensitive {
		if strings.Contains(lower, kw) && !strings.Contains(strings.ToLower(own.Body), kw) {
			return true
		}
	}
	return false
}

func crossAccountWriteSignal(resp httpclient.ResponseRecord) bool {
	return resp.StatusCode >= 200 && resp.StatusCode < 300 && !strings.Contains(strings.ToLower(resp.Body), "error")
}

func (r *Runner) runStepSkipping(ctx context.Context, target ScanTarget) []ModuleFinding {
	skipURLs := buildStepSkipURLs(target.EndpointURL)
	if len(skipURLs) == 0 {
		return nil
	}

	var out []ModuleFinding
	method := strings.ToUpper(target.Method)
	if method == "" {
		method = http.MethodPost
	}

	for _, skipURL := range skipURLs {
		if !r.scope.IsInScope(skipURL) {
			continue
		}
		baseline, err := r.client.Do(ctx, method, target.EndpointURL, []byte(`{"akca":"baseline"}`), map[string]string{
			"Content-Type": "application/json",
		})
		if err != nil {
			return out
		}
		headers := map[string]string{
			"Content-Type":     "application/json",
			"X-Requested-With": "",
		}
		body := `{"akca":"step_skip","confirmed":true,"state":"complete"}`
		rr, err := r.client.Do(ctx, method, skipURL, []byte(body), mergeHeaders(headers, r.wafHeaders(skipURL)))
		if err != nil {
			continue
		}
		if !stepSkipSignal(rr.Response, baseline.Response) {
			continue
		}
		p := defaultPayload("csrf", "step_skipping", skipURL, "workflow_step_skip")
		skipTarget := target
		skipTarget.EndpointURL = skipURL
		f := r.verifyAndBuild(ctx, "csrf", skipTarget, p, baseline, rr, "workflow_step_skip", false, false, "", "")
		if f != nil {
			f.Title = "Multi-step workflow bypass (step skipping) " + skipURL
			r.recordFinding(&out, f, "csrf", "workflow_step_skip")
		}

		for _, qv := range stepSkipQueryVariants(parseQuery(skipURL)) {
			polluted := skipURL
			if strings.Contains(skipURL, "?") {
				polluted = skipURL + "&" + qv
			} else {
				polluted = skipURL + "?" + qv
			}
			if !r.scope.IsInScope(polluted) {
				continue
			}
			rrP, err := r.client.Do(ctx, method, polluted, []byte(body), mergeHeaders(headers, r.wafHeaders(polluted)))
			if err != nil || !stepSkipSignal(rrP.Response, baseline.Response) {
				continue
			}
			p2 := defaultPayload("csrf", "step_pollution", polluted, "parameter_pollution_skip")
			f2 := r.verifyAndBuild(ctx, "csrf", skipTarget, p2, baseline, rrP, "parameter_pollution_skip", false, false, "", "")
			if f2 != nil {
				f2.Title = "Multi-step bypass via parameter pollution " + polluted
				r.recordFinding(&out, f2, "csrf", "parameter_pollution_skip")
			}
			break
		}
	}
	return out
}

func stepSkipSignal(probe, baseline httpclient.ResponseRecord) bool {
	if probe.StatusCode < 200 || probe.StatusCode >= 400 {
		return false
	}
	lower := strings.ToLower(probe.Body)
	if strings.Contains(lower, "csrf") || strings.Contains(lower, "invalid step") || strings.Contains(lower, "out of order") {
		return false
	}
	if strings.Contains(lower, "complete") || strings.Contains(lower, "receipt") || strings.Contains(lower, "success") || strings.Contains(lower, "confirmed") {
		return true
	}
	return probe.Body != baseline.Body && probe.StatusCode == 200
}

func parseQuery(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.RawQuery
}

func (r *Runner) runMethodSwimming(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, _ := r.shouldRunModule("idor", target); !ok {
		return nil
	}
	method := strings.ToUpper(target.Method)
	if method == "" {
		method = http.MethodPost
	}
	if method != http.MethodPost && method != http.MethodPut && method != http.MethodPatch {
		return nil
	}

	var out []ModuleFinding
	jsonBody := `{"akca":"swim","role":"user"}`
	baseline, err := r.probeWithBody(ctx, target, jsonBody, "application/json", nil)
	if err != nil {
		return nil
	}

	swims := []struct {
		method      string
		body        string
		contentType string
		signal      string
	}{
		{http.MethodGet, "", "", "get_method_swim"},
		{http.MethodPatch, jsonBody, "application/json", "patch_method_swim"},
		{http.MethodPost, "akca=swim&role=admin", "application/x-www-form-urlencoded", "form_urlencoded_swim"},
		{http.MethodPost, "<akca>swim</akca>", "text/xml", "xml_content_swim"},
		{http.MethodPost, "--akca\r\nContent-Disposition: form-data; name=\"akca\"\r\n\r\nswim\r\n--akca--", "multipart/form-data; boundary=akca", "multipart_swim"},
	}

	for _, swim := range swims {
		var rr httpclient.RequestResponse
		var err error
		if swim.method == http.MethodGet {
			rawURL, injErr := injectParameter(target.EndpointURL, target.Parameter, "swim")
			if injErr != nil {
				continue
			}
			rr, err = r.client.Do(ctx, http.MethodGet, rawURL, nil, r.wafHeaders(target.EndpointURL))
		} else {
			headers := map[string]string{}
			if swim.contentType != "" {
				headers["Content-Type"] = swim.contentType
			}
			rr, err = r.client.Do(ctx, swim.method, target.EndpointURL, []byte(swim.body), mergeHeaders(headers, r.wafHeaders(target.EndpointURL)))
		}
		if err != nil || !methodSwimSignal(rr.Response, baseline.Response) {
			continue
		}
		p := defaultPayload("idor", swim.signal, swim.method, swim.signal)
		f := r.verifyAndBuild(ctx, "idor", target, p, baseline, rr, swim.signal, false, false, "", "")
		if f != nil {
			f.Title = "Method/content-type swim (" + swim.signal + ") on " + target.EndpointURL
			r.recordFinding(&out, f, "idor", swim.signal)
		}
	}
	return out
}

func methodSwimSignal(probe, baseline httpclient.ResponseRecord) bool {
	if probe.StatusCode < 200 || probe.StatusCode >= 500 {
		return false
	}
	if probe.Body == baseline.Body {
		return false
	}
	lower := strings.ToLower(probe.Body)
	if strings.Contains(lower, "method not allowed") || strings.Contains(lower, "unsupported media") {
		return false
	}
	return probe.StatusCode == 200 || (probe.StatusCode >= 200 && probe.StatusCode < 300 && len(probe.Body) > 10)
}

func profileRequestHeaders(profile config.AuthProfile, extra map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range profile.Headers {
		out[k] = v
	}
	if len(profile.Cookies) > 0 {
		var parts []string
		for k, v := range profile.Cookies {
			parts = append(parts, k+"="+v)
		}
		out["Cookie"] = strings.Join(parts, "; ")
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func (r *Runner) probeAsProfile(ctx context.Context, profile config.AuthProfile, target ScanTarget, value string) (httpclient.RequestResponse, error) {
	return r.probeAsProfileWithValue(ctx, profile, target, target.Parameter, value)
}

func (r *Runner) probeAsProfileWithValue(ctx context.Context, profile config.AuthProfile, target ScanTarget, param, value string) (httpclient.RequestResponse, error) {
	method := strings.ToUpper(target.Method)
	if method == "" {
		method = http.MethodGet
	}
	loc := target.Location
	if loc == "" {
		loc = target.Profile.ParameterLocation
	}
	probeURL, body, headers, err := reflection.BuildProbeRequest(target.EndpointURL, method, param, loc, value)
	if err != nil {
		return httpclient.RequestResponse{}, err
	}
	headers = mergeHeaders(headers, r.wafHeaders(target.EndpointURL))
	if client, ok := r.client.(profiledHTTPDoer); ok {
		return client.DoWithAuthProfile(ctx, effectiveMethod(method, loc), probeURL, body, headers, profile)
	}
	headers = profileRequestHeaders(profile, headers)
	return r.client.Do(ctx, effectiveMethod(method, loc), probeURL, body, headers)
}

func (r *Runner) probeAsProfileWithMethod(ctx context.Context, profile config.AuthProfile, target ScanTarget, param, value, method string) (httpclient.RequestResponse, error) {
	method = strings.ToUpper(method)
	loc := target.Location
	if loc == "" {
		loc = target.Profile.ParameterLocation
	}
	probeURL, body, headers, err := reflection.BuildProbeRequest(target.EndpointURL, method, param, loc, value)
	if err != nil {
		return httpclient.RequestResponse{}, err
	}
	headers = mergeHeaders(headers, r.wafHeaders(target.EndpointURL))
	if client, ok := r.client.(profiledHTTPDoer); ok {
		return client.DoWithAuthProfile(ctx, effectiveMethod(method, loc), probeURL, body, headers, profile)
	}
	headers = profileRequestHeaders(profile, headers)
	return r.client.Do(ctx, effectiveMethod(method, loc), probeURL, body, headers)
}

type profiledHTTPDoer interface {
	DoWithAuthProfile(ctx context.Context, method, rawURL string, body []byte, headers map[string]string,
		profile config.AuthProfile) (httpclient.RequestResponse, error)
}
