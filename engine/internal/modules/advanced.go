package modules

import (
	"context"
	"strings"
	"time"

	"github.com/akha-security/akca/engine/internal/businesslogic"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/sspp"
	"github.com/akha-security/akca/engine/internal/verification"
)

func (r *Runner) runClientSSTI(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("client_ssti", target); !ok {
		r.emitSkip("client_ssti", target, reason)
		return nil
	}
	if r.browser == nil {
		r.emitSkip("client_ssti", target, "browser execution is unavailable; reflection alone is not proof")
		return nil
	}
	if strings.ToUpper(target.Method) != "" && strings.ToUpper(target.Method) != "GET" {
		r.emitSkip("client_ssti", target, "browser confirmation currently requires a GET/query surface")
		return nil
	}
	baseline, err := r.probe(ctx, target, "akca-base")
	if err != nil {
		return nil
	}
	token := randomToken(10)
	marker := "akca-csti-" + token
	probes := []struct{ payload, signal string }{
		{`{{constructor.constructor('document.documentElement.setAttribute("data-akca-csti","` + marker + `")')()}}`, "angular_dom_execution"},
	}
	var out []ModuleFinding
	for _, pr := range probes {
		rr, err := r.probe(ctx, target, pr.payload)
		if err != nil {
			continue
		}
		dom, renderErr := r.browser.Render(ctx, rr.Request.URL)
		if renderErr != nil || !strings.Contains(dom, `data-akca-csti="`+marker+`"`) {
			continue
		}
		p := defaultPayload("client_ssti", pr.signal, pr.payload, pr.signal)
		f := r.verifyAndBuild(ctx, "client_ssti", target, p, baseline, rr, pr.signal, true, true, "", "")
		if f != nil {
			f.Description = "Browser execution set the unique DOM marker " + marker + "; reflection-only responses are not reported."
		}
		r.recordFinding(&out, f, "client_ssti", pr.signal)
	}
	return out
}

func clientSSTISignal(body, baseline, signal string) bool {
	if body == baseline {
		return false
	}
	switch signal {
	case "client_template_eval", "ejs_client_signal":
		return hasStandaloneWord(body, "49") && !hasStandaloneWord(baseline, "49")
	case "angular_ssti":
		lower := strings.ToLower(body)
		baseLower := strings.ToLower(baseline)
		return strings.Contains(lower, "alert(") && !strings.Contains(baseLower, "alert(")
	}
	return false
}

func hasStandaloneWord(body, word string) bool {
	start := 0
	for {
		idx := strings.Index(body[start:], word)
		if idx == -1 {
			return false
		}
		actualIdx := start + idx
		isWordStart := actualIdx == 0 || body[actualIdx-1] < '0' || body[actualIdx-1] > '9'
		endIdx := actualIdx + len(word)
		isWordEnd := endIdx == len(body) || body[endIdx] < '0' || body[endIdx] > '9'
		if isWordStart && isWordEnd {
			return true
		}
		start = actualIdx + 1
	}
}

func (r *Runner) runSmuggling(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("smuggling", target); !ok {
		r.emitSkip("smuggling", target, reason)
		return nil
	}
	if r.smuggling == nil {
		return nil
	}
	var out []ModuleFinding
	for _, signal := range []string{"cl_te", "te_cl"} {
		result, err := r.smuggling.Probe(ctx, target.EndpointURL, signal)
		if err != nil || !result.Confirmed || len(result.Attempts) < 2 {
			continue
		}
		p := defaultPayload("smuggling", signal, result.Exchange.Request.Body, signal)
		targetForObservation := target
		observations := []verification.Observation{
			r.observation("smuggling", targetForObservation, verification.RoleNativeBaseline, 1, result.Control),
			r.observation("smuggling", targetForObservation, verification.RoleNegativeControl, 1, result.Control),
		}
		for attempt, exchange := range result.Attempts {
			role := verification.RolePositiveProbe
			if attempt > 0 {
				role = verification.RolePositiveReplay
			}
			observations = append(observations,
				r.observation("smuggling", targetForObservation, role, attempt+1, exchange))
		}
		candidate := verification.Candidate{
			ScanID: r.scanID, Title: "smuggling on " + target.Parameter, VulnClass: "smuggling",
			EndpointURL: target.EndpointURL, Method: target.Method, Parameter: target.Parameter,
			Payload: p.Value, Module: "smuggling", Signal: signal,
			Baseline: snapshot(result.Control.Response), Probe: snapshot(result.Attempts[0].Response),
			DirectTypedSignal: true, NegativeControlSet: true, NegativeControlOK: true,
			ProofPolicyVersion: verification.CurrentProofPolicyVersion,
			RequestedProofType: verification.ProofProtocolDesync, Observations: observations,
			TypedReplayHits: []bool{true, true},
		}
		verified := r.verifier.Verify(candidate)
		if verified.Suppressed || !verified.ProofSatisfied {
			continue
		}
		f := &ModuleFinding{
			Title:     "HTTP request smuggling (" + strings.ToUpper(strings.ReplaceAll(signal, "_", ".")) + ")",
			VulnClass: "smuggling", Severity: "high",
			Description: "Two independent raw HTTP/1.1 probes produced the same response-queue desynchronization: " + result.Reason,
			Endpoint:    target.EndpointURL, Parameter: target.Parameter, Location: target.Location,
			Confidence: verified.Confidence,
			Evidence: Evidence{
				Module: "smuggling", Signal: signal, Payload: p,
				Parameter: target.Parameter, Location: target.Location,
				Request: result.Exchange.Request, Response: result.Exchange.Response,
				Verification: verified,
				DetectedAt:   time.Now().UTC(),
			},
		}
		r.recordFinding(&out, f, "smuggling", signal)
	}
	return out
}

func smugglingSignal(headers map[string]string, body, baseline string) bool {
	_ = headers
	return strings.Contains(body, "response queue differential") && !strings.Contains(baseline, "response queue differential")
}

func (r *Runner) runPrototypePollution(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("prototype_pollution", target); !ok {
		r.emitSkip("prototype_pollution", target, reason)
		return nil
	}
	baseline, err := r.probeWithBody(ctx, target, `{"name":"akca"}`, "application/json", nil)
	if err != nil {
		return nil
	}
	var out []ModuleFinding
	for _, pr := range sspp.Probes() {
		if ctx.Err() != nil {
			break
		}
		rr, err := r.probeWithBody(ctx, target, pr.Body, "application/json", nil)
		if err != nil {
			continue
		}
		ok, signal := sspp.Analyze(baseline.Response.Body, baseline.Response.StatusCode, rr.Response.Body, rr.Response.StatusCode, pr)
		if !ok {
			continue
		}
		p := defaultPayload("prototype_pollution", pr.Name, pr.Body, signal)
		f := r.verifyAndBuild(ctx, "prototype_pollution", target, p, baseline, rr, signal, false, false, "", "")
		if f != nil {
			f.Title = "Server-side prototype pollution (" + signal + ")"
			r.recordFinding(&out, f, "prototype_pollution", signal)
		}
		if len(out) >= 3 {
			break
		}
	}
	return out
}

func (r *Runner) runLDAPXPathInjection(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("ldap_xpath_injection", target); !ok {
		r.emitSkip("ldap_xpath_injection", target, reason)
		return nil
	}
	baseline, err := r.probe(ctx, target, "akca")
	if err != nil {
		return nil
	}
	probes := []struct{ value, signal string }{
		{"*)(uid=*", "ldap_injection"},
		{"' or '1'='1", "xpath_injection"},
		{"test\r\nX-Injected: true", "header_injection"},
	}
	var out []ModuleFinding
	for _, pr := range probes {
		if pr.signal == "header_injection" {
			rr, err := r.probeWithHeaders(ctx, target, "test", map[string]string{"X-Test": pr.value})
			if err != nil || !strings.Contains(strings.ToLower(headerValue(rr.Response.Headers, "X-Injected")), "true") {
				continue
			}
			p := defaultPayload("ldap_xpath_injection", pr.signal, pr.value, pr.signal)
			f := r.verifyAndBuild(ctx, "ldap_xpath_injection", target, p, baseline, rr, pr.signal, false, false, "", "")
			r.recordFinding(&out, f, "ldap_xpath_injection", pr.signal)
			continue
		}
		rr, err := r.probe(ctx, target, pr.value)
		if err != nil {
			continue
		}
		p := defaultPayload("ldap_xpath_injection", pr.signal, pr.value, pr.signal)
		if runtimeFinding, handled := r.runtimeSinkProof(
			ctx, "ldap_xpath_injection", target, p, baseline, rr,
		); handled {
			if runtimeFinding != nil {
				r.recordFinding(&out, runtimeFinding, "ldap_xpath_injection", runtimeFinding.Evidence.Signal)
				return out
			}
			continue
		}
		if !ldapXPathSignal(rr.Response.Body, baseline.Response.Body, pr.signal) {
			continue
		}
		f := r.verifyAndBuild(ctx, "ldap_xpath_injection", target, p, baseline, rr, pr.signal, false, false, "", "")
		r.recordFinding(&out, f, "ldap_xpath_injection", pr.signal)
	}
	return out
}

func ldapXPathSignal(body, baseline, signal string) bool {
	lower := strings.ToLower(body)
	baseLower := strings.ToLower(baseline)
	switch signal {
	case "ldap_injection":
		for _, kw := range []string{"ldap error", "ldap:", "invalid credentials", "ldap matched", "matched users"} {
			if strings.Contains(lower, kw) && !strings.Contains(baseLower, kw) {
				return true
			}
		}
		if strings.Contains(lower, "ldap") && !strings.Contains(baseLower, "ldap") {
			return true
		}
		return false
	case "xpath_injection":
		for _, kw := range []string{"xpath", "xmlpath", "invalid predicate"} {
			if strings.Contains(lower, kw) && !strings.Contains(baseLower, kw) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func (r *Runner) runDebugAdmin(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("debug_admin", target); !ok {
		r.emitSkip("debug_admin", target, reason)
		return nil
	}
	baseline := httpclient.RequestResponse{Response: httpclient.ResponseRecord{StatusCode: 404, Body: "not found"}}
	rr, err := r.cachedEmptyProbe(ctx, target)
	if err != nil {
		return nil
	}
	if !debugAdminSignal(rr.Response.Body, rr.Response.StatusCode) {
		return nil
	}
	p := defaultPayload("debug_admin", "debug_exposure", target.EndpointURL, "debug_exposure")
	f := r.verifyAndBuild(ctx, "debug_admin", target, p, baseline, rr, "debug_exposure", false, false, "", "")
	var out []ModuleFinding
	r.recordFinding(&out, f, "debug_admin", "debug_exposure")
	return out
}

func debugAdminSignal(body string, status int) bool {
	if status != 200 {
		return false
	}
	lower := strings.ToLower(body)
	return strings.Contains(lower, "stack trace") || strings.Contains(lower, "phpinfo()") ||
		strings.Contains(lower, `"_links"`) && strings.Contains(lower, "actuator")
}

func (r *Runner) runBusinessLogicHeuristicDisabled(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("business_logic", target); !ok {
		r.emitSkip("business_logic", target, reason)
		return nil
	}
	baseline, err := r.probe(ctx, target, "100")
	if err != nil {
		return nil
	}
	var out []ModuleFinding
	probes := businesslogic.AllProbes(target.Parameter)
	for _, probe := range probes {
		if ctx.Err() != nil {
			break
		}
		rr, err := r.probe(ctx, target, probe.Value)
		if err != nil {
			continue
		}
		ok, signal := businesslogic.Analyze(baseline.Response.Body, rr.Response.Body, probe)
		if !ok {
			continue
		}
		p := defaultPayload("business_logic", probe.Name, probe.Value, signal)
		f := r.verifyAndBuild(ctx, "business_logic", target, p, baseline, rr, signal, false, false, "", "")
		if f != nil {
			f.Title = "Business logic (" + signal + ") on " + target.Parameter
			f.Description = probe.Name + " (" + probe.Value + ") — " + signal
			r.recordFinding(&out, f, "business_logic", signal)
		}
		if len(out) >= 3 {
			break
		}
	}
	return out
}

func (r *Runner) runRaceCondition(ctx context.Context, target ScanTarget) []ModuleFinding {
	return r.runRaceConditionProof(ctx, target)
}

func (r *Runner) runAPIVersioning(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("api_versioning", target); !ok {
		r.emitSkip("api_versioning", target, reason)
		return nil
	}
	baseline := httpclient.RequestResponse{Response: httpclient.ResponseRecord{StatusCode: 404, Body: "not found"}}
	var out []ModuleFinding
	for _, version := range []string{"/v1", "/v2", "/v3", "/api/v1", "/api/v2"} {
		u := strings.TrimSuffix(target.EndpointURL, "/") + version
		if !r.scope.IsInScope(u) {
			continue
		}
		rr, err := r.client.Do(ctx, "GET", u, nil, nil)
		if err != nil || rr.Response.StatusCode != 200 {
			continue
		}
		p := defaultPayload("api_versioning", "version_discovered", version, "version_discovered")
		f := r.verifyAndBuild(ctx, "api_versioning", target, p, baseline, rr, "version_discovered", false, false, "", "")
		r.recordFinding(&out, f, "api_versioning", "version_discovered")
	}
	return out
}
