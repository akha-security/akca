package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/html"

	"github.com/akha-security/akca/engine/internal/deserialization"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/sspp"
	"github.com/akha-security/akca/engine/internal/verification"
)

func (r *Runner) runClientSSTI(ctx context.Context, target ScanTarget) []ModuleFinding {
	return r.runBrowserCSTI(ctx, target, "client_ssti")
}

func (r *Runner) runBrowserCSTI(ctx context.Context, target ScanTarget, module string) []ModuleFinding {
	if ok, reason := r.shouldRunModule(module, target); !ok {
		r.emitSkip(module, target, reason)
		return nil
	}
	if r.browser == nil {
		r.runClientSSTICoverage(ctx, target, "browser execution is unavailable")
		r.emitSkip(module, target, "browser execution is unavailable; reflection alone is not proof")
		return nil
	}
	if !strings.EqualFold(target.Method, "GET") {
		if _, ok := r.browser.(BrowserHTMLRenderer); !ok {
			r.emitClientSSTIGap(target, "browser cannot render non-GET response bodies", false, false)
			r.emitSkip(module, target, "browser cannot render non-GET response bodies")
			return nil
		}
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
		dom, renderErr := r.renderProbeInBrowser(ctx, rr)
		if renderErr != nil || !rootDOMMarker(dom, "data-akca-csti", marker) || rootDOMMarker(rr.Response.Body, "data-akca-csti", marker) {
			continue
		}
		controlDOM, controlErr := r.renderProbeInBrowser(ctx, baseline)
		replayDOM, replayErr := r.renderProbeInBrowser(ctx, rr)
		if controlErr != nil || replayErr != nil || rootDOMMarker(controlDOM, "data-akca-csti", marker) || !rootDOMMarker(replayDOM, "data-akca-csti", marker) {
			continue
		}
		p := defaultPayload(module, pr.signal, pr.payload, pr.signal)
		f := r.verifyAndBuildWithCandidate(ctx, module, target, p, baseline, rr, pr.signal, true, true, "", "", func(c *verification.Candidate) { c.ExpectedEquivalent = true })
		if f != nil {
			f.Title = "Client-Side Template Injection (browser execution)"
			f.Description = "Browser execution set the unique DOM marker " + marker + "; reflection-only responses are not reported."
		}
		r.recordFinding(ctx, &out, f, module, pr.signal)
	}
	return out
}

func (r *Runner) runClientSSTICoverage(ctx context.Context, target ScanTarget, reason string) {
	if strings.ToUpper(target.Method) != "" && strings.ToUpper(target.Method) != "GET" {
		r.emitClientSSTIGap(target, reason, false, false)
		return
	}
	baseline, err := r.probe(ctx, target, "akca-base")
	if err != nil {
		r.emitClientSSTIGap(target, reason, false, false)
		return
	}
	probe, err := r.probe(ctx, target, "{{7*7}}")
	if err != nil {
		r.emitClientSSTIGap(target, reason, false, false)
		return
	}
	r.emitClientSSTIGap(target, reason, true,
		clientSSTISignal(probe.Response.Body, baseline.Response.Body, "client_template_eval"))
}

func (r *Runner) emitClientSSTIGap(target ScanTarget, reason string, probesDelivered, contentSignal bool) {
	r.emitOnce("client-ssti-coverage:"+target.EndpointURL, "coverage_gap",
		"Client-SSTI coverage requires browser DOM execution before reporting",
		map[string]interface{}{
			"module":                  "client_ssti",
			"endpoint":                target.EndpointURL,
			"method":                  target.Method,
			"parameter":               target.Parameter,
			"reason":                  reason,
			"probes_delivered":        probesDelivered,
			"content_signal_observed": contentSignal,
			"finding_requires_dom":    true,
		})
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
	probeURL := smugglingProbeURL(target.EndpointURL)
	probeTarget := target
	probeTarget.EndpointURL = probeURL
	probeTarget.Parameter = ""
	probeTarget.Location = "raw_http"
	var out []ModuleFinding
	for _, signal := range []string{
		"cl_te", "te_cl", "te_te_space", "te_te_prefix", "te_te_duplicate", "cl_cl_conflict",
		"cl_te_crlf", "te_cl_tab", "te_newline", "cl_zero", "h2_cl", "h2_te", "h2_crlf", "h2_pseudo", "h2c_upgrade_confusion",
	} {
		result, err := r.smuggling.Probe(ctx, probeURL, signal)
		if err != nil || !result.Confirmed || len(result.Attempts) < 2 {
			continue
		}
		p := defaultPayload("smuggling", signal, result.Exchange.Request.Body, signal)
		targetForObservation := probeTarget
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
			ScanID: r.scanID, Title: "smuggling on raw HTTP route", VulnClass: "smuggling",
			EndpointURL: probeTarget.EndpointURL, Method: probeTarget.Method, Parameter: probeTarget.Parameter,
			Payload: p.Value, Module: "smuggling", Signal: signal,
			Baseline: snapshot(result.Control.Response), Probe: snapshot(result.Attempts[0].Response),
			DirectTypedSignal: true, NegativeControlSet: true, NegativeControlOK: true,
			ProofPolicyVersion: verification.CurrentProofPolicyVersion,
			RequestedProofType: verification.ProofProtocolDesync, Observations: observations,
			TypedReplayHits: []bool{true, true},
		}
		verified := r.verifier.Verify(candidate)
		if verified.Suppressed || !verified.ProofSatisfied {
			r.recordVerificationOutcome(probeTarget, "smuggling", signal, verified)
			continue
		}
		f := &ModuleFinding{
			Title:     "HTTP request smuggling (" + strings.ToUpper(strings.ReplaceAll(signal, "_", ".")) + ")",
			VulnClass: "smuggling", Severity: "high",
			Description: "Two independent raw HTTP/1.1 probes produced the same response-queue desynchronization: " + result.Reason,
			Endpoint:    probeTarget.EndpointURL, Parameter: probeTarget.Parameter, Location: probeTarget.Location,
			Confidence: verified.Confidence,
			Evidence: Evidence{
				Module: "smuggling", Signal: signal, Payload: p,
				Parameter: probeTarget.Parameter, Location: probeTarget.Location,
				Request: result.Exchange.Request, Response: result.Exchange.Response,
				Verification: verified,
				DetectedAt:   time.Now().UTC(),
			},
		}
		r.recordFinding(ctx, &out, f, "smuggling", signal)
	}
	return out
}

func smugglingProbeURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
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
	var out []ModuleFinding
	var baseline httpclient.RequestResponse
	baselineReady := false

	// Server-side prototype pollution requires a request body carrier. Sending
	// JSON bodies to every discovered GET/query parameter adds traffic without
	// exercising the surface represented by that target.
	if serverPrototypeEligible(target) {
		var err error
		baseline, err = r.probeWithBody(ctx, target, `{"name":"akca"}`, "application/json", nil)
		if err != nil {
			return nil
		}
		baselineReady = true
		for _, pr := range sspp.Probes() {
			if ctx.Err() != nil {
				break
			}
			rr, probeErr := r.probeWithBody(ctx, target, pr.Body, "application/json", nil)
			if probeErr != nil {
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
				r.recordFinding(ctx, &out, f, "prototype_pollution", signal)
			}
			if len(out) >= 3 {
				break
			}
		}
	}

	// Client-side payloads are URL-level (__proto__/constructor keys), so one
	// browser proof per concrete route/query shape covers all parameters on that
	// page. Server-side parameter probes above remain parameter-specific.
	if len(out) == 0 && clientPrototypeEligible(target) &&
		r.moduleWorkOnce("prototype_pollution_browser", clientPrototypeWorkKey(target.EndpointURL)) {
		evaluator, browserOK := r.browser.(BrowserExpressionEvaluator)
		if !browserOK {
			r.emitSkip("prototype_pollution", target, "browser expression evaluation is unavailable for client-side proof")
			return out
		}
		if !baselineReady {
			var baselineErr error
			baseline, baselineErr = r.cachedEmptyProbe(ctx, target)
			if baselineErr != nil {
				return out
			}
			baselineReady = true
		}
		if !isHTMLResponse(baseline.Response) &&
			!strings.Contains(strings.ToLower(headerValue(baseline.Response.Headers, "Content-Type")), "html") {
			r.emitSkip("prototype_pollution", target, "client-side proof requires an HTML response")
			return out
		}
		baselineURL := target.EndpointURL
		baselineEvidence, baselineErr := evaluator.EvaluatePage(ctx, baselineURL, prototypeStateExpression)
		if baselineErr != nil {
			return out
		}
		for _, pr := range sspp.ClientSideProbes() {
			if ctx.Err() != nil {
				break
			}
			probeURL, err := clientPrototypeProbeURL(target.EndpointURL, pr.Body)
			if err != nil || !r.scope.IsInScope(probeURL) {
				continue
			}
			var evidence []string
			var probeResponses []httpclient.RequestResponse
			for attempt := 0; attempt < 2; attempt++ {
				rr, requestErr := r.client.Do(ctx, http.MethodGet, probeURL, nil,
					r.wafHeadersForModule("prototype_pollution", probeURL))
				if requestErr != nil {
					evidence = nil
					break
				}
				value, evalErr := evaluator.EvaluatePage(ctx, probeURL, prototypeStateExpression)
				if evalErr != nil || !clientPrototypeEvidence(pr, value, baselineEvidence) {
					evidence = nil
					break
				}
				evidence = append(evidence, value)
				probeResponses = append(probeResponses, rr)
			}
			if len(evidence) != 2 {
				continue
			}
			p := defaultPayload("prototype_pollution", pr.Name, pr.Body, "client_prototype_pollution")
			p.SelectionReason = "Chromium Object.prototype evidence: " + evidence[0]
			finding := r.verifyAndBuildWithCandidate(ctx, "prototype_pollution", target, p, baseline, probeResponses[0],
				"client_prototype_pollution", true, true, "", evidence[0], func(candidate *verification.Candidate) {
					candidate.RequestedProofType = verification.ProofDOMExecution
					candidate.NegativeControlSet, candidate.NegativeControlOK = true, true
					candidate.TypedReplayHits = []bool{true, true}
					candidate.Observations = append(candidate.Observations,
						r.observation("prototype_pollution", target, verification.RoleNegativeControl, 1, baseline),
						r.observation("prototype_pollution", target, verification.RolePositiveReplay, 2, probeResponses[1]))
				})
			if finding != nil {
				finding.Title = "Client-side prototype pollution confirmed in Chromium"
				finding.Severity = "high"
				finding.Description = "Two isolated Chromium documents observed the injected property on Object.prototype; the native URL did not contain it."
				r.recordFinding(ctx, &out, finding, "prototype_pollution", "client_prototype_pollution")
				return out
			}
		}
	}
	return out
}

func serverPrototypeEligible(target ScanTarget) bool {
	method := strings.ToUpper(strings.TrimSpace(target.Method))
	contentType := strings.ToLower(target.Profile.ContentType + " " + target.RequestTemplate.ContentType)
	location := strings.ToLower(strings.TrimSpace(target.Location))
	return method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch ||
		location == "body" || location == "json" || strings.Contains(contentType, "json")
}

func clientPrototypeEligible(target ScanTarget) bool {
	method := strings.ToUpper(strings.TrimSpace(target.Method))
	location := strings.ToLower(strings.TrimSpace(target.Location))
	return method == http.MethodGet && target.Parameter != "" && (location == "" || location == "query")
}

func clientPrototypeWorkKey(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	values := parsed.Query()
	for name := range values {
		values[name] = []string{"{value}"}
	}
	parsed.RawQuery = values.Encode()
	parsed.Fragment = ""
	return parsed.String()
}

const prototypeStateExpression = `JSON.stringify({polluted:Object.prototype.polluted||null,src:Object.prototype.src||null,innerHTML:Object.prototype.innerHTML||null,url:Object.prototype.url||null})`

func clientPrototypeProbeURL(rawURL, queryPayload string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if parsed.RawQuery == "" {
		parsed.RawQuery = queryPayload
	} else {
		parsed.RawQuery += "&" + queryPayload
	}
	return parsed.String(), nil
}

func clientPrototypeEvidence(probe sspp.Probe, value, baseline string) bool {
	if strings.TrimSpace(value) == "" || value == baseline {
		return false
	}
	switch probe.Name {
	case "client_proto_bracket", "client_proto_dot", "client_constructor_bracket":
		return strings.Contains(value, `"polluted":"akca_dom_polluted"`) &&
			!strings.Contains(baseline, `"polluted":"akca_dom_polluted"`)
	case "client_proto_script_src":
		return strings.Contains(value, `"src":"data:,alert(1)"`) && !strings.Contains(baseline, `"src":"data:,alert(1)"`)
	case "client_proto_innerhtml":
		return strings.Contains(value, `"innerHTML":"<img/src/onerror=alert(1)>"`) &&
			!strings.Contains(baseline, `"innerHTML":"<img/src/onerror=alert(1)>"`)
	case "client_proto_url_sink":
		return strings.Contains(value, `"url":"javascript:alert(1)"`) &&
			!strings.Contains(baseline, `"url":"javascript:alert(1)"`)
	default:
		return false
	}
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
			r.recordFinding(ctx, &out, f, "ldap_xpath_injection", pr.signal)
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
				r.recordFinding(ctx, &out, runtimeFinding, "ldap_xpath_injection", runtimeFinding.Evidence.Signal)
				return out
			}
			continue
		}
		if !ldapXPathSignal(rr.Response.Body, baseline.Response.Body, pr.signal) {
			continue
		}
		f := r.verifyAndBuild(ctx, "ldap_xpath_injection", target, p, baseline, rr, pr.signal, false, false, "", "")
		r.recordFinding(ctx, &out, f, "ldap_xpath_injection", pr.signal)
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
	r.recordFinding(ctx, &out, f, "debug_admin", "debug_exposure")
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

func (r *Runner) runRaceCondition(ctx context.Context, target ScanTarget) []ModuleFinding {
	return r.runRaceConditionProof(ctx, target)
}

func (r *Runner) runAPIVersioning(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("api_versioning", target); !ok {
		r.emitSkip("api_versioning", target, reason)
		return nil
	}
	targetParsed, err := url.Parse(target.EndpointURL)
	if err != nil {
		return nil
	}
	cleanPath := strings.TrimRight(targetParsed.Path, "/")
	// Only probe API versioning on root ("" or "/") or base API prefixes ("/api", "/rest")
	// Avoid probing deep content endpoints like /products/item-123 or /.env
	if cleanPath != "" && cleanPath != "/api" && cleanPath != "/rest" {
		return nil
	}
	hostKey := strings.ToLower(targetParsed.Host) + ":" + cleanPath
	r.moduleSeenMu.Lock()
	if _, seen := r.moduleSeen["api_versioning:"+hostKey]; seen {
		r.moduleSeenMu.Unlock()
		return nil
	}
	r.moduleSeen["api_versioning:"+hostKey] = struct{}{}
	r.moduleSeenMu.Unlock()

	baseURL := fmt.Sprintf("%s://%s%s", targetParsed.Scheme, targetParsed.Host, cleanPath)
	baseline := httpclient.RequestResponse{Response: httpclient.ResponseRecord{StatusCode: 404, Body: "not found"}}
	var out []ModuleFinding
	for _, version := range []string{"/v1", "/v2", "/v3", "/api/v1", "/api/v2"} {
		u := strings.TrimSuffix(baseURL, "/") + version
		if !r.scope.IsInScope(u) {
			continue
		}
		rr, err := r.client.Do(ctx, "GET", u, nil, nil)
		if err != nil || rr.Response.StatusCode != 200 {
			continue
		}
		// If the response was redirected, only allow trailing slash normalizations (e.g. /v1 -> /v1/)
		// Any redirect to other endpoints (e.g. /login, /, /error, /oauth) must be rejected immediately.
		if rr.Response.Redirected {
			finalClean := strings.TrimRight(rr.Response.FinalURL, "/")
			origClean := strings.TrimRight(u, "/")
			if finalClean != origClean {
				continue
			}
		}

		// Reject HTML web pages (login pages, custom 404s, SPA entrypoints)
		ct := strings.ToLower(rr.Response.Headers["Content-Type"])
		if strings.Contains(ct, "text/html") {
			continue
		}
		trimmedBody := strings.TrimSpace(rr.Response.Body)
		lowerBody := strings.ToLower(trimmedBody)
		if strings.Contains(lowerBody, "<!doctype") || strings.Contains(lowerBody, "<html") {
			continue
		}

		// API discovery requires a real API payload: valid JSON array or object
		if len(trimmedBody) < 2 {
			continue
		}
		var js interface{}
		if err := json.Unmarshal([]byte(trimmedBody), &js); err != nil {
			// If not valid JSON, check if it explicitly announces an API routes listing
			if !strings.Contains(lowerBody, "swagger") && !strings.Contains(lowerBody, "openapi") && !strings.Contains(lowerBody, "routes") {
				continue
			}
		}

		p := defaultPayload("api_versioning", "version_discovered", version, "version_discovered")
		f := r.verifyAndBuild(ctx, "api_versioning", target, p, baseline, rr, "version_discovered", false, false, "", "")
		r.recordFinding(ctx, &out, f, "api_versioning", "version_discovered")
	}
	return out
}

func (r *Runner) runInsecureDeserialization(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("insecure_deserialization", target); !ok {
		r.emitSkip("insecure_deserialization", target, reason)
		return nil
	}
	baseline, err := r.cachedEmptyProbe(ctx, target)
	if err != nil {
		return nil
	}
	var out []ModuleFinding
	for _, pr := range deserialization.Probes() {
		if ctx.Err() != nil {
			break
		}
		rr, err := r.probe(ctx, target, pr.Payload)
		if err != nil {
			continue
		}
		ok, signal := deserialization.AnalyzeResponse(baseline.Response.Body, baseline.Response.StatusCode, rr.Response.Body, rr.Response.StatusCode, pr)
		if !ok {
			continue
		}
		p := defaultPayload("insecure_deserialization", pr.Name, pr.Payload, signal)
		f := r.verifyAndBuild(ctx, "insecure_deserialization", target, p, baseline, rr, signal, false, false, "", "")
		if f != nil {
			f.Title = fmt.Sprintf("Insecure Deserialization (%s - %s)", strings.ToUpper(pr.Language), pr.Name)
			f.Severity = pr.Severity
			f.Description = fmt.Sprintf("Insecure deserialization vulnerability or diagnostic indicator detected via %s payload.", strings.ToUpper(pr.Language))
			r.recordFinding(ctx, &out, f, "insecure_deserialization", signal)
			break
		}
	}
	return out
}

func rootDOMMarker(body, key, value string) bool {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return false
	}
	for n := doc.FirstChild; n != nil; n = n.NextSibling {
		if n.Type == html.ElementNode && n.Data == "html" {
			for _, attr := range n.Attr {
				if attr.Key == key && attr.Val == value {
					return true
				}
			}
		}
	}
	return false
}
