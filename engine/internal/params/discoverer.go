package params

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/urlutil"
)

type HTTPDoer interface {
	Do(ctx context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error)
}

var differentialHeaders = []string{
	"User-Agent",
	"Referer",
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Real-IP",
	"X-Client-IP",
	"Client-IP",
	"X-Originating-IP",
	"True-Client-IP",
	"CF-Connecting-IP",
	"Fastly-Client-IP",
	"X-Original-URL",
	"X-Rewrite-URL",
	"X-Custom-IP-Authorization",
}

var probeValuesByType = []struct {
	val, hint string
}{
	{"1", "numeric"},
	{"true", "boolean"},
	{"akca_probe", "string"},
	{"akca@test.com", "email"},
	{"2026-01-01", "date"},
}

type Discoverer struct {
	scanID            string
	client            HTTPDoer
	scope             *scope.Engine
	db                *storage.DB
	emit              EventSink
	maxProbes         int
	wordlistCap       int
	maxHits           int
	maxTransferProbes int
	parallelism       int
	eventBatch        []map[string]interface{}
	mu                sync.Mutex
}

func NewDiscoverer(scanID string, client HTTPDoer, scopeEngine *scope.Engine, db *storage.DB, emit EventSink) *Discoverer {
	return &Discoverer{
		scanID: scanID, client: client, scope: scopeEngine, db: db, emit: emit,
		maxProbes: 0, wordlistCap: 0, maxHits: 0, parallelism: 8,
	}
}

func (d *Discoverer) DiscoverEndpoint(ctx context.Context, endpointID int64, endpointURL, method string, templates ...storage.DiscoveryRequestTemplate) ([]DiscoveredParameter, error) {
	if !urlutil.IsPlausibleEndpointURL(endpointURL) || !d.scope.IsInScope(endpointURL) || !ShouldDiscoverEndpoint(endpointURL, method) {
		return nil, nil
	}
	method = strings.ToUpper(method)
	if method == "" {
		method = http.MethodGet
	}
	template := storage.DiscoveryRequestTemplate{}
	if len(templates) > 0 {
		template = templates[0]
	}
	requestURL, requestBody, requestHeaders := nativeRequest(endpointURL, method, template)

	baselineRR, err := d.client.Do(ctx, method, requestURL, requestBody, requestHeaders)
	if err != nil {
		return nil, err
	}
	if baselineRR.Response.StatusCode == http.StatusNotFound || baselineRR.Response.StatusCode == http.StatusGone {
		return nil, nil
	}
	contentType := headerValue(baselineRR.Response.Headers, "Content-Type")
	passive := ExtractPassive(endpointURL, method, contentType, baselineRR.Response.Body, baselineRR.Request.Headers)

	var templateParams []DiscoveredParameter
	if template.Body != "" {
		templateParams = ExtractFromTemplateBody(endpointURL, method, template.ContentType, template.Body)
	}

	if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
		if getRR, gerr := d.client.Do(ctx, http.MethodGet, requestURL, nil, requestHeaders); gerr == nil {
			getCT := headerValue(getRR.Response.Headers, "Content-Type")
			for _, p := range ExtractPassive(endpointURL, method, getCT, getRR.Response.Body, getRR.Request.Headers) {
				if p.Location == LocationForm || p.Location == LocationHidden {
					p.EndpointMethod = method
					p.Priority += 5
					passive = append(passive, p)
				}
			}
		}
	}

	for _, p := range passive {
		_ = d.persist(endpointID, p)
	}
	if PassiveEnoughForSkip(passive, method) {
		return passive, nil
	}

	// Method-matched baselines map to prevent comparing GET probes against POST baselines
	baselines := map[string]ResponseFingerprint{}
	baselineBodies := map[string]string{}
	getBaseline(ctx, d.client, requestURL, method, requestHeaders, baselineRR, baselines, baselineBodies)

	// Calibrate baseline stability: check if the page naturally fluctuates on every request
	isDynamic := false
	noiseThreshold := 128
	if baselineRR2, bErr := d.client.Do(ctx, method, requestURL, requestBody, requestHeaders); bErr == nil {
		if baselineRR.Response.Body != baselineRR2.Response.Body {
			isDynamic = true
			noiseDelta := abs(len(baselineRR.Response.Body) - len(baselineRR2.Response.Body))
			if noiseDelta > 64 {
				noiseThreshold = noiseDelta * 2
			}
		}
	}

	// Random-control calibration probe to measure server's generic unknown-parameter rejection behavior
	var randCtrlFP ResponseFingerprint
	var randCtrlBody string
	randParam := "__akca_rand_ctrl_8f1"
	if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
		if probeURL, body := buildCustomQueryProbe(requestURL, randParam, "akca_probe"); d.scope.IsInScope(probeURL) {
			if rr, perr := d.client.Do(ctx, http.MethodGet, probeURL, body, requestHeaders); perr == nil {
				randCtrlFP = Fingerprint(rr.Response.StatusCode, rr.Response.Body, rr.Response.Duration.Milliseconds(), rr.Response.Headers)
				randCtrlBody = rr.Response.Body
			}
		}
	} else if body, location, ok := mutateNativeBody(template, randParam, "akca_probe"); ok && d.scope.IsInScope(requestURL) {
		if rr, perr := d.client.Do(ctx, method, requestURL, body, bodyProbeHeaders(requestHeaders, location)); perr == nil {
			randCtrlFP = Fingerprint(rr.Response.StatusCode, rr.Response.Body, rr.Response.Duration.Milliseconds(), rr.Response.Headers)
			randCtrlBody = rr.Response.Body
		}
	}

	var differential []DiscoveredParameter
	confirmedHits := map[string]map[string]struct{}{}

	recordHit := func(name, surfaceKey string) {
		if _, ok := confirmedHits[name]; !ok {
			confirmedHits[name] = map[string]struct{}{}
		}
		confirmedHits[name][surfaceKey] = struct{}{}
	}

	probes := 0
	wordlist := DifferentialWordlist(endpointURL, d.wordlistCap)

	// Inject JS parameters if any
	if rows, jerr := d.db.Conn().Query(`SELECT DISTINCT name FROM parameters WHERE priority >= 80 AND endpoint_id IN (SELECT id FROM endpoints WHERE scan_id = ?)`, d.scanID); jerr == nil {
		defer rows.Close()
		for rows.Next() {
			var jsParam string
			if rows.Scan(&jsParam) == nil {
				found := false
				for _, w := range wordlist {
					if w == jsParam {
						found = true
						break
					}
				}
				if !found {
					wordlist = append([]string{jsParam}, wordlist...)
				}
			}
		}
	}

	// Phase 1: Fast single-probe pass across all candidates so all wordlist items (url, category, webhook, etc.) get tested
	jsonPotentialHits := map[string]struct{}{}
	for _, candidate := range wordlist {
		if (d.maxProbes > 0 && probes >= d.maxProbes) || (d.maxHits > 0 && len(confirmedHits) >= d.maxHits) {
			break
		}

		if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
			// GET query probe matched against GET baseline
			if probeURL, body := buildCustomQueryProbe(requestURL, candidate, "akca_probe"); d.scope.IsInScope(probeURL) {
				if rr, perr := d.client.Do(ctx, http.MethodGet, probeURL, body, requestHeaders); perr == nil {
					probes++
					fp := Fingerprint(rr.Response.StatusCode, rr.Response.Body, rr.Response.Duration.Milliseconds(), rr.Response.Headers)
					baseFP, baseOK := baselines["GET"]
					if !baseOK {
						baseFP = Fingerprint(baselineRR.Response.StatusCode, baselineRR.Response.Body, baselineRR.Response.Duration.Milliseconds(), baselineRR.Response.Headers)
					}
					baseBody := baselineBodies["GET"]
					if baseBody == "" {
						baseBody = baselineRR.Response.Body
					}
					if isParameterHitWithControl(baseFP, fp, randCtrlFP, baseBody, rr.Response.Body, randCtrlBody,
						candidate, randParam, "akca_probe", isDynamic, noiseThreshold) {
						recordHit(candidate, "query")
					}
				}
			}
		}

		// Mutate the captured native body while preserving the original method,
		// headers and sibling fields. This keeps authenticated/API requests valid.
		if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
			if body, location, ok := mutateNativeBody(template, candidate, "akca_probe"); ok && d.scope.IsInScope(requestURL) {
				headers := bodyProbeHeaders(requestHeaders, location)
				if rr, perr := d.client.Do(ctx, method, requestURL, body, headers); perr == nil {
					probes++
					fp := Fingerprint(rr.Response.StatusCode, rr.Response.Body, rr.Response.Duration.Milliseconds(), rr.Response.Headers)
					baseFP, baseOK := baselines[method+"_native"]
					if !baseOK {
						baseFP = Fingerprint(baselineRR.Response.StatusCode, baselineRR.Response.Body, baselineRR.Response.Duration.Milliseconds(), baselineRR.Response.Headers)
					}
					baseBody := baselineBodies[method+"_native"]
					if baseBody == "" {
						baseBody = baselineRR.Response.Body
					}
					if isParameterHitWithControl(baseFP, fp, randCtrlFP, baseBody, rr.Response.Body, randCtrlBody,
						candidate, randParam, "akca_probe", isDynamic, noiseThreshold) {
						recordHit(candidate, string(location))
						if location == LocationJSON {
							jsonPotentialHits[candidate] = struct{}{}
						}
					}
				}
			}
		}
	}

	// Phase 2: Detailed type-mutation pass ONLY for candidates showing potential hits or remaining budget
	if (d.maxProbes <= 0 || probes < d.maxProbes) && (d.maxHits <= 0 || len(confirmedHits) < d.maxHits) {
		for candidate := range jsonPotentialHits {
			if d.maxProbes > 0 && probes >= d.maxProbes {
				break
			}
			for _, pv := range probeValuesByType {
				if body, location, ok := mutateNativeBody(template, candidate, pv.val); ok && location == LocationJSON && d.scope.IsInScope(requestURL) {
					if rr, perr := d.client.Do(ctx, method, requestURL, body, bodyProbeHeaders(requestHeaders, location)); perr == nil {
						probes++
						fp := Fingerprint(rr.Response.StatusCode, rr.Response.Body, rr.Response.Duration.Milliseconds(), rr.Response.Headers)
						baseFP, baseOK := baselines[method+"_native"]
						if !baseOK {
							baseFP = Fingerprint(baselineRR.Response.StatusCode, baselineRR.Response.Body, baselineRR.Response.Duration.Milliseconds(), baselineRR.Response.Headers)
						}
						baseBody := baselineBodies[method+"_native"]
						if baseBody == "" {
							baseBody = baselineRR.Response.Body
						}
						if isParameterHit(baseFP, fp, baseBody, rr.Response.Body, pv.val, isDynamic, noiseThreshold) {
							recordHit(candidate, "json")
							break
						}
					}
				}
			}
		}
	}

	for name, surfaces := range confirmedHits {
		loc := LocationQuery
		probeMethod := primaryProbeMethod(method)
		priority := 70
		if _, ok := surfaces["form"]; ok {
			loc = LocationForm
			priority = 88
			if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
				probeMethod = method
			} else {
				probeMethod = http.MethodPost
			}
		} else if _, ok := surfaces["json"]; ok {
			loc = LocationJSON
			priority = 84
			probeMethod = method
		} else if strings.HasPrefix(name, "X-") || name == "User-Agent" || name == "Referer" {
			loc = LocationHeader
			priority = 80
		}
		accepted := make([]string, 0, len(surfaces))
		for s := range surfaces {
			accepted = append(accepted, s)
		}
		p := DiscoveredParameter{
			Name: name, Location: loc, Priority: priority, MethodDependent: len(surfaces) > 1,
			AcceptedMethods: accepted, Confidence: 0.75, Source: "differential",
			EndpointURL: endpointURL, EndpointMethod: probeMethod,
		}
		differential = append(differential, p)
		_ = d.persist(endpointID, p)

		// Persist camelCase/kebab-case variants without inflating candidate hit count
		for _, variant := range paramVariants(name) {
			if variant != name {
				vp := p
				vp.Name = variant
				vp.Priority -= 5
				_ = d.persist(endpointID, vp)
			}
		}
	}

	for _, p := range templateParams {
		_ = d.persist(endpointID, p)
	}

	all := append(passive, differential...)
	all = append(all, templateParams...)
	return all, nil
}

func getBaseline(ctx context.Context, client HTTPDoer, endpointURL, method string, headers map[string]string, defaultRR httpclient.RequestResponse, baselines map[string]ResponseFingerprint, baselineBodies map[string]string) {
	if strings.ToUpper(method) == http.MethodGet {
		fp := Fingerprint(defaultRR.Response.StatusCode, defaultRR.Response.Body, defaultRR.Response.Duration.Milliseconds(), defaultRR.Response.Headers)
		baselines["GET"] = fp
		baselineBodies["GET"] = defaultRR.Response.Body
	} else {
		if getRR, err := client.Do(ctx, http.MethodGet, endpointURL, nil, headers); err == nil {
			fp := Fingerprint(getRR.Response.StatusCode, getRR.Response.Body, getRR.Response.Duration.Milliseconds(), getRR.Response.Headers)
			baselines["GET"] = fp
			baselineBodies["GET"] = getRR.Response.Body
		}
	}
	m := strings.ToUpper(method)
	if m == http.MethodPost || m == http.MethodPut || m == http.MethodPatch {
		fp := Fingerprint(defaultRR.Response.StatusCode, defaultRR.Response.Body, defaultRR.Response.Duration.Milliseconds(), defaultRR.Response.Headers)
		baselines[m+"_native"] = fp
		baselineBodies[m+"_native"] = defaultRR.Response.Body
	}
}

func (d *Discoverer) Run(ctx context.Context, limit int) error {
	_ = d.emit("parameter_discovery_started", "parameter discovery started", map[string]interface{}{
		"scan_id": d.scanID,
	})
	endpoints, err := d.db.ListDiscoveryEndpoints(d.scanID, limit)
	if err != nil {
		return err
	}

	// Perform cross-endpoint parameter transfer first
	d.crossEndpointTransfer(ctx, endpoints)

	workers := d.parallelism
	if workers <= 0 {
		workers = 4
	}
	endpointCh := make(chan storage.DiscoveryEndpoint, workers*2)
	var wg sync.WaitGroup
	completed := 0
	failures := 0
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ep := range endpointCh {
				if ctx.Err() != nil {
					return
				}
				func() {
					var discoverErr error
					defer func() {
						if recovered := recover(); recovered != nil {
							discoverErr = fmt.Errorf("parameter discovery panic: %v", recovered)
						}
						d.mu.Lock()
						completed++
						if discoverErr != nil {
							failures++
						}
						current := completed
						d.mu.Unlock()
						payload := map[string]interface{}{
							"scan_id": d.scanID, "completed": current, "total": len(endpoints),
						}
						if discoverErr != nil {
							payload["error"] = discoverErr.Error()
						}
						_ = d.emit("parameter_discovery_progress", "parameter discovery progress", payload)
					}()
					_, discoverErr = d.DiscoverEndpoint(ctx, ep.ID, ep.URL, ep.Method, ep.RequestTemplate)
				}()
			}
		}()
	}
feedLoop:
	for _, ep := range endpoints {
		select {
		case endpointCh <- ep:
		case <-ctx.Done():
			break feedLoop
		}
	}
	close(endpointCh)
	wg.Wait()
	if err := d.flushEvents(); err != nil {
		return err
	}
	_ = d.emit("parameter_discovery_finished", "parameter discovery finished", map[string]interface{}{
		"scan_id": d.scanID, "endpoints": len(endpoints),
	})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if failures > 0 {
		return fmt.Errorf("parameter discovery completed with %d endpoint errors", failures)
	}
	return nil
}

func (d *Discoverer) crossEndpointTransfer(ctx context.Context, endpoints []storage.DiscoveryEndpoint) {
	rows, err := d.db.Conn().Query(`
		SELECT DISTINCT p.name 
		FROM parameters p
		JOIN endpoints e ON e.id = p.endpoint_id 
		WHERE e.scan_id = ? AND p.priority >= 80`, d.scanID)
	if err != nil {
		return
	}
	defer rows.Close()

	var params []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err == nil {
			params = append(params, name)
		}
	}

	if len(params) == 0 {
		return
	}

	totalProbes := 0
	maxTransferProbes := d.maxTransferProbes

	for _, ep := range endpoints {
		if ctx.Err() != nil || (maxTransferProbes > 0 && totalProbes >= maxTransferProbes) {
			break
		}
		knownRows, err := d.db.Conn().Query(`SELECT name FROM parameters WHERE endpoint_id = ?`, ep.ID)
		if err != nil {
			continue
		}
		known := map[string]bool{}
		for knownRows.Next() {
			var name string
			if err := knownRows.Scan(&name); err == nil {
				known[name] = true
			}
		}
		knownRows.Close()

		for _, pName := range params {
			if maxTransferProbes > 0 && totalProbes >= maxTransferProbes {
				break
			}
			if !known[pName] {
				totalProbes++
				d.probeSingleParam(ctx, ep, pName)
			}
		}
	}
}

func (d *Discoverer) probeSingleParam(ctx context.Context, ep storage.DiscoveryEndpoint, param string) {
	m := strings.ToUpper(ep.Method)
	if m == "" {
		m = http.MethodGet
	}
	requestURL, requestBody, requestHeaders := nativeRequest(ep.URL, m, ep.RequestTemplate)
	baselineRR, err := d.client.Do(ctx, m, requestURL, requestBody, requestHeaders)
	if err != nil {
		return
	}
	baseline := Fingerprint(
		baselineRR.Response.StatusCode,
		baselineRR.Response.Body,
		baselineRR.Response.Duration.Milliseconds(),
		baselineRR.Response.Headers,
	)
	randParam := "__akca_rand_ctrl_8f1"

	if m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions {
		var controlFP ResponseFingerprint
		var controlBody string
		if controlURL, controlRequestBody := buildCustomQueryProbe(requestURL, randParam, "akca_probe"); d.scope.IsInScope(controlURL) {
			if rr, controlErr := d.client.Do(ctx, http.MethodGet, controlURL, controlRequestBody, requestHeaders); controlErr == nil {
				controlFP = Fingerprint(rr.Response.StatusCode, rr.Response.Body, rr.Response.Duration.Milliseconds(), rr.Response.Headers)
				controlBody = rr.Response.Body
			}
		}
		if probeURL, body := buildQueryProbe(requestURL, param); d.scope.IsInScope(probeURL) {
			if rr, perr := d.client.Do(ctx, http.MethodGet, probeURL, body, requestHeaders); perr == nil {
				fp := Fingerprint(rr.Response.StatusCode, rr.Response.Body, rr.Response.Duration.Milliseconds(), rr.Response.Headers)
				if isParameterHitWithControl(baseline, fp, controlFP, baselineRR.Response.Body, rr.Response.Body, controlBody,
					param, randParam, "akca_probe", false, 128) {
					_ = d.db.SaveParameter(ep.ID, param, "query", 75)
				}
			}
		}
	}
	if m == http.MethodPost || m == http.MethodPut || m == http.MethodPatch {
		var controlFP ResponseFingerprint
		var controlBody string
		if body, location, ok := mutateNativeBody(ep.RequestTemplate, randParam, "akca_probe"); ok {
			headers := bodyProbeHeaders(requestHeaders, location)
			if rr, controlErr := d.client.Do(ctx, m, requestURL, body, headers); controlErr == nil {
				controlFP = Fingerprint(rr.Response.StatusCode, rr.Response.Body, rr.Response.Duration.Milliseconds(), rr.Response.Headers)
				controlBody = rr.Response.Body
			}
		}
		if body, location, ok := mutateNativeBody(ep.RequestTemplate, param, "akca_probe"); ok {
			headers := bodyProbeHeaders(requestHeaders, location)
			if rr, probeErr := d.client.Do(ctx, m, requestURL, body, headers); probeErr == nil {
				fp := Fingerprint(rr.Response.StatusCode, rr.Response.Body, rr.Response.Duration.Milliseconds(), rr.Response.Headers)
				if isParameterHitWithControl(baseline, fp, controlFP, baselineRR.Response.Body, rr.Response.Body, controlBody,
					param, randParam, "akca_probe", false, 128) {
					_ = d.db.SaveParameter(ep.ID, param, string(location), 85)
				}
			}
		}
	}
}

func (d *Discoverer) persist(endpointID int64, p DiscoveredParameter) error {
	if err := d.db.SaveParameter(endpointID, p.Name, string(p.Location), p.Priority); err != nil {
		return err
	}
	d.mu.Lock()
	d.eventBatch = append(d.eventBatch, map[string]interface{}{
		"name": p.Name, "location": p.Location, "priority": p.Priority,
		"method_dependent": p.MethodDependent, "endpoint": p.EndpointURL,
	})
	shouldFlush := len(d.eventBatch) >= 25
	d.mu.Unlock()
	if shouldFlush {
		return d.flushEvents()
	}
	return nil
}

func (d *Discoverer) flushEvents() error {
	d.mu.Lock()
	batch := d.eventBatch
	d.eventBatch = nil
	d.mu.Unlock()
	if len(batch) == 0 {
		return nil
	}
	return d.emit("parameter_discovered", "parameter batch", map[string]interface{}{
		"scan_id": d.scanID, "count": len(batch), "parameters": batch,
	})
}

func buildQueryProbe(endpointURL, param string) (string, []byte) {
	return buildCustomQueryProbe(endpointURL, param, "akca_probe")
}

func buildCustomQueryProbe(endpointURL, param, value string) (string, []byte) {
	if !urlutil.IsPlausibleEndpointURL(endpointURL) {
		return "", nil
	}
	u, err := url.Parse(endpointURL)
	if err != nil {
		return endpointURL, nil
	}
	q := u.Query()
	q.Set(param, value)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func buildFormProbe(endpointURL, param string) (string, []byte) {
	return buildCustomFormProbe(endpointURL, param, "akca_probe")
}

func buildCustomFormProbe(endpointURL, param, value string) (string, []byte) {
	form := url.Values{}
	form.Set(param, value)
	return endpointURL, []byte(form.Encode())
}

func buildJSONProbe(endpointURL, param string) (string, []byte) {
	return buildCustomJSONProbe(endpointURL, param, "akca_probe")
}

func buildCustomJSONProbe(endpointURL, param, value string) (string, []byte) {
	return endpointURL, []byte(fmt.Sprintf(`{"%s":"%s"}`, param, value))
}

func nativeRequest(endpointURL, method string, template storage.DiscoveryRequestTemplate) (string, []byte, map[string]string) {
	reqURL := endpointURL
	if template.URL != "" && urlutil.IsPlausibleEndpointURL(template.URL) {
		reqURL = template.URL
	}
	headers := cloneHeaders(template.Headers)
	if template.ContentType != "" && headerValue(headers, "Content-Type") == "" {
		headers["Content-Type"] = template.ContentType
	}
	return reqURL, []byte(template.Body), headers
}

func mutateNativeBody(template storage.DiscoveryRequestTemplate, param, value string) ([]byte, Location, bool) {
	contentType := strings.ToLower(template.ContentType)
	if contentType == "" {
		contentType = strings.ToLower(headerValue(template.Headers, "Content-Type"))
	}
	body := strings.TrimSpace(template.Body)
	isJSON := strings.Contains(contentType, "json") || (body != "" && json.Valid([]byte(body)))
	if isJSON {
		var document map[string]interface{}
		if body == "" {
			document = make(map[string]interface{})
		} else if err := json.Unmarshal([]byte(body), &document); err != nil {
			return nil, "", false
		}
		setNestedPath(document, param, value)
		mutated, err := json.Marshal(document)
		return mutated, LocationJSON, err == nil
	}

	// Form is the compatibility fallback for older endpoint records that do
	// not have a request template. When a template exists, all sibling fields
	// are retained and only the candidate parameter is added/replaced.
	form, err := url.ParseQuery(template.Body)
	if err != nil {
		return nil, "", false
	}
	form.Set(param, value)
	return []byte(form.Encode()), LocationForm, true
}

func setNestedPath(doc map[string]interface{}, path string, value interface{}) {
	if !strings.Contains(path, ".") {
		doc[path] = value
		return
	}
	parts := strings.Split(path, ".")
	current := doc
	for i := 0; i < len(parts)-1; i++ {
		key := parts[i]
		if next, ok := current[key].(map[string]interface{}); ok {
			current = next
		} else {
			nested := make(map[string]interface{})
			current[key] = nested
			current = nested
		}
	}
	current[parts[len(parts)-1]] = value
}

func bodyProbeHeaders(base map[string]string, location Location) map[string]string {
	headers := cloneHeaders(base)
	if headerValue(headers, "Content-Type") == "" {
		if location == LocationJSON {
			headers["Content-Type"] = "application/json"
		} else {
			headers["Content-Type"] = "application/x-www-form-urlencoded"
		}
	}
	return headers
}

func cloneHeaders(headers map[string]string) map[string]string {
	cloned := make(map[string]string, len(headers)+1)
	for key, value := range headers {
		cloned[key] = value
	}
	return cloned
}

func buildProbe(endpointURL, method, param string) (string, []byte) {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return buildFormProbe(endpointURL, param)
	default:
		return buildQueryProbe(endpointURL, param)
	}
}

func headerValue(headers map[string]string, key string) string {
	for k, v := range headers {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

func isParameterHit(baseFP, probeFP ResponseFingerprint, baseBody, probeBody, probeVal string, isDynamic bool, noiseThreshold int) bool {
	return isParameterHitWithControl(baseFP, probeFP, ResponseFingerprint{}, baseBody, probeBody, "", "", "", probeVal, isDynamic, noiseThreshold)
}

func isParameterHitWithControl(baseFP, probeFP, randCtrlFP ResponseFingerprint, baseBody, probeBody, randCtrlBody,
	probeName, randCtrlName, probeVal string, isDynamic bool, noiseThreshold int,
) bool {
	controlAvailable := randCtrlFP.StatusCode != 0 || randCtrlFP.BodyHash != ""
	if controlAvailable && probeFP.StatusCode == randCtrlFP.StatusCode {
		// Exact equality is generic unknown-field behaviour regardless of whether
		// the server responds with an error or a successful echo page.
		if probeFP.BodyHash == randCtrlFP.BodyHash && probeFP.HeaderHash == randCtrlFP.HeaderHash {
			return false
		}
		// Many frameworks include the rejected field name in an otherwise
		// identical validation response. Normalize both candidate names and the
		// shared canary so this does not become a false hidden parameter.
		if normalizeUnknownParameterResponse(probeBody, probeName, probeVal) ==
			normalizeUnknownParameterResponse(randCtrlBody, randCtrlName, probeVal) {
			return false
		}
	}
	// 1. Status code changed (e.g. 200 -> 400, 422, 500)
	if probeFP.StatusCode != baseFP.StatusCode {
		return true
	}
	// 2. Semantic diff (JSON keys changed, or error/validation keywords)
	if SemanticDiffers(baseBody, probeBody) {
		return true
	}
	// 3. Injected probe value is reflected in the response (was absorbed/handled)
	if probeVal != "" && strings.Contains(probeBody, probeVal) && !strings.Contains(baseBody, probeVal) &&
		(!controlAvailable || !strings.Contains(randCtrlBody, probeVal)) {
		return true
	}
	// 4. On a static page, standard fingerprinted difference
	if !isDynamic {
		return Differs(baseFP, probeFP)
	}
	// 5. On a dynamic page, length change must exceed natural noise threshold by a solid margin
	lenDiff := abs(probeFP.BodyLength - baseFP.BodyLength)
	if lenDiff > noiseThreshold && lenDiff > 256 {
		return true
	}
	return false
}

func normalizeUnknownParameterResponse(body, parameter, value string) string {
	normalized := strings.ToLower(strings.TrimSpace(body))
	for _, token := range []string{strings.ToLower(parameter), strings.ToLower(value)} {
		if token != "" {
			normalized = strings.ReplaceAll(normalized, token, "__akca_value__")
		}
	}
	return strings.Join(strings.Fields(normalized), " ")
}

func SemanticDiffers(baseBody, probeBody string) bool {
	if baseBody == probeBody {
		return false
	}
	var baseMap, probeMap map[string]interface{}
	if json.Unmarshal([]byte(baseBody), &baseMap) == nil {
		if json.Unmarshal([]byte(probeBody), &probeMap) == nil {
			if len(baseMap) != len(probeMap) {
				return true
			}
			for k := range probeMap {
				if _, ok := baseMap[k]; !ok {
					return true
				}
			}
		}
	}
	baseLower := strings.ToLower(baseBody)
	probeLower := strings.ToLower(probeBody)
	for _, kw := range []string{"invalid", "missing", "required", "error", "bad request"} {
		if strings.Contains(baseLower, kw) != strings.Contains(probeLower, kw) {
			return true
		}
	}
	return false
}

func paramVariants(name string) []string {
	variants := []string{name}
	if strings.Contains(name, "_") {
		parts := strings.Split(name, "_")
		camel := parts[0]
		for _, p := range parts[1:] {
			if len(p) > 0 {
				camel += strings.Title(p)
			}
		}
		if camel != name {
			variants = append(variants, camel)
		}
	}
	var snake []rune
	for i, r := range name {
		if i > 0 && r >= 'A' && r <= 'Z' {
			snake = append(snake, '_')
		}
		snake = append(snake, unicode.ToLower(r))
	}
	snakeStr := string(snake)
	if snakeStr != name {
		variants = append(variants, snakeStr)
	}
	return variants
}

func (d *Discoverer) String() string {
	return fmt.Sprintf("discoverer[%s wordlist=%d cap=%d]", d.scanID, WordlistSize(), d.wordlistCap)
}

func (d *Discoverer) SetMaxProbes(n int) {
	d.maxProbes = n
}

func (d *Discoverer) SetWordlistCap(n int) {
	d.wordlistCap = n
}

func (d *Discoverer) SetMaxTransferProbes(n int) {
	d.maxTransferProbes = n
}

func (d *Discoverer) SetParallelism(n int) {
	if n > 0 {
		d.parallelism = n
	}
}

func Now() time.Time { return time.Now().UTC() }
