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
	"X-Forwarded-For",
	"User-Agent",
	"Referer",
	"X-Original-URL",
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
	scanID      string
	client      HTTPDoer
	scope       *scope.Engine
	db          *storage.DB
	emit        EventSink
	maxProbes   int
	wordlistCap int
	maxHits     int
	parallelism int
	eventBatch  []map[string]interface{}
	mu          sync.Mutex
}

func NewDiscoverer(scanID string, client HTTPDoer, scopeEngine *scope.Engine, db *storage.DB, emit EventSink) *Discoverer {
	return &Discoverer{
		scanID: scanID, client: client, scope: scopeEngine, db: db, emit: emit,
		maxProbes: 80, wordlistCap: 120, maxHits: 24, parallelism: 8,
	}
}

func (d *Discoverer) DiscoverEndpoint(ctx context.Context, endpointID int64, endpointURL, method string) ([]DiscoveredParameter, error) {
	if !urlutil.IsPlausibleEndpointURL(endpointURL) || !d.scope.IsInScope(endpointURL) || !ShouldDiscoverEndpoint(endpointURL, method) {
		return nil, nil
	}
	method = strings.ToUpper(method)
	if method == "" {
		method = http.MethodGet
	}

	baselineRR, err := d.client.Do(ctx, method, endpointURL, nil, nil)
	if err != nil {
		return nil, err
	}
	if baselineRR.Response.StatusCode == http.StatusNotFound || baselineRR.Response.StatusCode == http.StatusGone {
		return nil, nil
	}
	contentType := headerValue(baselineRR.Response.Headers, "Content-Type")
	passive := ExtractPassive(endpointURL, method, contentType, baselineRR.Response.Body, baselineRR.Request.Headers)

	if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
		if getRR, gerr := d.client.Do(ctx, http.MethodGet, endpointURL, nil, nil); gerr == nil {
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

	baseline := Fingerprint(
		baselineRR.Response.StatusCode,
		baselineRR.Response.Body,
		baselineRR.Response.Duration.Milliseconds(),
		baselineRR.Response.Headers,
	)

	var differential []DiscoveredParameter
	methodHits := map[string]map[string]struct{}{}

	recordHit := func(name, surfaceKey string, loc Location, probeMethod string, priority int) {
		if _, ok := methodHits[name]; !ok {
			methodHits[name] = map[string]struct{}{}
		}
		methodHits[name][surfaceKey] = struct{}{}
		
		// Autogen and probe variants of the discovered parameter
		for _, variant := range paramVariants(name) {
			if variant != name {
				methodHits[variant] = map[string]struct{}{surfaceKey: {}}
			}
		}
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

	for _, candidate := range wordlist {
		if probes >= d.maxProbes || len(methodHits) >= d.maxHits {
			break
		}

		// Probing with different types to bypass backend validation
		for _, pv := range probeValuesByType {
			// GET query probe
			if probeURL, body := buildCustomQueryProbe(endpointURL, candidate, pv.val); d.scope.IsInScope(probeURL) {
				if rr, perr := d.client.Do(ctx, http.MethodGet, probeURL, body, nil); perr == nil {
					probes++
					fp := Fingerprint(rr.Response.StatusCode, rr.Response.Body, rr.Response.Duration.Milliseconds(), rr.Response.Headers)
					if Differs(baseline, fp) || SemanticDiffers(baselineRR.Response.Body, rr.Response.Body) {
						recordHit(candidate, "query", LocationQuery, http.MethodGet, 70)
						break
					}
				}
			}

			// POST form probe
			if probeURL, body := buildCustomFormProbe(endpointURL, candidate, pv.val); d.scope.IsInScope(probeURL) {
				postMethod := http.MethodPost
				if method == http.MethodPut || method == http.MethodPatch {
					postMethod = method
				}
				if rr, perr := d.client.Do(ctx, postMethod, probeURL, body, map[string]string{
					"Content-Type": "application/x-www-form-urlencoded",
				}); perr == nil {
					probes++
					fp := Fingerprint(rr.Response.StatusCode, rr.Response.Body, rr.Response.Duration.Milliseconds(), rr.Response.Headers)
					if Differs(baseline, fp) || SemanticDiffers(baselineRR.Response.Body, rr.Response.Body) {
						recordHit(candidate, "form", LocationForm, postMethod, 85)
						break
					}
				}
			}

			// JSON body probe
			if probeURL, body := buildCustomJSONProbe(endpointURL, candidate, pv.val); d.scope.IsInScope(probeURL) {
				if rr, perr := d.client.Do(ctx, http.MethodPost, probeURL, body, map[string]string{
					"Content-Type": "application/json",
				}); perr == nil {
					probes++
					fp := Fingerprint(rr.Response.StatusCode, rr.Response.Body, rr.Response.Duration.Milliseconds(), rr.Response.Headers)
					if Differs(baseline, fp) || SemanticDiffers(baselineRR.Response.Body, rr.Response.Body) {
						recordHit(candidate, "json", LocationJSON, http.MethodPost, 82)
						break
					}
				}
			}
		}

		// Header injection probes.
		for _, hdr := range differentialHeaders {
			if rr, perr := d.client.Do(ctx, method, endpointURL, nil, map[string]string{hdr: "akca_probe_" + candidate}); perr == nil {
				probes++
				fp := Fingerprint(rr.Response.StatusCode, rr.Response.Body, rr.Response.Duration.Milliseconds(), rr.Response.Headers)
				if Differs(baseline, fp) || SemanticDiffers(baselineRR.Response.Body, rr.Response.Body) {
					recordHit(hdr, "header:"+hdr, LocationHeader, method, 78)
				}
			}
			if probes >= d.maxProbes || len(methodHits) >= d.maxHits {
				break
			}
		}
	}

	for name, surfaces := range methodHits {
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
			probeMethod = http.MethodPost
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
	}

	all := append(passive, differential...)
	return all, nil
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
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for _, ep := range endpoints {
		if ctx.Err() != nil {
			break
		}
		ep := ep
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			_, _ = d.DiscoverEndpoint(ctx, ep.ID, ep.URL, ep.Method)
		}()
	}
	wg.Wait()
	_ = d.flushEvents()
	_ = d.emit("parameter_discovery_finished", "parameter discovery finished", map[string]interface{}{
		"scan_id": d.scanID, "endpoints": len(endpoints),
	})
	return nil
}

func (d *Discoverer) crossEndpointTransfer(ctx context.Context, endpoints []storage.DiscoveryEndpoint) {
	rows, err := d.db.Conn().Query(`
		SELECT DISTINCT p.name 
		FROM parameters p
		JOIN endpoints e ON e.id = p.endpoint_id 
		WHERE e.scan_id = ?`, d.scanID)
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

	for _, ep := range endpoints {
		if ctx.Err() != nil {
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
			if !known[pName] {
				d.probeSingleParam(ctx, ep.ID, ep.URL, ep.Method, pName)
			}
		}
	}
}

func (d *Discoverer) probeSingleParam(ctx context.Context, endpointID int64, endpointURL, method, param string) {
	baselineRR, err := d.client.Do(ctx, method, endpointURL, nil, nil)
	if err != nil {
		return
	}
	baseline := Fingerprint(
		baselineRR.Response.StatusCode,
		baselineRR.Response.Body,
		baselineRR.Response.Duration.Milliseconds(),
		baselineRR.Response.Headers,
	)

	if probeURL, body := buildQueryProbe(endpointURL, param); d.scope.IsInScope(probeURL) {
		if rr, perr := d.client.Do(ctx, http.MethodGet, probeURL, body, nil); perr == nil {
			fp := Fingerprint(rr.Response.StatusCode, rr.Response.Body, rr.Response.Duration.Milliseconds(), rr.Response.Headers)
			if Differs(baseline, fp) || SemanticDiffers(baselineRR.Response.Body, rr.Response.Body) {
				_ = d.db.SaveParameter(endpointID, param, "query", 75)
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
		variants = append(variants, camel)
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
	aliases := map[string][]string{
		"user_id":      {"uid", "userId", "user-id", "u_id", "u"},
		"product_id":   {"pid", "productId", "prod_id"},
		"order_id":     {"oid", "orderId"},
		"token":        {"access_token", "auth_token", "bearer", "jwt"},
		"debug":        {"_debug", "debugMode", "debug_mode", "dev"},
		"admin":        {"is_admin", "isAdmin", "role", "superuser"},
		"is_admin":     {"admin", "isAdmin", "role", "superuser"},
		"access_token": {"token", "auth_token", "jwt"},
	}
	if extra, ok := aliases[name]; ok {
		variants = append(variants, extra...)
	}
	return variants
}

func (d *Discoverer) String() string {
	return fmt.Sprintf("discoverer[%s wordlist=%d cap=%d]", d.scanID, WordlistSize(), d.wordlistCap)
}

func (d *Discoverer) SetMaxProbes(n int) {
	if n > 0 {
		d.maxProbes = n
	}
}

func (d *Discoverer) SetWordlistCap(n int) {
	if n > 0 {
		d.wordlistCap = n
	}
}

func (d *Discoverer) SetParallelism(n int) {
	if n > 0 {
		d.parallelism = n
	}
}

func Now() time.Time { return time.Now().UTC() }

