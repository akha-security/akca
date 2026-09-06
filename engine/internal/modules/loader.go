package modules

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/akha-security/akca/engine/internal/learning"
	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/planner"
	"github.com/akha-security/akca/engine/internal/reflection"
)

func (r *Runner) LoadTargetsFromDB(limit int) ([]ScanTarget, error) {
	targets, err := r.loadTargetsUnplanned(limit)
	if err != nil {
		return nil, err
	}
	return r.planAndCapTargets(targets, limit)
}

func (r *Runner) loadTargetsUnplanned(limit int) ([]ScanTarget, error) {
	candidateLimit := 0
	if limit > 0 {
		candidateLimit = limit * 10
		if candidateLimit < 10000 {
			candidateLimit = 10000
		}
	}
	targets, err := r.loadParameterTargets(candidateLimit)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		seen[t.EndpointURL+"::"+t.Method+"::"+t.Parameter+"::"+t.Location] = struct{}{}
	}
	fallbacks, err := r.fallbackTargetsFromEndpoints(candidateLimit)
	if err == nil {
		for _, f := range fallbacks {
			key := f.EndpointURL + "::" + f.Method + "::" + f.Parameter + "::" + f.Location
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				targets = append(targets, f)
			}
		}
	}
	return targets, nil
}

// LoadTargetsWithEndpointsFromDB preserves parameter targets (from DB parameters
// and discovered URL query strings) and also adds one target for every discovered
// parameterless endpoint. Injection Group A needs an actual mutation surface, but
// endpoint-level modules (security headers, debug exposure, GraphQL, WebSocket, TLS
// and similar checks) must not vanish merely because some other endpoint in the
// scan had parameters.
func (r *Runner) LoadTargetsWithEndpointsFromDB(limit int) ([]ScanTarget, error) {
	targets, err := r.loadTargetsUnplanned(limit)
	if err != nil {
		return nil, err
	}
	seenParameters := make(map[string]struct{}, len(targets))
	seenEndpoints := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		if target.Parameter != "" {
			seenParameters[target.EndpointURL+"::"+target.Method+"::"+target.Parameter] = struct{}{}
		} else {
			seenEndpoints[targetSurfaceKey(target.EndpointURL, target.Method)] = struct{}{}
		}
	}
	endpoints, err := r.db.ListDiscoveryEndpoints(r.scanID, limit)
	if err != nil {
		return nil, err
	}
	for _, endpoint := range endpoints {
		if !r.scope.IsInScope(endpoint.URL) {
			continue
		}
		method := strings.ToUpper(strings.TrimSpace(endpoint.Method))
		if method == "" {
			method = http.MethodGet
		}
		// Extract URL query parameters for endpoints discovered during crawling
		params := paramsFromURL(endpoint.URL)
		if len(params) > 0 {
			for _, pName := range params {
				paramKey := endpoint.URL + "::" + method + "::" + pName
				if _, exists := seenParameters[paramKey]; !exists {
					seenParameters[paramKey] = struct{}{}
					targets = append(targets, ScanTarget{
						EndpointURL: endpoint.URL,
						Method:      method,
						Parameter:   pName,
						Location:    "query",
						Profile: reflection.ReflectionProfile{
							ScanID: r.scanID, EndpointURL: endpoint.URL, Method: method,
							Parameter: pName, ParameterLocation: "query",
						},
					})
				}
			}
		}
		// Extract path parameters for endpoints with URL rewrite / REST path IDs
		pathParams := pathParamsFromURL(endpoint.URL)
		if len(pathParams) > 0 {
			for _, pName := range pathParams {
				paramKey := endpoint.URL + "::" + method + "::" + pName + "::path"
				if _, exists := seenParameters[paramKey]; !exists {
					seenParameters[paramKey] = struct{}{}
					targets = append(targets, ScanTarget{
						EndpointURL: endpoint.URL,
						Method:      method,
						Parameter:   pName,
						Location:    "path",
						Profile: reflection.ReflectionProfile{
							ScanID: r.scanID, EndpointURL: endpoint.URL, Method: method,
							Parameter: pName, ParameterLocation: "path",
						},
					})
				}
			}
		}
		// Extract Form / Body / JSON parameters for POST/PUT endpoints discovered during crawling
		bodyParams, bodyLoc := paramsFromBody(endpoint.RequestTemplate.Body, endpoint.RequestTemplate.ContentType)
		if len(bodyParams) > 0 {
			for _, pName := range bodyParams {
				paramKey := endpoint.URL + "::" + method + "::" + pName + "::" + bodyLoc
				if _, exists := seenParameters[paramKey]; !exists {
					seenParameters[paramKey] = struct{}{}
					targets = append(targets, ScanTarget{
						EndpointURL:  endpoint.URL,
						Method:       method,
						Parameter:    pName,
						Location:     bodyLoc,
						BodyTemplate: endpoint.RequestTemplate.Body,
						Profile: reflection.ReflectionProfile{
							ScanID: r.scanID, EndpointURL: endpoint.URL, Method: method,
							Parameter: pName, ParameterLocation: bodyLoc,
							ContentType: endpoint.RequestTemplate.ContentType,
						},
						RequestTemplate: reflection.RequestTemplate{
							Method:      method,
							URL:         endpoint.URL,
							Headers:     endpoint.RequestTemplate.Headers,
							Body:        endpoint.RequestTemplate.Body,
							ContentType: endpoint.RequestTemplate.ContentType,
						},
					})
				}
			}
		}
		key := targetSurfaceKey(endpoint.URL, method)
		if _, exists := seenEndpoints[key]; !exists {
			seenEndpoints[key] = struct{}{}
			targets = append(targets, ScanTarget{
				EndpointURL: endpoint.URL,
				Method:      method,
				Profile: reflection.ReflectionProfile{
					ScanID: r.scanID, EndpointURL: endpoint.URL, Method: method,
				},
			})
		}
	}
	return r.planAndCapBalancedTargets(targets, limit)
}

// planAndCapBalancedTargets reserves part of the hard limit for parameterless
// endpoint targets. Without this reservation, a large parameter corpus can
// starve passive and endpoint-level modules entirely.
func (r *Runner) planAndCapBalancedTargets(targets []ScanTarget, limit int) ([]ScanTarget, error) {
	planned, err := r.applySmartPlan(targets)
	if err != nil {
		return planned, err
	}
	planned = orderTargetsByEndpointCoverage(planned)
	if limit <= 0 || len(planned) <= limit {
		return planned, nil
	}
	endpointCount, parameterCount := 0, 0
	for _, target := range planned {
		if target.Parameter == "" {
			endpointCount++
		} else {
			parameterCount++
		}
	}
	endpointBudget := limit / 4
	if endpointBudget < 1 && endpointCount > 0 {
		endpointBudget = 1
	}
	if endpointBudget > endpointCount {
		endpointBudget = endpointCount
	}
	parameterBudget := limit - endpointBudget
	if parameterBudget > parameterCount {
		parameterBudget = parameterCount
		endpointBudget = minInt(endpointCount, limit-parameterBudget)
	}
	if endpointBudget < endpointCount && endpointBudget+parameterBudget < limit {
		endpointBudget = minInt(endpointCount, limit-parameterBudget)
	}
	selected := make([]ScanTarget, 0, limit)
	usedEndpoints, usedParameters := 0, 0
	for _, target := range planned {
		if target.Parameter == "" {
			if usedEndpoints >= endpointBudget {
				continue
			}
			usedEndpoints++
		} else {
			if usedParameters >= parameterBudget {
				continue
			}
			usedParameters++
		}
		selected = append(selected, target)
	}
	return selected, nil
}

func (r *Runner) planAndCapTargets(targets []ScanTarget, limit int) ([]ScanTarget, error) {
	planned, err := r.applySmartPlan(targets)
	if err != nil {
		return nil, err
	}
	planned = orderTargetsByEndpointCoverage(planned)
	if limit > 0 && len(planned) > limit {
		planned = planned[:limit]
	}
	return planned, nil
}

// orderTargetsByEndpointCoverage keeps the smart planner's endpoint and
// parameter priority, but distributes work round-robin across endpoints. Each
// discovered route gets its first mutation surface before any route gets its
// second, and so on.
//
// Besides preventing hard-limit starvation, this also prevents a scan with no
// effective hard cap from spending minutes on every parameter/header of one
// route while later crawler links appear untouched.
func orderTargetsByEndpointCoverage(planned []ScanTarget) []ScanTarget {
	if len(planned) < 2 {
		return planned
	}
	endpointOrder := make([]string, 0)
	buckets := make(map[string][]ScanTarget)
	for _, target := range planned {
		key := targetSurfaceKey(target.EndpointURL, target.Method)
		if _, exists := buckets[key]; !exists {
			endpointOrder = append(endpointOrder, key)
		}
		buckets[key] = append(buckets[key], target)
	}

	ordered := make([]ScanTarget, 0, len(planned))
	for round := 0; len(ordered) < len(planned); round++ {
		for _, key := range endpointOrder {
			bucket := buckets[key]
			if round < len(bucket) {
				ordered = append(ordered, bucket[round])
			}
		}
	}
	return ordered
}

func capTargetsWithEndpointCoverage(planned []ScanTarget, limit int) []ScanTarget {
	ordered := orderTargetsByEndpointCoverage(planned)
	if limit > 0 && len(ordered) > limit {
		return ordered[:limit]
	}
	return ordered
}

func targetSurfaceKey(endpointURL, method string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = http.MethodGet
	}
	return endpointURL + "::" + method
}

func (r *Runner) applySmartPlan(targets []ScanTarget) ([]ScanTarget, error) {
	plans, err := r.db.ListEndpointPlans(r.scanID)
	if err != nil {
		return nil, err
	}
	profiles := map[string]learning.Profile{}
	store := learning.NewStore(r.db)
	items := make([]planner.RequestItem, 0, len(targets))
	byKey := map[string][]ScanTarget{}
	for i := range targets {
		t := targets[i]
		method := strings.ToUpper(t.Method)
		if method == "" {
			method = http.MethodGet
		}
		if plan, ok := plans[t.EndpointURL+"::"+method]; ok {
			t.EndpointType = plan.EndpointType
			t.RiskTags = append([]string(nil), plan.RiskTags...)
			t.RecommendedModules = append([]string(nil), plan.RecommendedModules...)
			t.Priority = 50 + len(plan.RecommendedModules)*5
			if plan.StateChanging || plan.AuthRequired {
				t.Priority += 10
			}
		}
		host := hostFromModuleURL(t.EndpointURL)
		if _, ok := profiles[host]; !ok {
			profiles[host] = store.Load(host, "")
		}
		key := t.EndpointURL + "::" + method + "::" + t.Parameter
		byKey[key] = append(byKey[key], t)
		items = append(items, planner.RequestItem{URL: t.EndpointURL, Method: method, Parameter: t.Parameter, Priority: t.Priority, Reason: "endpoint intelligence"})
	}
	ordered := planner.New(profiles).Order(items)
	out := make([]ScanTarget, 0, len(targets))
	for _, item := range ordered {
		key := item.URL + "::" + strings.ToUpper(item.Method) + "::" + item.Parameter
		bucket := byKey[key]
		if len(bucket) == 0 {
			continue
		}
		t := bucket[0]
		t.Priority = item.Priority
		out = append(out, t)
		byKey[key] = bucket[1:]
	}
	_ = r.emit("smart_plan_ready", "endpoint intelligence plan applied", map[string]interface{}{
		"scan_id": r.scanID, "targets": len(out), "intelligence_profiles": len(plans), "learning_domains": len(profiles),
	})
	return out, nil
}

func (r *Runner) loadParameterTargets(limit int) ([]ScanTarget, error) {
	params, err := r.db.ListParameterTargets(r.scanID, limit)
	if err != nil {
		return nil, err
	}
	profiles, err := r.db.ListReflectionProfileJSON(r.scanID, r.cfg.ReflectionProfileLimit())
	if err != nil {
		return nil, err
	}
	profileByKey := map[string]reflection.ReflectionProfile{}
	for _, raw := range profiles {
		var p reflection.ReflectionProfile
		if json.Unmarshal([]byte(raw), &p) == nil {
			key := makeProfileKey(p.Method, p.EndpointURL, p.Parameter, p.ParameterLocation)
			if _, exists := profileByKey[key]; !exists {
				profileByKey[key] = p
			}
			fallbackKey := p.EndpointURL + "::" + p.Parameter
			if _, exists := profileByKey[fallbackKey]; !exists {
				profileByKey[fallbackKey] = p
			}
		}
	}
	var targets []ScanTarget
	for _, param := range params {
		key := makeProfileKey(param.Method, param.EndpointURL, param.Parameter, param.Location)
		profile, found := profileByKey[key]
		if !found {
			profile = profileByKey[param.EndpointURL+"::"+param.Parameter]
		}
		if profile.EndpointURL == "" {
			profile = reflection.ReflectionProfile{
				ScanID: r.scanID, EndpointURL: param.EndpointURL, Method: param.Method,
				Parameter: param.Parameter, ParameterLocation: param.Location,
				ContentType: param.ContentType,
			}
		}
		if profile.ContentType == "" && param.ContentType != "" {
			profile.ContentType = param.ContentType
		}
		genRaw, _ := r.db.LoadPayloadGenerationJSON(param.EndpointURL + "::" + param.Parameter)
		var gen payloadgen.GenerationResult
		_ = json.Unmarshal([]byte(genRaw), &gen)
		targets = append(targets, ScanTarget{
			EndpointURL: param.EndpointURL, Method: param.Method,
			Parameter: param.Parameter, Location: param.Location,
			Profile: profile, Payloads: gen,
			BodyTemplate: param.BodyTemplate,
			RequestTemplate: reflection.RequestTemplate{
				Method: param.Method, URL: param.EndpointURL, Headers: param.Headers,
				Body: param.BodyTemplate, ContentType: param.ContentType,
			},
		})
	}
	return targets, nil
}

func (r *Runner) fallbackTargetsFromEndpoints(limit int) ([]ScanTarget, error) {
	if limit <= 0 {
		limit = 100
	}
	endpoints, err := r.db.ListDiscoveryEndpoints(r.scanID, limit)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var targets []ScanTarget
	headerParams := []string{"User-Agent", "Referer", "X-Forwarded-For", "Cookie"}
	includeHeaders := r.cfg.Explicit.EnableWAFBypassHeaders

	for _, ep := range endpoints {
		if !r.scope.IsInScope(ep.URL) {
			continue
		}
		method := strings.ToUpper(ep.Method)
		if method == "" {
			method = http.MethodGet
		}
		names := paramsFromURL(ep.URL)
		pathNames := pathParamsFromURL(ep.URL)
		if len(names) == 0 && len(pathNames) == 0 {
			continue
		}
		for _, name := range names {
			key := ep.URL + "::" + method + "::" + name
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			loc := "query"
			targets = append(targets, ScanTarget{
				EndpointURL: ep.URL,
				Method:      method,
				Parameter:   name,
				Location:    loc,
				Profile: reflection.ReflectionProfile{
					ScanID: r.scanID, EndpointURL: ep.URL, Method: method,
					Parameter: name, ParameterLocation: loc,
				},
				RequestTemplate: reflection.RequestTemplate{
					Method: ep.RequestTemplate.Method, URL: ep.RequestTemplate.URL,
					Headers: ep.RequestTemplate.Headers, Body: ep.RequestTemplate.Body,
					ContentType: ep.RequestTemplate.ContentType,
				},
			})
		}
		for _, name := range pathNames {
			key := ep.URL + "::" + method + "::" + name + "::path"
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			loc := "path"
			targets = append(targets, ScanTarget{
				EndpointURL: ep.URL,
				Method:      method,
				Parameter:   name,
				Location:    loc,
				Profile: reflection.ReflectionProfile{
					ScanID: r.scanID, EndpointURL: ep.URL, Method: method,
					Parameter: name, ParameterLocation: loc,
				},
				RequestTemplate: reflection.RequestTemplate{
					Method: ep.RequestTemplate.Method, URL: ep.RequestTemplate.URL,
					Headers: ep.RequestTemplate.Headers, Body: ep.RequestTemplate.Body,
					ContentType: ep.RequestTemplate.ContentType,
				},
			})
		}
		bodyParams, bodyLoc := paramsFromBody(ep.RequestTemplate.Body, ep.RequestTemplate.ContentType)
		for _, name := range bodyParams {
			key := ep.URL + "::" + method + "::" + name + "::" + bodyLoc
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			targets = append(targets, ScanTarget{
				EndpointURL:  ep.URL,
				Method:       method,
				Parameter:    name,
				Location:     bodyLoc,
				BodyTemplate: ep.RequestTemplate.Body,
				Profile: reflection.ReflectionProfile{
					ScanID: r.scanID, EndpointURL: ep.URL, Method: method,
					Parameter: name, ParameterLocation: bodyLoc,
					ContentType: ep.RequestTemplate.ContentType,
				},
				RequestTemplate: reflection.RequestTemplate{
					Method:      method,
					URL:         ep.URL,
					Headers:     ep.RequestTemplate.Headers,
					Body:        ep.RequestTemplate.Body,
					ContentType: ep.RequestTemplate.ContentType,
				},
			})
		}
		if includeHeaders {
			for _, hName := range headerParams {
				key := ep.URL + "::" + method + "::header::" + hName
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				targets = append(targets, ScanTarget{
					EndpointURL: ep.URL,
					Method:      method,
					Parameter:   hName,
					Location:    "header",
					Profile: reflection.ReflectionProfile{
						ScanID: r.scanID, EndpointURL: ep.URL, Method: method,
						Parameter: hName, ParameterLocation: "header",
					},
					RequestTemplate: reflection.RequestTemplate{
						Method: ep.RequestTemplate.Method, URL: ep.RequestTemplate.URL,
						Headers: ep.RequestTemplate.Headers, Body: ep.RequestTemplate.Body,
						ContentType: ep.RequestTemplate.ContentType,
					},
				})
			}
		}
		if len(targets) >= limit {
			return targets[:limit], nil
		}
	}
	return targets, nil
}

func paramsFromURL(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil || u.RawQuery == "" {
		return nil
	}
	var out []string
	for name := range u.Query() {
		name = strings.TrimSpace(name)
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

var loaderPathUUIDRe = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func pathParamsFromURL(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Path == "" {
		return nil
	}
	for _, placeholder := range []string{"{", ":", "["} {
		if strings.Contains(u.Path, placeholder) {
			return []string{"path_segment"}
		}
	}
	segs := strings.Split(strings.Trim(u.Path, "/"), "/")
	for _, seg := range segs {
		seg = strings.TrimSpace(seg)
		if len(seg) == 0 {
			continue
		}
		if (seg[0] >= '0' && seg[0] <= '9') || loaderPathUUIDRe.MatchString(seg) {
			return []string{"path_segment"}
		}
	}
	return nil
}

func makeProfileKey(method, endpointURL, param, location string) string {
	m := strings.ToUpper(strings.TrimSpace(method))
	if m == "" {
		m = "GET"
	}
	loc := strings.ToLower(strings.TrimSpace(location))
	return m + "::" + endpointURL + "::" + param + "::" + loc
}

func (r *Runner) RunGroupAFromDB(ctx context.Context, limit int) ([]ModuleFinding, error) {
	targets, err := r.LoadTargetsFromDB(limit)
	if err != nil {
		return nil, err
	}
	return r.RunGroupA(ctx, targets)
}

func paramsFromBody(body, contentType string) ([]string, string) {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return nil, "query"
	}
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "json") || strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		var doc interface{}
		if err := json.Unmarshal([]byte(trimmed), &doc); err == nil {
			var keys []string
			collectJSONKeys(doc, "", &keys)
			if len(keys) > 0 {
				return deduplicateStrings(keys), "json"
			}
		}
	}
	// Default to form urlencoded
	if parsed, err := url.ParseQuery(trimmed); err == nil && len(parsed) > 0 {
		var keys []string
		for k := range parsed {
			k = strings.TrimSpace(k)
			if k != "" {
				keys = append(keys, k)
			}
		}
		if len(keys) > 0 {
			return deduplicateStrings(keys), "form"
		}
	}
	return nil, "form"
}

func deduplicateStrings(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		if _, exists := seen[item]; !exists {
			seen[item] = struct{}{}
			out = append(out, item)
		}
	}
	return out
}

func collectJSONKeys(doc interface{}, prefix string, keys *[]string) {
	switch v := doc.(type) {
	case map[string]interface{}:
		for k, val := range v {
			fullKey := k
			if prefix != "" {
				fullKey = prefix + "." + k
			}
			switch val.(type) {
			case map[string]interface{}, []interface{}:
				collectJSONKeys(val, fullKey, keys)
			default:
				*keys = append(*keys, fullKey)
			}
		}
	case []interface{}:
		for i, item := range v {
			indexedPrefix := strconv.Itoa(i)
			if prefix != "" {
				indexedPrefix = prefix + "." + indexedPrefix
			}
			switch item.(type) {
			case map[string]interface{}, []interface{}:
				collectJSONKeys(item, indexedPrefix, keys)
				if prefix != "" {
					collectJSONKeys(item, prefix, keys)
				}
			default:
				*keys = append(*keys, indexedPrefix)
			}
			if i >= 2 {
				break
			}
		}
	}
}
