package modules

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/akha-security/akca/engine/internal/learning"
	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/planner"
	"github.com/akha-security/akca/engine/internal/reflection"
)

func (r *Runner) LoadTargetsFromDB(limit int) ([]ScanTarget, error) {
	targets, err := r.loadParameterTargets(limit)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		targets, err = r.fallbackTargetsFromEndpoints(limit)
		if err != nil {
			return nil, err
		}
	}
	return r.applySmartPlan(targets)
}

// LoadTargetsWithEndpointsFromDB preserves parameter targets and also adds one
// target for every discovered parameterless endpoint. Injection Group A needs
// an actual mutation surface, but endpoint-level modules (security headers,
// debug exposure, GraphQL, WebSocket, TLS and similar checks) must not vanish
// merely because some other endpoint in the scan had parameters.
func (r *Runner) LoadTargetsWithEndpointsFromDB(limit int) ([]ScanTarget, error) {
	targets, err := r.loadParameterTargets(limit)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		seen[targetSurfaceKey(target.EndpointURL, target.Method)] = struct{}{}
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
		key := targetSurfaceKey(endpoint.URL, method)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		targets = append(targets, ScanTarget{
			EndpointURL: endpoint.URL,
			Method:      method,
			Profile: reflection.ReflectionProfile{
				ScanID: r.scanID, EndpointURL: endpoint.URL, Method: method,
			},
		})
	}
	return r.applySmartPlan(targets)
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
			key := p.EndpointURL + "::" + p.Parameter
			profileByKey[key] = p
		}
	}
	var targets []ScanTarget
	for _, param := range params {
		key := param.EndpointURL + "::" + param.Parameter
		profile := profileByKey[key]
		if profile.EndpointURL == "" {
			profile = reflection.ReflectionProfile{
				ScanID: r.scanID, EndpointURL: param.EndpointURL, Method: param.Method,
				Parameter: param.Parameter, ParameterLocation: param.Location,
			}
		}
		genRaw, _ := r.db.LoadPayloadGenerationJSON(param.EndpointURL + "::" + param.Parameter)
		var gen payloadgen.GenerationResult
		_ = json.Unmarshal([]byte(genRaw), &gen)
		targets = append(targets, ScanTarget{
			EndpointURL: param.EndpointURL, Method: param.Method,
			Parameter: param.Parameter, Location: param.Location,
			Profile: profile, Payloads: gen,
			BodyTemplate: param.BodyTemplate,
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
	for _, ep := range endpoints {
		if !r.scope.IsInScope(ep.URL) {
			continue
		}
		method := strings.ToUpper(ep.Method)
		if method == "" {
			method = http.MethodGet
		}
		names := paramsFromURL(ep.URL)
		if len(names) == 0 {
			continue
		}
		for _, name := range names {
			key := ep.URL + "::" + name
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			loc := "query"
			if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
				loc = "form"
			}
			targets = append(targets, ScanTarget{
				EndpointURL: ep.URL,
				Method:      method,
				Parameter:   name,
				Location:    loc,
				Profile: reflection.ReflectionProfile{
					ScanID: r.scanID, EndpointURL: ep.URL, Method: method,
					Parameter: name, ParameterLocation: loc,
				},
			})
			if len(targets) >= limit {
				return targets, nil
			}
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

func (r *Runner) RunGroupAFromDB(ctx context.Context, limit int) ([]ModuleFinding, error) {
	targets, err := r.LoadTargetsFromDB(limit)
	if err != nil {
		return nil, err
	}
	return r.RunGroupA(ctx, targets)
}
