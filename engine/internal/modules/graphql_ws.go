package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/akha-security/akca/engine/internal/graphqlattack"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/verification"
)

const graphQLIntrospectionQuery = `{"query":"{ __schema { types { name fields { name } } } }"}`

func (r *Runner) runGraphQL(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("graphql", target); !ok {
		r.emitSkip("graphql", target, reason)
		return nil
	}
	field := strings.TrimSpace(target.Parameter)
	if field == "" || strings.EqualFold(field, "body") {
		field = "user"
	}
	var out []ModuleFinding

	// Probe GraphQL Introspection
	introspection, err := r.probeWithBody(ctx, target, graphQLIntrospectionQuery, "application/json", nil)
	if err == nil && graphqlIntrospectionSignal(introspection.Response.Body) {
		p := defaultPayload("graphql", "graphql_introspection", graphQLIntrospectionQuery, "graphql_schema_exposure")
		f := r.verifyAndBuildWithCandidate(ctx, "graphql", target, p, introspection, introspection, "graphql_schema_exposure", false, false, "", "", func(candidate *verification.Candidate) {
			candidate.RequestedProofType = verification.ProofSchemaExposure
		})
		if f != nil {
			f.Title = "GraphQL Introspection Enabled"
			f.Severity = "medium"
			f.Description = "GraphQL Introspection is enabled on this endpoint, exposing full schema types and field structures."
			r.recordFinding(ctx, &out, f, "graphql", "graphql_schema_exposure")
		}
	}

	fields := uniqueGraphQLFields(append([]string{field}, graphqlCandidateFieldsFromIntrospection(introspection.Response.Body)...))
	if len(fields) > 3 {
		fields = fields[:3]
	}
	for _, candidateField := range fields {
		typenameQuery := fmt.Sprintf(`{"query":"{%s { __typename } }"}`, graphqlFieldName(candidateField))
		baseline, err := r.probeWithBody(ctx, target, typenameQuery, "application/json", nil)
		if err != nil {
			continue
		}
		out = append(out, r.runGraphQLAbuse(ctx, target, baseline, candidateField)...)
		if len(out) >= 3 {
			break
		}
	}
	return out
}

func (r *Runner) runGraphQLAbuse(ctx context.Context, target ScanTarget, baseline httpclient.RequestResponse, field string) []ModuleFinding {
	var out []ModuleFinding
	probes := append([]graphqlattack.Probe{
		graphqlattack.BuildBatchProbe(100),
		graphqlattack.BuildSuggestionsProbe(field),
		graphqlattack.BuildCircularDepthProbe(field),
		graphqlattack.BuildAliasOverloadProbe(field),
		graphqlattack.BuildMutationPrivilegeProbe(field),
	}, append(append(graphqlattack.BuildTypeInversionProbes(field), graphqlattack.BuildAuthorizationBypassProbes(field)...), graphqlattack.BuildFilterWhereEvalProbes(field)...)...)
	for _, probe := range probes {
		if ctx.Err() != nil {
			break
		}
		rr, err := r.probeWithBody(ctx, target, probe.Body, "application/json", nil)
		if err != nil {
			continue
		}
		ok, signal := graphqlattack.Analyze(baseline.Response.Body, rr.Response.Body, probe)
		if !ok {
			continue
		}
		p := defaultPayload("graphql", probe.Name, probe.Body[:min(80, len(probe.Body))], signal)
		f := r.verifyAndBuildWithCandidate(ctx, "graphql", target, p, baseline, rr, signal, false, false, "", "", func(candidate *verification.Candidate) {
			candidate.RequestedProofType = verification.ProofSchemaExposure
		})
		if f != nil {
			switch signal {
			case "graphql_filter_where_rce":
				f.Title = "GraphQL In-Memory Filter Code Execution ($where RCE)"
				f.Severity = "critical"
				f.Description = "Unauthenticated arbitrary JavaScript code execution confirmed in server-side memory query engine (sift/MongoDB $where evaluation)."
			case "graphql_sift_where_detected":
				f.Title = "GraphQL In-Memory Filter ($where) Surface Detected"
				f.Severity = "high"
				f.Description = "GraphQL query accepts in-memory $where filtering functions, exposing dynamic evaluation."
			case "graphql_auth_bypass_admin", "graphql_auth_bypass_users", "graphql_auth_bypass_system", "graphql_auth_bypass_mutation":
				f.Title = "GraphQL Broken Function Level Authorization (BFLA)"
				f.Severity = "high"
				f.Description = "An unauthorized query or mutation accessed privileged administrative functions or user records without authorization."
			case "graphql_field_auth_leak":
				f.Title = "GraphQL Field-Level Authorization Bypass / Data Leak"
				f.Severity = "high"
				f.Description = "Sensitive internal fields (e.g. API keys, secrets, credentials, or tokens) were returned without proper field-level authorization controls."
			default:
				f.Title = "GraphQL abuse (" + signal + ")"
			}
			r.recordFinding(ctx, &out, f, "graphql", signal)
		}
		if len(out) >= 5 {
			break
		}
	}
	return out
}

func graphqlIntrospectionSignal(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, "__schema") && strings.Contains(lower, "types")
}

func graphqlSensitiveField(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, "password") || strings.Contains(lower, "secret") || strings.Contains(lower, "token")
}

func graphqlCandidateFieldsFromIntrospection(body string) []string {
	var doc struct {
		Data struct {
			Schema struct {
				Types []struct {
					Name   string `json:"name"`
					Fields []struct {
						Name string `json:"name"`
					} `json:"fields"`
				} `json:"types"`
			} `json:"__schema"`
		} `json:"data"`
	}
	if json.Unmarshal([]byte(body), &doc) != nil {
		return nil
	}
	preferredTypes := map[string]bool{"Query": true, "Mutation": true}
	var out []string
	for _, typ := range doc.Data.Schema.Types {
		if !preferredTypes[typ.Name] && strings.HasPrefix(typ.Name, "__") {
			continue
		}
		if !preferredTypes[typ.Name] && len(out) > 0 {
			continue
		}
		for _, field := range typ.Fields {
			name := graphqlFieldName(field.Name)
			if name != "" && name != "user" || strings.EqualFold(field.Name, "user") {
				out = append(out, name)
			}
		}
	}
	return out
}

func uniqueGraphQLFields(fields []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, field := range fields {
		field = graphqlFieldName(field)
		if field == "" {
			continue
		}
		key := strings.ToLower(field)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, field)
	}
	return out
}

func graphqlFieldName(field string) string {
	if field == "" {
		return "user"
	}
	for _, ch := range field {
		if (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9') && ch != '_' {
			return "user"
		}
	}
	return field
}

func (r *Runner) runWebSocket(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("websocket", target); !ok {
		r.emitSkip("websocket", target, reason)
		return nil
	}
	if r.websocket == nil {
		return nil
	}
	baseline, err := r.websocket.Probe(ctx, target.EndpointURL, "akca-websocket-negative-control")
	if err != nil || baseline.Response.StatusCode == 0 {
		return nil
	}
	probes := []struct{ payload, signal string }{
		{`' OR 1=1--`, "ws_sqli"},
		{`{"action":"login","user":"admin' OR '1'='1"}`, "ws_sqli"},
		{`<script>alert(1)</script>`, "ws_xss"},
		{`{"action":"message","text":"<svg/onload=alert(1)>"}`, "ws_xss"},
		{`{"id":2}`, "ws_idor"},
		{`{"action":"get_user","user_id":1}`, "ws_idor"},
		{`{"action":"subscribe","channel":"internal_admin_feed"}`, "ws_idor"},
		{`{"action":"handshake_test","origin":"https://evil-attacker.com"}`, "ws_cswsh"},
	}
	var out []ModuleFinding
	for _, pr := range probes {
		rr, err := r.websocket.Probe(ctx, target.EndpointURL, pr.payload)
		if err != nil {
			continue
		}
		if !websocketSignal(rr.Response.Body, pr.signal) {
			continue
		}
		replays := make([]httpclient.RequestResponse, 0, 2)
		replayHits := []bool{true}
		for attempt := 0; attempt < 2; attempt++ {
			replay, replayErr := r.websocket.Probe(ctx, target.EndpointURL, pr.payload)
			if replayErr != nil {
				replayHits = append(replayHits, false)
				continue
			}
			replays = append(replays, replay)
			replayHits = append(replayHits, websocketSignal(replay.Response.Body, pr.signal))
		}
		if len(replays) != 2 || countTrue(replayHits) < 3 ||
			websocketSignal(baseline.Response.Body, pr.signal) {
			continue
		}
		p := defaultPayload("websocket", pr.signal, pr.payload, pr.signal)
		f := r.verifyAndBuildWithCandidate(ctx, "websocket", target, p, baseline, rr,
			pr.signal, false, false, "", "", func(candidate *verification.Candidate) {
				candidate.RequestedProofType = verification.ProofDifferentialReplay
				candidate.NegativeControlSet = true
				candidate.NegativeControlOK = true
				candidate.TypedReplayHits = replayHits
				candidate.StabilityRuns = []verification.ResponseSnapshot{
					snapshot(rr.Response), snapshot(replays[0].Response), snapshot(replays[1].Response),
				}
				candidate.Observations = append(candidate.Observations,
					r.observation("websocket", target, verification.RoleNegativeControl, 1, baseline),
					r.observation("websocket", target, verification.RolePositiveReplay, 2, replays[0]),
					r.observation("websocket", target, verification.RolePositiveReplay, 3, replays[1]),
				)
			})
		if f != nil && pr.signal == "ws_cswsh" {
			f.Title = "Cross-Site WebSocket Hijacking (CSWSH)"
			f.Severity = "high"
			f.Description = "WebSocket endpoint accepted connections originating from arbitrary cross-domain origins without origin validation."
		}
		r.recordFinding(ctx, &out, f, "websocket", pr.signal)
	}
	return out
}

func websocketSignal(body, signal string) bool {
	lower := strings.ToLower(body)
	switch signal {
	case "ws_sqli":
		return strings.Contains(lower, "sql") || strings.Contains(lower, "syntax error")
	case "ws_xss":
		return strings.Contains(body, "<script>") || strings.Contains(lower, "alert")
	case "ws_idor":
		return strings.Contains(lower, "email") || strings.Contains(lower, "unauthorized data")
	case "ws_cswsh":
		return strings.Contains(lower, "pong") || strings.Contains(lower, "authorized") || strings.Contains(lower, "welcome")
	default:
		return false
	}
}
