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
	// Introspection, including sensitive-looking schema field names, is
	// discovery metadata rather than proof of unauthorized data disclosure.
	// Keep the request for endpoint characterization but do not report it.
	introspection, _ := r.probeWithBody(ctx, target, graphQLIntrospectionQuery, "application/json", nil)
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
	}, graphqlattack.BuildTypeInversionProbes(field)...)
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
		f := r.verifyAndBuild(ctx, "graphql", target, p, baseline, rr, signal, false, false, "", "")
		if f != nil {
			f.Title = "GraphQL abuse (" + signal + ")"
			r.recordFinding(&out, f, "graphql", signal)
		}
		if len(out) >= 3 {
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
		{`<script>alert(1)</script>`, "ws_xss"},
		{`{"id":2}`, "ws_idor"},
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
		r.recordFinding(&out, f, "websocket", pr.signal)
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
	default:
		return false
	}
}
