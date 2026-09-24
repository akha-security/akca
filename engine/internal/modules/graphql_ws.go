package modules

import (
	"context"

	"github.com/akha-security/akca/engine/internal/graphqlattack"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/secretscan"
	"github.com/akha-security/akca/engine/internal/sensitivedata"
	"github.com/akha-security/akca/engine/internal/verification"
)

const graphQLIntrospectionQuery = graphqlattack.IntrospectionQuery

func (r *Runner) runGraphQL(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("graphql", target); !ok {
		r.emitSkip("graphql", target, reason)
		return nil
	}
	// Crawlers may discover this URL as GET; JSON GraphQL operations use POST.
	target.Method = "POST"
	target.Parameter = "body"
	target.Location = "body"
	if !r.endpointModuleOnce("graphql", target) {
		return nil
	}
	baseline, err := r.probeWithBody(ctx, target, graphqlattack.BaselineQuery, "application/json", nil)
	if err != nil {
		return nil
	}
	introspection, err := r.probeWithBody(ctx, target, graphQLIntrospectionQuery, "application/json", nil)
	probes := graphqlattack.DiscoveryProbes()
	if err == nil && graphqlattack.HasSchema(introspection.Response.Body) {
		probes = append(probes, graphqlattack.SchemaProbes(introspection.Response.Body)...)
		if r.emit != nil {
			_ = r.emit("graphql_inventory", "GraphQL schema discovered; introspection alone is not a vulnerability", map[string]interface{}{
				"endpoint": target.EndpointURL, "schema_queries": len(probes) - len(graphqlattack.DiscoveryProbes()),
			})
		}
	}
	var out []ModuleFinding
	seen := map[string]bool{}
	// Inspect baseline and schema responses too: disclosures can be persistent.
	r.graphqlFindings(ctx, target, baseline, baseline, graphqlattack.Probe{Body: graphqlattack.BaselineQuery, Name: "baseline"}, seen, &out)
	if err == nil {
		r.graphqlFindings(ctx, target, baseline, introspection, graphqlattack.Probe{Body: graphQLIntrospectionQuery, Name: "introspection"}, seen, &out)
	}
	for _, probe := range probes {
		if ctx.Err() != nil {
			break
		}
		rr, err := r.probeWithBody(ctx, target, probe.Body, "application/json", nil)
		if err != nil {
			continue
		}
		r.graphqlFindings(ctx, target, baseline, rr, probe, seen, &out)
	}
	return out
}

func (r *Runner) graphqlFindings(ctx context.Context, target ScanTarget, baseline, rr httpclient.RequestResponse,
	probe graphqlattack.Probe, seen map[string]bool, out *[]ModuleFinding) {
	for _, signal := range graphqlattack.Signals(rr.Response.Body) {
		if seen[signal] {
			continue
		}
		p := defaultPayload("graphql", probe.Name, probe.Body, signal)
		f := r.verifyAndBuildWithCandidate(ctx, "graphql", target, p, baseline, rr, signal, false, false, "", "", func(c *verification.Candidate) {
			c.RequestedProofType = verification.ProofContentEvidence
			c.ExpectedEquivalent = true
		})
		if f == nil {
			continue
		}
		switch signal {
		case "graphql_stack_trace_disclosure":
			f.Title = "GraphQL Server Stack Trace Disclosure"
			f.Severity = "medium"
			f.Description = "A structured GraphQL error exposes server stack frames and implementation paths. This does not prove code execution."
		case "graphql_database_error_disclosure":
			f.Title = "GraphQL Database Error Disclosure"
			f.Severity = "medium"
			f.Description = "A GraphQL error exposes a database-specific exception or SQLSTATE. This does not by itself prove SQL injection."
		case "graphql_server_secret_exposure":
			f.Title = "GraphQL Server Credential Material Exposure"
			f.Severity = "high"
			f.Description = "GraphQL response data contains recognizable server credential material. Credential validity and unauthorized access have not been established."
		}
		if r.recordFinding(ctx, out, f, "graphql", signal) {
			seen[signal] = true
		}
	}
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
		{`'`, "ws_database_error_disclosure"},
		{`{"action":"akca_probe","value":"'"}`, "ws_database_error_disclosure"},
		{`{"action":`, "ws_stack_trace_disclosure"},
		{`{"action":"akca_probe"}`, "ws_server_secret_exposure"},
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
		if f != nil {
			switch pr.signal {
			case "ws_database_error_disclosure":
				f.Title = "WebSocket Database Error Disclosure"
				f.Severity = "medium"
				f.Description = "A WebSocket message produced a reproducible database-specific exception. This does not by itself prove SQL injection."
			case "ws_stack_trace_disclosure":
				f.Title = "WebSocket Stack Trace Disclosure"
				f.Severity = "medium"
			case "ws_server_secret_exposure":
				f.Title = "WebSocket Server Credential Material Exposure"
				f.Severity = "high"
			}
		}
		r.recordFinding(ctx, &out, f, "websocket", pr.signal)
	}
	return out
}

func websocketSignal(body, signal string) bool {
	switch signal {
	case "ws_database_error_disclosure":
		for _, finding := range sensitivedata.Analyze(body) {
			if finding.Kind == "database_error" {
				return true
			}
		}
	case "ws_stack_trace_disclosure":
		for _, finding := range sensitivedata.Analyze(body) {
			if finding.Kind == "stack_trace" {
				return true
			}
		}
	case "ws_server_secret_exposure":
		for _, match := range secretscan.Detect(body) {
			if secretscan.IsReportable(match) {
				return true
			}
		}
	default:
		return false
	}
	return false
}
