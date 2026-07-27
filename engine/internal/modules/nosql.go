package modules

import (
	"context"
	"net/http"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/nosql"
	"github.com/akha-security/akca/engine/internal/verification"
)

func (r *Runner) runNoSQLi(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("nosql", target); !ok {
		r.emitSkip("nosql", target, reason)
		return nil
	}
	if !nosqlSurface(target) {
		r.emitSkip("nosql", target, "endpoint not a JSON/login surface")
		return nil
	}

	baseline, err := r.probeForModule(ctx, "nosql", target, "akca-nosql-base")
	if err != nil {
		return nil
	}

	var controlRR httpclient.RequestResponse
	if jsonBodySurface(target) {
		controlRR, _ = r.probeWithBodyForModule(ctx, "nosql", target, nosql.ControlBody(target.Parameter), "application/json", nil)
	}
	queryControlRR, _ := r.probeForModule(ctx, "nosql", target, "akca-nosql-control")

	probes := nosql.ProbesForTarget(
		target.Parameter,
		target.EndpointURL,
		target.Profile.ContentType,
		target.Method,
	)

	var out []ModuleFinding
	for _, probe := range probes {
		if ctx.Err() != nil {
			break
		}
		rr, err := r.nosqlProbe(ctx, target, probe)
		if err != nil {
			continue
		}
		actx := nosql.ResponseContext{
			BaselineBody:   baseline.Response.Body,
			ProbeBody:      rr.Response.Body,
			ControlBody:    controlRR.Response.Body,
			BaselineStatus: baseline.Response.StatusCode,
			ProbeStatus:    rr.Response.StatusCode,
			ControlStatus:  controlRR.Response.StatusCode,
		}
		ok, signal := nosql.AnalyzeWithContext(actx, probe)
		if !ok {
			continue
		}
		reprobe, err := r.nosqlProbe(ctx, target, probe)
		if err != nil || !nosqlReprobeConfirmed(actx, reprobe.Response, probe, signal) {
			continue
		}
		p := defaultPayload("nosql", probe.Name, probeValue(probe, target.Parameter), signal)
		negativeControl := queryControlRR
		if probe.Mode == "json_body" && controlRR.Request.Method != "" {
			negativeControl = controlRR
		}
		f := r.verifyAndBuildWithCandidate(ctx, "nosql", target, p, baseline, rr, signal,
			false, false, "", "", func(candidate *verification.Candidate) {
				if negativeControl.Request.Method == "" ||
					!usableNegativeControl(baseline.Response, negativeControl.Response) {
					return
				}
				controlPayload := defaultPayload("nosql", "negative_control", "akca-nosql-control", signal)
				candidate.NegativeControlSet = true
				candidate.NegativeControlOK = !moduleSignalConfirmed(
					"nosql", controlPayload, signal,
					baseline.Response, negativeControl.Response, false, "",
				)
				candidate.Observations = append(candidate.Observations,
					r.observation("nosql", target, verification.RoleNegativeControl, 1, negativeControl))
			})
		if f != nil && f.Confidence == verification.NeedsManualReview {
			continue
		}
		if f != nil {
			r.recordFinding(&out, f, "nosql", signal)
		}
	}
	return out
}

func nosqlReprobeConfirmed(first nosql.ResponseContext, repeated httpclient.ResponseRecord, probe nosql.Probe, signal string) bool {
	if isInfrastructureError(repeated.StatusCode) || repeated.StatusCode != first.ProbeStatus {
		return false
	}
	repeatedCtx := first
	repeatedCtx.ProbeBody = repeated.Body
	repeatedCtx.ProbeStatus = repeated.StatusCode
	ok, repeatedSignal := nosql.AnalyzeWithContext(repeatedCtx, probe)
	if !ok || repeatedSignal != signal {
		return false
	}
	return bodyDiffRatio(normalizeVolatileFields(first.ProbeBody), normalizeVolatileFields(repeated.Body)) <= 0.12
}

func nosqlSurface(target ScanTarget) bool {
	ct := strings.ToLower(target.Profile.ContentType)
	if strings.Contains(ct, "json") {
		return true
	}
	lower := strings.ToLower(target.EndpointURL)
	if nosql.IsLoginLikeEndpoint(target.EndpointURL) {
		return true
	}
	if strings.Contains(lower, "/api") || strings.Contains(lower, "/graphql") ||
		strings.Contains(lower, "/v1/") || strings.Contains(lower, "/v2/") ||
		strings.Contains(lower, "/v3/") {
		return true
	}
	m := strings.ToUpper(target.Method)
	if m == "POST" || m == "PUT" || m == "PATCH" {
		return strings.Contains(lower, "/api") || strings.Contains(lower, "/graphql") ||
			strings.Contains(lower, "/v1/") || strings.Contains(lower, "/v2/")
	}
	return false
}

func jsonBodySurface(target ScanTarget) bool {
	return strings.Contains(strings.ToLower(target.Profile.ContentType), "json") ||
		strings.ToUpper(target.Method) == "POST"
}

func (r *Runner) nosqlProbe(ctx context.Context, target ScanTarget, probe nosql.Probe) (httpclient.RequestResponse, error) {
	switch probe.Mode {
	case "json_body":
		method := strings.ToUpper(target.Method)
		if method == "" || method == http.MethodGet {
			method = http.MethodPost
		}
		ct := probe.ContentType
		if ct == "" {
			ct = "application/json"
		}
		sub := target
		sub.Method = method
		return r.probeWithBodyForModule(ctx, "nosql", sub, probe.Value, ct, nil)
	case "bracket_query":
		op := "ne"
		if probe.Name == "bracket_gt" {
			op = "gt"
		}
		rawURL, err := nosql.BracketProbeURL(target.EndpointURL, target.Parameter, op)
		if err != nil {
			return httpclient.RequestResponse{}, err
		}
		return r.client.Do(ctx, http.MethodGet, rawURL, nil, r.wafHeadersForModule("nosql", target.EndpointURL))
	default:
		return r.probeForModule(ctx, "nosql", target, probe.Value)
	}
}

func probeValue(probe nosql.Probe, parameter string) string {
	if probe.Value != "" {
		return probe.Value
	}
	if probe.Mode == "bracket_query" {
		operator := "$ne"
		if probe.Name == "bracket_gt" {
			operator = "$gt"
		}
		return parameter + "[" + operator + "]=akca"
	}
	return probe.Name
}
