package modules

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/akha-security/akca/engine/internal/findingtext"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/sensor"
	"github.com/akha-security/akca/engine/internal/verification"
)

const runtimeTraceWait = 750 * time.Millisecond

func (r *Runner) registerRuntimeProbe(target ScanTarget, payload string, headers map[string]string) map[string]string {
	if r.runtimeSensor == nil || !r.runtimeSensor.ActiveFor(target.EndpointURL) {
		return headers
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return headers
	}
	requestID := "req-" + hex.EncodeToString(random)
	sum := sha256.Sum256([]byte(r.scanID + "\x00" + target.EndpointURL + "\x00" + target.Parameter + "\x00" + payload + "\x00" + requestID))
	candidateID := "candidate-" + hex.EncodeToString(sum[:12])
	location := strings.TrimSpace(target.Location)
	if location == "" {
		location = strings.TrimSpace(target.Profile.ParameterLocation)
	}
	if err := r.runtimeSensor.Register(sensor.Binding{
		RequestID: requestID, ScanID: r.scanID, CandidateID: candidateID,
		Endpoint: target.EndpointURL, Parameter: target.Parameter, Location: location,
	}); err != nil {
		return headers
	}
	out := make(map[string]string, len(headers)+7)
	for key, value := range headers {
		out[key] = value
	}
	out["X-Akca-Request-ID"] = requestID
	out["X-Akca-Scan-ID"] = r.scanID
	out["X-Akca-Candidate-ID"] = candidateID
	out["X-Akca-Endpoint"] = target.EndpointURL
	out["X-Akca-Parameter"] = target.Parameter
	out["X-Akca-Location"] = location
	out["X-Akca-Sensor-Token"] = r.runtimeSensor.Token()
	return out
}

func (r *Runner) runtimeAssessment(ctx context.Context, rr httpclient.RequestResponse) (sensor.Event, sensor.Assessment, bool) {
	if r.runtimeSensor == nil {
		return sensor.Event{}, sensor.Assessment{}, false
	}
	requestID := requestHeader(rr.Request.Headers, "X-Akca-Request-ID")
	if requestID == "" {
		return sensor.Event{}, sensor.Assessment{}, false
	}
	waitCtx, cancel := context.WithTimeout(ctx, runtimeTraceWait)
	defer cancel()
	return r.runtimeSensor.Await(waitCtx, requestID)
}

func requestHeader(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

// runtimeSinkProof converts a correlated source-to-sink trace into a
// class-specific deterministic proof. A matching safe trace is also handled
// here and suppresses response-only heuristics for that probe.
func (r *Runner) runtimeSinkProof(ctx context.Context, module string, target ScanTarget, p payloadgen.Payload,
	baseline, probe httpclient.RequestResponse) (*ModuleFinding, bool) {
	event, assessment, observed := r.runtimeAssessment(ctx, probe)
	if !observed || assessment.Sink == nil ||
		!runtimeSinkMatchesModule(module, assessment.Sink.Type) {
		return nil, false
	}
	if assessment.Safe {
		return nil, true
	}
	if !assessment.Vulnerable || event.TraceID == "" || event.RequestID == "" {
		return nil, false
	}
	sinkName := strings.ToLower(strings.TrimSpace(assessment.Sink.Type)) + ":" +
		strings.TrimSpace(assessment.Sink.Operation)
	signal := "runtime_unsafe_" + strings.ToLower(strings.TrimSpace(assessment.Sink.Type)) + "_sink"
	location := strings.TrimSpace(target.Location)
	if location == "" {
		location = strings.TrimSpace(target.Profile.ParameterLocation)
	}
	candidate := verification.Candidate{
		ScanID: r.scanID, Title: module + " on " + target.Parameter, VulnClass: module,
		EndpointURL: target.EndpointURL, Method: target.Method, Parameter: target.Parameter,
		Payload: p.Value, Module: module, Signal: signal,
		Baseline: snapshot(baseline.Response), Probe: snapshot(probe.Response),
		Reflection: &target.Profile, DirectTypedSignal: true,
		ProofPolicyVersion: verification.CurrentProofPolicyVersion,
		RequestedProofType: verification.ProofRuntimeTrace,
	}
	candidate.Observations = append(candidate.Observations,
		r.observation(module, target, verification.RoleNativeBaseline, 1, baseline),
		r.observation(module, target, verification.RolePositiveProbe, 1, probe),
		verification.NewRuntimeObservation(
			r.scanID, module, target.EndpointURL, target.Parameter, location,
			event.RequestID, event.TraceID, sinkName, 1, false,
		),
	)
	result := r.verifier.Verify(candidate)
	if result.Suppressed || !result.ProofSatisfied {
		return nil, true
	}
	return &ModuleFinding{
		Title: findingtext.HumanTitle(module), VulnClass: module,
		Severity: severityFor(module, result.Confidence), Endpoint: target.EndpointURL,
		Parameter: target.Parameter, Location: location, Confidence: result.Confidence,
		Description: findingtext.HumanDescription(
			module, signal, target.Parameter, target.EndpointURL, p.Value, p.Variant, location,
		),
		Evidence: Evidence{
			Module: module, Signal: signal, Payload: p,
			Parameter: target.Parameter, Location: location,
			ResponseMarkers: []string{"correlated runtime trace", sinkName},
			Request:         probe.Request, Response: probe.Response, Verification: result,
			DetectedAt: time.Now().UTC(),
		},
	}, true
}

func runtimeSinkMatchesModule(module, sinkType string) bool {
	sinkType = strings.ToLower(strings.TrimSpace(sinkType))
	switch strings.ToLower(strings.TrimSpace(module)) {
	case "command_injection", "rce":
		return sinkType == "command"
	case "ssti":
		return sinkType == "template"
	case "ssrf":
		return sinkType == "http"
	case "xxe":
		return sinkType == "xml"
	case "lfi":
		return sinkType == "file"
	case "ldap_xpath_injection":
		return sinkType == "ldap" || sinkType == "xpath"
	case "deserialization", "react_rsc_rce":
		return sinkType == "deserialization"
	default:
		return false
	}
}
