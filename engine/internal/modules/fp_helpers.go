package modules

import (
	"net/http"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/secretscan"
)

// differentialWithStatusGuard is the standard body-diff confirmation used by
// modules that rely on response deltas. It rejects method/status error pages,
// payload-only reflections, and trivially small changes.
func differentialWithStatusGuard(body, baseline, payload string, probeStatus, baseStatus int) bool {
	if body == baseline {
		return false
	}
	if statusOnlyDifferential(probeStatus, baseStatus) {
		return false
	}
	// Any infrastructure or CDN error is never valid vulnerability evidence.
	if isInfrastructureError(probeStatus) {
		return false
	}
	if injectionPayloadReflected(payload, body, baseline) {
		return false
	}
	return differentialBodyConfirmed(body, baseline, payload)
}

func statusOnlyDifferential(probeStatus, baseStatus int) bool {
	if probeStatus == baseStatus {
		return false
	}
	// Reject injection-style FPs where a healthy baseline becomes a client/server error page.
	if baseStatus >= 200 && baseStatus < 300 {
		if clientErrorStatus(probeStatus) || probeStatus >= 500 {
			return true
		}
	}
	return false
}

func contentExposureConfirmed(body, baseline, needle string) bool {
	body = strings.TrimSpace(body)
	if len(body) < 12 {
		return false
	}
	if needle != "" && !strings.Contains(body, needle) {
		return false
	}
	if baseline != "" && body == baseline {
		return false
	}
	if baseline != "" && strings.Contains(baseline, needle) && strings.Contains(body, needle) {
		return false
	}
	return true
}

func secretExposureConfirmed(body, baseline, kind string) bool {
	if strings.TrimSpace(body) == "" {
		return false
	}
	probeMatches := secretscan.Detect(body)
	if len(probeMatches) == 0 {
		return false
	}
	if baseline != "" {
		baseMatches := secretscan.Detect(baseline)
		for _, pm := range probeMatches {
			if pm.Kind != kind {
				continue
			}
			foundInBase := false
			for _, bm := range baseMatches {
				if bm.Kind == pm.Kind && bm.Value == pm.Value {
					foundInBase = true
					break
				}
			}
			if !foundInBase {
				return true
			}
		}
		return false
	}
	for _, m := range probeMatches {
		if m.Kind == kind {
			return true
		}
	}
	return false
}

func jwtModuleConfirmed(body, baseline, signal string, probeStatus, baseStatus int) bool {
	if signal == "identity_change_confirmed" {
		return probeStatus >= 200 && probeStatus < 300 &&
			baseStatus >= 200 && baseStatus < 300 &&
			jwtSignal(body, baseline, signal)
	}
	if statusOnlyDifferential(probeStatus, baseStatus) {
		return false
	}
	return jwtSignal(body, baseline, signal)
}

func oauthModuleConfirmed(body, baseline, signal string, probeStatus, baseStatus int) bool {
	if statusOnlyDifferential(probeStatus, baseStatus) {
		return false
	}
	return oauthSignal(body, baseline, signal)
}

func ldapXPathModuleConfirmed(body, baseline, payload, signal string, probeStatus, baseStatus int) bool {
	if !ldapXPathSignal(body, baseline, signal) {
		return false
	}
	if injectionPayloadReflected(payload, body, baseline) {
		return false
	}
	return differentialWithStatusGuard(body, baseline, payload, probeStatus, baseStatus) ||
		(!strings.Contains(strings.ToLower(baseline), strings.ToLower(signal)) &&
			bodyDiffRatio(baseline, body) >= 0.03)
}

func clientSSTIModuleConfirmed(body, baseline, payload, signal string, probeStatus, baseStatus int) bool {
	if statusOnlyDifferential(probeStatus, baseStatus) {
		return false
	}
	if injectionPayloadReflected(payload, body, baseline) {
		return false
	}
	return clientSSTISignal(body, baseline, signal)
}

func smugglingModuleConfirmed(headers map[string]string, body, baseline string, probeStatus, baseStatus int) bool {
	if statusOnlyDifferential(probeStatus, baseStatus) {
		return false
	}
	return smugglingSignal(headers, body, baseline)
}

func raceConditionConfirmed(successBodies []string) bool {
	return len(successBodies) >= 2
}

func sqliFindingAllowed(p payloadgen.Payload, signal string, baseline, probe httpclient.ResponseRecord, oastURL string) bool {
	// CDN / reverse-proxy errors are never valid SQLi evidence.
	if isInfrastructureError(probe.StatusCode) {
		return false
	}
	// A method-rejection page proves that the selected request shape was not
	// accepted by the endpoint. Its latency and body are not SQL execution
	// evidence, even when they happen to match a timing or differential probe.
	if probe.StatusCode == http.StatusMethodNotAllowed || baseline.StatusCode == http.StatusMethodNotAllowed {
		return false
	}
	if (signal == "timing_differential" || signal == "stacked_timing") &&
		statusOnlyDifferential(probe.StatusCode, baseline.StatusCode) {
		return false
	}
	if !moduleSignalConfirmed("sqli", p, signal, baseline, probe, false, oastURL) {
		return false
	}
	if signal == "union_signal" {
		if statusOnlyDifferential(probe.StatusCode, baseline.StatusCode) {
			return false
		}
	}
	return true
}
