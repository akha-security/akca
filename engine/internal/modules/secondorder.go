package modules

import (
	"context"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/verification"
)

func (r *Runner) trackStoredMarker(endpointURL, parameter, marker string) {
	if !r.cfg.EnableSecondOrderTracking || marker == "" {
		return
	}
	r.storedMu.Lock()
	r.stored[endpointURL+"::"+parameter] = marker
	r.storedMu.Unlock()
	if r.db != nil {
		if err := r.db.SaveSecondOrderMarker(r.scanID, endpointURL, parameter, marker); err != nil {
			r.emitOnce("second_order_marker_save_failed", "coverage_gap", "Second-order stored marker could not be persisted", map[string]interface{}{
				"scan_id": r.scanID, "endpoint": endpointURL, "parameter": parameter, "error": err.Error(),
			})
		}
	}
}

func (r *Runner) runSecondOrder(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("second_order", target); !ok {
		r.emitSkip("second_order", target, reason)
		return nil
	}
	r.storedMu.Lock()
	storedLen := len(r.stored)
	r.storedMu.Unlock()
	if storedLen == 0 && r.db != nil {
		if dbMarkers, err := r.db.ListSecondOrderMarkers(r.scanID); err == nil && len(dbMarkers) > 0 {
			r.storedMu.Lock()
			for _, m := range dbMarkers {
				r.stored[m.EndpointURL+"::"+m.Parameter] = m.Marker
			}
			storedLen = len(r.stored)
			r.storedMu.Unlock()
		}
	}
	if storedLen == 0 {
		r.emitSkip("second_order", target, "no stored injection markers")
		return nil
	}
	var out []ModuleFinding
	baseline := httpclient.RequestResponse{
		Response: httpclient.ResponseRecord{
			StatusCode: 200, Body: "", Headers: map[string]string{"Content-Type": "text/html"},
		},
	}

	r.storedMu.Lock()
	storedCopy := make(map[string]string, len(r.stored))
	for k, v := range r.stored {
		storedCopy[k] = v
	}
	r.storedMu.Unlock()

	for injectKey, marker := range storedCopy {
		rr, err := r.cachedEmptyProbe(ctx, target)
		if err != nil {
			continue
		}
		body := rr.Response.Body
		if !strings.Contains(body, marker) {
			continue
		}

		domExecuted := false
		if r.browser != nil && rr.Request.Method == "GET" && target.EndpointURL != "" {
			rendered, renderErr := r.browser.Render(ctx, target.EndpointURL)
			domExecuted = renderErr == nil && (strings.Contains(rendered, marker) || verification.CheckDOMExecution(rendered))
		}

		isExecutable := domExecuted || xssExecutableReflection(body, marker) || strings.Contains(body, "<script>") || strings.Contains(body, "onerror=")
		signal := "cross_endpoint_trigger"
		if isExecutable {
			signal = "stored_xss_executable"
		}

		p := defaultPayload("second_order", "stored_xss_trigger", marker, signal)
		f := r.verifyAndBuildWithCandidate(ctx, "second_order", target, p, baseline, rr, signal, isExecutable, domExecuted, "", marker, func(c *verification.Candidate) {
			c.DirectTypedSignal = true
			c.ProofPolicyVersion = verification.CurrentProofPolicyVersion
			c.RequestedProofType = verification.ProofStoredExecution
			c.Observations = append(c.Observations,
				r.observation("second_order", target, verification.RolePositiveProbe, 1, rr),
			)
		})

		if f != nil {
			f.Title = "Stored XSS / Second-Order Injection on " + target.EndpointURL
			f.Severity = "high"
			f.Description = "Second-order stored payload injected at " + injectKey + " was reflected and triggered on " + target.EndpointURL
			r.recordFinding(ctx, &out, f, "second_order", signal)
		}
	}
	return out
}
