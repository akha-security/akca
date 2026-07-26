package modules

import (
	"context"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

func (r *Runner) trackStoredMarker(endpointURL, parameter, marker string) {
	if !r.cfg.EnableSecondOrderTracking || marker == "" {
		return
	}
	r.storedMu.Lock()
	r.stored[endpointURL+"::"+parameter] = marker
	r.storedMu.Unlock()
}

func (r *Runner) runSecondOrder(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("second_order", target); !ok {
		r.emitSkip("second_order", target, reason)
		return nil
	}
	r.storedMu.Lock()
	storedLen := len(r.stored)
	r.storedMu.Unlock()
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
		if !strings.Contains(rr.Response.Body, marker) {
			continue
		}
		p := defaultPayload("second_order", "stored_trigger", marker, "delayed_trigger")
		f := r.verifyAndBuild(ctx, "second_order", target, p, baseline, rr, "cross_endpoint_trigger", false, false, "", marker)
		if f != nil {
			f.Description = "marker from " + injectKey + " triggered on " + target.EndpointURL
			r.recordFinding(&out, f, "second_order", "cross_endpoint_trigger")
		}
	}
	return out
}
