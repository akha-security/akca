package modules

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/akha-security/akca/engine/internal/findingtext"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/php2shell"
	"github.com/akha-security/akca/engine/internal/verification"
	"time"
)

// runPHP2Shell is an exposure assessment with optional active crash-signal
// probes. It does not execute code or treat version banners as RCE proof.
func (r *Runner) runPHP2Shell(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ctx.Err() != nil || (r.scope != nil && !r.scope.IsInScope(target.EndpointURL)) {
		return nil
	}
	if ok, reason := r.shouldRunModule("php2shell", target); !ok {
		r.emitSkip("php2shell", target, reason)
		return nil
	}
	if !r.contentModuleOnce("php2shell", target) {
		return nil
	}
	rr, observed := observedResponse(ctx, target, false)
	// Requests made by the dedicated PHP2Shell path still need to flow through
	// the observation wrapper.  Otherwise the target-run accounting never sees
	// the request/response, which makes an otherwise completed active check
	// appear as a failed/empty module result in the CLI summary.
	httpDoer := observedHTTP{r.client}
	if r.cfg.OnlyPHP2Shell() && !observed {
		// Dedicated mode has no crawler response to reuse. Fetch only the
		// explicit URL; full scans continue using previously observed metadata.
		// Active mode must do this harmless GET too: using the multipart control
		// response as the assessment can turn a vulnerable endpoint's 5xx into
		// a generic "blocked" result and hide the normal version finding.
		var err error
		rr, err = httpDoer.Do(ctx, http.MethodGet, target.EndpointURL, nil, nil)
		observed = err == nil && rr.Response.StatusCode > 0
		r.emitPHP2ShellExchange("baseline", target, rr, err, map[string]interface{}{
			"request_body_bytes": 0,
			"observed":           observed,
			"request_attempted":  true,
		})
	}
	controlStatus := 0
	if r.cfg.PHP2ShellActive {
		// Mirror the reference flow's harmless control request. A server-side
		// 5xx here is a stop condition: do not continue with larger bodies.
		controlBody := []byte("--x\r\nContent-Disposition:name=a;filename=\r\n\r\n")
		control, err := httpDoer.Do(ctx, http.MethodPost, target.EndpointURL, controlBody, map[string]string{
			"Content-Type": "multipart/form-data; boundary=x",
			"Connection":   "close",
		})
		if err == nil && control.Response.StatusCode > 0 {
			controlStatus = control.Response.StatusCode
			if !observed {
				rr, observed = control, true
			}
		}
		r.emitPHP2ShellExchange("control", target, control, err, map[string]interface{}{
			"request_body_bytes": len(controlBody),
			"continue":           err == nil && control.Response.StatusCode > 0 && control.Response.StatusCode < 500,
			"continue_probes":    err == nil && control.Response.StatusCode > 0 && control.Response.StatusCode < 500,
			"request_attempted":  true,
		})
	}
	a := php2shell.Inspect(target.EndpointURL, rr.Response.StatusCode, rr.Response.Headers)
	if !observed {
		r.emitSkip("php2shell", target, a.Reason)
	}
	if r.cfg.PHP2ShellActive && observed && controlStatus > 0 && controlStatus < 500 {
		r.runPHP2ShellActive(ctx, target, &a)
	} else if r.cfg.PHP2ShellActive {
		stopReason := "control response unavailable"
		if controlStatus >= 500 {
			stopReason = fmt.Sprintf("control response HTTP %d", controlStatus)
		}
		r.emitPHP2ShellExchange("active_stop", target, httpclient.RequestResponse{}, nil, map[string]interface{}{
			"request_body_bytes": 0,
			"continue_probes":    false,
			"request_attempted":  false,
			"stop_reason":        stopReason,
		})
	}
	data := map[string]interface{}{
		"scan_id": r.scanID, "module": "php2shell", "endpoint": target.EndpointURL,
		"status": a.Status, "reason": a.Reason, "assessment": a,
		"exploit_verified": false,
	}
	if r.db != nil {
		raw, err := json.Marshal(a)
		if err == nil {
			err = r.db.SaveEvidence(r.scanID, "php2shell_assessment", string(raw))
		}
		if err != nil {
			r.executionErrors.Add(1)
			if r.emit != nil {
				_ = r.emit("scan_error", "PHP2Shell assessment could not be persisted: "+err.Error(), data)
			}
			return nil
		}
	}
	if r.emit != nil {
		if err := r.emit("php2shell_assessment", a.Summary(), data); err != nil {
			r.executionErrors.Add(1)
		}
	}
	var out []ModuleFinding
	if a.Status == "potential" || a.Status == "manual_review" || a.Status == "active_signal" {
		confidence := verification.Potential
		severity := "critical"
		signal := "version_evidence"
		if a.Status == "active_signal" {
			signal = "memory_exhaustion_signature"
		}
		f := &ModuleFinding{
			Title: findingtext.HumanTitle("php2shell"), VulnClass: "php2shell", Severity: severity,
			Description: a.Reason, Endpoint: target.EndpointURL, Confidence: confidence,
			Evidence: Evidence{Module: "php2shell", Signal: signal, Request: rr.Request, Response: rr.Response,
				Payload: defaultPayload("php2shell", signal, "", signal), DetectedAt: time.Now().UTC()},
		}
		observation := verification.NewHTTPObservation(
			r.scanID, "php2shell", target.EndpointURL, "", target.Location,
			verification.RolePositiveProbe, 1, "", rr.Request.Method, rr.Request.URL,
			rr.Request.Body, rr.Request.Headers, snapshot(rr.Response),
		)
		f.Evidence.Verification = verification.Result{
			Confidence: confidence, Score: 0.55, ProofType: verification.ProofContentEvidence,
			ProofPolicy: verification.CurrentProofPolicyVersion, ProofSatisfied: true,
			Observations: []verification.Observation{observation}, VerifiedAt: time.Now().UTC(),
		}
		r.recordFinding(ctx, &out, f, "php2shell", signal)
	}
	return out
}

// runPHP2ShellActive mirrors the supplied Nuclei flow's bounded 1/8/20 MiB
// multipart probes. It is reachable only for a validated explicit target and
// never passes the body through WAF/payload mutation. Operators must restrict
// its use to authorized isolated test systems.
func (r *Runner) runPHP2ShellActive(ctx context.Context, target ScanTarget, assessment *php2shell.Assessment) {
	for _, probe := range []struct{ sizeMiB, parts int }{{1, 4000}, {8, 1020}, {20, 1020}} {
		if ctx.Err() != nil {
			r.emitPHP2ShellExchange("probe", target, httpclient.RequestResponse{}, ctx.Err(), map[string]interface{}{
				"size_mib": probe.sizeMiB, "parts": probe.parts, "continue": false,
				"stop_reason": "context cancelled", "request_attempted": false,
			})
			return
		}
		body := php2ShellProbeBody(probe.sizeMiB, probe.parts)
		rr, err := observedHTTP{r.client}.Do(ctx, "POST", target.EndpointURL, body, map[string]string{
			"Content-Type": "multipart/form-data; boundary=",
			"Connection":   "close",
		})
		if err != nil {
			r.emitPHP2ShellExchange("probe", target, rr, err, map[string]interface{}{
				"size_mib": probe.sizeMiB, "parts": probe.parts,
				"request_body_bytes": len(body), "continue": false,
				"stop_reason": "transport error", "request_attempted": true,
			})
			return
		}
		lower := strings.ToLower(rr.Response.Body)
		memoryError := strings.Contains(lower, "allowed memory size of") &&
			strings.Contains(lower, "bytes exhausted") && strings.Contains(lower, "unknown")
		assessment.RecordActiveSignal(rr.Response.StatusCode, probe.sizeMiB, memoryError)
		// Match the Nuclei flow: a generic probe 5xx is not itself a
		// rejection. Continue with the next bounded body unless the response
		// carries the memory-exhaustion signature or a listed reject status.
		stop := memoryError || rr.Response.StatusCode == 400 || rr.Response.StatusCode == 403 ||
			rr.Response.StatusCode == 411 || rr.Response.StatusCode == 413 ||
			rr.Response.StatusCode == 414 || rr.Response.StatusCode == 417 ||
			rr.Response.StatusCode == 422 || rr.Response.StatusCode == 429 ||
			rr.Response.StatusCode == 431
		r.emitPHP2ShellExchange("probe", target, rr, nil, map[string]interface{}{
			"size_mib": probe.sizeMiB, "parts": probe.parts,
			"request_body_bytes": len(body), "memory_error": memoryError,
			"continue":          !stop,
			"request_attempted": true,
			"stop_reason":       php2ShellProbeStopReason(rr.Response.StatusCode, memoryError),
		})
		if stop {
			return
		}
	}
}

func php2ShellProbeStopReason(status int, memoryError bool) string {
	if memoryError {
		return "memory exhaustion signature"
	}
	if status == 400 || status == 403 || status == 411 || status == 413 || status == 414 ||
		status == 417 || status == 422 || status == 429 || status == 431 {
		return fmt.Sprintf("probe rejected with HTTP %d", status)
	}
	return ""
}

func (r *Runner) emitPHP2ShellExchange(phase string, target ScanTarget, rr httpclient.RequestResponse, err error, fields map[string]interface{}) {
	if r.emit == nil {
		return
	}
	data := map[string]interface{}{
		"scan_id":  r.scanID,
		"module":   "php2shell",
		"endpoint": target.EndpointURL,
		"phase":    phase,
		"method":   rr.Request.Method,
		"url":      rr.Request.URL,
		"status":   rr.Response.StatusCode,
	}
	for key, value := range fields {
		data[key] = value
	}
	if err != nil {
		data["error"] = err.Error()
	}
	message := fmt.Sprintf("%s HTTP %d", phase, rr.Response.StatusCode)
	if bodyBytes, ok := fields["request_body_bytes"].(int); ok {
		message += fmt.Sprintf(" body=%dB", bodyBytes)
	}
	if sizeMiB, ok := fields["size_mib"].(int); ok && sizeMiB > 0 {
		message += fmt.Sprintf(" size=%dMiB", sizeMiB)
	}
	if parts, ok := fields["parts"].(int); ok && parts > 0 {
		message += fmt.Sprintf(" parts=%d", parts)
	}
	if continued, ok := fields["continue"].(bool); ok {
		message += fmt.Sprintf(" continue=%t", continued)
	} else if continued, ok := fields["continue_probes"].(bool); ok {
		message += fmt.Sprintf(" continue=%t", continued)
	}
	if err != nil {
		message += " error=" + err.Error()
	} else if stopReason, ok := fields["stop_reason"].(string); ok && strings.TrimSpace(stopReason) != "" {
		message += " stop=" + stopReason
	}
	_ = r.emit("php2shell_probe", message, data)
}

func php2ShellProbeBody(sizeMiB, parts int) []byte {
	if sizeMiB < 1 {
		sizeMiB = 1
	}
	if parts < 1 {
		parts = 1
	}
	nested := strings.Repeat("[a]", 62)
	part := "--\nContent-Disposition:name=a[]" + nested + ";filename=\n\n"
	base := strings.Repeat(part, parts)
	fillerCount := (sizeMiB*1024*1024 - len(base)) / 3
	if fillerCount < 0 {
		fillerCount = 0
	}
	body := make([]byte, 0, len(base)+fillerCount*3+16)
	body = append(body, []byte("--\n")...)
	body = append(body, bytes.Repeat([]byte("x:\n"), fillerCount)...)
	if len(base) >= 3 {
		body = append(body, []byte(base[3:])...)
	}
	body = bytes.TrimSuffix(body, []byte("\n"))
	return body
}
