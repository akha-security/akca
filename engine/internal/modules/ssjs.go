package modules

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/verification"
)

func (r *Runner) runSSJS(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("server_side_js_injection", target); !ok {
		r.emitSkip("server_side_js_injection", target, reason)
		return nil
	}

	if target.Parameter == "" {
		return nil
	}

	baseline, baselineErr := r.cachedEmptyProbe(ctx, target)
	if baselineErr != nil {
		return nil
	}

	var out []ModuleFinding

	// Test 1: Arithmetic & Global Object Evaluation
	evalPayload := "res.end((7777*7777).toString())"
	evalRR, err := r.probe(ctx, target, evalPayload)
	if err == nil && evalRR.Response.StatusCode == 200 && strings.Contains(evalRR.Response.Body, "60481729") {
		signal := "ssjs_eval_arithmetic"
		p := defaultPayload("server_side_js_injection", signal, evalPayload, signal)
		f := r.verifyAndBuildWithCandidate(ctx, "server_side_js_injection", target, p, baseline, evalRR,
			signal, false, false, "", "", func(candidate *verification.Candidate) {
				candidate.RequestedProofType = verification.ProofContentEvidence
			})
		if f != nil {
			f.Severity = "critical"
			f.Title = "Server-Side JavaScript (Node.js) Code Execution"
			f.Description = fmt.Sprintf("Server-side JavaScript injection confirmed on parameter '%s' via arbitrary arithmetic code evaluation.", target.Parameter)
			r.recordFinding(ctx, &out, f, "server_side_js_injection", signal)
			return out
		}
	}

	// Test 2: Node.js global process/require execution
	processPayload := "global.process.mainModule.require('child_process').execSync('echo akcassjs'+'marker')"
	procRR, pErr := r.probe(ctx, target, processPayload)
	if pErr == nil && procRR.Response.StatusCode == 200 && strings.Contains(procRR.Response.Body, "akcassjsmarker") {
		signal := "ssjs_child_process_exec"
		p := defaultPayload("server_side_js_injection", signal, processPayload, signal)
		f := r.verifyAndBuildWithCandidate(ctx, "server_side_js_injection", target, p, baseline, procRR,
			signal, false, false, "", "", func(candidate *verification.Candidate) {
				candidate.RequestedProofType = verification.ProofContentEvidence
			})
		if f != nil {
			f.Severity = "critical"
			f.Title = "Server-Side JavaScript (Node.js) RCE via child_process"
			f.Description = fmt.Sprintf("Arbitrary shell command execution confirmed on parameter '%s' via Node.js require('child_process').execSync.", target.Parameter)
			r.recordFinding(ctx, &out, f, "server_side_js_injection", signal)
			return out
		}
	}

	// Test 3: OAST Out-of-band SSRF via require('http')
	if r.cfg.EnableOAST && r.oast != nil {
		if oastURL := strings.TrimSpace(r.oastURL(ctx, "ssjs-oast", target, "server_side_js_injection")); oastURL != "" {
			r.sendOASTProbe(ctx, target, oastURL)
		}
		if codeOASTURL := strings.TrimSpace(r.oastURL(ctx, "ssjs-code-oast", target, "server_side_js_injection")); codeOASTURL != "" {
			if callback := appendOASTURLPath(codeOASTURL, "ssjs"); callback != "" {
				r.sendOASTProbe(ctx, target, fmt.Sprintf("require('http').get('%s')", callback))
			}
		}
	}

	// Test 4: Time-delay (Busy-Wait Loop)
	if !ssjsTimingResponseUsable(baseline.Response) {
		return out
	}
	busyPayload := "var a=new Date(); do{var b=new Date();}while(b-a<5000);"
	start := time.Now()
	busyRR, bErr := r.probe(ctx, target, busyPayload)
	firstBusyMs := measuredResponseMs(busyRR, time.Since(start))
	if bErr != nil || !ssjsTimingResponseUsable(busyRR.Response) || firstBusyMs < 4500 {
		return out
	}

	zeroPayload := "var a=new Date(); do{var b=new Date();}while(b-a<0);"
	zeroRR, zErr := r.probe(ctx, target, zeroPayload)
	if zErr != nil || !ssjsTimingResponseUsable(zeroRR.Response) ||
		!ssjsSameTimingSurface(baseline.Response, busyRR.Response, zeroRR.Response) {
		return out
	}
	firstZeroMs := responseDurationMs(zeroRR)
	if firstZeroMs <= 0 || firstZeroMs >= 2500 {
		return out
	}

	busySamples := []int64{firstBusyMs}
	zeroSamples := []int64{firstZeroMs}
	busyReplays := make([]httpclient.RequestResponse, 0, 2)
	zeroControls := []httpclient.RequestResponse{zeroRR}
	for i := 0; i < 2; i++ {
		busyReplay, err := r.probe(ctx, target, busyPayload)
		if err != nil || !ssjsTimingResponseUsable(busyReplay.Response) {
			return out
		}
		zeroControl, err := r.probe(ctx, target, zeroPayload)
		if err != nil || !ssjsTimingResponseUsable(zeroControl.Response) ||
			!ssjsSameTimingSurface(baseline.Response, busyReplay.Response, zeroControl.Response) {
			return out
		}
		busyMs, zeroMs := responseDurationMs(busyReplay), responseDurationMs(zeroControl)
		if busyMs <= 0 || zeroMs <= 0 {
			return out
		}
		busySamples = append(busySamples, busyMs)
		zeroSamples = append(zeroSamples, zeroMs)
		busyReplays = append(busyReplays, busyReplay)
		zeroControls = append(zeroControls, zeroControl)
	}
	if _, significant := verification.CalibrateTiming(busySamples, zeroSamples); !significant {
		return out
	}

	signal := "ssjs_time_delay"
	p := defaultPayload("server_side_js_injection", signal, busyPayload, signal)
	f := r.verifyAndBuildWithCandidate(ctx, "server_side_js_injection", target, p, baseline, busyRR,
		signal, false, false, "", "", func(candidate *verification.Candidate) {
			candidate.RequestedProofType = verification.ProofTiming
			candidate.TimingSamples = append([]int64(nil), busySamples...)
			candidate.TimingControl = append([]int64(nil), zeroSamples...)
			candidate.NegativeControlSet = true
			candidate.NegativeControlOK = true
			for i, replay := range busyReplays {
				candidate.Observations = append(candidate.Observations,
					r.observation("server_side_js_injection", target, verification.RolePositiveReplay, i+2, replay))
			}
			for i, control := range zeroControls {
				candidate.Observations = append(candidate.Observations,
					r.observation("server_side_js_injection", target, verification.RoleNegativeControl, i+1, control))
			}
		})
	if f != nil {
		f.Severity = "critical"
		f.Title = "Server-Side JavaScript (Node.js) Blind Timing Injection"
		f.Description = fmt.Sprintf("Server-side JavaScript blind timing delay confirmed on parameter '%s' with three delayed probes and three matched zero-delay controls.", target.Parameter)
		r.recordFinding(ctx, &out, f, "server_side_js_injection", signal)
	}

	return out
}

func ssjsSignalConfirmed(body, baseline, signal string, probeStatus, baseStatus int) bool {
	if signal == "ssjs_time_delay" {
		return probeStatus >= 200 && probeStatus < 400 && baseStatus >= 200 && baseStatus < 400 &&
			!rateLimitBlockSignal(probeStatus, body) && !ssjsBlockPage(body) && !ssjsBlockPage(baseline)
	}
	if probeStatus != 200 || body == baseline && probeStatus == baseStatus {
		return false
	}
	switch signal {
	case "ssjs_eval_arithmetic":
		return strings.Contains(body, "60481729") && !strings.Contains(baseline, "60481729")
	case "ssjs_child_process_exec":
		return strings.Contains(body, "akcassjsmarker") && !strings.Contains(baseline, "akcassjsmarker")
	default:
		return false
	}
}

func measuredResponseMs(rr httpclient.RequestResponse, elapsed time.Duration) int64 {
	if ms := responseDurationMs(rr); ms > 0 {
		return ms
	}
	return elapsed.Milliseconds()
}

func ssjsTimingResponseUsable(response httpclient.ResponseRecord) bool {
	return response.StatusCode >= 200 && response.StatusCode < 400 &&
		!rateLimitBlockSignal(response.StatusCode, response.Body) && !ssjsBlockPage(response.Body)
}

func ssjsSameTimingSurface(baseline, delayed, control httpclient.ResponseRecord) bool {
	return baseline.StatusCode == delayed.StatusCode && delayed.StatusCode == control.StatusCode
}

func ssjsBlockPage(body string) bool {
	lower := strings.ToLower(body)
	for _, token := range []string{
		"request rejected", "requested url was rejected", "please consult with your administrator",
		"your support id is", "request blocked", "access denied", "web application firewall",
		"attention required", "cf-browser-verification", "incapsula_resource", "captcha",
	} {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}
