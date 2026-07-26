package modules

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/timingblind"
)

func (r *Runner) runCommandInjection(ctx context.Context, target ScanTarget) []ModuleFinding {
	var out []ModuleFinding
	baseline, err := r.probe(ctx, target, "akca-cmd-base")
	if err != nil {
		return nil
	}
	timingBase := r.calibrateTargetTiming(ctx, target)
	sleepSec := timingblind.RecommendSleepSec(timingBase)
	windows := strings.Contains(strings.ToLower(r.techDatabaseHint(target.EndpointURL)+" "+target.EndpointURL), "windows")

	probes := payloadsForClass(target.Payloads.Payloads, "command_injection")
	primarySeed, verificationSeed := commandCanarySeeds(r.scanID, target)
	canaryProbes := []payloadgen.Payload{commandCanaryProbe(payloadgen.Payload{}, windows, primarySeed, "primary")}
	if len(probes) == 0 {
		probes = append(canaryProbes, []payloadgen.Payload{
			{Value: `|id`, VulnClass: "command_injection", Variant: "pipe", ExpectedSignal: "command_output"},
			{Value: `;id`, VulnClass: "command_injection", Variant: "semicolon", ExpectedSignal: "command_output"},
		}...)
	} else {
		probes = append(canaryProbes, probes...)
	}
	for _, p := range probes {
		probePayload := p
		if timingblind.IsTimeDelayPayload(p.Value, p.ExpectedSignal) {
			probePayload.Value = timingblind.RewriteSleepDuration(p.Value, sleepSec)
		}
		start := time.Now()
		attempts := r.injectionProbeAttempts(ctx, target, probePayload.Value)
		attempt := pickBodyDiffAttempt(attempts, baseline.Response.Body)
		if len(attempts) == 0 {
			continue
		}
		rr := attempt.RR
		if isInfrastructureError(rr.Response.StatusCode) {
			continue
		}
		probeTarget := attempt.Target
		if probeTarget.EndpointURL == "" {
			probeTarget = target
		}
		if runtimeFinding, handled := r.runtimeSinkProof(
			ctx, "command_injection", probeTarget, probePayload, baseline, rr,
		); handled {
			if runtimeFinding != nil {
				r.recordFinding(&out, runtimeFinding, "command_injection", runtimeFinding.Evidence.Signal)
				return out
			}
			continue
		}
		elapsed := time.Since(start).Milliseconds()
		if rr.Response.Duration.Milliseconds() > 0 {
			elapsed = rr.Response.Duration.Milliseconds()
		}
		signal := detectCommandSignal(probePayload, rr.Response.Body, baseline.Response.Body, elapsed, timingBase, sleepSec)
		if signal == "" && r.cfg.EnableOAST && r.oast != nil {
			if oast := strings.TrimSpace(r.oastURL(ctx, "cmd-"+target.Parameter, target, "command_injection")); oast != "" {
				if callbackPayload := commandOASTPayload(oast, windows); callbackPayload != "" {
					r.sendOASTProbe(ctx, target, callbackPayload)
				}
			}
			continue
		}
		if signal == "" {
			continue
		}
		if !cmdInjSignalConfirmed(probePayload, rr.Response.Body, baseline.Response.Body, signal) {
			continue
		}
		// Every output-based signal must pass a second, independently computed
		// canary. The expected marker is not present verbatim in the request, so
		// URL/HTML reflection cannot satisfy this proof.
		if signal == "separator_output" || signal == "command_output" || signal == "canary_output" {
			proofPayload := commandCanaryProbe(probePayload, windows, verificationSeed, "verification")
			reprobe, repErr := r.probe(ctx, probeTarget, proofPayload.Value)
			if repErr != nil || !cmdInjSignalConfirmed(proofPayload, reprobe.Response.Body, baseline.Response.Body, "canary_output") {
				continue
			}
			probePayload = proofPayload
			rr = reprobe
			signal = "canary_output"
		}
		if signal == "timing_signal" {
			r.scheduleDelayedTimingProbe(delayedTimingProbe{
				Target: target, Module: "command_injection", Payload: probePayload,
				Baseline: timingBase, SleepSec: sleepSec, FirstMs: elapsed, Scheduled: time.Now(),
			})
			continue
		}
		f := r.verifyAndBuild(ctx, "command_injection", probeTarget, probePayload, baseline, rr, signal, false, false, "", "")
		if f != nil {
			if signal == "canary_output" {
				f.Evidence.ResponseMarkers = []string{commandExpectedMarker(probePayload)}
				f.Description += " Proof: the response contained a computed marker that was not present verbatim in the request."
			}
			r.recordFinding(&out, f, "command_injection", signal)
		}
	}

	dyn := timingblind.CommandSleepPayload(sleepSec, windows)
	start := time.Now()
	attempts := r.injectionProbeAttempts(ctx, target, dyn.Value)
	attempt := pickSlowestAttempt(attempts)
	if len(attempts) == 0 {
		return out
	}
	rr := attempt.RR
	if isInfrastructureError(rr.Response.StatusCode) {
		return out
	}
	elapsed := time.Since(start).Milliseconds()
	if rr.Response.Duration.Milliseconds() > 0 {
		elapsed = rr.Response.Duration.Milliseconds()
	}
	if ok, _ := timingblind.VerifyProbe(elapsed, timingBase, sleepSec); ok {
		r.scheduleDelayedTimingProbe(delayedTimingProbe{
			Target: target, Module: "command_injection", Payload: dyn,
			Baseline: timingBase, SleepSec: sleepSec, FirstMs: elapsed, Scheduled: time.Now(),
		})
	}
	return out
}

func commandCanarySeeds(scanID string, target ScanTarget) (int, int) {
	sum := sha256.Sum256([]byte(scanID + "|" + target.EndpointURL + "|" + target.Parameter + "|" + target.Location + "|command-canary"))
	primary := 10000 + int(binary.BigEndian.Uint32(sum[:4])%80000)
	verification := 10000 + int(binary.BigEndian.Uint32(sum[4:8])%80000)
	if verification == primary {
		verification = 10000 + (verification-9999)%80000
	}
	return primary, verification
}

func commandOASTPayload(callbackURL string, windows bool) string {
	u, err := url.Parse(strings.TrimSpace(callbackURL))
	if err != nil || u.Hostname() == "" {
		return ""
	}
	if windows {
		return "&nslookup " + u.Hostname()
	}
	return ";nslookup " + u.Hostname()
}

func detectCommandSignal(p payloadgen.Payload, body, baseline string, elapsedMs int64, timingBase timingblind.Baseline, sleepSec int) string {
	if expected := commandExpectedMarker(p); expected != "" && !strings.Contains(p.Value, expected) &&
		strings.Contains(body, expected) && !strings.Contains(baseline, expected) {
		return "canary_output"
	}
	if commandOutputForPayload(p, body) && !commandOutputForPayload(p, baseline) {
		return "separator_output"
	}
	if timingblind.IsTimeDelayPayload(p.Value, p.ExpectedSignal) {
		if ok, _ := timingblind.VerifyProbe(elapsedMs, timingBase, sleepSec); ok {
			return "timing_signal"
		}
	}
	return ""
}

func commandCanaryProbe(original payloadgen.Payload, windows bool, seed int, stage string) payloadgen.Payload {
	separator := ";"
	value := strings.TrimSpace(original.Value)
	if strings.HasPrefix(value, "|") {
		separator = "|"
	} else if strings.HasPrefix(value, "&&") {
		separator = "&&"
	}
	payload := fmt.Sprintf(`%sprintf 'AKCA_CMD_%%d' $((%d+1))`, separator, seed)
	variant := "unix_computed_canary_" + stage
	if windows {
		payload = fmt.Sprintf(`&cmd /V:ON /C "set /A x=%d+1&echo AKCA_CMD_!x!"`, seed)
		variant = "windows_computed_canary_" + stage
	}
	return payloadgen.Payload{
		Value: payload, VulnClass: "command_injection", Family: "command_injection",
		Variant: variant, ExpectedSignal: "canary_output", VerificationStrategy: "computed_output_pair",
		NoiseLevel: "high", RiskLevel: "active", Priority: 80, BudgetCost: 2,
	}
}

var commandCanaryMathRe = regexp.MustCompile(`\(\((\d+)\+1\)\)|(?i:set\s+/a\s+x=(\d+)\+1)`)

func commandExpectedMarker(p payloadgen.Payload) string {
	match := commandCanaryMathRe.FindStringSubmatch(p.Value)
	if len(match) == 0 {
		return ""
	}
	number := match[1]
	if number == "" && len(match) > 2 {
		number = match[2]
	}
	seed, err := strconv.Atoi(number)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("AKCA_CMD_%d", seed+1)
}
