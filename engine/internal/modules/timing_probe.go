package modules

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/akha-security/akca/engine/internal/evidencemarkers"
	"github.com/akha-security/akca/engine/internal/findingtext"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/timingblind"
)

type delayedTimingProbe struct {
	Target    ScanTarget
	Module    string
	Payload   payloadgen.Payload
	Baseline  timingblind.Baseline
	SleepSec  int
	FirstMs   int64
	Scheduled time.Time
}

func (r *Runner) calibrateTargetTiming(ctx context.Context, target ScanTarget) timingblind.Baseline {
	n := timingblind.DefaultBaselineSampleCount()
	samples := make([]int64, 0, n)
	value := nativeTargetValue(target)
	for i := 0; i < n; i++ {
		start := time.Now()
		rr, err := r.probe(ctx, target, value)
		if err != nil {
			continue
		}
		ms := rr.Response.Duration.Milliseconds()
		if ms <= 0 {
			ms = time.Since(start).Milliseconds()
		}
		samples = append(samples, ms)
	}
	return timingblind.Calibrate(samples)
}

func (r *Runner) scheduleDelayedTimingProbe(entry delayedTimingProbe) {
	if !timingblind.UseDelayedVerification(r.cfg) {
		return
	}
	r.timingMu.Lock()
	defer r.timingMu.Unlock()
	r.delayedTiming = append(r.delayedTiming, entry)
}

func (r *Runner) flushDelayedTimingVerifications(ctx context.Context) []ModuleFinding {
	r.timingMu.Lock()
	pending := append([]delayedTimingProbe(nil), r.delayedTiming...)
	r.delayedTiming = nil
	r.timingMu.Unlock()
	if len(pending) == 0 {
		return nil
	}
	delay := timingblind.DelayInterval(r.cfg)
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil
	case <-timer.C:
	}
	var out []ModuleFinding
	for _, item := range pending {
		if ctx.Err() != nil {
			break
		}
		start := time.Now()
		rr, err := r.probe(ctx, item.Target, item.Payload.Value)
		if err != nil {
			continue
		}
		elapsed := time.Since(start).Milliseconds()
		if rr.Response.Duration.Milliseconds() > 0 {
			elapsed = rr.Response.Duration.Milliseconds()
		}
		if item.Module == "sqli" && !usableTimingSQLiResponse(rr.Response) {
			continue
		}
		zeroValue := "akca-timing-zero-control"
		if item.Module == "sqli" {
			zeroValue = timingblind.SQLiMatchedZeroDelayPayload(item.Payload.Value, r.techDatabaseHint(item.Target.EndpointURL)).Value
		}
		zeroRR, err := r.probe(ctx, item.Target, zeroValue)
		if err != nil {
			continue
		}
		if item.Module == "sqli" && (!usableTimingSQLiResponse(zeroRR.Response) || zeroRR.Response.StatusCode != rr.Response.StatusCode) {
			continue
		}
		zeroMs := responseDurationMs(zeroRR)
		zeroSamples := []int64{zeroMs}
		for len(zeroSamples) < 3 {
			repeatZero, repeatErr := r.probe(ctx, item.Target, zeroValue)
			if repeatErr != nil || item.Module == "sqli" &&
				(!usableTimingSQLiResponse(repeatZero.Response) || repeatZero.Response.StatusCode != rr.Response.StatusCode) {
				zeroSamples = nil
				break
			}
			zeroSamples = append(zeroSamples, responseDurationMs(repeatZero))
		}
		if len(zeroSamples) < 3 {
			continue
		}
		ok, reason := timingblind.VerifyProbeWithControl(elapsed, zeroMs, item.Baseline, item.SleepSec)
		if !ok {
			continue
		}
		if item.Module == "sqli" {
			if falseControl, hasFalseControl := timingblind.SQLiXORFalseConditionControl(item.Payload.Value); hasFalseControl {
				falseRR, falseErr := r.probe(ctx, item.Target, falseControl.Value)
				if falseErr != nil || !usableTimingSQLiResponse(falseRR.Response) || falseRR.Response.StatusCode != rr.Response.StatusCode {
					continue
				}
				if matched, _ := timingblind.VerifyProbeWithControl(elapsed, responseDurationMs(falseRR), item.Baseline, item.SleepSec); !matched {
					continue
				}
			}
		}
		thirdRR, err := r.probe(ctx, item.Target, item.Payload.Value)
		if err != nil {
			continue
		}
		if item.Module == "sqli" && (!usableTimingSQLiResponse(thirdRR.Response) || thirdRR.Response.StatusCode != rr.Response.StatusCode) {
			continue
		}
		thirdMs := responseDurationMs(thirdRR)
		if ok, _ := timingblind.VerifyProbeWithControl(thirdMs, zeroMs, item.Baseline, item.SleepSec); !ok {
			continue
		}
		f := r.buildTimedFinding(ctx, item.Target, item.Module, item.Payload, zeroRR, thirdRR,
			"delayed_timing_confirmed", reason, item.Baseline, item.FirstMs, elapsed, thirdMs, zeroSamples, item.SleepSec)
		if f != nil {
			r.recordFinding(&out, f, item.Module, "delayed_timing_confirmed")
		}
	}
	return out
}

func responseDurationMs(rr httpclient.RequestResponse) int64 {
	if ms := rr.Response.Duration.Milliseconds(); ms > 0 {
		return ms
	}
	return 0
}

func (r *Runner) buildTimedFinding(ctx context.Context, target ScanTarget, module string, p payloadgen.Payload,
	baseline, probe httpclient.RequestResponse, signal, reason string, base timingblind.Baseline,
	firstMs, secondMs, thirdMs int64, zeroSamples []int64, sleepSec int) *ModuleFinding {
	if !moduleSignalConfirmed(module, p, signal, baseline.Response, probe.Response, false, "") {
		return nil
	}
	candidate := r.buildCandidate(ctx, module, target, p, baseline, probe, signal)
	candidate.TimingSamples = []int64{firstMs, secondMs, thirdMs}
	candidate.TimingBaseline = append([]int64(nil), base.Samples...)
	candidate.TimingMatchedControl = append([]int64(nil), zeroSamples...)
	candidate.TimingControl = append([]int64(nil), zeroSamples...)
	result := r.verifier.Verify(candidate)
	if result.Suppressed {
		return nil
	}
	responseMarkers := evidencemarkers.ForResponse(p.Value, signal, baseline.Response.Body, probe.Response.Body, "")
	if strings.Contains(strings.ToLower(signal), "timing") {
		// Timing evidence is the measured delayed/control sample set below;
		// arbitrary body differences must never be highlighted as proof.
		responseMarkers = nil
	}
	return &ModuleFinding{
		Title:     findingtext.HumanTitle(module),
		VulnClass: module,
		Severity:  severityFor(module, result.Confidence),
		Endpoint:  target.EndpointURL,
		Parameter: target.Parameter,
		Location:  target.Location,
		Description: findingtext.HumanDescription(module, signal, target.Parameter, target.EndpointURL, p.Value, p.Variant, target.Location) +
			fmt.Sprintf(" Timing: delayed probes %d/%d/%dms, zero control %dms, baseline avg %.0fms, sleep %ds (%s).",
				firstMs, secondMs, thirdMs, medianInt64(zeroSamples), base.AvgMs, sleepSec, reason),
		Confidence: result.Confidence,
		Evidence: Evidence{
			Module: module, Signal: signal, Payload: p,
			Parameter: target.Parameter, Location: target.Location,
			ResponseMarkers: responseMarkers,
			Request:         probe.Request, Response: probe.Response, Verification: result,
			DetectedAt: time.Now().UTC(),
		},
	}
}
