package timingblind

import (
	"math"
	"sort"
	"time"

	"github.com/akha-security/akca/engine/internal/config"
)

const (
	defaultBaselineSamples = 5
	minSleepSec            = 4
	maxSleepSec            = 12
)

// Baseline holds harmless-request timing statistics for a target parameter.
type Baseline struct {
	Samples []int64
	AvgMs   float64
	MedianMs int64
	JitterMs float64
}

// Calibrate computes t_avg from harmless probe durations.
func Calibrate(samples []int64) Baseline {
	b := Baseline{Samples: append([]int64(nil), samples...)}
	if len(b.Samples) == 0 {
		return b
	}
	var sum float64
	for _, s := range b.Samples {
		sum += float64(s)
	}
	b.AvgMs = sum / float64(len(b.Samples))
	b.MedianMs = median(b.Samples)
	b.JitterMs = stddev(b.Samples)
	return b
}

// RecommendSleepSec picks a sleep duration that stays above network jitter.
func RecommendSleepSec(b Baseline) int {
	sleep := minSleepSec
	switch {
	case b.AvgMs > 2500 || b.JitterMs > 1200:
		sleep = maxSleepSec
	case b.AvgMs > 1200 || b.JitterMs > 700:
		sleep = 7
	case b.AvgMs > 600 || b.JitterMs > 350:
		sleep = 6
	}
	if sleep < minSleepSec {
		return minSleepSec
	}
	if sleep > maxSleepSec {
		return maxSleepSec
	}
	return sleep
}

// VerifyProbe checks whether probeMs ≈ t_avg + sleepSec (delayed blind leak).
func VerifyProbe(probeMs int64, b Baseline, sleepSec int) (matched bool, reason string) {
	if sleepSec <= 0 || len(b.Samples) < 3 {
		return false, "insufficient_baseline"
	}
	expected := b.AvgMs + float64(sleepSec*1000)
	margin := math.Max(b.JitterMs*1.5, 300)
	delta := float64(probeMs) - expected
	if math.Abs(delta) <= margin {
		return true, "timing_match_expected"
	}
	// Accept clear delay above baseline + sleep minus tight slack.
	threshold := expected - margin*0.3
	if float64(probeMs) >= threshold && float64(probeMs) >= b.AvgMs+float64(sleepSec*1000)-400 {
		return true, "timing_exceeded_threshold"
	}
	return false, "timing_within_noise"
}

// DelayInterval returns how long to wait before delayed re-verification.
func DelayInterval(cfg config.ScanConfig) time.Duration {
	switch cfg.ScanIntensity {
	case "fast":
		return 0
	case "stealth":
		return 5 * time.Minute
	default:
		return 45 * time.Second
	}
}

// UseDelayedVerification reports whether a second timed probe should run.
func UseDelayedVerification(cfg config.ScanConfig) bool {
	return DelayInterval(cfg) > 0
}

func median(vals []int64) int64 {
	if len(vals) == 0 {
		return 0
	}
	cp := append([]int64(nil), vals...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	mid := len(cp) / 2
	if len(cp)%2 == 0 {
		return (cp[mid-1] + cp[mid]) / 2
	}
	return cp[mid]
}

func stddev(vals []int64) float64 {
	if len(vals) == 0 {
		return 0
	}
	var sum float64
	for _, v := range vals {
		sum += float64(v)
	}
	mean := sum / float64(len(vals))
	var varSum float64
	for _, v := range vals {
		d := float64(v) - mean
		varSum += d * d
	}
	return math.Sqrt(varSum / float64(len(vals)))
}

func DefaultBaselineSampleCount() int { return defaultBaselineSamples }

// VerifyProbeWithControl confirms delay payload exceeds zero-delay control and baseline.
func VerifyProbeWithControl(probeMs, zeroMs int64, b Baseline, sleepSec int) (matched bool, reason string) {
	if sleepSec <= 0 || len(b.Samples) < 3 {
		return false, "insufficient_baseline"
	}
	if ok, _ := VerifyProbe(probeMs, b, sleepSec); !ok {
		return false, "delay_mismatch"
	}
	zeroMargin := math.Max(b.JitterMs*1.5, 350)
	if math.Abs(float64(zeroMs)-b.AvgMs) > zeroMargin*2 {
		return false, "zero_control_slow"
	}
	delta := float64(probeMs) - float64(zeroMs)
	minDelta := float64(sleepSec*1000) * 0.80
	if delta < minDelta {
		return false, "insufficient_delta_vs_zero"
	}
	return true, "timing_with_zero_control"
}
