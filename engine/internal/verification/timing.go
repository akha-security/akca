package verification

import (
	"math"
	"sort"
)

func CalibrateTiming(samples, control []int64) (deltaMs float64, significant bool) {
	// A single slow request is indistinguishable from network or server noise.
	// Require at least three observations on both sides and use robust medians.
	if len(samples) < 3 || len(control) < 3 {
		return 0, false
	}
	probeMedian := median(samples)
	controlMedian := median(control)
	deltaMs = float64(probeMedian - controlMedian)
	controlMAD := medianAbsoluteDeviation(control, controlMedian)
	probeMAD := medianAbsoluteDeviation(samples, probeMedian)
	// MAD is resistant to one-off outliers. Keep stddev as a secondary guard
	// for broadly unstable baselines that MAD alone can understate.
	jitter := math.Max(float64(controlMAD)*1.4826, stddev(control))
	if jitter > math.Max(350, float64(controlMedian)*0.75) ||
		float64(probeMAD)*1.4826 > math.Max(500, deltaMs*0.60) {
		return deltaMs, false
	}
	threshold := math.Max(750, jitter*4)
	if deltaMs < threshold {
		return deltaMs, false
	}
	// At least two thirds of delayed probes must clear the robust control
	// threshold. This rejects a median influenced by intermittent congestion.
	consistent := 0
	for _, sample := range samples {
		if float64(sample-controlMedian) >= threshold {
			consistent++
		}
	}
	return deltaMs, float64(consistent)/float64(len(samples)) >= 2.0/3.0
}

// RobustTimingDifference is used for low-amplitude differential channels such
// as account enumeration. Unlike delay-payload verification it accepts either
// direction, but demands large separation relative to both MAD values.
func RobustTimingDifference(a, b []int64, minimumDeltaMs int64) (float64, bool) {
	if len(a) < 15 || len(b) < 15 {
		return 0, false
	}
	aMedian, bMedian := median(a), median(b)
	delta := aMedian - bMedian
	absolute := delta
	if absolute < 0 {
		absolute = -absolute
	}
	aMAD := medianAbsoluteDeviation(a, aMedian)
	bMAD := medianAbsoluteDeviation(b, bMedian)
	jitter := math.Max(float64(aMAD), float64(bMAD)) * 1.4826
	threshold := math.Max(float64(minimumDeltaMs), jitter*6)
	return float64(delta), float64(absolute) >= threshold
}

func medianAbsoluteDeviation(vals []int64, center int64) int64 {
	deviations := make([]int64, 0, len(vals))
	for _, value := range vals {
		d := value - center
		if d < 0 {
			d = -d
		}
		deviations = append(deviations, d)
	}
	return median(deviations)
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
