package businesslogic

import (
	"math"
	"regexp"
	"strconv"
	"strings"
)

var (
	totalRe     = regexp.MustCompile(`(?i)(?:total|subtotal|amount|balance|price|cost)\s*[:=]?\s*\$?\s*(-?\d+(?:\.\d+)?)`)
	confirmedRe = regexp.MustCompile(`(?i)(order\s+confirmed|payment\s+success|checkout\s+complete|transaction\s+approved)`)
	errorRe     = regexp.MustCompile(`(?i)(invalid|error|denied|forbidden|overflow|nan|not\s+a\s+number)`)
)

// Analyze compares baseline and probe responses for business-logic anomalies.
func Analyze(baselineBody, probeBody string, probe Probe) (bool, string) {
	if probeBody == "" || probeBody == baselineBody {
		return false, ""
	}
	lower := strings.ToLower(probeBody)

	switch probe.Signal {
	case "nan_accepted", "infinity_accepted":
		if !errorRe.MatchString(probeBody) && (strings.Contains(lower, "nan") || strings.Contains(lower, "infinity") ||
			confirmedRe.MatchString(probeBody) || totalRe.MatchString(probeBody)) {
			return true, probe.Signal
		}
	case "negative_quantity_accepted", "negative_price_accepted":
		if bt, ok := extractTotal(baselineBody); ok {
			if pt, ok2 := extractTotal(probeBody); ok2 && pt < bt && pt <= 0 {
				return true, "negative_total_anomaly"
			}
		}
		if confirmedRe.MatchString(probeBody) {
			return true, probe.Signal
		}
	case "float_rounding_anomaly", "float_overflow_anomaly", "negative_zero_anomaly":
		if bt, ok := extractTotal(baselineBody); ok {
			if pt, ok2 := extractTotal(probeBody); ok2 && math.Abs(pt-bt) > 0.0001 && pt < bt {
				return true, probe.Signal
			}
		}
	case "integer_overflow_anomaly":
		if confirmedRe.MatchString(probeBody) && !errorRe.MatchString(probeBody) {
			return true, probe.Signal
		}
		if bt, ok := extractTotal(baselineBody); ok {
			if pt, ok2 := extractTotal(probeBody); ok2 && (pt < 0 || pt < bt*0.5) {
				return true, probe.Signal
			}
		}
	case "zero_price_accepted", "zero_quantity_accepted":
		if confirmedRe.MatchString(probeBody) {
			if pt, ok := extractTotal(probeBody); ok && pt <= 0 {
				return true, probe.Signal
			}
		}
	default:
		if confirmedRe.MatchString(probeBody) && !errorRe.MatchString(probeBody) {
			if bt, ok := extractTotal(baselineBody); ok {
				if pt, ok2 := extractTotal(probeBody); ok2 && pt != bt {
					return true, "price_manipulation"
				}
			}
			return true, "order_without_validation"
		}
	}

	// Legacy signal for simple price swap tests.
	if bodyDiffersWithSuccess(baselineBody, probeBody) {
		return true, "price_manipulation"
	}
	return false, ""
}

func extractTotal(body string) (float64, bool) {
	m := totalRe.FindStringSubmatch(body)
	if len(m) < 2 {
		return 0, false
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func bodyDiffersWithSuccess(baseline, probe string) bool {
	if probe == baseline {
		return false
	}
	lower := strings.ToLower(probe)
	return strings.Contains(lower, "order confirmed") ||
		(strings.Contains(lower, "total:") && !errorRe.MatchString(probe))
}
