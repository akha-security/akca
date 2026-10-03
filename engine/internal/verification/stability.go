package verification

import (
	"strings"
)

const stabilityRepeats = 5

func EvaluateStability(matches []bool) (ratio float64, level ConfidenceLevel, suppress bool) {
	if len(matches) < 3 {
		// Yetersiz örnek sayısında otomatik NeedsManualReview'a düşür
		return 0.5, NeedsManualReview, false
	}
	hits := 0
	for _, m := range matches {
		if m {
			hits++
		}
	}
	ratio = float64(hits) / float64(len(matches))
	switch {
	case ratio >= 0.8:
		return ratio, HighConfidence, false
	case ratio >= 0.5:
		return ratio, NeedsManualReview, false
	case ratio >= 0.3:
		// Load-balanced/cached environments may yield inconsistent responses.
		// Downgrade to manual review instead of full suppression so that real
		// findings behind infrastructure noise are not silently discarded.
		return ratio, NeedsManualReview, false
	default:
		return ratio, Suppressed, true
	}
}

func StabilityFromRuns(base ResponseSnapshot, runs []ResponseSnapshot) []bool {
	out := make([]bool, 0, len(runs))
	if len(runs) == 0 {
		return out
	}
	// Use the median-length response as the reference instead of always the
	// first one. If the first response was an outlier (e.g. a cache miss or
	// transient error), all subsequent correct responses would be wrongly
	// marked as inconsistent.
	reference := medianResponse(runs)
	for _, r := range runs {
		// A repeat must both differ from the baseline and agree with the first
		// probe response. Merely returning a different/random page each time is
		// not stable vulnerability evidence.
		positive := SemanticDiffers(base, r) && responsesConsistent(reference, r)
		out = append(out, positive)
	}
	return out
}

func responsesConsistent(a, b ResponseSnapshot) bool {
	if a.StatusCode != b.StatusCode {
		return false
	}
	an := NormalizeVolatileFields(a.Body)
	bn := NormalizeVolatileFields(b.Body)
	if an == bn {
		return true
	}
	jsonResponse := strings.Contains(strings.ToLower(a.ContentType), "json") ||
		strings.Contains(strings.ToLower(b.ContentType), "json")
	if jsonResponse {
		return len(ExtractJSONKeyPaths(an)) > 0 && CompareJSONKeyPaths(an, bn)
	}
	htmlResponse := strings.Contains(strings.ToLower(a.ContentType), "html") ||
		strings.Contains(strings.ToLower(b.ContentType), "html") || strings.Contains(an, "<") || strings.Contains(bn, "<")
	if htmlResponse {
		return CompareDOMStructure(AnalyzeDOMStructure(an), AnalyzeDOMStructure(bn)) &&
			ContainsErrorKeywords(an) == ContainsErrorKeywords(bn)
	}
	return false
}

func medianResponse(runs []ResponseSnapshot) ResponseSnapshot {
	if len(runs) <= 2 {
		return runs[0]
	}
	type indexed struct {
		index int
		len   int
	}
	sorted := make([]indexed, len(runs))
	for i, r := range runs {
		sorted[i] = indexed{i, len(r.Body)}
	}
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j].len < sorted[j-1].len; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	return runs[sorted[len(sorted)/2].index]
}
