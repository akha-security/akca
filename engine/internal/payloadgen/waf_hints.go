package payloadgen

import (
	"sort"
	"strings"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/models"
	"github.com/akha-security/akca/engine/internal/wafintel"
)

// WAFHintsForProfile is shared by stored payload planning and runtime modules.
// Callers must load the profile for the exact scan and request host. Learning
// alone never activates auto on a host without a current WAF profile/signal.
func WAFHintsForProfile(cfg config.ScanConfig, profile models.WAFProfile, learn wafintel.LearningProfile) WAFHints {
	mode := cfg.EffectiveWAFPayloadMode()
	hints := WAFHints{
		Vendor:                  strings.TrimSpace(profile.Vendor),
		CautiousModeRecommended: profile.CautiousModeRecommended || profile.ChallengePageDetected || profile.RateLimitDetected,
		PreferredTechniques:     wafintel.PreferredTechniques(learn),
		BlockedChars:            append([]string(nil), learn.BlockedChars...),
		AllowedChars:            append([]string(nil), learn.AllowedChars...),
		QueryURLDecodeDepth:     learn.Decoder.QueryURLDecodeDepth,
		QueryURLDecodeObserved:  learn.Decoder.QueryURLDecodeObserved,
		QueryURLDecodeConflict:  learn.Decoder.QueryURLDecodeConflict,
		QueryPlusAsSpace:        learn.Decoder.QueryPlusAsSpace,
		QueryPlusObserved:       learn.Decoder.QueryPlusObserved,
		QueryPlusConflict:       learn.Decoder.QueryPlusConflict,
	}
	switch mode {
	case config.WAFPayloadAuto:
		// A CDN-only profile or cautious pacing recommendation is not proof of
		// blocking. A detected vendor can still select bounded candidate variants;
		// their efficacy must be established by matched probes and controls.
		hints.AllowEvasion = hints.Vendor != "" || profile.ChallengePageDetected || profile.RateLimitDetected
		hints.MaxVariants = 2
		for technique, score := range learn.TechniqueScores {
			if score < 0 {
				hints.AvoidTechniques = append(hints.AvoidTechniques, strings.ToLower(strings.TrimSpace(technique)))
			}
		}
	case config.WAFPayloadOn:
		hints.AllowEvasion = true
		hints.CautiousModeRecommended = true // permit generic variants without a detected vendor
	}
	return hints
}

func prioritizeWAFVariants(variants []wafVariant, hints WAFHints, location string) []wafVariant {
	preferred := make(map[string]int, len(hints.PreferredTechniques))
	for i, technique := range hints.PreferredTechniques {
		technique = strings.ToLower(strings.TrimSpace(technique))
		if _, exists := preferred[technique]; !exists {
			preferred[technique] = i
		}
	}
	observed := tomographyURLTechnique(hints, location)
	// Stable ordering keeps the vendor/context fallback order intact.
	rank := func(technique string) int {
		if technique == observed && observed != "" {
			return -1
		}
		if index, ok := preferred[technique]; ok {
			return index
		}
		return len(preferred) + 1
	}
	sort.SliceStable(variants, func(i, j int) bool { return rank(variants[i].enc) < rank(variants[j].enc) })
	return variants
}

func avoidWAFTechnique(hints WAFHints, technique string) bool {
	for _, blocked := range hints.AvoidTechniques {
		if strings.EqualFold(blocked, technique) {
			return true
		}
	}
	return false
}

// WithoutWAFAdaptation prevents persisted variants from overriding a later
// explicit opt-out when a scan resumes after payload generation was completed.
func WithoutWAFAdaptation(result GenerationResult) GenerationResult {
	payloads := make([]Payload, 0, len(result.Payloads))
	for _, payload := range result.Payloads {
		if !payload.WAFAdapted {
			payloads = append(payloads, payload)
		}
	}
	result.Payloads = payloads
	result.TestCases = buildTestCases(payloads)
	result.EstimatedRequests = estimateRequests(payloads)
	result.BudgetUsed = 0
	for _, payload := range payloads {
		if !payload.IsControl && !payload.IsNegativeControl {
			result.BudgetUsed += payload.BudgetCost
		}
	}
	result.Shadow = compareShadow(payloads, result.TestCases, result.BudgetUsed)
	return result
}
