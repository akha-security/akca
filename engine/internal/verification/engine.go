package verification

import (
	"math"
	"time"

	"github.com/akha-security/akca/engine/internal/storage"
)

type Engine struct {
	db   *storage.DB
	emit EventSink
}

func NewEngine(db *storage.DB, emit EventSink) *Engine {
	return &Engine{db: db, emit: emit}
}

func (e *Engine) Verify(candidate Candidate) Result {
	result := Result{
		VerifiedAt:   time.Now().UTC(),
		ProofPolicy:  candidate.ProofPolicyVersion,
		Observations: append([]Observation(nil), candidate.Observations...),
	}
	var reasons []DowngradeReason
	var upgrades []string

	isOASTConfirmed := validOASTCorrelation(candidate)
	if candidate.OAST != nil && !isOASTConfirmed {
		reasons = append(reasons, ReasonOASTMismatch)
	}

	if len(candidate.HoneypotCanaries) >= 3 && len(candidate.HoneypotBodies) >= 3 && !isOASTConfirmed {
		if DetectHoneypot(candidate.HoneypotCanaries, candidate.HoneypotBodies) {
			reasons = append(reasons, ReasonHoneypotParameter)
			result.Suppressed = true
			result.Confidence = Suppressed
			return e.finalize(candidate, result)
		}
	}

	if fp, ok := MatchErrorFingerprint(candidate.Probe.Body, candidate.Probe.StatusCode, candidate.Probe.Headers); ok {
		result.ErrorFingerprint = fp.Source
		switch fp.Classification {
		case "waf_block":
			reasons = append(reasons, ReasonWAFBlockPage)
		case "generic_error":
			reasons = append(reasons, ReasonGenericErrorPage)
		case "login_redirect":
			reasons = append(reasons, ReasonLoginRedirect)
		case "framework_error":
			// A framework exception page can be genuine vulnerability evidence
			// (for example an SQL exception). Downgrade it, but do not apply the
			// hard suppression reserved for generic proxy/server error pages.
			reasons = append(reasons, ReasonFrameworkError)
		}
	}

	if !candidate.ExpectedEquivalent && IsSoft404(candidate.Baseline, candidate.Probe) {
		reasons = append(reasons, ReasonSoft404)
	}

	result.BaselineMatch = CompareParameterBaseline(candidate.Baseline, candidate.Probe)
	result.SemanticDelta = CompareSemantic(candidate.Baseline, candidate.Probe)
	result.SemanticDiff = result.SemanticDelta.SecurityRelevant
	if candidate.RequestedProofType == ProofHeaderEvidence && SignificantHeaderDiff(candidate.Baseline, candidate.Probe) {
		result.SemanticDelta.ChangedHeaders = true
		result.SemanticDelta.SecurityRelevant = true
		result.SemanticDiff = true
	}
	if result.BaselineMatch && !result.SemanticDiff && !candidate.ExpectedEquivalent {
		reasons = append(reasons, ReasonBaselineMatch)
	}

	isXSS := candidate.Module == "xss" || candidate.VulnClass == "xss"
	if isXSS && !candidate.DirectTypedSignal && !candidate.DOMPresent && !candidate.DOMExecuted &&
		candidate.Reflection != nil && candidate.Reflection.Context == "html_body" &&
		candidate.Reflection.ReflectionKind == "raw" {
		if CompareDOMStructure(AnalyzeDOMStructure(candidate.Baseline.Body), AnalyzeDOMStructure(candidate.Probe.Body)) {
			reasons = append(reasons, ReasonSafeTextContainer)
		}
	}

	stabilityMatches := candidate.TypedReplayHits
	if len(stabilityMatches) == 0 && len(candidate.StabilityRuns) > 0 {
		if candidate.ExpectedEquivalent {
			stabilityMatches = equivalenceFromRuns(candidate.Baseline, candidate.StabilityRuns)
		} else {
			stabilityMatches = StabilityFromRuns(candidate.Baseline, candidate.StabilityRuns)
		}
	}
	if len(candidate.TypedReplayHits) > 0 {
		result.TypedReplayRatio = boolRatio(candidate.TypedReplayHits)
		if result.TypedReplayRatio < 2.0/3.0 && !isOASTConfirmed && !candidate.DOMExecuted {
			reasons = append(reasons, ReasonTypedReplayFailed)
			result.Suppressed = true
			result.Confidence = Suppressed
			result.DowngradeReasons = reasons
			return e.finalize(candidate, result)
		}
	}
	if candidate.NegativeControlSet {
		result.NegativeControlOK = candidate.NegativeControlOK
		if !candidate.NegativeControlOK && !isOASTConfirmed && !candidate.DOMExecuted {
			reasons = append(reasons, ReasonNegativeControlHit)
			result.Suppressed = true
			result.Confidence = Suppressed
			result.DowngradeReasons = reasons
			return e.finalize(candidate, result)
		}
	}
	if len(stabilityMatches) > 0 {
		ratio, stabilityLevel, suppress := EvaluateStability(stabilityMatches)
		result.StabilityRatio = ratio
		if suppress && !isOASTConfirmed {
			reasons = append(reasons, ReasonUnstableResponse)
			result.Suppressed = true
			result.Confidence = Suppressed
			return e.finalize(candidate, result)
		}
		if stabilityLevel == NeedsManualReview {
			reasons = append(reasons, ReasonUnstableResponse)
		}
	}

	if len(candidate.PolymorphicHits) > 0 {
		result.PolymorphicOK = ConfirmPolymorphic(candidate.PolymorphicHits)
		if !result.PolymorphicOK {
			reasons = append(reasons, ReasonNoPolymorphicMatch)
		}
	} else {
		result.PolymorphicOK = false
	}

	if RequiresDifferentialEvidence(candidateModule(candidate)) && !candidate.ExpectedEquivalent {
		if result.BaselineMatch && !result.SemanticDiff && !isOASTConfirmed &&
			!candidate.DOMExecuted && len(candidate.TimingSamples) == 0 &&
			candidate.RequestedProofType != ProofRuntimeTrace {
			result.Suppressed = true
			result.Confidence = Suppressed
			result.DowngradeReasons = reasons
			return e.finalize(candidate, result)
		}
	}

	if isOASTConfirmed {
		result.OASTConfirmed = true
		upgrades = append(upgrades, "oast_callback_correlated")
	}

	if len(candidate.TimingSamples) > 0 {
		var sig bool
		if candidateModule(candidate) == "account_enum" {
			_, sig = RobustTimingDifference(candidate.TimingSamples, candidate.TimingControl, 100)
		} else {
			_, sig = CalibrateTiming(candidate.TimingSamples, candidate.TimingControl)
		}
		if !sig {
			if len(candidate.TimingSamples) < 3 || len(candidate.TimingControl) < 3 {
				reasons = append(reasons, ReasonTimingSamples)
			} else {
				reasons = append(reasons, ReasonTimingNoise)
			}
			if !isOASTConfirmed && !candidate.DOMExecuted {
				result.Suppressed = true
				result.Confidence = Suppressed
				result.DowngradeReasons = reasons
				return e.finalize(candidate, result)
			}
		} else {
			result.TimingConfirmed = true
			upgrades = append(upgrades, "timing_signal_calibrated")
		}
	}

	if candidate.DOMPresent || candidate.DOMExecuted {
		level, domReason := SeparateDOMExecution(candidate.DOMPresent, candidate.DOMExecuted)
		if domReason != "" {
			reasons = append(reasons, domReason)
		}
		if level == Confirmed {
			upgrades = append(upgrades, "dom_xss_execution_confirmed")
		}
	}

	if requiresClassSpecificProof(candidate) && !hasClassSpecificProof(candidate, result) {
		reasons = append(reasons, ReasonInsufficientProof)
		result.Suppressed = true
		result.Confidence = Suppressed
		result.DowngradeReasons = reasons
		result.UpgradeReasons = upgrades
		return e.finalize(candidate, result)
	}
	result.ProofType, result.ProofSatisfied = evaluateProofPolicy(candidate, result)
	if !result.ProofSatisfied {
		reasons = append(reasons, ReasonInsufficientProof)
		result.Suppressed = true
		result.Confidence = Suppressed
		result.DowngradeReasons = reasons
		result.UpgradeReasons = upgrades
		return e.finalize(candidate, result)
	}
	if validBooleanPairProof(candidate.BooleanPairProof) {
		proofCopy := *candidate.BooleanPairProof
		result.BooleanPairProof = &proofCopy
	}

	result.DowngradeReasons = reasons
	result.UpgradeReasons = upgrades
	result.Confidence, result.Score = ScoreConfidence(candidate, result)
	return e.finalize(candidate, result)
}

func boolRatio(items []bool) float64 {
	if len(items) == 0 {
		return 0
	}
	n := 0
	for _, item := range items {
		if item {
			n++
		}
	}
	return float64(n) / float64(len(items))
}

func equivalenceFromRuns(base ResponseSnapshot, runs []ResponseSnapshot) []bool {
	out := make([]bool, 0, len(runs))
	for _, run := range runs {
		out = append(out, CompareParameterBaseline(base, run) && !SemanticDiffers(base, run))
	}
	return out
}

func (e *Engine) finalize(candidate Candidate, result Result) Result {
	if e.db != nil {
		_ = e.db.SaveVerificationResult(candidate.ScanID, candidate, result)
	}
	if e.emit != nil {
		_ = e.emit("finding_verified", candidate.Title, map[string]interface{}{
			"scan_id": candidate.ScanID, "vuln_class": candidate.VulnClass,
			"confidence": result.Confidence, "score": result.Score,
			"suppressed": result.Suppressed, "downgrade_reasons": result.DowngradeReasons,
			"upgrade_reasons": result.UpgradeReasons,
		})
	}
	return result
}

func ScoreConfidence(c Candidate, r Result) (ConfidenceLevel, float64) {
	if r.Suppressed {
		return Suppressed, 0
	}
	// A candidate starts as an untrusted lead. Confidence is earned only from
	// independently reproduced, class-specific evidence.
	score := 0.10
	if r.SemanticDiff {
		score += 0.05
	}
	if c.DirectTypedSignal {
		// The module's parser/guard matched its vulnerability-specific signal.
		// It is useful corroboration, but a single response must never reach a
		// high-confidence tier by itself. Independent replay/control, OAST,
		// timing, DOM execution, or a boolean-pair proof supplies that upgrade.
		if r.TypedReplayRatio < 2.0/3.0 && !r.OASTConfirmed && !r.TimingConfirmed &&
			!c.DOMExecuted && !validBooleanPairProof(c.BooleanPairProof) {
			score += 0.20
			// Stateful and identity-bound proofs include independent before/after
			// or role/control observations. Preserve their stronger weight while
			// keeping one-shot content matches at the Potential tier.
			if isStatefulProof(r.ProofType) {
				score += 0.30
			}
		}
	}
	if r.PolymorphicOK {
		score += 0.15
	}
	// Typed replays are also the stability sample for module-specific guards;
	// do not award both bonuses for the same requests.
	if r.TypedReplayRatio == 0 {
		if r.StabilityRatio >= 0.8 {
			score += 0.20
		} else if r.StabilityRatio >= 0.5 {
			score -= 0.05
		}
	}
	if r.OASTConfirmed {
		score += 0.75
	}
	if r.TimingConfirmed {
		score += 0.55
	}
	if r.TypedReplayRatio >= 2.0/3.0 {
		score += 0.45
	}
	if c.NegativeControlSet && r.NegativeControlOK {
		score += 0.25
	}
	if validBooleanPairProof(c.BooleanPairProof) {
		score += 0.30
	}
	if c.DOMExecuted {
		score += 0.75
	}
	if r.ProofType == ProofRuntimeTrace {
		score += 0.75
	}
	switch r.ProofType {
	case ProofHeaderEvidence:
		score += 0.10
	case ProofContentEvidence, ProofConfiguration, ProofSchemaExposure:
		score += 0.25
	case ProofProtocolDesync, ProofRequestPolicy, ProofAnonymousAccess:
		score += 0.80
	case ProofStoredExecution:
		score += 0.35
	}
	for _, reason := range r.DowngradeReasons {
		switch reason {
		case ReasonWAFBlockPage, ReasonGenericErrorPage, ReasonHoneypotParameter,
			ReasonInsufficientProof, ReasonTypedReplayFailed, ReasonNegativeControlHit:
			return Suppressed, 0
		case ReasonSafeTextContainer, ReasonDOMPresenceOnly, ReasonBaselineMatch:
			score -= 0.2
		case ReasonUnstableResponse, ReasonNoPolymorphicMatch, ReasonTimingNoise, ReasonTimingSamples,
			ReasonOASTMismatch, ReasonFrameworkError:
			score -= 0.1
		case ReasonSoft404, ReasonLoginRedirect:
			score -= 0.15
		}
	}
	if c.LearningFP >= 0.5 {
		score -= 0.15
	} else if c.LearningFP >= 0.3 {
		score -= 0.08
	}
	// Confidence is a normalized score, not an additive point total. Strong
	// evidence combinations may exceed 1.0 internally, but must never leak a
	// value such as 1.05 to storage, events, or the CLI.
	if score < 0 {
		score = 0
	} else if score > 1 {
		score = 1
	}
	score = math.Round(score*100) / 100
	if score >= 0.9 || r.OASTConfirmed && r.StabilityRatio >= 0.8 {
		return Confirmed, score
	}
	if score >= 0.75 {
		return HighConfidence, score
	}
	if score >= 0.55 {
		return Potential, score
	}
	return NeedsManualReview, score
}

func isStatefulProof(proof ProofType) bool {
	switch proof {
	case ProofStateMutation, ProofIdentityBoundary, ProofFileRetrieval,
		ProofPolicyViolation, ProofRequestPolicy, ProofAnonymousAccess,
		ProofStoredExecution:
		return true
	default:
		return false
	}
}
