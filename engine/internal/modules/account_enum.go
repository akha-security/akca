package modules

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/verification"
)

func (r *Runner) runAccountEnum(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("account_enum", target); !ok {
		r.emitSkip("account_enum", target, reason)
		return nil
	}
	if len(r.cfg.KnownAccounts) == 0 || strings.TrimSpace(r.cfg.KnownAccounts[0]) == "" {
		r.emitSkip("account_enum", target, "known real account is required; result is inconclusive")
		return nil
	}
	known := strings.TrimSpace(r.cfg.KnownAccounts[0])
	unknown := "akca-unknown-" + randomAccountNonce() + "@example.invalid"
	var knownSamples, unknownSamples []int64
	var knownResponses, unknownResponses []httpclient.RequestResponse
	for round := 0; round < 2; round++ {
		for index := 0; index < 15; index++ {
			order := []struct {
				value string
				known bool
			}{{known, true}, {unknown, false}}
			if (round+index)%2 == 1 {
				order[0], order[1] = order[1], order[0]
			}
			for _, sample := range order {
				if ctx.Err() != nil {
					return nil
				}
				rr, err := r.probe(ctx, target, sample.value)
				if err != nil {
					continue
				}
				if sample.known {
					knownSamples = append(knownSamples, rr.Response.Duration.Milliseconds())
					knownResponses = append(knownResponses, rr)
				} else {
					unknownSamples = append(unknownSamples, rr.Response.Duration.Milliseconds())
					unknownResponses = append(unknownResponses, rr)
				}
			}
		}
	}
	if len(knownResponses) < 15 || len(unknownResponses) < 15 {
		return nil
	}
	knownRR, unknownRR := knownResponses[0], unknownResponses[0]
	if stableResponseClass(knownResponses) != "" && stableResponseClass(unknownResponses) != "" &&
		stableResponseClass(knownResponses) != stableResponseClass(unknownResponses) &&
		accountEnumErrorDiff(knownRR, unknownRR) {
		payload := defaultPayload("account_enum", "error_message_diff", unknown, "error_message_diff")
		finding := r.verifyAndBuildWithCandidate(ctx, "account_enum", target, payload, knownRR, unknownRR,
			"error_message_diff", false, false, "", "", func(candidate *verification.Candidate) {
				candidate.RequestedProofType = verification.ProofDifferentialReplay
				candidate.NegativeControlSet = true
				candidate.NegativeControlOK = true
				candidate.TypedReplayHits = make([]bool, len(unknownResponses))
				for index := range candidate.TypedReplayHits {
					candidate.TypedReplayHits[index] = true
				}
				for index, rr := range unknownResponses[1:] {
					candidate.Observations = append(candidate.Observations,
						r.observation("account_enum", target, verification.RolePositiveReplay, index+2, rr))
				}
				for index, rr := range knownResponses[1:] {
					candidate.Observations = append(candidate.Observations,
						r.observation("account_enum", target, verification.RoleNegativeControl, index+1, rr))
				}
			})
		if finding != nil {
			finding.Description = "A user-supplied known account and a randomized nonexistent account produced stable, distinct response classes across two interleaved rounds."
			var out []ModuleFinding
			r.recordFinding(ctx, &out, finding, "account_enum", "error_message_diff")
			return out
		}
	}
	if _, significant := verification.RobustTimingDifference(knownSamples, unknownSamples, 100); significant {
		payload := defaultPayload("account_enum", "timing_differential", unknown, "timing_differential")
		finding := r.verifyAndBuildWithCandidate(ctx, "account_enum", target, payload, knownRR, unknownRR,
			"timing_differential", false, false, "", "", func(candidate *verification.Candidate) {
				candidate.RequestedProofType = verification.ProofTiming
				candidate.TimingSamples = knownSamples
				candidate.TimingControl = unknownSamples
				for index, rr := range knownResponses {
					candidate.Observations = append(candidate.Observations,
						r.observation("account_enum", target, verification.RolePositiveReplay, index+1, rr))
				}
				for index, rr := range unknownResponses {
					candidate.Observations = append(candidate.Observations,
						r.observation("account_enum", target, verification.RoleNegativeControl, index+1, rr))
				}
			})
		if finding != nil {
			finding.Description = "Known and randomized nonexistent accounts produced a robust timing separation across two interleaved 15-sample rounds."
			var out []ModuleFinding
			r.recordFinding(ctx, &out, finding, "account_enum", "timing_differential")
			return out
		}
	}
	return nil
}

func accountEnumErrorDiff(validRR, invalidRR httpclient.RequestResponse) bool {
	validBody := validRR.Response.Body
	invalidBody := invalidRR.Response.Body
	if validBody == invalidBody || statusOnlyDifferential(invalidRR.Response.StatusCode, validRR.Response.StatusCode) {
		return false
	}
	lowerValid := strings.ToLower(validBody)
	lowerInvalid := strings.ToLower(invalidBody)
	return (strings.Contains(lowerInvalid, "not found") || strings.Contains(lowerInvalid, "invalid user") ||
		strings.Contains(lowerInvalid, "no account") || strings.Contains(lowerInvalid, "does not exist")) &&
		!strings.Contains(lowerValid, "not found")
}

func stableResponseClass(responses []httpclient.RequestResponse) string {
	counts := map[string]int{}
	best, bestCount := "", 0
	for _, rr := range responses {
		hash := booleanResponseHash(strconv.Itoa(rr.Response.StatusCode) + "|" + rr.Response.Body)
		counts[hash]++
		if counts[hash] > bestCount {
			best, bestCount = hash, counts[hash]
		}
	}
	if bestCount*100/len(responses) < 80 {
		return ""
	}
	return best
}

func randomAccountNonce() string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "fallback"
	}
	return hex.EncodeToString(raw[:])
}

func accountEnumTimingDiff(validMs, invalidMs int64) bool {
	if validMs <= 0 || invalidMs <= 0 {
		return false
	}
	delta := validMs - invalidMs
	if delta < 0 {
		delta = -delta
	}
	return delta >= 100
}
