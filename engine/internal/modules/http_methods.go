package modules

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/akha-security/akca/engine/internal/safemutation"
	"github.com/akha-security/akca/engine/internal/verification"
)

func (r *Runner) runHTTPMethods(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("http_methods", target); !ok {
		r.emitSkip("http_methods", target, reason)
		return nil
	}

	var out []ModuleFinding
	base := strings.TrimRight(target.EndpointURL, "/")
	if idx := strings.Index(base, "?"); idx != -1 {
		base = base[:idx]
	}

	// 1. Deterministic PUT + GET + DELETE Verification
	tokenBytes := make([]byte, 6)
	_, _ = rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)

	proofFilename := fmt.Sprintf("akca_proof_%s.txt", token)
	proofContent := fmt.Sprintf("akca_put_test_token_%s", token)
	putURL := base + "/" + proofFilename

	putTarget := target
	putTarget.EndpointURL = putURL
	putTarget.Method = "PUT"

	beforeTarget := putTarget
	beforeTarget.Method = "GET"
	before, beforeErr := r.probe(ctx, beforeTarget, "")
	if beforeErr == nil {
		tx, beginErr := r.safeMutationGuard().Begin(safemutation.Operation{
			ID: "http-put-canary", Risk: safemutation.ReversibleWrite,
			ResourceID: putURL, CleanupDefined: true,
		}, responseStateHash(before))
		if beginErr == nil {
			rrPut, putErr := r.probeWithBody(ctx, putTarget, proofContent, "text/plain", nil)
			putAccepted := putErr == nil && (rrPut.Response.StatusCode == 200 || rrPut.Response.StatusCode == 201 || rrPut.Response.StatusCode == 204)

			// Verify file existence via GET
			getTarget := putTarget
			getTarget.Method = "GET"
			rrGet, errGet := r.probe(ctx, getTarget, "")
			verified := putAccepted && errGet == nil && rrGet.Response.StatusCode == 200 && strings.Contains(rrGet.Response.Body, proofContent)

			// Cleanup is mandatory even when PUT returned an unexpected status: a
			// server may have persisted the body despite an error response.
			delTarget := putTarget
			delTarget.Method = "DELETE"
			rrDelete, deleteErr := r.probe(ctx, delTarget, "")
			afterCleanup, cleanupGetErr := r.probe(ctx, getTarget, "")
			deleteAccepted := deleteErr == nil && ((rrDelete.Response.StatusCode >= 200 && rrDelete.Response.StatusCode < 300) || rrDelete.Response.StatusCode == 404)
			contentRemoved := cleanupGetErr == nil && !strings.Contains(afterCleanup.Response.Body, proofContent)
			_, finishErr := r.safeMutationGuard().Finish(tx.ID, responseStateHash(rrGet), deleteAccepted && contentRemoved)

			if verified && finishErr == nil {
				signal := "http_put_unauthenticated_upload"
				p := defaultPayload("http_methods", "PUT", proofContent, signal)
				f := r.verifyAndBuildWithCandidate(ctx, "http_methods", putTarget, p, before, rrGet, signal, false, false, "", "", func(candidate *verification.Candidate) {
					candidate.RequestedProofType = verification.ProofFileRetrieval
					candidate.NegativeControlSet = true
					candidate.NegativeControlOK = !strings.Contains(before.Response.Body, proofContent)
					candidate.Observations = append(candidate.Observations,
						r.observation("http_methods", putTarget, verification.RoleNegativeControl, 1, before),
						r.observation("http_methods", putTarget, verification.RoleStateAfter, 1, rrGet))
				})
				if f != nil {
					f.Title = "Unauthenticated Arbitrary File Upload via HTTP PUT"
					f.Severity = "critical"
					f.Description = fmt.Sprintf("The server allowed arbitrary file creation via HTTP PUT at %s. File creation was verified via HTTP GET and cleaned up.", putURL)
					r.recordFinding(ctx, &out, f, "http_methods", signal)
				}
			}
		}
	}

	// 2. HTTP TRACE / XST Verification
	traceTarget := target
	traceTarget.Method = "TRACE"
	traceHeaderName := "X-Akca-Trace-Test"
	traceHeaderValue := "trace_token_" + token
	customHeaders := map[string]string{traceHeaderName: traceHeaderValue}

	rrTrace, errTrace := r.probeWithBody(ctx, traceTarget, "", "text/plain", customHeaders)
	if errTrace == nil && rrTrace.Response.StatusCode == 200 {
		if strings.Contains(rrTrace.Response.Body, traceHeaderName) && strings.Contains(rrTrace.Response.Body, traceHeaderValue) {
			baseline, baselineErr := r.cachedEmptyProbe(ctx, target)
			control, controlErr := r.probeWithBody(ctx, traceTarget, "", "text/plain", nil)
			if baselineErr != nil || controlErr != nil || strings.Contains(control.Response.Body, traceHeaderValue) {
				return out
			}
			signal := "http_trace_xst"
			p := defaultPayload("http_methods", "TRACE", traceHeaderValue, signal)
			f := r.verifyAndBuildWithCandidate(ctx, "http_methods", traceTarget, p, baseline, rrTrace, signal, false, false, "", "", func(candidate *verification.Candidate) {
				candidate.RequestedProofType = verification.ProofHeaderEvidence
				candidate.NegativeControlSet = true
				candidate.NegativeControlOK = true
				candidate.Observations = append(candidate.Observations,
					r.observation("http_methods", traceTarget, verification.RoleNegativeControl, 1, control))
			})
			if f != nil {
				f.Title = "Cross-Site Tracing (XST) via HTTP TRACE"
				f.Severity = "medium"
				f.Description = "The server responds to HTTP TRACE requests and echoes sensitive request headers back in the body."
				r.recordFinding(ctx, &out, f, "http_methods", signal)
			}
		}
	}

	return out
}

func responseStateHash(rr interface{}) string {
	value := fmt.Sprintf("%#v", rr)
	return fmt.Sprintf("%x", sha256.Sum256([]byte(value)))
}
