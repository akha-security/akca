package modules

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/akha-security/akca/engine/internal/urlutil"
)

func (r *Runner) runParserDifferential(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("parser_differential", target); !ok {
		r.emitSkip("parser_differential", target, reason)
		return nil
	}

	var out []ModuleFinding
	targetURL := strings.TrimSpace(target.EndpointURL)
	if !urlutil.IsPlausibleEndpointURL(targetURL) || !r.scope.IsInScope(targetURL) {
		return nil
	}

	method := strings.ToUpper(strings.TrimSpace(target.Method))
	if method == "" {
		method = http.MethodPost
	}
	// A generic duplicate-key payload sent to POST/PUT/PATCH/DELETE can mutate
	// real account or authorization state. An HTTP 200 and a different response
	// only prove parser behavior, not a security boundary bypass. Until a
	// recorded state/cleanup contract is available, keep this probe read-only.
	if method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions {
		r.emitStatefulProofGap("parser_differential", target, "state-changing parser probes require an explicit state and cleanup policy")
		r.emitSkip("parser_differential", target, "state-changing parser probes require an explicit state and cleanup policy")
		return nil
	}

	// 1. JSON Duplicate Key Precedence Differential
	if strings.Contains(strings.ToLower(target.Profile.ContentType), "json") || strings.HasPrefix(strings.TrimSpace(target.BodyTemplate), "{") {
		if findings := r.probeJSONDuplicateKeyDifferential(ctx, target, method, targetURL); len(findings) > 0 {
			return findings
		}
	}

	return out
}

func (r *Runner) probeJSONDuplicateKeyDifferential(ctx context.Context, target ScanTarget, method, targetURL string) []ModuleFinding {
	var out []ModuleFinding

	baselineRR, err := r.probeWithoutInjectedPayload(ctx, "parser_differential", target)
	if err != nil || baselineRR.Response.StatusCode >= 400 {
		return nil
	}

	// Craft duplicate key JSON body with contradictory values
	duplicateKeyBody := `{"role":"user","role":"admin","access":"restricted","access":"granted"}`
	headers := map[string]string{
		"Content-Type": "application/json",
	}

	diffRR, diffErr := r.client.Do(ctx, method, targetURL, []byte(duplicateKeyBody), headers)
	if diffErr != nil {
		return nil
	}

	// Detect if duplicate keys are processed with state difference and no parsing error
	if diffRR.Response.StatusCode == http.StatusOK &&
		diffRR.Response.Body != baselineRR.Response.Body &&
		!authDeniedBody(strings.ToLower(diffRR.Response.Body)) &&
		len(strings.TrimSpace(diffRR.Response.Body)) > 20 {

		// Replay confirmation
		replayRR, replayErr := r.client.Do(ctx, method, targetURL, []byte(duplicateKeyBody), headers)
		if replayErr != nil || replayRR.Response.StatusCode != http.StatusOK || replayRR.Response.Body != diffRR.Response.Body {
			return nil
		}

		p := defaultPayload("parser_differential", "json_duplicate_key", duplicateKeyBody, "duplicate_key_precedence_accepted")
		f := r.verifyAndBuild(ctx, "parser_differential", target, p, baselineRR, diffRR,
			"duplicate_key_precedence_accepted", false, false, "", "")
		if f != nil {
			f.Title = "Parser Differential: Duplicate Key Precedence Discrepancy"
			f.Description = fmt.Sprintf("The endpoint %s accepted conflicting duplicate JSON keys without rejection, exhibiting last-value precedence that may bypass upstream API gateway validation filters.", targetURL)
			f.Severity = "Medium"
		}
		r.recordFinding(ctx, &out, f, "parser_differential", "duplicate_key_precedence_accepted")
	}

	return out
}
