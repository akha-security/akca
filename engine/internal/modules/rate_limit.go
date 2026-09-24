package modules

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/verification"
)

func (r *Runner) runRateLimit(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("rate_limit", target); !ok {
		r.emitSkip("rate_limit", target, reason)
		return nil
	}
	policy, ok := ratePolicyForTarget(r.cfg.RateLimitPolicies, target.EndpointURL)
	if !ok || policy.Threshold < 1 || strings.TrimSpace(policy.Account) == "" || policy.CooldownSeconds < 1 {
		if rateLimitSensitiveSurface(target) && rateLimitAuthParameter(target.Parameter) &&
			(r.cfg.PayloadBudget == config.PayloadBudgetHigh || r.cfg.PayloadBudget == config.PayloadBudgetUnlimited) {
			return r.runRateLimitThresholdDiscovery(ctx, target)
		}
		r.emitSkip("rate_limit", target, "a target-specific account, threshold and cooldown policy are required")
		return nil
	}
	attemptCount := policy.Threshold + 3
	if policy.WindowSeconds < 1 {
		r.emitSkip("rate_limit", target, "window_seconds is required to prove that the configured threshold was exceeded within one window")
		return nil
	}
	windowStart := time.Now()
	if policy.Threshold >= 50 {
		r.emitSkip("rate_limit", target, "configured threshold exceeds the 50-attempt verification ceiling")
		return nil
	}
	if attemptCount > 50 {
		attemptCount = 50
	}
	var attempts, controls []httpclient.RequestResponse
	for index := 0; index < attemptCount; index++ {
		if ctx.Err() != nil {
			return nil
		}
		rr, err := r.probeForModule(ctx, "rate_limit", target, policy.Account)
		if err != nil {
			return nil
		}
		if rateLimitBlockSignal(rr.Response.StatusCode, rr.Response.Body) {
			return r.runRateLimitXFFBypass(ctx, target, policy, rr)
		}
		if !failedAuthenticationOutcome(rr.Response) {
			return nil
		}
		attempts = append(attempts, rr)
		if time.Since(windowStart) >= time.Duration(policy.WindowSeconds)*time.Second {
			r.emitSkip("rate_limit", target, "verification exceeded the configured rate-limit window")
			return nil
		}
		if index%3 == 2 {
			control, err := r.probeForModule(ctx, "rate_limit", target, "akca-control-"+randomAccountNonce()+"@example.invalid")
			if err != nil || rateLimitBlockSignal(control.Response.StatusCode, control.Response.Body) {
				return nil
			}
			controls = append(controls, control)
		}
	}
	if len(attempts) < policy.Threshold+1 || len(controls) < 2 {
		return nil
	}
	payload := defaultPayload("rate_limit", "configured_threshold_exceeded",
		fmt.Sprintf("account_hash_only; threshold=%d", policy.Threshold), "policy_violation_confirmed")
	finding := r.verifyAndBuildWithCandidate(ctx, "rate_limit", target, payload, attempts[0], attempts[len(attempts)-1],
		"policy_violation_confirmed", false, false, "", "", func(candidate *verification.Candidate) {
			candidate.RequestedProofType = verification.ProofPolicyViolation
			candidate.ExpectedEquivalent = true
			candidate.NegativeControlSet = true
			candidate.NegativeControlOK = true
			for index, rr := range attempts {
				candidate.Observations = append(candidate.Observations,
					r.observation("rate_limit", target, verification.RolePositiveReplay, index+10, rr))
			}
			for index, rr := range controls {
				candidate.Observations = append(candidate.Observations,
					r.observation("rate_limit", target, verification.RoleNegativeControl, index+1, rr))
			}
		})
	if finding == nil {
		return nil
	}
	finding.Description = fmt.Sprintf(
		"The same account processed %d verified failed authentication attempts without a block, exceeding the supplied threshold of %d; interleaved different-account controls remained available.",
		len(attempts), policy.Threshold,
	)
	var out []ModuleFinding
	r.recordFinding(ctx, &out, finding, "rate_limit", "policy_violation_confirmed")
	return out
}

func (r *Runner) runRateLimitXFFBypass(ctx context.Context, target ScanTarget, policy config.RateLimitPolicy,
	blocked httpclient.RequestResponse) []ModuleFinding {
	if !policy.PerIP {
		return nil
	}
	var blockedControls []httpclient.RequestResponse
	var bypasses []httpclient.RequestResponse
	for index := 0; index < 3; index++ {
		control, err := r.probeForModule(ctx, "rate_limit", target, policy.Account)
		if err != nil || !rateLimitBlockSignal(control.Response.StatusCode, control.Response.Body) {
			return nil
		}
		blockedControls = append(blockedControls, control)
		bypass, err := r.probeWithHeadersForModule(ctx, "rate_limit", target, policy.Account, map[string]string{
			"X-Forwarded-For": fmt.Sprintf("198.51.100.%d", index+20),
		})
		if err != nil || rateLimitBlockSignal(bypass.Response.StatusCode, bypass.Response.Body) ||
			!failedAuthenticationOutcome(bypass.Response) {
			return nil
		}
		bypasses = append(bypasses, bypass)
	}
	timer := time.NewTimer(time.Duration(policy.CooldownSeconds)*time.Second + 250*time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil
	case <-timer.C:
	}
	recovered, err := r.probeForModule(ctx, "rate_limit", target, policy.Account)
	if err != nil || rateLimitBlockSignal(recovered.Response.StatusCode, recovered.Response.Body) ||
		!failedAuthenticationOutcome(recovered.Response) {
		return nil
	}
	payload := defaultPayload("rate_limit", "xff_after_real_block",
		fmt.Sprintf("redacted XFF rotation; cooldown=%ds", policy.CooldownSeconds), "xff_policy_bypass_confirmed")
	finding := r.verifyAndBuildWithCandidate(ctx, "rate_limit", target, payload, blocked, bypasses[0],
		"policy_violation_confirmed", false, false, "", "", func(candidate *verification.Candidate) {
			candidate.RequestedProofType = verification.ProofPolicyViolation
			candidate.NegativeControlSet, candidate.NegativeControlOK = true, true
			for index, rr := range bypasses {
				candidate.Observations = append(candidate.Observations,
					r.observation("rate_limit", target, verification.RolePositiveReplay, index+10, rr))
			}
			for index, rr := range blockedControls {
				candidate.Observations = append(candidate.Observations,
					r.observation("rate_limit", target, verification.RoleNegativeControl, index+1, rr))
			}
			candidate.Observations = append(candidate.Observations,
				r.observation("rate_limit", target, verification.RoleBaselineReplay, 1, recovered))
		})
	if finding == nil {
		return nil
	}
	finding.Title = "Rate limit bypass through X-Forwarded-For after a real block"
	finding.Description = fmt.Sprintf("The original client remained blocked in three interleaved controls while three distinct X-Forwarded-For values processed the same account action. Recovery was independently verified after the configured %d-second cooldown.", policy.CooldownSeconds)
	var out []ModuleFinding
	r.recordFinding(ctx, &out, finding, "rate_limit", "xff_policy_bypass_confirmed")
	return out
}

func ratePolicyForTarget(policies []config.RateLimitPolicy, endpoint string) (config.RateLimitPolicy, bool) {
	for _, policy := range policies {
		if policy.URLContains != "" && strings.Contains(strings.ToLower(endpoint), strings.ToLower(policy.URLContains)) {
			return policy, true
		}
	}
	return config.RateLimitPolicy{}, false
}

func failedAuthenticationOutcome(response httpclient.ResponseRecord) bool {
	if rateLimitBlockSignal(response.StatusCode, response.Body) || response.StatusCode >= 500 || response.StatusCode == 0 {
		return false
	}
	lower := strings.ToLower(response.Body)
	if response.StatusCode == 401 {
		return true
	}
	for _, marker := range []string{"invalid password", "invalid credentials", "login failed", "authentication failed"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func rateLimitBlockSignal(status int, body string) bool {
	if status == 429 || status == 423 {
		return true
	}
	return rateLimitBodyBlockSignal(body)
}

func rateLimitBodyBlockSignal(body string) bool {
	lower := strings.ToLower(body)
	for _, token := range []string{"too many", "rate limit", "ratelimit", "try again later", "captcha", "temporarily locked"} {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

func rateLimitSensitiveSurface(target ScanTarget) bool {
	lower := strings.ToLower(target.EndpointURL + " " + target.Parameter + " " + target.Location)
	for _, token := range []string{"login", "auth", "token", "password", "otp", "mfa", "reset", "forgot", "coupon", "redeem", "claim"} {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

func rateLimitAuthParameter(param string) bool {
	lower := strings.ToLower(param)
	if lower == "" {
		return false
	}
	for _, kw := range []string{"user", "username", "email", "login", "account", "pass", "password", "otp", "token"} {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func rateLimitAttemptProcessed(status int, body string) bool {
	return status != 0 && status != 429 && status < 500 && !rateLimitBodyBlockSignal(body)
}

func rateLimitMeaningfulResponse(body string, target ScanTarget) bool {
	return failedAuthenticationOutcome(httpclient.ResponseRecord{StatusCode: 401, Body: body}) ||
		(strings.Contains(strings.ToLower(target.EndpointURL), "api") && len(strings.TrimSpace(body)) >= 8)
}

func (r *Runner) runRateLimitThresholdDiscovery(ctx context.Context, target ScanTarget) []ModuleFinding {
	const maxBurst = 25
	account := "akca-threshold-" + randomAccountNonce() + "@example.invalid"
	started := time.Now()
	processed := 0
	for i := 0; i < maxBurst; i++ {
		if ctx.Err() != nil {
			return nil
		}
		rr, err := r.probeForModule(ctx, "rate_limit", target, account)
		if err != nil {
			return nil
		}
		if rateLimitBlockSignal(rr.Response.StatusCode, rr.Response.Body) {
			r.emitDiscovery("rate_limit", target, "throttling_observed",
				fmt.Sprintf("A blocking response was observed after %d processed failures in %s; account/IP scope and threshold remain unproven", processed, time.Since(started)))
			return nil
		}
		if !failedAuthenticationOutcome(rr.Response) {
			r.emitSkip("rate_limit", target, "request did not produce a verified authentication failure")
			return nil
		}
		processed++
	}
	r.emitDiscovery("rate_limit", target, "rate_limit_not_observed",
		fmt.Sprintf("No block observed during %d failed authentication requests over %s; no target policy was supplied, so this is not a vulnerability finding", processed, time.Since(started)))
	return nil
}
