package waf

import (
	"testing"

	"github.com/akha-security/akca/engine/internal/models"
	"github.com/akha-security/akca/engine/internal/ratelimit"
)

func TestDetectCloudflareAkamaiAWSModSecurity(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		body    string
		status  int
		want    string
	}{
		{
			name:    "cloudflare headers",
			headers: map[string]string{"server": "cloudflare", "cf-ray": "abc"},
			body:    "",
			status:  200,
			want:    "Cloudflare",
		},
		{
			name:    "akamai header",
			headers: map[string]string{"x-akamai-transformed": "1"},
			body:    "",
			status:  200,
			want:    "Akamai",
		},
		{
			name:    "aws waf header",
			headers: map[string]string{"x-amzn-requestid": "req-1"},
			body:    "",
			status:  403,
			want:    "AWS WAF",
		},
		{
			name:    "modsecurity body",
			headers: map[string]string{},
			body:    "blocked by mod_security",
			status:  403,
			want:    "ModSecurity",
		},
		{
			name:    "litespeed cache header",
			headers: map[string]string{"x-litespeed-cache": "hit"},
			body:    "",
			status:  200,
			want:    "LiteSpeed",
		},
		{
			name:    "litespeed ls prefix header",
			headers: map[string]string{"x-ls-cache": "hit"},
			body:    "",
			status:  200,
			want:    "LiteSpeed",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := models.WAFProfile{}
			(&Profiler{}).applyResponse(&p, tc.headers, tc.body, tc.status)
			if p.Vendor != tc.want {
				t.Fatalf("vendor=%q want %q", p.Vendor, tc.want)
			}
		})
	}
}

func TestChallengeAndRateLimitDetection(t *testing.T) {
	p := models.WAFProfile{}
	(&Profiler{}).applyResponse(&p, map[string]string{}, "please complete captcha challenge", 403)
	if !p.ChallengePageDetected {
		t.Fatal("expected challenge page")
	}

	p2 := models.WAFProfile{}
	(&Profiler{}).applyResponse(&p2, map[string]string{}, "", 429)
	if !p2.RateLimitDetected {
		t.Fatal("expected rate limit")
	}
}

func TestCautiousModeConfidence(t *testing.T) {
	p := models.WAFProfile{Vendor: "Cloudflare", HeaderSignatures: []string{"cf-ray:x"}, ChallengePageDetected: true}
	if confidenceScore(p) < 0.6 {
		t.Fatalf("expected high confidence, got %v", confidenceScore(p))
	}
	if !p.CautiousModeRecommended {
		p.CautiousModeRecommended = p.Vendor != "" || p.ChallengePageDetected || p.RateLimitDetected
	}
	if !p.CautiousModeRecommended {
		t.Fatal("expected cautious mode")
	}
}

func TestApplyCautiousModeDynamicSlowdown(t *testing.T) {
	limiter := ratelimit.New(20.0, 10.0)
	p := models.WAFProfile{CautiousModeRecommended: true}
	ApplyCautiousMode(limiter, p, 20.0, 3.0)

	_, _, mult := limiter.Rates()
	expectedMult := 20.0 / 3.0
	if mult < expectedMult-0.01 || mult > expectedMult+0.01 {
		t.Fatalf("expected multiplier around %f, got %f", expectedMult, mult)
	}

	// Verify that DecayWAFSlowDown successfully reduces multiplier back toward 1.0
	limiter.DecayWAFSlowDown(1.0)
	_, _, decayedMult := limiter.Rates()
	if decayedMult >= mult {
		t.Fatalf("expected multiplier to decay, got %f", decayedMult)
	}
}

