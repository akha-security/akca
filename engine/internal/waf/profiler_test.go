package waf

import (
	"testing"

	"github.com/akha-security/akca/engine/internal/models"
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
