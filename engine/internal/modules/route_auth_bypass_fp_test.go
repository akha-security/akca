package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/ratelimit"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/verification"
)

func TestRouteAuthBypassProxyResourceProof(t *testing.T) {
	const privateBody = `{"user_id":"customer-731","email":"owner@internal.test","balance":1731,"secret":"private-route-canary-731"}`
	const otherBody = `{"user_id":"customer-842","email":"other@internal.test","balance":2842,"secret":"different-private-value"}`
	const publicBody = `<html><body>Explore our dashboard, account and billing features. Get started with our public product overview.</body></html>`
	for _, tc := range []struct {
		name            string
		owner           bool
		canary          bool
		ignoreHeader    bool
		anyHeaderValue  bool
		missingControl  bool
		missingRoot     bool
		replayChanges   bool
		transientDenial bool
		publicReference bool
		want            int
	}{
		{name: "dashboard keyword on public page"},
		{name: "private-looking JSON without authenticated reference", anyHeaderValue: true},
		{name: "ignored header with changing public homepage", owner: true, ignoreHeader: true},
		{name: "all proxy header values expose same page", owner: true, anyHeaderValue: true},
		{name: "nonexistent route control returns server error", owner: true, missingControl: true},
		{name: "public root control unavailable", owner: true, missingRoot: true},
		{name: "different resource on replay", owner: true, replayChanges: true},
		{name: "private canary disappears on replay", canary: true, replayChanges: true},
		{name: "canonical denial is transient", owner: true, transientDenial: true},
		{name: "authenticated reference is only public marketing", owner: true, publicReference: true},
		{name: "confirmed proxy bypass with authenticated private resource", owner: true, want: 1},
		{name: "confirmed proxy bypass with configured private canary", canary: true, want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var positiveRequests, anonymousCanonical, homepageRequests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if req.URL.Path == "/dashboard/account" {
					if tc.owner && req.Header.Get("Authorization") != "" {
						if tc.publicReference {
							_, _ = w.Write([]byte(publicBody))
						} else {
							_, _ = w.Write([]byte(privateBody))
						}
						return
					}
					if anonymousCanonical.Add(1) > 1 && tc.transientDenial {
						_, _ = w.Write([]byte(privateBody))
						return
					}
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write([]byte(`{"error":"access denied"}`))
					return
				}
				if strings.Contains(req.URL.Path, "__akca_nonexistent_route_") {
					if tc.missingControl {
						w.WriteHeader(http.StatusServiceUnavailable)
					} else {
						w.WriteHeader(http.StatusNotFound)
					}
					return
				}
				if req.URL.Path == "/" {
					header := req.Header.Get("X-Original-URL")
					if header != "" && !tc.ignoreHeader {
						if header != "/dashboard/account" && !tc.anyHeaderValue {
							w.WriteHeader(http.StatusNotFound)
							return
						}
						body := privateBody
						if header == "/dashboard/account" && positiveRequests.Add(1) > 1 && tc.replayChanges {
							body = otherBody
						}
						_, _ = w.Write([]byte(body))
						return
					}
					if tc.missingRoot {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					// Public pages need not be byte-identical between requests.
					n := homepageRequests.Add(1)
					_, _ = w.Write([]byte(publicBody + strings.Repeat(" ", int(n))))
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			defer server.Close()
			cfg := config.DefaultScanConfig()
			cfg.Targets = []string{server.URL}
			cfg.IncludeDomains = []string{"127.0.0.1"}
			cfg.GlobalRateLimit, cfg.PerHostRateLimit = 10000, 10000
			if tc.owner {
				cfg.CustomHeaders = map[string]string{"Authorization": "Bearer test-owner"}
			}
			if tc.canary {
				cfg.ContentProofPolicies = []config.ContentProofPolicy{{Module: "route_auth_bypass", URLContains: "/dashboard/account", PrivateCanary: "private-route-canary-731"}}
			}
			scopeEngine := scope.NewEngine(cfg)
			client, err := httpclient.New(cfg, scopeEngine, ratelimit.New(cfg.GlobalRateLimit, cfg.PerHostRateLimit))
			if err != nil {
				t.Fatal(err)
			}
			runner := NewRunner("route-proof-test", client, scopeEngine, nil, verification.NewEngine(nil, nil), nil,
				func(kind, message string, _ map[string]interface{}) error { t.Log(kind, message); return nil }, cfg)
			findings := runner.runRouteAuthBypass(context.Background(), ScanTarget{EndpointURL: server.URL + "/dashboard/account", Method: "GET"})
			if len(findings) != tc.want {
				t.Fatalf("findings=%d, want=%d", len(findings), tc.want)
			}
			if tc.want == 0 {
				return
			}
			if !strings.Contains(findings[0].Title, "x_original_url_header") {
				t.Fatalf("unexpected technique: %s", findings[0].Title)
			}
			if tc.owner && (findings[0].Evidence.ResourceReference == nil || findings[0].Evidence.ResourceReference.Body != privateBody) {
				t.Fatal("authenticated private-resource reference is missing from report evidence")
			}
			var realMissingControl, headerControl bool
			for _, step := range findings[0].Evidence.ReplayPlan {
				if step.ExpectedNormalizedHash == "" {
					t.Fatal("proof request is missing its expected response hash")
				}
				if step.Role != verification.RoleNegativeControl {
					continue
				}
				realMissingControl = realMissingControl || strings.Contains(step.Request.URL, "__akca_nonexistent_route_")
				headerControl = headerControl || strings.Contains(step.Request.Headers["X-Original-Url"], "__akca_nonexistent_route_")
			}
			if !realMissingControl || !headerControl {
				t.Fatal("proof must retain actual nonexistent-route and proxy-header control requests")
			}
		})
	}
}

func TestRouteAuthBypassRejectsMinifiedJSBeforeRequests(t *testing.T) {
	calls := 0
	client := auditDoer(func(_ context.Context, method, raw string, _ []byte, headers map[string]string) (httpclient.RequestResponse, error) {
		calls++
		return httpclient.RequestResponse{}, nil
	})
	runner := newActiveRunner(t, client)
	findings := runner.runRouteAuthBypass(context.Background(), ScanTarget{EndpointURL: "https://example.com/dashboard/%26%26%28j=E,E=null%29,E%26%26I.send%28E%29,j%26%26I.end%28j%29", Method: "GET"})
	if len(findings) != 0 || calls != 0 {
		t.Fatalf("minified JS was scanned as a route: findings=%d requests=%d", len(findings), calls)
	}
}
