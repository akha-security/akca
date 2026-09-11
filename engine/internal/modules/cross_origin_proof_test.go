package modules

import (
	"context"
	"fmt"
	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/verification"
	"strings"
	"testing"
)

type proofBrowser struct {
	anonymous, private string
	fail               bool
	calls              int
}

func (b *proofBrowser) Render(context.Context, string) (string, error) { return "", nil }
func (b *proofBrowser) ReadCrossOrigin(_ context.Context, _, _, _ string, auth bool) (string, error) {
	b.calls++
	if b.fail {
		return "", fmt.Errorf("browser unavailable")
	}
	if auth {
		return b.private, nil
	}
	return b.anonymous, nil
}
func TestCrossOriginReadRequiresPrivateBrowserProof(t *testing.T) {
	for _, module := range []string{"jsonp_callback", "ws_cswsh"} {
		for _, scenario := range []string{"private", "public", "unavailable", "no-canary", "no-private-data"} {
			t.Run(module+"/"+scenario, func(t *testing.T) {
				c := &activeDynamicClient{handler: func(_, u string, h map[string]string) httpclient.ResponseRecord {
					return httpclient.ResponseRecord{StatusCode: 200, Body: "ordinary public data"}
				}}
				r := newActiveRunner(t, c)
				const canary = "private-proof-canary-98342"
				r.cfg.ContentProofPolicies = []config.ContentProofPolicy{{ID: "test", Module: module, URLContains: "/api", PrivateCanary: canary}}
				b := &proofBrowser{anonymous: "{}", private: canary}
				switch scenario {
				case "public":
					b.anonymous = canary
				case "unavailable":
					b.fail = true
				case "no-canary":
					r.cfg.ContentProofPolicies = nil
				case "no-private-data":
					b.private = "{}"
				}
				r.browser = b
				target := ScanTarget{EndpointURL: "https://example.com/api", Method: "GET", Parameter: "callback", Location: "query"}
				base := httpclient.RequestResponse{Request: httpclient.RequestRecord{Method: "GET", URL: target.EndpointURL}, Response: httpclient.ResponseRecord{StatusCode: 200, Body: "{}"}}
				probe := base
				probe.Response.Body = "cb({})"
				kind := "jsonp"
				if module == "ws_cswsh" {
					kind = "websocket"
					probe.Response.StatusCode = 101
					probe.Response.Body = ""
				}
				f := r.proveCrossOriginRead(context.Background(), module, target, kind, "cb", base, probe)
				if scenario != "private" {
					if f != nil {
						t.Fatal("unproven private access produced finding")
					}
					return
				}
				if f == nil {
					t.Fatal("private browser read suppressed")
				}
				if f.Evidence.Verification.ProofType != verification.ProofCrossOriginRead || b.calls != 3 {
					t.Fatalf("bad proof or calls: %v %d", f.Evidence.Verification.ProofType, b.calls)
				}
				raw := 0
				for _, o := range f.Evidence.Verification.Observations {
					if o.BrowserRead && strings.Contains(o.BrowserData, canary) {
						raw++
					}
				}
				if raw != 2 {
					t.Fatal("raw browser evidence was lost")
				}
			})
		}
	}
}
