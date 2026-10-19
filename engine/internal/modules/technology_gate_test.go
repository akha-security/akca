package modules

import (
	"context"
	"errors"
	"testing"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/payloadgen"
)

func TestBackendModulesSkipKnownUnrelatedStack(t *testing.T) {
	target := ScanTarget{
		EndpointURL: "https://example.com/static/app.js",
		Parameter:   "value",
		Payloads: payloadgen.GenerationResult{Tech: payloadgen.TechHints{
			BackendLanguage: "PHP",
			Framework:       "Laravel",
			ServerCDN:       "cloudflare",
			JSFramework:     "React",
		}},
	}

	checks := []struct {
		name string
		gate func(ScanTarget) (bool, string)
	}{
		{"nextjs", nextJSReady},
		{"spring", springReady},
		{"server-side-js", serverSideJSReady},
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			if ok, _ := tc.gate(target); ok {
				t.Fatalf("%s gate accepted known unrelated stack: %+v", tc.name, target.Payloads.Tech)
			}
		})
	}
}

func TestServerModulesDoNotTreatCDNAsOriginFingerprint(t *testing.T) {
	target := ScanTarget{EndpointURL: "https://example.com/static/app.js", Payloads: payloadgen.GenerationResult{
		Tech: payloadgen.TechHints{ServerCDN: "cloudflare"},
	}}
	if ok, reason := nginxReady(target); !ok {
		t.Fatalf("CDN-only evidence should leave the origin server unknown for nginx probing: %s", reason)
	}
	if ok, reason := iisReady(target); !ok {
		t.Fatalf("CDN-only evidence should leave the origin server unknown for IIS probing: %s", reason)
	}
}

func TestServerModulesRejectKnownUnrelatedOrigin(t *testing.T) {
	target := ScanTarget{EndpointURL: "https://example.com/static/app.js", Payloads: payloadgen.GenerationResult{
		Tech: payloadgen.TechHints{ServerCDN: "Apache/2.4"},
	}}
	if ok, _ := nginxReady(target); ok {
		t.Fatal("nginx gate accepted a known Apache origin")
	}
	if ok, _ := iisReady(target); ok {
		t.Fatal("IIS gate accepted a known Apache origin")
	}
}

func TestPlatformModulesAcceptMatchingFingerprint(t *testing.T) {
	tests := []struct {
		name   string
		target ScanTarget
		gate   func(ScanTarget) (bool, string)
	}{
		{
			name: "nginx",
			target: ScanTarget{EndpointURL: "https://example.com/assets/app.js",
				Payloads: payloadgen.GenerationResult{Tech: payloadgen.TechHints{ServerCDN: "nginx"}}},
			gate: nginxReady,
		},
		{
			name: "iis-aspnet",
			target: ScanTarget{EndpointURL: "https://example.com/login.aspx",
				Payloads: payloadgen.GenerationResult{Tech: payloadgen.TechHints{BackendLanguage: "ASP.NET"}}},
			gate: iisReady,
		},
		{
			name: "nextjs",
			target: ScanTarget{EndpointURL: "https://example.com/dashboard",
				Payloads: payloadgen.GenerationResult{Tech: payloadgen.TechHints{JSFramework: "Next.js"}}},
			gate: nextJSReady,
		},
		{
			name: "spring",
			target: ScanTarget{EndpointURL: "https://example.com/",
				Payloads: payloadgen.GenerationResult{Tech: payloadgen.TechHints{Framework: "Spring"}}},
			gate: springReady,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if ok, reason := tc.gate(tc.target); !ok {
				t.Fatalf("matching technology was rejected: %s", reason)
			}
		})
	}
}

func TestUnknownFingerprintUsesBoundedCapabilityPath(t *testing.T) {
	target := ScanTarget{EndpointURL: "https://example.com/static/app.js", Parameter: "value"}
	if ok, reason := nginxReady(target); !ok {
		t.Fatalf("unknown stack should permit bounded nginx capability probe: %s", reason)
	}
	if ok, reason := iisReady(target); !ok {
		t.Fatalf("unknown stack should permit bounded IIS capability probe: %s", reason)
	}
}

func TestServerSideJSUnknownStackRequiresExecutionSemantics(t *testing.T) {
	generic := ScanTarget{EndpointURL: "https://example.com/profile?id=1", Parameter: "id"}
	if ok, _ := serverSideJSReady(generic); ok {
		t.Fatal("generic parameter on an unknown stack should not receive SSJS RCE/timing probes")
	}
	code := ScanTarget{EndpointURL: "https://example.com/eval?code=1", Parameter: "code"}
	if ok, reason := serverSideJSReady(code); !ok {
		t.Fatalf("code-evaluation surface on an unknown stack was rejected: %s", reason)
	}
	nodeGeneric := generic
	nodeGeneric.Payloads.Tech.BackendLanguage = "Node.js"
	if ok, reason := serverSideJSReady(nodeGeneric); !ok {
		t.Fatalf("known Node.js target was rejected: %s", reason)
	}
}

type hardLimitCountingClient struct{ calls int }

func (c *hardLimitCountingClient) Do(context.Context, string, string, []byte, map[string]string) (httpclient.RequestResponse, error) {
	c.calls++
	return httpclient.RequestResponse{Response: httpclient.ResponseRecord{StatusCode: 404}}, nil
}

func TestLimitedModuleDoCapsUnlimitedFullScan(t *testing.T) {
	client := &hardLimitCountingClient{}
	runner := &Runner{client: client, hardProbeUsage: map[string]int{}}
	for i := 0; i < 35; i++ {
		_, err := runner.limitedModuleDo(context.Background(), "nginx_alias", 30, "GET", "https://example.com/static", nil, nil)
		if i < 30 && err != nil {
			t.Fatalf("request %d rejected before limit: %v", i+1, err)
		}
		if i >= 30 && !errors.Is(err, errModuleHardProbeLimit) {
			t.Fatalf("request %d did not return hard-limit error: %v", i+1, err)
		}
	}
	if client.calls != 30 {
		t.Fatalf("network calls=%d, want exactly 30", client.calls)
	}
}

func TestCachedBaselineConsumesHardLimitOnlyOnNetworkUse(t *testing.T) {
	client := &hardLimitCountingClient{}
	runner := newActiveRunner(t, client)
	target := ScanTarget{EndpointURL: "https://example.com/static/app.js", Method: "GET"}

	if _, err := runner.cachedEmptyProbeWithHardLimit(context.Background(), "nginx_alias", 1, target); err != nil {
		t.Fatalf("initial baseline failed: %v", err)
	}
	if _, err := runner.cachedEmptyProbeWithHardLimit(context.Background(), "nginx_alias", 1, target); err != nil {
		t.Fatalf("cached baseline was incorrectly rejected by hard limit: %v", err)
	}
	if client.calls != 1 {
		t.Fatalf("baseline network calls=%d, want 1", client.calls)
	}
	if _, err := runner.limitedModuleDo(context.Background(), "nginx_alias", 1, "GET", target.EndpointURL, nil, nil); !errors.Is(err, errModuleHardProbeLimit) {
		t.Fatalf("network quota was not consumed exactly once: %v", err)
	}
}

func TestRunModuleDoesNotScheduleKnownUnrelatedPlatform(t *testing.T) {
	client := &hardLimitCountingClient{}
	runner := newActiveRunner(t, client)
	target := ScanTarget{
		EndpointURL: "https://example.com/static/app.js",
		Method:      "GET",
		Payloads: payloadgen.GenerationResult{Tech: payloadgen.TechHints{
			BackendLanguage: "PHP",
			ServerCDN:       "Apache/2.4",
			JSFramework:     "React",
		}},
	}
	findings, err := runner.RunModule(context.Background(), "nginx_alias", []ScanTarget{target})
	if err != nil {
		t.Fatalf("RunModule returned error: %v", err)
	}
	if len(findings) != 0 || client.calls != 0 {
		t.Fatalf("known non-nginx target was probed: findings=%d calls=%d", len(findings), client.calls)
	}
}

func TestMergeTechHintsCarriesRoutingSignals(t *testing.T) {
	merged := mergeTechHints(payloadgen.TechHints{Database: "PostgreSQL"}, payloadgen.TechHints{
		ServerCDN:   "Microsoft-IIS/10.0",
		JSFramework: "Next.js",
		Hints:       []string{"server:iis", "js:Next.js"},
	})
	if merged.ServerCDN != "Microsoft-IIS/10.0" || merged.JSFramework != "Next.js" || len(merged.Hints) != 2 {
		t.Fatalf("routing technology signals were lost: %+v", merged)
	}
	if merged.Database != "PostgreSQL" {
		t.Fatalf("existing technology hints were overwritten: %+v", merged)
	}
}
