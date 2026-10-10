package modules

import (
	"context"
	"testing"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

func TestComponentFingerprintsReachCuratedCatalogIdentities(t *testing.T) {
	cases := []struct {
		body, product, version string
	}{
		{"Apache/2.4.67", "http_server", "2.4.67"},
		{"next.js/15.1.8", "nextjs", "15.1.8"},
		{"react-server-dom-webpack@19.1.1", "react-server-dom", "19.1.1"},
		{`<script src="/vendor/jquery@3.6.1/dist/jquery.min.js"></script>`, "jquery", "3.6.1"},
		{`<link href="/vendor/bootstrap@5.3.0/dist/css/bootstrap.min.css">`, "bootstrap", "5.3.0"},
		{`<script src="/website-builder/cdn/6.17.0/assets/live.js"></script>`, "site_creator", "6.17.0"},
	}
	for _, tc := range cases {
		components := detectComponents(nil, tc.body)
		found := false
		for _, component := range components {
			if component.Product == tc.product && component.Version == tc.version {
				found = true
			}
		}
		if !found {
			t.Fatalf("%q did not produce %s %s: %+v", tc.body, tc.product, tc.version, components)
		}
	}
}

func TestComponentModulesAnalyzeEachObservedContentURLWithoutNewTraffic(t *testing.T) {
	runner := groupDRunner(t, &groupDClient{})
	targets := []ScanTarget{
		{
			EndpointURL: "https://example.com/one", Method: "GET",
			ObservedResponse: &httpclient.RequestResponse{
				Request:  httpclient.RequestRecord{Method: "GET", URL: "https://example.com/one"},
				Response: httpclient.ResponseRecord{StatusCode: 200, Body: `jquery@3.6.1/jquery.min.js`},
			},
		},
		{
			EndpointURL: "https://example.com/two", Method: "GET",
			ObservedResponse: &httpclient.RequestResponse{
				Request:  httpclient.RequestRecord{Method: "GET", URL: "https://example.com/two"},
				Response: httpclient.ResponseRecord{StatusCode: 200, Body: `bootstrap@5.3.0/bootstrap.min.css`},
			},
		},
	}

	for _, module := range []string{"vulnerable_components", "known_cve"} {
		for _, target := range targets {
			state := &targetRun{}
			ctx := withTargetRun(context.Background(), state)
			switch module {
			case "vulnerable_components":
				runner.runVulnerableComponents(ctx, target)
			case "known_cve":
				runner.runKnownCVE(ctx, target)
			}
			if state.requests.Load() != 0 || state.responses.Load() != 1 || !state.evidence.Load() {
				t.Fatalf("%s did not consume observed response for %s: requests=%d responses=%d evidence=%v",
					module, target.EndpointURL, state.requests.Load(), state.responses.Load(), state.evidence.Load())
			}
		}
		if budgetWorkKey(module, targets[0]) == budgetWorkKey(module, targets[1]) {
			t.Fatalf("%s collapsed distinct content URLs into one work item", module)
		}
	}

	if runner.budgetEligible("known_cve", ScanTarget{EndpointURL: "https://example.com/unseen", Method: "GET"}) {
		t.Fatal("unobserved URL must not inflate passive CVE coverage")
	}
}
