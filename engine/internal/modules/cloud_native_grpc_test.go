package modules

import (
	"context"
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

func TestCloudNativeExposure(t *testing.T) {
	c := &activeTestClient{
		responses: map[string]httpclient.ResponseRecord{
			"GET https://example.com/": {
				StatusCode: 200, Body: "<html>Home</html>", Headers: map[string]string{"Content-Type": "text/html"},
			},
			"GET https://example.com/v1.24/containers/json": {
				StatusCode: 200,
				Body:       `[{"Id":"c1a2b3","Image":"nginx:latest","Command":"nginx -g 'daemon off;'","Created":1700000000}]`,
				Headers:    map[string]string{"Content-Type": "application/json"},
			},
			"GET https://example.com/v1/sys/health": {
				StatusCode: 200,
				Body:       `{"initialized":true,"sealed":false,"standby":false,"server_time_utc":1700000000,"version":"1.15.0"}`,
				Headers:    map[string]string{"Content-Type": "application/json"},
			},
		},
	}

	r := newActiveRunner(t, c)
	target := ScanTarget{EndpointURL: "https://example.com/", Method: "GET"}
	findings := r.runCloudNativeExposure(context.Background(), target)

	if len(findings) < 2 {
		t.Fatalf("expected at least 2 cloud native findings (Docker + Vault), got %d", len(findings))
	}

	hasDocker := false
	hasVault := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Docker") {
			hasDocker = true
		}
		if strings.Contains(f.Title, "Vault") {
			hasVault = true
		}
	}

	if !hasDocker {
		t.Errorf("expected Docker finding, got: %+v", findings)
	}
	if !hasVault {
		t.Errorf("expected Vault finding, got: %+v", findings)
	}
}

func TestCloudNativeKubernetesPodListRequiresHTTP200(t *testing.T) {
	var podListCheck func(int, string) bool
	for _, probe := range cloudNativeProbes {
		if probe.signal == "k8s_api_pods_exposed" {
			podListCheck = probe.check
			break
		}
	}
	if podListCheck == nil {
		t.Fatal("k8s pod list probe not found")
	}
	body := `{"kind":"PodList","items":[{"metadata":{"name":"pod-a"}}]}`
	if podListCheck(500, body) {
		t.Fatal("Kubernetes PodList marker without HTTP 200 must not confirm exposure")
	}
	if !podListCheck(200, body) {
		t.Fatal("Kubernetes PodList marker with HTTP 200 should confirm exposure")
	}
}

func TestGRPCScan(t *testing.T) {
	c := &activeDynamicClient{
		handler: func(method, rawURL string, headers map[string]string) httpclient.ResponseRecord {
			if strings.Contains(rawURL, "ServerReflectionInfo") {
				return httpclient.ResponseRecord{
					StatusCode: 200,
					Headers: map[string]string{
						"Content-Type": "application/grpc",
						"grpc-status":  "0",
					},
					Body: "\x00\x00\x00\x00\x15grpc.reflection.v1alpha",
				}
			}
			return httpclient.ResponseRecord{StatusCode: 200, Body: "Normal Page"}
		},
	}

	r := newActiveRunner(t, c)
	target := ScanTarget{EndpointURL: "https://example.com/", Method: "GET"}
	findings := r.runGRPCScan(context.Background(), target)

	if len(findings) == 0 {
		t.Fatal("expected gRPC reflection finding")
	}
	if !strings.Contains(findings[0].Title, "gRPC Server Reflection") {
		t.Fatalf("unexpected title: %s", findings[0].Title)
	}
}
