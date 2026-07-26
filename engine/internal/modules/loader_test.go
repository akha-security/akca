package modules

import (
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/verification"
)

func TestParamsFromURL(t *testing.T) {
	names := paramsFromURL("http://example.com/search?q=test&page=1")
	if len(names) != 2 {
		t.Fatalf("expected 2 params, got %d", len(names))
	}
	if paramsFromURL("http://example.com/no-params") != nil {
		t.Fatal("expected nil for URL without query string")
	}
}

func TestFallbackTargetsSkipsEndpointsWithoutQueryParams(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/loader.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	scanID := "scan-loader"
	if err := db.EnsureScan(scanID); err != nil {
		t.Fatal(err)
	}
	for _, ep := range []struct {
		url    string
		method string
	}{
		{"http://example.com/static", "GET"},
		{"http://example.com/search?q=1", "GET"},
	} {
		if err := db.SaveDiscoveredEndpoint(scanID, map[string]interface{}{
			"url": ep.url, "method": ep.method, "source": "test", "confidence": 1.0,
		}); err != nil {
			t.Fatal(err)
		}
	}

	cfg := config.DefaultScanConfig()
	r := NewRunner(scanID, &httpclient.Client{}, scope.NewEngine(cfg), db, verification.NewEngine(nil, nil), nil, func(string, string, map[string]interface{}) error { return nil }, cfg)
	targets, err := r.fallbackTargetsFromEndpoints(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target from real query param only, got %d", len(targets))
	}
	if targets[0].Parameter != "q" {
		t.Fatalf("expected param q, got %q", targets[0].Parameter)
	}
}

func TestEndpointAwareLoaderKeepsParameterlessPassiveSurfaces(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/endpoint-aware-loader.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	scanID := "scan-endpoint-aware"
	if err := db.EnsureScan(scanID); err != nil {
		t.Fatal(err)
	}
	for _, rawURL := range []string{
		"http://example.com/search?q=1",
		"http://example.com/passive/headers",
	} {
		if err := db.SaveDiscoveredEndpoint(scanID, map[string]interface{}{
			"url": rawURL, "method": "GET", "source": "test", "confidence": 1.0,
		}); err != nil {
			t.Fatal(err)
		}
	}

	cfg := config.DefaultScanConfig()
	r := NewRunner(scanID, &httpclient.Client{}, scope.NewEngine(cfg), db,
		verification.NewEngine(nil, nil), nil,
		func(string, string, map[string]interface{}) error { return nil }, cfg)
	targets, err := r.LoadTargetsWithEndpointsFromDB(10)
	if err != nil {
		t.Fatal(err)
	}
	var foundPassive bool
	for _, target := range targets {
		if target.EndpointURL == "http://example.com/passive/headers" && target.Parameter == "" {
			foundPassive = true
		}
	}
	if !foundPassive {
		t.Fatalf("parameterless passive endpoint was omitted: %+v", targets)
	}
}
