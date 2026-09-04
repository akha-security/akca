package modules

import (
	"fmt"
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

func TestEndpointAwareLoaderHonorsHardLimit(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/loader-limit.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	scanID := "scan-loader-limit"
	if err := db.EnsureScan(scanID); err != nil {
		t.Fatal(err)
	}
	for _, rawURL := range []string{
		"http://example.com/a?q=1", "http://example.com/b?p=1", "http://example.com/passive",
	} {
		if err := db.SaveDiscoveredEndpoint(scanID, map[string]interface{}{
			"url": rawURL, "method": "GET", "source": "test", "confidence": 1.0,
		}); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.DefaultScanConfig()
	r := NewRunner(scanID, &httpclient.Client{}, scope.NewEngine(cfg), db,
		verification.NewEngine(nil, nil), nil, func(string, string, map[string]interface{}) error { return nil }, cfg)
	targets, err := r.LoadTargetsWithEndpointsFromDB(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) > 1 {
		t.Fatalf("target hard limit exceeded: got %d", len(targets))
	}
	if len(targets) == 1 && targets[0].Parameter != "" {
		t.Fatalf("single-slot balanced limit must reserve an endpoint target: %+v", targets[0])
	}
}

func TestEndpointAwareLoaderBalancesParameterAndEndpointTargets(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/loader-balance.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	scanID := "scan-loader-balance"
	if err := db.EnsureScan(scanID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		rawURL := fmt.Sprintf("http://example.com/route-%d?q=%d", i, i)
		if err := db.SaveDiscoveredEndpoint(scanID, map[string]interface{}{
			"url": rawURL, "method": "GET", "source": "test", "confidence": 1.0,
		}); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.DefaultScanConfig()
	r := NewRunner(scanID, &httpclient.Client{}, scope.NewEngine(cfg), db,
		verification.NewEngine(nil, nil), nil, func(string, string, map[string]interface{}) error { return nil }, cfg)
	targets, err := r.LoadTargetsWithEndpointsFromDB(4)
	if err != nil {
		t.Fatal(err)
	}
	parameters, endpoints := 0, 0
	for _, target := range targets {
		if target.Parameter == "" {
			endpoints++
		} else {
			parameters++
		}
	}
	if len(targets) != 4 || endpoints < 1 || parameters < 1 {
		t.Fatalf("unbalanced targets: total=%d parameters=%d endpoints=%d", len(targets), parameters, endpoints)
	}
}

func TestCapTargetsWithEndpointCoveragePreventsRouteStarvation(t *testing.T) {
	planned := []ScanTarget{
		{EndpointURL: "http://example.com/first", Method: "GET", Parameter: "a"},
		{EndpointURL: "http://example.com/first", Method: "GET", Parameter: "b"},
		{EndpointURL: "http://example.com/first", Method: "GET", Parameter: "c"},
		{EndpointURL: "http://example.com/second", Method: "GET", Parameter: "q"},
		{EndpointURL: "http://example.com/third", Method: "POST", Parameter: "template"},
	}

	got := capTargetsWithEndpointCoverage(planned, 3)
	if len(got) != 3 {
		t.Fatalf("target limit not honored: got %d", len(got))
	}
	covered := map[string]bool{}
	for _, target := range got {
		covered[targetSurfaceKey(target.EndpointURL, target.Method)] = true
	}
	for _, endpoint := range []string{
		"http://example.com/first::GET",
		"http://example.com/second::GET",
		"http://example.com/third::POST",
	} {
		if !covered[endpoint] {
			t.Fatalf("endpoint %s was starved by another route's parameters: %+v", endpoint, got)
		}
	}
}

func TestCapTargetsWithEndpointCoverageFillsRemainingSlotsByPriorityOrder(t *testing.T) {
	planned := []ScanTarget{
		{EndpointURL: "http://example.com/first", Method: "GET", Parameter: "highest"},
		{EndpointURL: "http://example.com/first", Method: "GET", Parameter: "next"},
		{EndpointURL: "http://example.com/second", Method: "GET", Parameter: "only"},
		{EndpointURL: "http://example.com/first", Method: "GET", Parameter: "last"},
	}

	got := capTargetsWithEndpointCoverage(planned, 3)
	if len(got) != 3 || got[0].Parameter != "highest" || got[1].Parameter != "only" || got[2].Parameter != "next" {
		t.Fatalf("unexpected coverage/priority selection: %+v", got)
	}
}

func TestOrderTargetsByEndpointCoverageInterleavesAllRounds(t *testing.T) {
	planned := []ScanTarget{
		{EndpointURL: "http://example.com/first", Method: "GET", Parameter: "a1"},
		{EndpointURL: "http://example.com/first", Method: "GET", Parameter: "a2"},
		{EndpointURL: "http://example.com/first", Method: "GET", Parameter: "a3"},
		{EndpointURL: "http://example.com/second", Method: "GET", Parameter: "b1"},
		{EndpointURL: "http://example.com/second", Method: "GET", Parameter: "b2"},
	}

	got := orderTargetsByEndpointCoverage(planned)
	want := []string{"a1", "b1", "a2", "b2", "a3"}
	if len(got) != len(want) {
		t.Fatalf("ordered target count = %d, want %d", len(got), len(want))
	}
	for index, parameter := range want {
		if got[index].Parameter != parameter {
			t.Fatalf("ordered[%d] = %q, want %q; all=%+v", index, got[index].Parameter, parameter, got)
		}
	}
}
