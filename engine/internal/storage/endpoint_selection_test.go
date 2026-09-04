package storage

import (
	"net/http"
	"testing"
)

func TestSelectEndpointsBalanced(t *testing.T) {
	all := []DiscoveryEndpoint{
		{ID: 1, URL: "https://example.com/a"},
		{ID: 2, URL: "https://example.com/b"},
		{ID: 3, URL: "https://sub.example.com/x"},
		{ID: 4, URL: "https://sub.example.com/y"},
		{ID: 5, URL: "https://api.example.com/z"},
	}
	got := selectEndpointsBalanced(all, 3)
	if len(got) != 3 {
		t.Fatalf("expected 3 endpoints, got %d", len(got))
	}
	hosts := map[string]int{}
	for _, ep := range got {
		hosts[endpointHost(ep.URL)]++
	}
	if len(hosts) < 2 {
		t.Fatalf("expected host diversity, got %+v", hosts)
	}
}

func TestEndpointProbeScorePrefersAPI(t *testing.T) {
	api := DiscoveryEndpoint{URL: "https://example.com/api/users?id=1", Method: "GET"}
	static := DiscoveryEndpoint{URL: "https://example.com/static/app.js", Method: "GET"}
	if endpointProbeScore(api) <= endpointProbeScore(static) {
		t.Fatalf("api=%d static=%d", endpointProbeScore(api), endpointProbeScore(static))
	}
}

func TestListDiscoveryEndpointsPrioritizesWriteMethodsBeforeQueryGET(t *testing.T) {
	db, err := Open(t.TempDir() + "/endpoint-order.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureScan("scan-order"); err != nil {
		t.Fatal(err)
	}
	for _, ep := range []map[string]interface{}{
		{
			"url": "https://example.com/search?q=one", "method": http.MethodGet,
			"normalized_url": "https://example.com/search?q=one", "source": "test",
		},
		{
			"url": "https://example.com/api/orders", "method": http.MethodPost,
			"normalized_url": "https://example.com/api/orders", "source": "test",
			"request_template": map[string]interface{}{
				"method": http.MethodPost, "url": "https://example.com/api/orders",
				"body": `{"item_id":1}`, "content_type": "application/json",
			},
		},
	} {
		if err := db.SaveDiscoveredEndpoint("scan-order", ep); err != nil {
			t.Fatal(err)
		}
	}
	endpoints, err := db.ListDiscoveryEndpoints("scan-order", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(endpoints) != 2 {
		t.Fatalf("endpoints=%d want 2", len(endpoints))
	}
	if endpoints[0].Method != http.MethodPost || endpoints[0].URL != "https://example.com/api/orders" {
		t.Fatalf("POST API endpoint should be first, got %+v", endpoints)
	}
}
