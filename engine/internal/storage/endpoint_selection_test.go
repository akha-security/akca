package storage

import "testing"

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
