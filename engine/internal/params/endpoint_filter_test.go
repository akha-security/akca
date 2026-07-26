package params

import (
	"net/http"
	"testing"
)

func TestShouldDiscoverEndpointSkipsStatic(t *testing.T) {
	if ShouldDiscoverEndpoint("https://example.com/app.js", "GET") {
		t.Fatal("expected static js to skip")
	}
	if !ShouldDiscoverEndpoint("https://example.com/api/users", "GET") {
		t.Fatal("expected api endpoint to probe")
	}
}

func TestDifferentialWordlistCap(t *testing.T) {
	wl := DifferentialWordlist("https://example.com/search", 20)
	if len(wl) != 20 {
		t.Fatalf("expected cap 20, got %d", len(wl))
	}
	if wl[0] != "q" && wl[0] != "id" {
		t.Fatalf("expected prioritized names first, got %q", wl[0])
	}
}

func TestPassiveEnoughForSkip(t *testing.T) {
	passive := []DiscoveredParameter{
		{Priority: 95}, {Priority: 95}, {Priority: 95}, {Priority: 80},
		{Priority: 80}, {Priority: 80}, {Priority: 80}, {Priority: 80},
	}
	if !PassiveEnoughForSkip(passive, http.MethodGet) {
		t.Fatal("expected skip with 4 passive params on GET")
	}
	if PassiveEnoughForSkip(passive, http.MethodPost) {
		t.Fatal("POST endpoints should never skip active probing")
	}
}
