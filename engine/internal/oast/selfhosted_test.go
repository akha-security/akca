package oast

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSelfHostedHTTPCallbackPreservesRawRequestMetadata(t *testing.T) {
	provider := NewSelfHostedProvider(SelfHostedConfig{
		Domain: "127.0.0.1", HTTPAddr: "127.0.0.1:0",
	})
	if err := provider.Start(); err != nil {
		t.Fatal(err)
	}
	defer provider.Stop()
	generated, err := provider.GenerateURL("ssrf-header")
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodPost, generated.URL+"?token=query-secret",
		strings.NewReader(`{"api_key":"body-secret"}`))
	request.Header.Set("Authorization", "Bearer secret-value")
	request.Header.Set("X-API-Key", "header-secret")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("unexpected callback response: %d", response.StatusCode)
	}
	var interactions []Interaction
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		interactions, _ = provider.Poll()
		if len(interactions) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(interactions) != 1 || interactions[0].Protocol != "http" {
		t.Fatalf("expected HTTP interaction, got %+v", interactions)
	}
	if !strings.Contains(interactions[0].UniqueID, generated.CorrelationToken) {
		t.Fatal("callback did not retain the exact correlation token")
	}
	if !strings.Contains(interactions[0].RawRequest, "secret-value") ||
		!strings.Contains(interactions[0].RawRequest, "header-secret") ||
		!strings.Contains(interactions[0].RawRequest, "query-secret") ||
		!strings.Contains(interactions[0].RawRequest, "body-secret") {
		t.Fatal("callback authorization metadata was not preserved")
	}
}

func TestInteractionStrengthRanksHTTPAboveDNS(t *testing.T) {
	if InteractionStrength("http") <= InteractionStrength("dns") {
		t.Fatal("HTTP callback must be stronger evidence than DNS-only")
	}
}
