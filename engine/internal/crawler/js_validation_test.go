package crawler

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
)

func TestJSValidationDoesNotRecrawlObservedPagesOrHTMLFallback(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/js-validation.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	const scanID = "js-validation"
	if err := db.SaveDiscoveredEndpoint(scanID, map[string]interface{}{
		"url": "https://api.example.test/known", "method": "GET", "source": "js_bundle",
		"request_template": map[string]interface{}{"response_status": 200},
	}); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"*.example.test"}
	client := &discoveryClient{responses: map[string]httpclient.ResponseRecord{
		"https://api.example.test/start": {StatusCode: 302, Headers: map[string]string{"Location": "/final"}},
		"https://api.example.test/final": {StatusCode: 200, Headers: map[string]string{"Content-Type": "text/html", "Link": "</noise>; rel=next"}, Body: `<a href="/loop">loop</a><script src="/app.js"></script>`},
	}, visited: map[string]bool{}}
	c := New(scanID, cfg, client, scope.NewEngine(cfg), db, nil)
	c.SetBrowser(&documentBrowser{status: 200})
	err = c.CrawlEndpointSeeds(context.Background(), []DiscoveredEndpoint{
		{URL: "https://api.example.test/known", Method: "GET", Source: SourceJSBundle, Confidence: .9},
		{URL: "https://api.example.test/start", Method: "GET", Source: SourceJSBundle, Confidence: .9},
		{URL: "https://api.example.test/save", Method: "POST", Source: SourceJSBundle, Confidence: .9,
			RequestTemplate: &RequestTemplate{Method: "POST", URL: "https://api.example.test/save", Body: `{"name":"keep"}`, ContentType: "application/json"}},
	}, Budget{})
	if err != nil {
		t.Fatal(err)
	}
	if len(client.visited) != 2 || !client.visited["https://api.example.test/start"] || !client.visited["https://api.example.test/final"] {
		t.Fatalf("JS validation expanded or repeated requests: %v", client.visited)
	}
	endpoints, err := db.ListDiscoveryEndpoints(scanID, 0)
	if err != nil {
		t.Fatal(err)
	}
	foundPOST := false
	for _, ep := range endpoints {
		if ep.Method == "POST" && ep.URL == "https://api.example.test/save" {
			foundPOST = ep.RequestTemplate.Body == `{"name":"keep"}` && ep.RequestTemplate.ContentType == "application/json"
		}
	}
	if !foundPOST {
		t.Fatal("POST template was lost during read-only validation")
	}
}

type failingJSClient struct{}

func (failingJSClient) Do(ctx context.Context, _, _ string, _ []byte, _ map[string]string) (httpclient.RequestResponse, error) {
	if _, ok := ctx.Deadline(); !ok {
		panic("JS API request has no deadline")
	}
	return httpclient.RequestResponse{}, errors.New("transport unavailable")
}

func TestJSValidationReportsTransportFailure(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/js-failure.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"example.test"}
	c := New("js-failure", cfg, failingJSClient{}, scope.NewEngine(cfg), db, nil)
	err = c.CrawlEndpointSeeds(context.Background(), []DiscoveredEndpoint{{URL: "https://example.test/api", Method: http.MethodGet, Source: SourceJSBundle, Confidence: .9}}, Budget{})
	if !errors.Is(err, ErrIncomplete) {
		t.Fatalf("failed validation was reported as successful: %v", err)
	}
}
