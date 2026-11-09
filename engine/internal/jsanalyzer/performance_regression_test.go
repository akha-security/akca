package jsanalyzer

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/queue"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
)

type concurrentScriptClient struct {
	mu           sync.Mutex
	active, peak int
	requests     map[string]int
	started      chan string
	release      chan struct{}
}

func (c *concurrentScriptClient) Do(ctx context.Context, method, rawURL string, _ []byte, _ map[string]string) (httpclient.RequestResponse, error) {
	c.mu.Lock()
	c.active++
	c.peak = max(c.peak, c.active)
	c.requests[rawURL]++
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.active--; c.mu.Unlock() }()
	c.started <- rawURL
	select {
	case <-c.release:
	case <-ctx.Done():
		return httpclient.RequestResponse{}, ctx.Err()
	}
	body := `fetch("/api/other")`
	if strings.HasSuffix(rawURL, "/app.js") {
		body = `import("/chunks/123.js"); import("/chunks/456.js"); fetch("/api/save", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:"keep"})})`
	}
	return httpclient.RequestResponse{
		Request:  httpclient.RequestRecord{URL: rawURL, Method: method},
		Response: httpclient.ResponseRecord{StatusCode: 200, Headers: map[string]string{"Content-Type": "application/javascript"}, Body: body},
	}, nil
}

func TestJSDownloadsAreConcurrentBoundedAndPreserveLazyChunksAndPOST(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/parallel-js.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"example.test"}
	client := &concurrentScriptClient{requests: map[string]int{}, started: make(chan string, 8), release: make(chan struct{})}
	a := New("parallel-js", client, scope.NewEngine(cfg), db, queue.NewRequestQueue(), nil)
	a.SetConcurrency(2)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- a.Run(ctx, []string{"https://example.test/app.js", "https://example.test/other.js", "https://example.test/app.js#duplicate"})
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-client.started:
		case <-ctx.Done():
			close(client.release)
			<-done
			t.Fatal("script downloads were serialized")
		}
	}
	close(client.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.peak != 2 || len(client.requests) != 4 || client.requests["https://example.test/app.js"] != 1 {
		t.Fatalf("concurrency/dedup/dependency traversal failed: peak=%d requests=%v", client.peak, client.requests)
	}
	for _, chunk := range []string{"123.js", "456.js"} {
		if client.requests["https://example.test/chunks/"+chunk] != 1 {
			t.Fatalf("chunk %s was not analyzed", chunk)
		}
	}
	endpoints, err := db.ListJSDiscoveredAPIEndpoints("parallel-js", 0)
	if err != nil {
		t.Fatal(err)
	}
	var postFound bool
	for _, ep := range endpoints {
		if strings.HasSuffix(ep.URL, "/api/save") {
			if ep.Method != "POST" || !strings.Contains(ep.Body, "name") || ep.ContentType != "application/json" {
				t.Fatalf("HTTP method/body was guessed incorrectly: %+v", ep)
			}
			postFound = true
		}
	}
	if !postFound {
		t.Fatal("POST API endpoint was lost")
	}
}

func TestJSCallExtractionDoesNotInventGETForPOSTAndKeepsBothRealMethods(t *testing.T) {
	a := &Analyzer{}
	result := a.AnalyzeContent("https://example.test/app.js", `
fetch("/api/save", {method:"POST", body:"name=x"});
fetch("/api/shared", {method:"POST"}); fetch("/api/shared");
window.postMessage("hello"); fetch("/api/read");
`)
	methods := map[string]map[string]bool{}
	for _, ep := range result.Endpoints {
		if methods[ep.URL] == nil {
			methods[ep.URL] = map[string]bool{}
		}
		methods[ep.URL][ep.Method] = true
	}
	if len(methods["https://example.test/api/save"]) != 1 || !methods["https://example.test/api/save"]["POST"] {
		t.Fatalf("POST produced a synthetic GET: %+v", methods)
	}
	if len(methods["https://example.test/api/shared"]) != 2 || !methods["https://example.test/api/read"]["GET"] {
		t.Fatalf("call-specific HTTP methods were lost: %+v", methods)
	}
}

func TestNormalizeJSTemplatePreservesOriginAndChunkIdentity(t *testing.T) {
	if got := NormalizeTemplate("https://127.0.0.1/users/123"); got != "https://127.0.0.1/users/:id" {
		t.Fatalf("origin corrupted: %s", got)
	}
	eps := DeduplicateSemantic([]ExtractedEndpoint{{URL: "/chunks/123.js", Method: http.MethodGet}, {URL: "/chunks/456.js", Method: http.MethodGet}})
	if len(eps) != 2 {
		t.Fatalf("different chunks collapsed: %+v", eps)
	}
}
