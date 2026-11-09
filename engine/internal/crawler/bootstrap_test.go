package crawler

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
)

type slowEntryClient struct {
	mu   sync.Mutex
	urls []string
}

func (s *slowEntryClient) Do(ctx context.Context, method, rawURL string, _ []byte, _ map[string]string) (httpclient.RequestResponse, error) {
	s.mu.Lock()
	s.urls = append(s.urls, rawURL)
	s.mu.Unlock()
	body := "child content"
	if rawURL == "https://example.test/" {
		select {
		case <-time.After(40 * time.Millisecond):
		case <-ctx.Done():
			return httpclient.RequestResponse{}, ctx.Err()
		}
		body = `<a href="/child">child</a>`
	}
	return httpclient.RequestResponse{Request: httpclient.RequestRecord{Method: method, URL: rawURL}, Response: httpclient.ResponseRecord{StatusCode: 200, Body: body, Headers: map[string]string{"Content-Type": "text/html"}}}, nil
}

func TestSlowEntryDoesNotLetGuessedPathsConsumeCrawlBudget(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/bootstrap.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"example.test"}
	cfg.MaxPages = 2
	cfg.MaxConcurrency = 8
	client := &slowEntryClient{}
	c := New("bootstrap", cfg, client, scope.NewEngine(cfg), db, nil)
	_ = c.Crawl(context.Background(), []string{"https://example.test/"})
	if len(client.urls) != 2 || client.urls[0] != "https://example.test/" || client.urls[1] != "https://example.test/child" {
		t.Fatalf("speculative requests starved observed links: %v", client.urls)
	}
}
