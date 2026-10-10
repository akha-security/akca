package params

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/scope"
)

type performanceDoer func(context.Context, string, string, []byte, map[string]string) (httpclient.RequestResponse, error)

func (f performanceDoer) Do(ctx context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	return f(ctx, method, rawURL, body, headers)
}

func TestShouldAttemptJSONPivot(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		contentType string
		want        bool
	}{
		{"json response", "https://example.test/search", "application/json", true},
		{"api path", "https://example.test/api/users", "text/plain", true},
		{"graphql path", "https://example.test/graphql", "text/html", true},
		{"ordinary html", "https://example.test/products", "text/html; charset=utf-8", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httpclient.RequestResponse{Response: httpclient.ResponseRecord{
				StatusCode: http.StatusOK,
				Headers:    map[string]string{"Content-Type": tt.contentType},
			}}
			if got := shouldAttemptJSONPivot(tt.url, rr); got != tt.want {
				t.Fatalf("shouldAttemptJSONPivot()=%v, want %v", got, tt.want)
			}
		})
	}
}

func TestQueryPrefilterCollapsesIgnoredCandidates(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"example.test"}
	var requests atomic.Int32
	d := NewDiscoverer("performance", performanceDoer(func(_ context.Context, method, rawURL string, _ []byte, _ map[string]string) (httpclient.RequestResponse, error) {
		requests.Add(1)
		return httpclient.RequestResponse{Response: httpclient.ResponseRecord{
			StatusCode: http.StatusOK, Body: "baseline", Headers: map[string]string{"Content-Type": "text/html"},
		}}, nil
	}), scope.NewEngine(cfg), nil, nil)
	candidates := make([]string, 24)
	for i := range candidates {
		candidates[i] = "candidate_" + string(rune('a'+i))
	}
	base := Fingerprint(http.StatusOK, "baseline", 0, map[string]string{"Content-Type": "text/html"})
	kept, used := d.prefilterQueryCandidates(context.Background(), "https://example.test/search", nil,
		candidates, base, "baseline", base, "baseline", "__control", false, 100)
	if used != 2 || requests.Load() != 2 {
		t.Fatalf("batch requests=%d/%d, want 2", used, requests.Load())
	}
	if len(kept) != 0 {
		t.Fatalf("ignored candidate groups should be eliminated, kept=%v", kept)
	}
}

func TestQueryPrefilterKeepsInterestingGroup(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"example.test"}
	d := NewDiscoverer("performance", performanceDoer(func(_ context.Context, _ string, rawURL string, _ []byte, _ map[string]string) (httpclient.RequestResponse, error) {
		body := "baseline"
		if strings.Contains(rawURL, "candidate_f=") {
			body = "different"
		}
		return httpclient.RequestResponse{Response: httpclient.ResponseRecord{StatusCode: http.StatusOK, Body: body}}, nil
	}), scope.NewEngine(cfg), nil, nil)
	candidates := make([]string, 24)
	for i := range candidates {
		candidates[i] = "candidate_" + string(rune('a'+i))
	}
	base := Fingerprint(http.StatusOK, "baseline", 0, nil)
	kept, used := d.prefilterQueryCandidates(context.Background(), "https://example.test/search", nil,
		candidates, base, "baseline", base, "baseline", "__control", false, 100)
	if used != 2 {
		t.Fatalf("batch requests=%d, want 2", used)
	}
	if len(kept) != parameterPrefilterBatchSize || kept[5] != "candidate_f" {
		t.Fatalf("interesting batch was not retained: %v", kept)
	}
}

func TestDiscoveryGlobalProbeLimit(t *testing.T) {
	var active atomic.Int32
	var peak atomic.Int32
	d := NewDiscoverer("performance", performanceDoer(func(ctx context.Context, _ string, _ string, _ []byte, _ map[string]string) (httpclient.RequestResponse, error) {
		current := active.Add(1)
		defer active.Add(-1)
		for {
			old := peak.Load()
			if current <= old || peak.CompareAndSwap(old, current) {
				break
			}
		}
		select {
		case <-time.After(10 * time.Millisecond):
		case <-ctx.Done():
		}
		return httpclient.RequestResponse{}, nil
	}), nil, nil, nil)
	d.SetParallelism(3)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = d.do(context.Background(), http.MethodGet, "https://example.test", nil, nil)
		}()
	}
	wg.Wait()
	if got := peak.Load(); got > 3 {
		t.Fatalf("peak discovery requests=%d, want <=3", got)
	}
}
