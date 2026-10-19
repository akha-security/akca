package params

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
)

type selectiveDiscoveryClient struct{}

func (selectiveDiscoveryClient) Do(_ context.Context, method, rawURL string, _ []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	if strings.Contains(rawURL, "/api/fail") {
		return httpclient.RequestResponse{}, errors.New("dial tcp 127.0.0.1:443: connect: connection refused")
	}
	return httpclient.RequestResponse{
		Request: httpclient.RequestRecord{Method: method, URL: rawURL, Headers: headers},
		Response: httpclient.ResponseRecord{
			StatusCode: http.StatusNotFound,
			Body:       "not found",
			Headers:    map[string]string{"Content-Type": "text/plain"},
		},
	}, nil
}

func newRunErrorDiscoverer(t *testing.T, scanID string, endpointURLs []string, emit EventSink) *Discoverer {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "parameter-errors.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureScan(scanID); err != nil {
		t.Fatal(err)
	}
	for _, endpointURL := range endpointURLs {
		if err := db.SaveDiscoveredEndpoint(scanID, map[string]interface{}{
			"url": endpointURL, "method": http.MethodGet, "normalized_url": endpointURL, "source": "test",
		}); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"example.test"}
	d := NewDiscoverer(scanID, selectiveDiscoveryClient{}, scope.NewEngine(cfg), db, emit)
	d.SetMaxProbes(1)
	d.SetWordlistCap(1)
	d.SetParallelism(2)
	return d
}

func TestRunTreatsPartialEndpointErrorsAsCoverageGap(t *testing.T) {
	var mu sync.Mutex
	var summary map[string]interface{}
	var coverage map[string]interface{}
	d := newRunErrorDiscoverer(t, "partial-errors", []string{
		"https://example.test/api/ok?kind=1",
		"https://example.test/api/fail?other=1",
	}, func(eventType, _ string, payload map[string]interface{}) error {
		mu.Lock()
		defer mu.Unlock()
		switch eventType {
		case "parameter_discovery_error_summary":
			summary = payload
		case "coverage_gap":
			coverage = payload
		}
		return nil
	})

	if err := d.Run(context.Background(), 10); err != nil {
		t.Fatalf("partial endpoint failure should not fail discovery: %v", err)
	}
	if summary == nil || summary["class"] != "connection_refused" || summary["count"] != 1 {
		t.Fatalf("unexpected grouped error summary: %#v", summary)
	}
	if coverage == nil || coverage["failed_endpoints"] != 1 || coverage["successful_endpoints"] != 1 {
		t.Fatalf("unexpected coverage gap: %#v", coverage)
	}
}

func TestRunFailsWhenEverySelectedEndpointFails(t *testing.T) {
	d := newRunErrorDiscoverer(t, "all-errors", []string{
		"https://example.test/api/fail?kind=1",
	}, func(string, string, map[string]interface{}) error { return nil })
	if err := d.Run(context.Background(), 10); err == nil {
		t.Fatal("discovery should fail when every selected endpoint fails")
	}
}

func TestParameterDiscoveryErrorClass(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{context.DeadlineExceeded, "timeout"},
		{errors.New("x509: certificate signed by unknown authority"), "tls_error"},
		{errors.New("lookup example.test: no such host"), "dns_error"},
		{errors.New("stopped: request budget exhausted"), "budget_exhausted"},
	}
	for _, tc := range tests {
		if got := parameterDiscoveryErrorClass(tc.err); got != tc.want {
			t.Fatalf("classify %q=%q, want %q", tc.err, got, tc.want)
		}
	}
}
