package crawler

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
)

type failingCrawlerClient struct{ err error }

func (c failingCrawlerClient) Do(context.Context, string, string, []byte, map[string]string) (httpclient.RequestResponse, error) {
	return httpclient.RequestResponse{}, c.err
}

func TestClassifyNetworkError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "timeout", err: context.DeadlineExceeded, want: "timeout"},
		{name: "canceled", err: context.Canceled, want: "canceled"},
		{name: "host deferred", err: httpclient.ErrHostDeferred, want: "host_deferred"},
		{name: "request budget", err: errors.New("global request budget exhausted after 10 requests"), want: "request_budget"},
		{name: "proxy", err: errors.New("proxy request via http://127.0.0.1:8080 failed"), want: "proxy"},
		{name: "dns", err: &net.DNSError{Err: "no such host", Name: "example.test"}, want: "dns"},
		{name: "connection refused", err: syscall.ECONNREFUSED, want: "connection_refused"},
		{name: "connection reset", err: syscall.ECONNRESET, want: "connection_reset"},
		{name: "tls", err: errors.New("tls handshake failed: x509: certificate signed by unknown authority"), want: "tls"},
		{name: "other", err: errors.New("unexpected transport failure"), want: "transport"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := classifyNetworkError(test.err); got != test.want {
				t.Fatalf("classifyNetworkError(%v) = %q, want %q", test.err, got, test.want)
			}
		})
	}
}

func TestFormatNetworkErrorKindsIsStable(t *testing.T) {
	got := formatNetworkErrorKinds(map[string]int{"transport": 1, "dns": 4, "tls": 4, "timeout": 2})
	if got != "dns=4, tls=4, timeout=2, transport=1" {
		t.Fatalf("unexpected network error summary: %q", got)
	}
}

func TestCrawlReportsNetworkFailureKinds(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"example.test"}
	cfg.EnableHeadlessCrawler = false
	db, err := storage.Open(t.TempDir() + "/network-errors.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}

	var finishedKinds map[string]int
	var gapKinds map[string]int
	emit := func(kind, _ string, payload map[string]interface{}) error {
		if kind == "crawler_finished" {
			finishedKinds, _ = payload["network_error_kinds"].(map[string]int)
		}
		if kind == "coverage_gap" && payload["reason"] == "no_usable_content" {
			gapKinds, _ = payload["network_error_kinds"].(map[string]int)
		}
		return nil
	}
	c := New("network-errors", cfg, failingCrawlerClient{err: &net.DNSError{Err: "no such host", Name: "example.test"}}, scope.NewEngine(cfg), db, emit)
	err = c.Crawl(context.Background(), []string{"https://example.test/"})
	if err == nil || !strings.Contains(err.Error(), "dns=") {
		t.Fatalf("crawl error did not expose the grouped DNS cause: %v", err)
	}
	if finishedKinds["dns"] == 0 || finishedKinds["dns"] != gapKinds["dns"] {
		t.Fatalf("network error kinds were not preserved across events: finished=%v gap=%v", finishedKinds, gapKinds)
	}
	if got := formatNetworkErrorKinds(finishedKinds); !strings.HasPrefix(got, fmt.Sprintf("dns=%d", finishedKinds["dns"])) {
		t.Fatalf("unexpected grouped failure detail: %q", got)
	}
}
