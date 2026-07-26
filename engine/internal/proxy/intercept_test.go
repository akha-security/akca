package proxy

import (
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
)

func TestInterceptScopeBlock(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/akca.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"inscope.test"}
	s := NewInterceptServer(db, scope.NewEngine(cfg), "sess-1")
	if s.scope.IsInScope("https://evil.test/") {
		t.Fatal("evil host should be blocked")
	}
	if !s.scope.IsInScope("https://inscope.test/path") {
		t.Fatal("in-scope host should be allowed")
	}
}

func TestTrafficPersist(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/akca.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	s := NewInterceptServer(db, scope.NewEngine(config.DefaultScanConfig()), "sess-2")
	_ = s.db.SaveProxySession("sess-2", `{"enabled":true}`)
	s.persist(TrafficRecord{Method: "GET", URL: "https://example.com", StatusCode: 200})
	rows, err := db.ListProxyTraffic("sess-2", 10)
	if err != nil || len(rows) == 0 {
		t.Fatalf("traffic not saved: %v len=%d", err, len(rows))
	}
}

func TestProxyChunkedWriteBodyUnion(t *testing.T) {
	rec := &TrafficRecord{}
	cw := &captureWriter{
		ResponseWriter: &mockResponseWriter{},
		record:         rec,
	}
	
	// Test appending multiple chunked writes
	_, _ = cw.Write([]byte("chunk1"))
	_, _ = cw.Write([]byte("chunk2"))
	
	if rec.RespBody != "chunk1chunk2" {
		t.Fatalf("expected chunk1chunk2, got %q", rec.RespBody)
	}
	
	// Test truncation limit
	rec2 := &TrafficRecord{}
	cw2 := &captureWriter{
		ResponseWriter: &mockResponseWriter{},
		record:         rec2,
	}
	// Write more than 2MB
	largeChunk := make([]byte, 2*1024*1024 + 100)
	for i := range largeChunk {
		largeChunk[i] = 'A'
	}
	_, _ = cw2.Write(largeChunk)
	
	if len(rec2.RespBody) > 2*1024*1024 + 100 {
		t.Fatalf("expected truncation under 2MB + metadata size")
	}
	if !strings.HasSuffix(rec2.RespBody, "[TRUNCATED - RESPONSE TOO LARGE]") {
		t.Fatalf("expected truncated metadata suffix in response body")
	}
}

type mockResponseWriter struct{}
func (m *mockResponseWriter) Header() http.Header { return http.Header{} }
func (m *mockResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (m *mockResponseWriter) WriteHeader(statusCode int) {}

func TestProxyCONNECTTunnelClose(t *testing.T) {
	c1, s1 := net.Pipe()
	c2, s2 := net.Pipe()
	
	// Start tunnel asynchronously
	go tunnel(s1, s2)
	
	// Write from client 1 side
	go func() {
		_, _ = c1.Write([]byte("hello"))
		_ = c1.Close() // Half close simulation: client 1 stops writing
	}()
	
	// Read from client 2 side
	buf := make([]byte, 5)
	n, err := io.ReadFull(c2, buf)
	if err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("tunnel failed to forward client 1 write: %v", err)
	}
}

func TestProxyMalformedURLTarget(t *testing.T) {
	db, _ := storage.Open(t.TempDir() + "/akca.db")
	defer db.Close()
	_ = db.Migrate()
	s := NewInterceptServer(db, scope.NewEngine(config.DefaultScanConfig()), "sess-3")
	s.enabled = true
	
	rec := &mockResponseWriterWithStatus{}
	req := &http.Request{
		Method: "GET",
		Host:   "example.com:invalid-port",
		URL: &url.URL{
			Scheme: "http",
			Host:   "example.com:invalid-port",
			Path:   "/",
		},
	}
	s.handle(rec, req)
	
	if rec.status != http.StatusBadRequest {
		t.Fatalf("expected HTTP 400 Bad Request for malformed target, got %d", rec.status)
	}
}

type mockResponseWriterWithStatus struct {
	status int
}
func (m *mockResponseWriterWithStatus) Header() http.Header { return http.Header{} }
func (m *mockResponseWriterWithStatus) Write(b []byte) (int, error) { return len(b), nil }
func (m *mockResponseWriterWithStatus) WriteHeader(statusCode int) { m.status = statusCode }
