package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
)

type InterceptServer struct {
	mu            sync.Mutex
	db            *storage.DB
	scope         *scope.Engine
	sessionID     string
	listener      net.Listener
	enabled       bool
	onCapture     func(TrafficRecord)
	forwardClient *http.Client
}

type TrafficRecord struct {
	Method     string `json:"method"`
	URL        string `json:"url"`
	ReqHeaders string `json:"req_headers"`
	ReqBody    string `json:"req_body"`
	StatusCode int    `json:"status_code"`
	RespBody   string `json:"resp_body"`
}

func NewInterceptServer(db *storage.DB, scopeEngine *scope.Engine, sessionID string) *InterceptServer {
	return &InterceptServer{
		db: db, scope: scopeEngine, sessionID: sessionID,
		forwardClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (s *InterceptServer) Start(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = ln
	s.enabled = true
	s.mu.Unlock()
	go func() {
		_ = http.Serve(ln, http.HandlerFunc(s.handle))
	}()
	_ = s.db.SaveProxySession(s.sessionID, `{"addr":"`+addr+`","enabled":true}`)
	return nil
}

func (s *InterceptServer) Stop() error {
	s.mu.Lock()
	s.enabled = false
	listener := s.listener
	s.listener = nil
	s.mu.Unlock()
	if listener != nil {
		return listener.Close()
	}
	return nil
}

func (s *InterceptServer) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	enabled := s.enabled
	s.mu.Unlock()
	if !enabled {
		http.Error(w, "proxy disabled", http.StatusServiceUnavailable)
		return
	}
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}
	target := r.URL.String()
	if !strings.HasPrefix(target, "http") {
		target = "http://" + r.Host + r.URL.RequestURI()
	}
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		http.Error(w, "invalid target format: url parse failed or host is empty", http.StatusBadRequest)
		return
	}
	if s.scope == nil || !s.scope.IsInScope(target) {
		http.Error(w, "out of scope", http.StatusForbidden)
		return
	}
	rec := TrafficRecord{Method: r.Method, URL: target, ReqHeaders: headersJSON(r.Header)}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	rec.ReqBody = string(body)
	r.Body = io.NopCloser(bytes.NewReader(body))

	// NewSingleHostReverseProxy joins the target path to the incoming request
	// path. An explicit proxy request already contains the destination path, so
	// use only the destination origin here to avoid forwarding /x as /x/x.
	proxy := httputil.NewSingleHostReverseProxy(&url.URL{Scheme: u.Scheme, Host: u.Host})
	proxy.ErrorHandler = func(rw http.ResponseWriter, _ *http.Request, err error) {
		http.Error(rw, err.Error(), http.StatusBadGateway)
	}
	rw := &captureWriter{ResponseWriter: w, record: &rec}
	proxy.ServeHTTP(rw, r)
	s.persist(rec)
	if s.onCapture != nil {
		s.onCapture(rec)
	}
}

func (s *InterceptServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	// TLS MITM requires generated certs; tunnel pass-through for in-scope hosts.
	if s.scope == nil || !s.scope.IsInScope("https://"+r.Host) {
		http.Error(w, "out of scope", http.StatusForbidden)
		return
	}
	hij, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hij.Hijack()
	if err != nil {
		return
	}
	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	dest, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		_ = clientConn.Close()
		return
	}
	tunnel(clientConn, dest)
}

func tunnel(clientConn, dest net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		// Try to half-close dst to notify it that src won't write anymore
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}

	go cp(dest, clientConn)
	go cp(clientConn, dest)

	go func() {
		wg.Wait()
		_ = dest.Close()
		_ = clientConn.Close()
	}()
}

func (s *InterceptServer) persist(rec TrafficRecord) {
	raw, _ := json.Marshal(rec)
	_ = s.db.SaveProxyTraffic(s.sessionID, string(raw))
}

func (s *InterceptServer) Forward(ctx context.Context, method, rawURL string, body string, headers map[string]string) (TrafficRecord, error) {
	if s.scope == nil || !s.scope.IsInScope(rawURL) {
		return TrafficRecord{}, fmt.Errorf("out of scope: %s", rawURL)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, strings.NewReader(body))
	if err != nil {
		return TrafficRecord{}, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := s.forwardClient.Do(req)
	if err != nil {
		return TrafficRecord{}, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	rec := TrafficRecord{
		Method: method, URL: rawURL, ReqBody: body, StatusCode: resp.StatusCode, RespBody: string(respBody),
	}
	s.persist(rec)
	return rec, nil
}

type captureWriter struct {
	http.ResponseWriter
	record    *TrafficRecord
	bytesRead int
	truncated bool
}

func (w *captureWriter) Write(b []byte) (int, error) {
	const maxLimit = 2 * 1024 * 1024 // 2MB upper limit
	if !w.truncated {
		remaining := maxLimit - w.bytesRead
		if len(b) > remaining {
			w.record.RespBody += string(b[:remaining])
			w.record.RespBody += "\n[TRUNCATED - RESPONSE TOO LARGE]"
			w.truncated = true
			w.bytesRead = maxLimit
		} else {
			w.record.RespBody += string(b)
			w.bytesRead += len(b)
		}
	}
	return w.ResponseWriter.Write(b)
}

func headersJSON(h http.Header) string {
	m := map[string]string{}
	for k, v := range h {
		m[k] = strings.Join(v, ", ")
	}
	b, _ := json.Marshal(m)
	return string(b)
}
