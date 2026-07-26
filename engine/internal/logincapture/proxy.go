package logincapture

import (
	"bytes"
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

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/safemutation"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/workflow"
)

// CaptureServer is a local HTTP proxy that records cookies and auth headers during interactive login.
type CaptureServer struct {
	mu        sync.Mutex
	db        *storage.DB
	scope     *scope.Engine
	sessionID string
	listener  net.Listener
	addr      string
	enabled   bool
	jar       *CookieJar
	onUpdate  func(Session)
	recorder  *workflow.Recorder
	stepCount int
}

func (s *CaptureServer) EnableWorkflowRecording(workflowID, name, identity string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recorder = workflow.NewRecorder(workflowID, name, identity)
	s.stepCount = 0
}

func NewCaptureServer(db *storage.DB, scopeEngine *scope.Engine, sessionID string) *CaptureServer {
	return &CaptureServer{
		db:        db,
		scope:     scopeEngine,
		sessionID: sessionID,
		jar:       NewCookieJar(),
	}
}

func (s *CaptureServer) Start(addr string) (string, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.listener = ln
	s.addr = ln.Addr().String()
	s.enabled = true
	s.mu.Unlock()
	go func() {
		_ = http.Serve(ln, http.HandlerFunc(s.handle))
	}()
	_ = s.db.SaveProxySession(s.sessionID, `{"addr":"`+s.addr+`","mode":"login_capture","enabled":true}`)
	return s.addr, nil
}

func (s *CaptureServer) Stop() error {
	s.mu.Lock()
	s.enabled = false
	ln := s.listener
	s.mu.Unlock()
	if ln != nil {
		return ln.Close()
	}
	return nil
}

func (s *CaptureServer) ProxyURL() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.addr == "" {
		return ""
	}
	return "http://" + s.addr
}

func (s *CaptureServer) Session() Session {
	session := s.jar.Snapshot()
	s.mu.Lock()
	recorder := s.recorder
	s.mu.Unlock()
	if recorder != nil {
		definition := recorder.Definition()
		session.Workflow = &definition
	}
	return session
}

func (s *CaptureServer) handle(w http.ResponseWriter, r *http.Request) {
	if !s.enabled {
		http.Error(w, "login capture disabled", http.StatusServiceUnavailable)
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
	if s.scope != nil && !s.scope.IsInScope(target) {
		http.Error(w, "out of scope", http.StatusForbidden)
		return
	}

	reqHeaders := map[string]string{}
	for k, v := range r.Header {
		reqHeaders[k] = strings.Join(v, ", ")
	}
	s.jar.IngestRequestHeaders(reqHeaders)
	requestBody, bodyErr := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	if bodyErr != nil {
		http.Error(w, "request body capture failed", http.StatusBadRequest)
		return
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(requestBody))

	u, _ := url.Parse(target)
	proxy := httputil.NewSingleHostReverseProxy(u)
	proxy.Transport = httpTransport(true)
	proxy.ErrorHandler = func(rw http.ResponseWriter, _ *http.Request, err error) {
		http.Error(rw, err.Error(), http.StatusBadGateway)
	}
	rw := &captureWriter{ResponseWriter: w, onHeaders: s.ingestResponseHeaders}
	proxy.ServeHTTP(rw, r)
	s.persistTraffic(r.Method, target, reqHeaders, rw.statusCode, rw.body.String())
	s.recordWorkflowStep(r.Method, target, reqHeaders, requestBody, rw)
	if s.onUpdate != nil {
		s.onUpdate(s.jar.Snapshot())
	}
}

func (s *CaptureServer) recordWorkflowStep(method, target string, headers map[string]string, body []byte,
	writer *captureWriter) {
	s.mu.Lock()
	recorder := s.recorder
	s.stepCount++
	stepID := fmt.Sprintf("step-%03d", s.stepCount)
	s.mu.Unlock()
	if recorder == nil {
		return
	}
	risk := safemutation.PotentiallyDestructive
	if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
		risk = safemutation.ReadOnly
	}
	_ = recorder.Record(stepID, httpclient.RequestResponse{
		Request: httpclient.RequestRecord{
			Method: method, URL: target, Headers: headers, Body: string(body),
		},
		Response: httpclient.ResponseRecord{
			StatusCode: writer.statusCode, Headers: headerMap(writer.Header()), Body: writer.body.String(),
		},
	}, risk, nil)
}

func headerMap(headers http.Header) map[string]string {
	out := make(map[string]string, len(headers))
	for key, values := range headers {
		out[key] = strings.Join(values, ", ")
	}
	return out
}

func (s *CaptureServer) ingestResponseHeaders(h http.Header) {
	for k, vals := range h {
		if strings.EqualFold(k, "set-cookie") {
			for _, v := range vals {
				s.jar.IngestSetCookie(v)
			}
		}
	}
}

func (s *CaptureServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if s.scope != nil && !s.scope.IsInScope("https://"+host) {
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
	defer clientConn.Close()
	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	dest, err := net.DialTimeout("tcp", host, 15*time.Second)
	if err != nil {
		return
	}
	defer dest.Close()
	go pipe(dest, clientConn)
	pipe(clientConn, dest)
}

func pipe(dst net.Conn, src net.Conn) {
	defer dst.Close()
	defer src.Close()
	_, _ = io.Copy(dst, src)
}

func (s *CaptureServer) persistTraffic(method, target string, reqHeaders map[string]string, status int, respBody string) {
	rec := map[string]interface{}{
		"method":      method,
		"url":         target,
		"req_headers": reqHeaders,
		"status_code": status,
		"resp_body":   respBody,
	}
	raw, _ := json.Marshal(rec)
	_ = s.db.SaveProxyTraffic(s.sessionID, string(raw))
}

type captureWriter struct {
	http.ResponseWriter
	onHeaders  func(http.Header)
	statusCode int
	body       bytes.Buffer
}

func (w *captureWriter) WriteHeader(code int) {
	w.statusCode = code
	if w.onHeaders != nil {
		w.onHeaders(w.Header())
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *captureWriter) Write(b []byte) (int, error) {
	if w.statusCode == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if len(b) > 0 && w.body.Len() < 1<<20 {
		remain := (1 << 20) - w.body.Len()
		if len(b) > remain {
			b = b[:remain]
		}
		_, _ = w.body.Write(b)
	}
	return w.ResponseWriter.Write(b)
}
