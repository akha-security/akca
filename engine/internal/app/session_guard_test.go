package app

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/ratelimit"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/session"
	"github.com/akha-security/akca/engine/internal/storage"
)

func TestSessionHeartbeatHealthy(t *testing.T) {
	credentials := &config.LoginCredentials{
		LoggedInMarker:  "Welcome Alice",
		LoggedOutMarker: "Session expired",
	}
	tests := []struct {
		name    string
		status  int
		headers map[string]string
		body    string
		want    bool
	}{
		{name: "authenticated marker", status: 200, body: "Welcome Alice", want: true},
		{name: "missing authenticated marker", status: 200, body: "public page"},
		{name: "logged out marker", status: 200, body: "Session expired - Welcome Alice"},
		{name: "unauthorized", status: 401, body: "Welcome Alice"},
		{name: "login redirect", status: 302, headers: map[string]string{"location": "/sign-in"}},
		{
			name:   "automatic password form detection",
			status: 200,
			body:   `<form><input type="password" name="password"></form>`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lc := credentials
			if strings.Contains(tt.name, "automatic") {
				lc = &config.LoginCredentials{}
			}
			got, _, err := sessionHeartbeatHealthy(tt.status, tt.headers, tt.body, lc)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("healthy = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEnsureAuthenticatedSessionReloginsAndVerifies(t *testing.T) {
	var loginPosts atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			loginPosts.Add(1)
			if r.FormValue("username") != "alice" || r.FormValue("password") != "secret" {
				http.Error(w, "bad credentials", http.StatusUnauthorized)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "fresh", Path: "/"})
			_, _ = w.Write([]byte("Welcome Alice"))
			return
		}
		if cookie, err := r.Cookie("session"); err == nil && cookie.Value == "fresh" {
			_, _ = w.Write([]byte("Welcome Alice"))
			return
		}
		_, _ = w.Write([]byte(`<form method="post" action="/login">` +
			`<input name="username"><input type="password" name="password"></form>`))
	})
	mux.HandleFunc("/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie("session"); err == nil && cookie.Value == "fresh" {
			_, _ = w.Write([]byte("Welcome Alice"))
			return
		}
		_, _ = w.Write([]byte(`<input type="password" name="password">`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	eng := newSessionGuardTestEngine(t, server.URL, false)
	defer eng.Close()

	if err := eng.ensureAuthenticatedSession(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := loginPosts.Load(); got != 1 {
		t.Fatalf("login POST count = %d, want 1", got)
	}
	if got := eng.session.Snapshot().Config.SessionCookies["session"]; got != "fresh" {
		t.Fatalf("refreshed session cookie = %q, want fresh", got)
	}
}

func TestEnsureAuthenticatedSessionFailsClosedWhenReloginDisabled(t *testing.T) {
	var loginPosts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			loginPosts.Add(1)
		}
		_, _ = w.Write([]byte(`<input type="password" name="password">`))
	}))
	defer server.Close()

	eng := newSessionGuardTestEngine(t, server.URL, true)
	defer eng.Close()

	err := eng.ensureAuthenticatedSession(context.Background())
	if err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("expected fail-closed disabled error, got %v", err)
	}
	if got := loginPosts.Load(); got != 0 {
		t.Fatalf("unexpected login POST count: %d", got)
	}
}

func newSessionGuardTestEngine(t *testing.T, baseURL string, disableRelogin bool) *Engine {
	t.Helper()
	db, err := storage.Open(t.TempDir() + "/session-guard.db")
	if err != nil {
		t.Fatal(err)
	}
	eng, err := NewWithDB(&mockEventsWriter{}, db)
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultScanConfig()
	cfg.EnableOAST = false
	cfg.ScanID = fmt.Sprintf("session-guard-%s", strings.ReplaceAll(parsed.Port(), ":", ""))
	cfg.Targets = []string{baseURL}
	cfg.IncludeDomains = []string{parsed.Hostname()}
	cfg.SessionCookies = map[string]string{"session": "expired"}
	cfg.LoginCredentials = &config.LoginCredentials{
		LoginURL:           baseURL + "/login",
		HeartbeatURL:       baseURL + "/heartbeat",
		Username:           "alice",
		Password:           "secret",
		UsernameField:      "username",
		PasswordField:      "password",
		LoggedInMarker:     "Welcome Alice",
		DisableAutoRelogin: disableRelogin,
	}
	scopeEngine := scope.NewEngine(cfg)
	limiter := ratelimit.New(cfg.GlobalRateLimit, cfg.PerHostRateLimit)
	client, err := httpclient.New(cfg, scopeEngine, limiter)
	if err != nil {
		t.Fatal(err)
	}
	eng.scope = scopeEngine
	eng.limiter = limiter
	eng.client = client
	eng.session = session.NewScanSession(cfg)
	return eng
}
