package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/ratelimit"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/verification"
)

func TestRouteAuthBypass_ConfirmedFinding(t *testing.T) {
	// Mock server that returns 403 on /admin/users, but 200 with sensitive users data on /admin;/users
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.RequestURI
		if strings.Contains(path, "?") {
			path = path[:strings.Index(path, "?")]
		}
		if path == "/admin/users" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"Forbidden: Admin access required"}`))
			return
		}
		if strings.Contains(path, "__akca_nonexistent_route_") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`404 Not Found`))
			return
		}
		if path == "/admin;/users" || strings.Contains(path, ";") || strings.Contains(path, "//") || strings.Contains(path, "/.") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"users":[{"id":1,"username":"admin","email":"admin@corp.internal"}]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cfg := config.DefaultScanConfig()
	cfg.Targets = []string{server.URL}
	cfg.IncludeDomains = []string{"127.0.0.1"}
	cfg.ScanID = "test-route-bypass"
	scopeEngine := scope.NewEngine(cfg)
	limiter := ratelimit.New(cfg.GlobalRateLimit, cfg.PerHostRateLimit)
	client, err := httpclient.New(cfg, scopeEngine, limiter)
	if err != nil {
		t.Fatalf("httpclient.New: %v", err)
	}

	db, _ := storage.Open(":memory:")
	defer db.Close()
	_ = db.Migrate()
	_ = db.EnsureScan(cfg.ScanID)
	verifier := verification.NewEngine(db, nil)

	runner := NewRunner(cfg.ScanID, client, scopeEngine, db, verifier, nil, nil, cfg)

	target := ScanTarget{
		EndpointURL: server.URL + "/admin/users",
		Method:      "GET",
	}
	findings := runner.runRouteAuthBypass(context.Background(), target)

	if len(findings) == 0 {
		t.Fatal("expected confirmed finding for route_auth_bypass, got none")
	}
	if findings[0].VulnClass != "route_auth_bypass" {
		t.Errorf("expected vulnClass route_auth_bypass, got %s", findings[0].VulnClass)
	}
}

func TestRouteAuthBypass_Soft404CatchAll_Suppressed(t *testing.T) {
	// Mock SPA server that returns 200 OK for ALL routes including nonexistent routes
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body><div id="app">SPA Root App</div></body></html>`))
	}))
	defer server.Close()

	cfg := config.DefaultScanConfig()
	cfg.Targets = []string{server.URL}
	cfg.IncludeDomains = []string{"127.0.0.1"}
	scopeEngine := scope.NewEngine(cfg)
	limiter := ratelimit.New(cfg.GlobalRateLimit, cfg.PerHostRateLimit)
	client, err := httpclient.New(cfg, scopeEngine, limiter)
	if err != nil {
		t.Fatalf("httpclient.New: %v", err)
	}

	db, _ := storage.Open(":memory:")
	defer db.Close()
	_ = db.Migrate()
	_ = db.EnsureScan(cfg.ScanID)
	verifier := verification.NewEngine(db, nil)

	runner := NewRunner(cfg.ScanID, client, scopeEngine, db, verifier, nil, nil, cfg)

	findings := runner.runRouteAuthBypass(context.Background(), ScanTarget{
		EndpointURL: server.URL + "/admin/users",
		Method:      "GET",
	})

	if len(findings) > 0 {
		t.Fatalf("expected soft-404 catch-all server to produce 0 findings (false-positive prevention), got %d", len(findings))
	}
}

func TestRouteAuthBypass_LoginRedirectIn200_Suppressed(t *testing.T) {
	// Mock server that returns 403 on /admin, and returns 200 with Login Form on /admin;/users
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/admin/users" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`Forbidden`))
			return
		}
		// Returns 200 but content is actually a login page
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body><h2>Please Log In</h2><form action="/login"><input name="user"/></form></body></html>`))
	}))
	defer server.Close()

	cfg := config.DefaultScanConfig()
	cfg.Targets = []string{server.URL}
	cfg.IncludeDomains = []string{"127.0.0.1"}
	scopeEngine := scope.NewEngine(cfg)
	limiter2 := ratelimit.New(cfg.GlobalRateLimit, cfg.PerHostRateLimit)
	client, err := httpclient.New(cfg, scopeEngine, limiter2)
	if err != nil {
		t.Fatalf("httpclient.New: %v", err)
	}

	db, _ := storage.Open(":memory:")
	defer db.Close()
	_ = db.Migrate()
	_ = db.EnsureScan(cfg.ScanID)
	verifier := verification.NewEngine(db, nil)

	runner := NewRunner(cfg.ScanID, client, scopeEngine, db, verifier, nil, nil, cfg)

	findings := runner.runRouteAuthBypass(context.Background(), ScanTarget{
		EndpointURL: server.URL + "/admin/users",
		Method:      "GET",
	})

	if len(findings) > 0 {
		t.Fatalf("expected login page returned in 200 OK to produce 0 findings, got %d", len(findings))
	}
}
