package bypass403

import (
	"context"
	"fmt"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/fuzzing"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
)

type soft404BypassDoer struct {
	counter atomic.Int64
}

func (d *soft404BypassDoer) Do(_ context.Context, method, rawURL string, _ []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	u, _ := url.Parse(rawURL)
	if method == "GET" && u.Path == "/admin" && len(headers) == 0 {
		return httpclient.RequestResponse{
			Request:  httpclient.RequestRecord{Method: method, URL: rawURL, Headers: headers},
			Response: httpclient.ResponseRecord{StatusCode: 403, Body: "forbidden access denied"},
		}, nil
	}
	build := d.counter.Add(1)
	body := fmt.Sprintf(`<!DOCTYPE html><html><head><script src="/app.bundle-%012x.js"></script></head><body><h1>Public application shell</h1><p>Welcome to the site</p></body></html>`, build)
	return httpclient.RequestResponse{
		Request:  httpclient.RequestRecord{Method: method, URL: rawURL, Headers: headers},
		Response: httpclient.ResponseRecord{StatusCode: 200, Body: body},
	}, nil
}

type publicFallbackDoer struct{}

func (d *publicFallbackDoer) Do(_ context.Context, method, rawURL string, _ []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	u, _ := url.Parse(rawURL)
	body := "forbidden access denied"
	status := 403
	if headers["X-Forwarded-For"] == "127.0.0.1" && (u.Path == "/admin" || u.Path == "/") {
		status = 200
		body = `<!DOCTYPE html><html><body><h1>Public home page</h1><p>Welcome to the site</p></body></html>`
	}
	return httpclient.RequestResponse{
		Request:  httpclient.RequestRecord{Method: method, URL: rawURL, Headers: headers},
		Response: httpclient.ResponseRecord{StatusCode: status, Body: body, Headers: map[string]string{"Content-Type": "text/html"}},
	}, nil
}

type seqDoer struct {
	responses map[string]httpclient.ResponseRecord
}

func (s *seqDoer) Do(_ context.Context, method, rawURL string, _ []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	u, _ := url.Parse(rawURL)
	key := method + " " + u.Path
	if len(headers) > 0 {
		if v, ok := headers["X-Original-URL"]; ok && v == "/admin" {
			key = method + " " + rawURL + "#x-original-url"
		}
	}
	resp, ok := s.responses[key]
	if !ok {
		resp = httpclient.ResponseRecord{StatusCode: 403, Body: "forbidden"}
	}
	return httpclient.RequestResponse{
		Request:  httpclient.RequestRecord{Method: method, URL: rawURL, Headers: headers},
		Response: resp,
	}, nil
}

func TestEngineConsumesQueueAndVerifiesBypass(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"127.0.0.1"}
	scopeEngine := scope.NewEngine(cfg)

	client := &seqDoer{responses: map[string]httpclient.ResponseRecord{
		"GET /admin": {StatusCode: 403, Body: "forbidden"},
		"GET http://127.0.0.1/admin#x-original-url": {StatusCode: 200, Body: `{"admin":true}`},
	}}

	db, err := storage.Open(t.TempDir() + "/bypass.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_ = db.Migrate()

	q := fuzzing.NewQueue403(10)
	q.Enqueue("http://127.0.0.1/admin", "GET")

	var attempted, succeeded int
	be := NewEngine("scan-b", client, scopeEngine, db, q, func(eventType, message string, payload map[string]interface{}) error {
		switch eventType {
		case "four_oh_three_bypass_attempted":
			attempted++
		case "four_oh_three_bypass_succeeded":
			succeeded++
		}
		return nil
	}, 1)

	if err := be.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if attempted == 0 {
		t.Fatal("expected bypass attempts")
	}
	if succeeded == 0 {
		t.Fatal("expected at least one verified bypass")
	}
	if q.Metrics().TotalProcessed != 1 {
		t.Fatalf("expected queue consumed, metrics=%+v", q.Metrics())
	}
}

func TestEngineScopeBlocksBypass(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"allowed.test"}
	scopeEngine := scope.NewEngine(cfg)
	client := &seqDoer{responses: map[string]httpclient.ResponseRecord{
		"GET /admin": {StatusCode: 403, Body: "forbidden"},
	}}

	db, err := storage.Open(t.TempDir() + "/bypass-scope.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_ = db.Migrate()

	q := fuzzing.NewQueue403(10)
	q.Enqueue("http://127.0.0.1/admin", "GET")

	var blocked int
	be := NewEngine("scan-s", client, scopeEngine, db, q, func(eventType, _ string, _ map[string]interface{}) error {
		if eventType == "scope_blocked" {
			blocked++
		}
		return nil
	}, 1)

	if err := be.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if blocked == 0 {
		t.Fatal("expected scope_blocked event")
	}
}

func TestEngineSuppressesDynamicSoft404AndPublicShell(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"127.0.0.1"}
	scopeEngine := scope.NewEngine(cfg)

	db, err := storage.Open(t.TempDir() + "/bypass-soft404.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}

	q := fuzzing.NewQueue403(10)
	q.Enqueue("http://127.0.0.1/admin", "GET")
	var succeeded int
	engine := NewEngine("scan-soft404", &soft404BypassDoer{}, scopeEngine, db, q, func(eventType, _ string, _ map[string]interface{}) error {
		if eventType == "four_oh_three_bypass_succeeded" {
			succeeded++
		}
		return nil
	}, 1)
	if err := engine.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if succeeded != 0 {
		t.Fatalf("dynamic public shell produced %d bypass findings", succeeded)
	}
	findings, err := db.ListFindings("scan-soft404", 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no persisted soft-404 findings, got %d", len(findings))
	}
}

func TestVerifyCandidateRejectsPublicHomepageFallback(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"127.0.0.1"}
	scopeEngine := scope.NewEngine(cfg)
	client := &publicFallbackDoer{}
	engine := &Engine{client: client, scope: scopeEngine}
	baseline := Baseline{
		URL: "http://127.0.0.1/admin", Method: "GET", StatusCode: 403,
		Body: "forbidden access denied", BodyLength: 23,
	}
	attempt := Attempt{
		Category: IPTrustHeader, Label: "x-forwarded-for", Method: "GET",
		URL: baseline.URL, Headers: map[string]string{"X-Forwarded-For": "127.0.0.1"},
	}
	first, err := client.Do(context.Background(), attempt.Method, attempt.URL, nil, attempt.Headers)
	if err != nil {
		t.Fatal(err)
	}
	result := engine.verifyCandidate(context.Background(), baseline, attempt, first, "ok_access")
	if result.Succeeded || result.Reason != "candidate_matches_public_content" {
		t.Fatalf("public homepage fallback must be suppressed: %+v", result)
	}
}
