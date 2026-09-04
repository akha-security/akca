package modules

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/oast"
	"github.com/akha-security/akca/engine/internal/reflection"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/verification"
)

type blindXSSRecordingClient struct {
	requests []httpclient.RequestRecord
}

func (c *blindXSSRecordingClient) Do(_ context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	req := httpclient.RequestRecord{Method: method, URL: rawURL, Body: string(body), Headers: headers}
	c.requests = append(c.requests, req)
	return httpclient.RequestResponse{
		Request: req,
		Response: httpclient.ResponseRecord{
			StatusCode: 200, Body: "accepted", Headers: map[string]string{"Content-Type": "text/html"},
		},
	}, nil
}

func TestBlindXSSCallbackProducesConfirmedFinding(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/blind-xss.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	const scanID = "scan-blind-xss"
	if err := db.EnsureScan(scanID); err != nil {
		t.Fatal(err)
	}

	listener, err := oast.NewListener(db, func(string, string, map[string]interface{}) error { return nil },
		oast.Config{PollInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := listener.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer listener.Stop()
	listener.SetScanID(scanID)

	var pending bool
	cfg := config.DefaultScanConfig()
	cfg.EnableOAST = true
	client := &blindXSSRecordingClient{}
	runner := NewRunner(scanID, client, scope.NewEngine(cfg), db, verification.NewEngine(db, nil), listener,
		func(eventType, _ string, _ map[string]interface{}) error {
			if eventType == "oast_verification_pending" {
				pending = true
			}
			return nil
		}, cfg)
	target := ScanTarget{
		EndpointURL: "http://example.com/review", Method: "GET", Parameter: "comment", Location: "query",
		Profile: reflection.ReflectionProfile{ContentType: "text/html"},
	}
	if findings := runner.runBlindXSS(ctx, target); len(findings) != 0 {
		t.Fatalf("blind XSS must not be reported before a callback, got %d findings", len(findings))
	}
	if !pending {
		t.Fatal("expected an explicit pending OAST verification event")
	}

	callbackHost := callbackHostFromBlindXSSRequests(client.requests)
	if callbackHost == "" {
		t.Fatal("blind XSS probe did not contain a usable OAST callback URL")
	}
	listener.Provider().(*oast.LocalProvider).InjectInteraction(callbackHost, "http", "203.0.113.10")
	listener.Drain(ctx, time.Millisecond)

	findings, err := FinalizeOASTFindings(db, scanID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("confirmed callback findings = %d, want 1", len(findings))
	}
	finding := findings[0]
	if finding.VulnClass != "blind_xss" || finding.Evidence.Signal != "blind_xss_oast_callback" ||
		finding.Confidence != verification.Confirmed || !finding.Evidence.Verification.OASTConfirmed {
		t.Fatalf("unexpected blind XSS finding: %+v", finding)
	}
}

func callbackHostFromBlindXSSRequests(requests []httpclient.RequestRecord) string {
	for _, request := range requests {
		u, err := url.Parse(request.URL)
		if err != nil {
			continue
		}
		payload := u.Query().Get("comment")
		start := strings.Index(payload, "http://")
		if start < 0 {
			continue
		}
		callbackURL := payload[start:]
		if end := strings.IndexAny(callbackURL, "'\"<>"); end > 0 {
			callbackURL = callbackURL[:end]
		}
		parsed, err := url.Parse(callbackURL)
		if err == nil && strings.HasSuffix(parsed.Hostname(), ".oast.akca.local") {
			return parsed.Hostname()
		}
	}
	return ""
}
