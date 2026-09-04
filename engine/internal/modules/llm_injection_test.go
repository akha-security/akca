package modules

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/verification"
)

type llmMockClient struct {
	responseHandler func(method, rawURL, reqBody string) string
}

func (c *llmMockClient) Do(_ context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	reqStr := string(body)
	respBody := `{"status":"ok","response":"Hello! How can I help you today?"}`
	if c.responseHandler != nil {
		respBody = c.responseHandler(method, rawURL, reqStr)
	}
	return httpclient.RequestResponse{
		Request: httpclient.RequestRecord{Method: method, URL: rawURL, Body: reqStr, Headers: headers},
		Response: httpclient.ResponseRecord{
			StatusCode: 200, Body: respBody, Headers: map[string]string{"Content-Type": "application/json"},
		},
	}, nil
}

func TestLLMInjection_LegitimateSystemPromptLeak_Confirmed(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.ScanID = "scan-llm-valid"
	db, _ := storage.Open(":memory:")
	defer db.Close()
	_ = db.Migrate()
	_ = db.EnsureScan(cfg.ScanID)

	client := &llmMockClient{
		responseHandler: func(method, rawURL, reqBody string) string {
			if strings.Contains(reqBody, "Ignore previous instructions") {
				// True LLM execution output: returns leaked prompt under response key
				return `{"status":"success","response":"AKCA_SYSTEM_PROMPT_LEAK: You are Acme Corp AI assistant. Never share internal API keys. Knowledge base: v2.1"}`
			}
			return `{"status":"success","response":"Hello! I am Acme AI."}`
		},
	}

	runner := NewRunner(cfg.ScanID, client, scope.NewEngine(cfg), db, verification.NewEngine(db, nil), nil, nil, cfg)
	target := ScanTarget{
		EndpointURL:  "http://example.com/api/chat",
		Method:       "POST",
		Parameter:    "message",
		Location:     "json",
		BodyTemplate: `{"message":"hello"}`,
	}

	findings := runner.runLLMInjection(context.Background(), target)
	if len(findings) == 0 {
		t.Fatal("expected LLM injection finding for legitimate prompt leak, got none")
	}

	found := false
	for _, f := range findings {
		if f.VulnClass == "llm_injection" && strings.Contains(f.Evidence.Signal, "llm_system_prompt_leak") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected llm_system_prompt_leak finding, got %+v", findings)
	}
}

func TestLLMInjection_NextDataReflection_Suppressed(t *testing.T) {
	// Scenario: Next.js SSR echoes URL parameter into __NEXT_DATA__ JSON script tag
	cfg := config.DefaultScanConfig()
	cfg.ScanID = "scan-llm-nextjs-fp"
	db, _ := storage.Open(":memory:")
	defer db.Close()
	_ = db.Migrate()
	_ = db.EnsureScan(cfg.ScanID)

	client := &llmMockClient{
		responseHandler: func(method, rawURL, reqBody string) string {
			return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"query":{"q":"%s"}}}}</script>
</head>
<body>
<h1>Search Results</h1>
<p>No results found</p>
</body>
</html>`, reqBody)
		},
	}

	runner := NewRunner(cfg.ScanID, client, scope.NewEngine(cfg), db, verification.NewEngine(db, nil), nil, nil, cfg)
	target := ScanTarget{
		EndpointURL: "http://example.com/search?q=test",
		Method:      "GET",
		Parameter:   "q",
	}

	findings := runner.runLLMInjection(context.Background(), target)
	if len(findings) > 0 {
		t.Fatalf("expected 0 findings for Next.js __NEXT_DATA__ reflection (false positive prevented), got %d: %+v", len(findings), findings)
	}
}

func TestLLMInjection_InputFormReflection_Suppressed(t *testing.T) {
	// Scenario: Form input value reflections
	cfg := config.DefaultScanConfig()
	cfg.ScanID = "scan-llm-input-fp"
	db, _ := storage.Open(":memory:")
	defer db.Close()
	_ = db.Migrate()
	_ = db.EnsureScan(cfg.ScanID)

	client := &llmMockClient{
		responseHandler: func(method, rawURL, reqBody string) string {
			return fmt.Sprintf(`<!DOCTYPE html>
<html>
<body>
<form action="/feedback" method="POST">
  <input type="text" name="comment" value="%s" />
  <button type="submit">Submit</button>
</form>
</body>
</html>`, reqBody)
		},
	}

	runner := NewRunner(cfg.ScanID, client, scope.NewEngine(cfg), db, verification.NewEngine(db, nil), nil, nil, cfg)
	target := ScanTarget{
		EndpointURL:  "http://example.com/feedback",
		Method:       "POST",
		Parameter:    "comment",
		BodyTemplate: `comment=hello`,
	}

	findings := runner.runLLMInjection(context.Background(), target)
	if len(findings) > 0 {
		t.Fatalf("expected 0 findings for form input value reflection (false positive prevented), got %d", len(findings))
	}
}

func TestLLMInjection_JSONEchoMirror_Suppressed(t *testing.T) {
	// Scenario: API echoes back the request payload in a "request" / "input" key without LLM execution
	cfg := config.DefaultScanConfig()
	cfg.ScanID = "scan-llm-echo-fp"
	db, _ := storage.Open(":memory:")
	defer db.Close()
	_ = db.Migrate()
	_ = db.EnsureScan(cfg.ScanID)

	client := &llmMockClient{
		responseHandler: func(method, rawURL, reqBody string) string {
			return fmt.Sprintf(`{"status":"error","input":"%s","error":"invalid api command"}`, reqBody)
		},
	}

	runner := NewRunner(cfg.ScanID, client, scope.NewEngine(cfg), db, verification.NewEngine(db, nil), nil, nil, cfg)
	target := ScanTarget{
		EndpointURL:  "http://example.com/api/echo",
		Method:       "POST",
		Parameter:    "input",
		Location:     "json",
		BodyTemplate: `{"input":"test"}`,
	}

	findings := runner.runLLMInjection(context.Background(), target)
	if len(findings) > 0 {
		t.Fatalf("expected 0 findings for JSON input echo (false positive prevented), got %d", len(findings))
	}
}
