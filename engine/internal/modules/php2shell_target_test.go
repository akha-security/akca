package modules

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/verification"
)

func TestPHP2ShellFullScanTargetsStayOnExplicitOrigins(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.Targets = []string{"https://example.test/app", "https://example.test/other", "https://second.test/"}
	r := NewRunner("php2shell-roots", nil, nil, nil, nil, nil, nil, cfg)
	root := &httpclient.RequestResponse{Response: httpclient.ResponseRecord{StatusCode: 200}}
	index := &httpclient.RequestResponse{Response: httpclient.ResponseRecord{StatusCode: 200}}
	selected := r.php2ShellFullScanTargets([]ScanTarget{
		{EndpointURL: "https://example.test/app/page", Method: "GET", ObservedResponse: root},
		{EndpointURL: "https://child.example.test/index.php", Method: "GET", ObservedResponse: root},
		{EndpointURL: "https://example.test/index.php?x=1", Method: "GET", ObservedResponse: root},
		{EndpointURL: "https://example.test/index.php", Method: "POST", ObservedResponse: root},
		{EndpointURL: "https://example.test/", Method: "GET", ObservedResponse: root},
		{EndpointURL: "https://example.test/index.php", Method: "GET", ObservedResponse: index},
	})
	if len(selected) != 2 {
		t.Fatalf("selected %d targets, want one per explicit origin: %+v", len(selected), selected)
	}
	if selected[0].EndpointURL != "https://example.test/index.php" || selected[0].ObservedResponse != index {
		t.Fatalf("first target = %+v, want observed /index.php", selected[0])
	}
	if selected[1].EndpointURL != "https://second.test/index.php" || selected[1].ObservedResponse != nil {
		t.Fatalf("second target = %+v, want direct /index.php fallback", selected[1])
	}
}

func TestPHP2ShellFullScanProbesOnlyIndexWithoutFollowingRedirect(t *testing.T) {
	var mu sync.Mutex
	hits := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		hits[req.Method+" "+req.URL.Path]++
		mu.Unlock()
		if req.URL.Path == "/index.php" {
			http.Redirect(w, req, "/discovered", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	cfg := config.DefaultScanConfig()
	cfg.Targets = []string{srv.URL}
	cfg.PerHostRateLimit = 1000
	cfg.GlobalRateLimit = 1000
	sc := scope.NewEngine(cfg)
	client, err := httpclient.New(cfg, sc, nil)
	if err != nil {
		t.Fatal(err)
	}
	var finished map[string]interface{}
	r := NewRunner("php2shell-one-root", client, sc, nil, verification.NewEngine(nil, nil), nil,
		func(kind, _ string, data map[string]interface{}) error {
			if kind == "module_target_finished" {
				finished = data
			}
			return nil
		}, cfg)
	_, err = r.RunModule(context.Background(), "php2shell", []ScanTarget{
		{EndpointURL: srv.URL + "/app", Method: "GET"},
		{EndpointURL: srv.URL + "/other", Method: "GET"},
		{EndpointURL: srv.URL + "/index.php?item=1", Method: "GET"},
	})
	if err != nil && !errors.Is(err, ErrModuleAssessmentInconclusive) {
		t.Fatalf("%v; target=%+v", err, finished)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(hits) != 1 || hits["GET /index.php"] != 1 {
		t.Fatalf("PHP2Shell requests = %+v, want only one direct GET /index.php", hits)
	}
}

func TestPHP2ShellFullScanRunsBoundedActiveCheckAndReportsItsProofRequest(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.Targets = []string{"https://example.test/"}
	cfg.PHP2ShellActive = true
	cfg.PerHostRateLimit = 1000
	cfg.GlobalRateLimit = 1000
	var requests []string
	r := NewRunner("php-active-full", auditDoer(func(_ context.Context, method, raw string, body []byte, headers map[string]string) (httpclient.RequestResponse, error) {
		requests = append(requests, method+" "+raw)
		response := httpclient.ResponseRecord{StatusCode: 200, Headers: map[string]string{"Content-Type": "text/html"}}
		if method == http.MethodPost && strings.HasSuffix(headers["Content-Type"], "boundary=") {
			response.StatusCode = http.StatusInternalServerError
			response.Body = "Allowed memory size of 134217728 bytes exhausted (tried to allocate 2 bytes) in Unknown on line 0"
		}
		return httpclient.RequestResponse{
			Request:  httpclient.RequestRecord{Method: method, URL: raw, Body: string(body), Headers: headers},
			Response: response,
		}, nil
	}), nil, nil, nil, nil, func(string, string, map[string]interface{}) error { return nil }, cfg)
	defer r.Close()

	findings, err := r.RunModule(context.Background(), "php2shell", []ScanTarget{{EndpointURL: "https://example.test/page", Method: http.MethodGet}})
	if err != nil {
		t.Fatalf("full-scan active assessment failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want one memory-signature candidate", len(findings))
	}
	if len(requests) != 3 || requests[0] != "GET https://example.test/index.php" || requests[1] != "POST https://example.test/index.php" || requests[2] != requests[1] {
		t.Fatalf("unexpected active request sequence: %v", requests)
	}
	evidence := findings[0].Evidence
	if evidence.Request.Method != http.MethodPost || evidence.Request.URL != "https://example.test/index.php" || evidence.Response.StatusCode != http.StatusInternalServerError {
		t.Fatalf("finding does not cite the signature-producing request: method=%s url=%s status=%d", evidence.Request.Method, evidence.Request.URL, evidence.Response.StatusCode)
	}
	if !strings.Contains(evidence.Request.Body, "omitted") || len(evidence.Request.Body) > 128 {
		t.Fatalf("large probe body was not compacted in saved evidence: %d bytes", len(evidence.Request.Body))
	}
}

func TestPHP2ShellUnknownIsInconclusiveAndNotRepeatedAsClean(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.Targets = []string{"https://example.test"}
	requests := 0
	var finished map[string]interface{}
	r := NewRunner("unknown-php", auditDoer(func(_ context.Context, method, raw string, _ []byte, _ map[string]string) (httpclient.RequestResponse, error) {
		requests++
		if method != "GET" || raw != "https://example.test/index.php" {
			t.Fatalf("unexpected request %s %s", method, raw)
		}
		return httpclient.RequestResponse{Request: httpclient.RequestRecord{Method: method, URL: raw}, Response: httpclient.ResponseRecord{StatusCode: 200, Headers: map[string]string{"Content-Type": "text/html"}}}, nil
	}), nil, nil, nil, nil, func(kind, _ string, data map[string]interface{}) error {
		if kind == "module_target_finished" {
			finished = data
		}
		return nil
	}, cfg)
	defer r.Close()
	inputs := []ScanTarget{{EndpointURL: "https://example.test/other", Method: "GET"}}
	findings, err := r.RunModule(context.Background(), "php2shell", r.PendingTargets("php2shell", inputs))
	if !errors.Is(err, ErrModuleAssessmentInconclusive) || len(findings) != 0 || finished["status"] != "inconclusive" {
		t.Fatalf("unknown version treated as a negative finding: err=%v findings=%d outcome=%+v", err, len(findings), finished)
	}
	if pending := r.PendingTargets("php2shell", inputs); len(pending) != 0 || requests != 1 {
		t.Fatalf("inconclusive assessment would run again as a completed check: pending=%d requests=%d", len(pending), requests)
	}
}

func TestPHP2ShellPrefersActualVersionEvidenceOverEmptyIndex(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.Targets = []string{"https://example.test"}
	r := NewRunner("php-version-selection", nil, nil, nil, nil, nil, nil, cfg)
	defer r.Close()
	for _, indexStatus := range []int{200, 404} {
		root := &httpclient.RequestResponse{Response: httpclient.ResponseRecord{StatusCode: 200, Headers: map[string]string{"X-Powered-By": "PHP/8.3.35"}}}
		selected := r.php2ShellFullScanTargets([]ScanTarget{
			{EndpointURL: "https://example.test/", Method: "GET", ObservedResponse: root},
			{EndpointURL: "https://example.test/index.php", Method: "GET", ObservedResponse: &httpclient.RequestResponse{Response: httpclient.ResponseRecord{StatusCode: indexStatus}}},
		})
		if len(selected) != 1 || selected[0].ObservedResponse != root {
			t.Fatalf("PHP version evidence was discarded in favor of index status %d", indexStatus)
		}
	}
}
