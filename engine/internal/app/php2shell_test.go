package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/events"
	"github.com/akha-security/akca/engine/internal/php2shell"
	"github.com/akha-security/akca/engine/internal/storage"
)

type php2ShellTransportFunc func(*http.Request) (*http.Response, error)

func (f php2ShellTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestPHP2ShellDedicatedPipelineChecksOnlyExplicitTargets(t *testing.T) {
	for _, tc := range []struct {
		name, banner, status string
		code                 int
		active               bool
		timeout              bool
		requests             int
	}{
		{name: "older_version", banner: "PHP/8.3.35", code: 200, status: "potential", requests: 1},
		{name: "fixed_version", banner: "PHP/8.3.36", code: 200, status: "fixed_version_observed", requests: 1},
		{name: "hidden_version", code: 200, status: "unknown", requests: 1},
		{name: "redirect_not_followed", code: 302, status: "unknown", requests: 1},
		{name: "blocked", code: 403, status: "blocked", requests: 1},
		{name: "connection_timeout", timeout: true, status: "unknown", requests: 1},
		{name: "active_lab", banner: "PHP/8.3.35", code: 200, status: "active_signal", active: true, requests: 3},
		{name: "active_retries_after_generic_5xx", banner: "PHP/8.3.35", code: 200, status: "active_signal", active: true, requests: 4},
		{name: "active_no_version_runs_all_probes", code: 200, status: "unknown", active: true, requests: 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			storage.SetDataDirOverride(t.TempDir())
			var output bytes.Buffer
			engine, err := New(events.NewNDJSONWriter(&output))
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			cfg := config.DefaultScanConfig()
			cfg.ScanID = "php2shell-" + tc.name
			cfg.Targets = []string{"http://127.0.0.1:8080/explicit/index.php"}
			cfg.SkipAutoReport = true
			cfg.PHP2ShellActive = tc.active
			if err := config.ApplyScanModes(&cfg, "php2shell"); err != nil {
				t.Fatal(err)
			}
			// A leftover API import must not be opened by dedicated mode.
			if !tc.active {
				cfg.APIImportFiles = []string{"not-a-real-api-spec.yaml"}
			}
			var mu sync.Mutex
			var requests []string
			cfg.TestRoundTripper = php2ShellTransportFunc(func(req *http.Request) (*http.Response, error) {
				mu.Lock()
				requests = append(requests, req.Method+" "+req.URL.String())
				count := len(requests)
				mu.Unlock()
				if tc.timeout {
					return nil, context.DeadlineExceeded
				}
				code := tc.code
				if tc.active && count > 2 && tc.name != "active_no_version_runs_all_probes" {
					code = 500
				}
				body := `<a href="/must-not-crawl">link</a><script src="/must-not-fetch.js"></script>`
				if tc.active && count > 2 && tc.name != "active_no_version_runs_all_probes" && !(tc.name == "active_retries_after_generic_5xx" && count == 3) {
					body = "Allowed memory size of 134217728 bytes exhausted (Unknown)"
				}
				return &http.Response{
					StatusCode: code,
					Header: http.Header{
						"X-Powered-By": []string{tc.banner},
						"Content-Type": []string{"text/html"},
						"Location":     []string{"/must-not-follow"},
					},
					Body:    io.NopCloser(strings.NewReader(body)),
					Request: req,
				}, nil
			})
			if err := engine.StartScan(cfg); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := engine.WaitScanDone(ctx); (err != nil) != tc.timeout {
				t.Fatalf("WaitScanDone error = %v, want error: %v", err, tc.timeout)
			}
			mu.Lock()
			gotRequests := append([]string(nil), requests...)
			mu.Unlock()
			if len(gotRequests) != tc.requests {
				t.Fatalf("requests = %v, want exactly %d direct requests", gotRequests, tc.requests)
			}
			for i, got := range gotRequests {
				method := "GET"
				if tc.active && i > 0 {
					method = "POST"
				}
				if want := method + " " + cfg.Targets[0]; got != want {
					t.Errorf("request = %s, want %s", got, want)
				}
			}
			evidence, err := engine.db.ListEvidenceRecords(cfg.ScanID, 100)
			if err != nil {
				t.Fatal(err)
			}
			assessments := 0
			for _, record := range evidence {
				if record.EvidenceType != "php2shell_assessment" {
					continue
				}
				assessments++
				var a php2shell.Assessment
				if err := json.Unmarshal([]byte(record.EvidenceJSON), &a); err != nil {
					t.Fatal(err)
				}
				if a.Status != tc.status {
					t.Errorf("assessment status = %s, want %s", a.Status, tc.status)
				}
			}
			if assessments != 1 {
				t.Errorf("assessments = %d, want 1", assessments)
			}
			findings, err := engine.db.ListFindings(cfg.ScanID, 100, 0)
			if err != nil {
				t.Fatal(err)
			}
			wantFinding := tc.status == "potential" || tc.status == "active_signal"
			if got := len(findings) > 0; got != wantFinding {
				t.Errorf("finding present = %v, want %v (findings=%d)", got, wantFinding, len(findings))
			}
			if err := engine.Close(); err != nil {
				t.Fatal(err)
			}
			for _, line := range strings.Split(strings.TrimSpace(output.String()), "\n") {
				var event events.Event
				if err := json.Unmarshal([]byte(line), &event); err != nil {
					t.Fatal(err)
				}
				if event.Type == "phase_started" {
					phase, _ := event.Payload["phase"].(string)
					if phase != "bootstrap" && phase != "vuln_module_php2shell" {
						t.Errorf("unexpected phase %q", phase)
					}
				}
			}
		})
	}
}
