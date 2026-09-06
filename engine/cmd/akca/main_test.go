package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/akha-security/akca/engine/internal/events"
	"github.com/akha-security/akca/engine/internal/storage"
)

func TestVersionIsStableReleaseString(t *testing.T) {
	if version != "0.1.5" {
		t.Fatalf("version=%q, want 0.1.5", version)
	}
}

func TestUsageHelpAndVersionPrintBrandBanner(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"empty", nil},
		{"short_help", []string{"-h"}},
		{"long_help", []string{"--help"}},
		{"help_command", []string{"help"}},
		{"version_command", []string{"version"}},
		{"version_flag", []string{"--version"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code := 0
			stdout, stderr := captureCLIOutput(t, func() {
				code = runCLI(tc.args)
			})
			if code != 0 {
				t.Fatalf("runCLI(%v) exit=%d", tc.args, code)
			}
			combined := stdout + stderr
			if !strings.Contains(combined, akcaASCII[0]) {
				t.Fatalf("ASCII wordmark missing for %s: %q", tc.name, combined)
			}
			if !strings.Contains(combined, "AKCA ADVANCED WEB SECURITY SCANNER v0.1.5") {
				t.Fatalf("brand/version line missing for %s: %q", tc.name, combined)
			}
		})
	}
}

func TestOriginalBlockWordmarkAndSingleProductName(t *testing.T) {
	if len(akcaASCII) != 6 || akcaASCII[0] != ` █████╗ ██╗  ██╗ ██████╗ █████╗ ` || akcaASCII[5] != `╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝` {
		t.Fatalf("original six-line AKCA block wordmark changed: %#v", akcaASCII)
	}
	_, stderr := captureCLIOutput(t, printBanner)
	if got := strings.Count(stderr, "AKCA ADVANCED WEB SECURITY SCANNER"); got != 1 {
		t.Fatalf("product name rendered %d times in banner, want exactly once: %q", got, stderr)
	}
}

func captureCLIOutput(t *testing.T, fn func()) (stdout string, stderr string) {
	t.Helper()
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	dir := t.TempDir()
	stdoutFile, err := os.CreateTemp(dir, "stdout-*.log")
	if err != nil {
		t.Fatal(err)
	}
	stderrFile, err := os.CreateTemp(dir, "stderr-*.log")
	if err != nil {
		t.Fatal(err)
	}

	os.Stdout = stdoutFile
	os.Stderr = stderrFile
	defer func() {
		os.Stdout = oldStdout
		os.Stderr = oldStderr
		_ = stdoutFile.Close()
		_ = stderrFile.Close()
	}()

	fn()

	if _, err := stdoutFile.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := stderrFile.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	stdoutBytes, err := io.ReadAll(stdoutFile)
	if err != nil {
		t.Fatal(err)
	}
	stderrBytes, err := io.ReadAll(stderrFile)
	if err != nil {
		t.Fatal(err)
	}
	return string(stdoutBytes), string(stderrBytes)
}

func TestFindingStatusDoesNotCallManualReviewVerified(t *testing.T) {
	glyph, label, _, confirmed := findingStatus("NeedsManualReview")
	if confirmed || label != "MANUAL REVIEW" || glyph != "◇" {
		t.Fatalf("manual review status was mislabelled: glyph=%q label=%q confirmed=%v", glyph, label, confirmed)
	}

	glyph, label, _, confirmed = findingStatus("Confirmed")
	if !confirmed || label != "CONFIRMED" || glyph != "◆" {
		t.Fatalf("confirmed status was not represented as proven: glyph=%q label=%q confirmed=%v", glyph, label, confirmed)
	}

	glyph, label, _, confirmed = findingStatus("HighConfidence")
	if confirmed || label != "HIGH CONFIDENCE" || glyph != "◇" {
		t.Fatalf("high-confidence status was not represented live: glyph=%q label=%q confirmed=%v", glyph, label, confirmed)
	}
}

func TestFlagWasSetDistinguishesDefaultBoolFromExplicitChoice(t *testing.T) {
	fs := flag.NewFlagSet("akca", flag.ContinueOnError)
	var wafEvasion bool
	fs.BoolVar(&wafEvasion, "waf-evasion", false, "")
	if flagWasSet(fs, "waf-evasion") {
		t.Fatal("unset bool flag should not be reported as set")
	}
	if err := fs.Parse([]string{"--waf-evasion=false"}); err != nil {
		t.Fatal(err)
	}
	if !flagWasSet(fs, "waf-evasion") || wafEvasion {
		t.Fatalf("explicit false should be tracked without enabling: set=%v value=%v", flagWasSet(fs, "waf-evasion"), wafEvasion)
	}
}

func TestFindingProofExplainsTimingState(t *testing.T) {
	if got := findingProof("timing_differential", map[string]interface{}{"timing_confirmed": true}); got != "Paired timing controls passed" {
		t.Fatalf("confirmed timing proof = %q", got)
	}
	if got := findingProof("timing_differential", nil); got != "Timing signal requires manual reproduction" {
		t.Fatalf("manual timing proof = %q", got)
	}
}

func TestSessionOASTStatus(t *testing.T) {
	status, _ := sessionOASTStatus(map[string]interface{}{"oast_enabled": true})
	if status != "READY" {
		t.Fatalf("enabled OAST status = %q", status)
	}
	status, _ = sessionOASTStatus(map[string]interface{}{"oast_enabled": false})
	if status != "OFF" {
		t.Fatalf("disabled OAST status = %q", status)
	}
}

func TestOASTCallbackPanelIsStructuredAndDeduplicated(t *testing.T) {
	payload := map[string]interface{}{
		"protocol": "dns", "vuln_class": "command_injection",
		"endpoint": "http://burpbountylab.com/rce/blind?input=test", "parameter": "input",
	}
	panel := oastCallbackPanel(payload)
	for _, want := range []string{
		"OAST CALLBACK", "DNS CALLBACK", "OS Command Injection", "HIGH CONFIDENCE",
		"COMMAND_INJECTION", "http://burpbountylab.com/rce/blind?input=test",
		"Server-side DNS resolution observed",
	} {
		if !strings.Contains(panel, want) {
			t.Fatalf("OAST panel omitted %q: %q", want, panel)
		}
	}
	if strings.Contains(panel, "callbackCOMMAND") {
		t.Fatalf("OAST panel joined words without spacing: %q", panel)
	}

	cw := NewConsoleWriter()
	if !cw.acceptOASTCallback(payload) || cw.acceptOASTCallback(payload) {
		t.Fatal("identical OAST callback surface must be displayed once")
	}
	httpUpgrade := map[string]interface{}{}
	for key, value := range payload {
		httpUpgrade[key] = value
	}
	httpUpgrade["protocol"] = "http"
	if !cw.acceptOASTCallback(httpUpgrade) {
		t.Fatal("stronger HTTP callback must remain visible after DNS evidence")
	}
}

func TestScanSessionPanelIsCompactAndUsesStringTargets(t *testing.T) {
	panel := scanSessionPanel(map[string]interface{}{
		"targets":                []string{"http://example.test"},
		"global_rate_limit":      50.0,
		"max_pages":              1000,
		"max_endpoints":          1000,
		"crawler_request_budget": 1000,
		"payload_budget":         "unlimited",
		"scan_profile":           "FullBugBounty",
		"oast_enabled":           true,
	})
	for _, want := range []string{
		"http://example.test", "FullBugBounty", "50 req/s",
		"1000 URLs", "1000 crawler requests", "1000 endpoints", "Payloads", "unlimited", "OAST", "READY", "RUNNING",
	} {
		if !strings.Contains(panel, want) {
			t.Fatalf("session panel omitted %q: %q", want, panel)
		}
	}
	if strings.Contains(panel, "[OAST ACTIVE]") || strings.Contains(panel, "domain=") {
		t.Fatalf("legacy duplicate OAST banner leaked into session panel: %q", panel)
	}
	lines := strings.Split(strings.TrimSuffix(panel, "\n\n"), "\n")
	if len(lines) != 8 {
		t.Fatalf("session panel should remain compact, lines=%d: %q", len(lines), panel)
	}
	for _, line := range lines {
		if visibleLen(line) > uiWidth+4 {
			t.Fatalf("session panel line overflows (%d columns): %q", visibleLen(line), line)
		}
	}
}

func TestScanSessionLineIsStructuredAndShowsBudgets(t *testing.T) {
	line := scanSessionLine(map[string]interface{}{
		"targets": []string{"https://example.test"}, "scan_profile": "Full Scan",
		"max_pages": 1000, "max_endpoints": 1000, "crawler_request_budget": 1000,
		"request_budget": 0, "payload_budget": "unlimited", "memory_limit_mb": 4096,
	})
	for _, want := range []string{"SCAN START", "urls=1000", "endpoints=1000", "payloads=unlimited", "total_requests=unlimited", "memory=4096MB"} {
		if !strings.Contains(line, want) {
			t.Fatalf("structured session line omitted %q: %q", want, line)
		}
	}
}

func TestRunningStatusPanelShowsScanHealth(t *testing.T) {
	cw := NewConsoleWriter()
	cw.target = "http://example.test/"
	cw.scanProfile = "Full Scan"
	cw.oastEnabled = true
	cw.requestRate = 42.5
	cw.peakRequestRate = 52
	cw.urlsCrawled = 318
	cw.urlLimit = 1000
	cw.progressPercent = 50
	cw.processMemoryMB = 620
	cw.memoryLimitMB = 12_284
	cw.eta = "00:02:10"
	panel := cw.runningStatusPanel()
	for _, want := range []string{"LIVE SCAN", "RUNNING", "http://example.test/", "Full Scan", "42.5 req/s", "peak: 52.0", "Ready (Active)", "50%", "00:02:10", "318 / 1000 URLs", "620 / 12284 MB"} {
		if !strings.Contains(panel, want) {
			t.Fatalf("running panel omitted %q: %q", want, panel)
		}
	}
	if strings.Contains(panel, "⊡") {
		t.Fatalf("legacy health marker leaked into running panel: %q", panel)
	}
	for _, line := range strings.Split(panel, "\n") {
		if visibleLen(line) > uiWidth+4 {
			t.Fatalf("running panel line overflows (%d columns): %q", visibleLen(line), line)
		}
	}
}

func TestFindingCardUsesSeverityColorForEveryBorderSegment(t *testing.T) {
	enableColors()
	var output bytes.Buffer
	cw := NewConsoleWriter()
	cw.out = &output
	cw.interactive = true
	if err := cw.WriteEvent(events.Event{Type: "finding_detected", Payload: map[string]interface{}{
		"title": "Verified SQL injection", "severity": "High", "confidence": "Confirmed",
		"vuln_class": "sqli", "endpoint_url": "https://example.test/search", "method": "POST",
		"parameter": "query", "location": "body", "score": 0.99,
	}}); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(output.String()), "\n") {
		if !strings.Contains(line, boxV) {
			continue
		}
		if !strings.HasPrefix(line, bRose+boxV+rst) || !strings.HasSuffix(line, bRose+boxV+rst) {
			t.Fatalf("finding border is not fully severity-colored: %q", line)
		}
	}
}

func TestSilentCrawlerEventsDoNotEraseLiveStatus(t *testing.T) {
	var output bytes.Buffer
	cw := NewConsoleWriter()
	cw.out = &output
	cw.interactive = true
	cw.scanActive = true
	cw.progressLineOpen = true
	if err := cw.WriteEvent(events.Event{Type: "crawler_started"}); err != nil {
		t.Fatal(err)
	}
	if output.Len() != 0 || !cw.progressLineOpen {
		t.Fatalf("silent crawler event disturbed live status: output=%q open=%v", output.String(), cw.progressLineOpen)
	}
}

func TestLiveStatusIsAtomicallyReplaced(t *testing.T) {
	var output bytes.Buffer
	cw := NewConsoleWriter()
	cw.out = &output
	cw.interactive = true
	cw.scanActive = true
	cw.writeRunningStatus()
	cw.writeRunningStatus()
	got := output.String()
	if strings.Count(got, "\r") != 2 || strings.Contains(got, "\033[2K") || strings.Contains(got, "\033[K") {
		t.Fatalf("live status cleared the row before replacing it: %q", got)
	}
}

func TestScanProgressUsesPipelineStagesInsteadOfEndpointGuess(t *testing.T) {
	tests := []struct {
		name                                                        string
		phase                                                       string
		crawled, urlLimit, paramDone, paramTotal, modDone, modTotal int
		want                                                        int
	}{
		{name: "crawl", phase: "crawling", crawled: 89, urlLimit: 1000, want: 9},
		{name: "parameters", phase: "parameter_discovery", paramDone: 50, paramTotal: 100, want: 38},
		{name: "modules start", phase: "vuln_module_xss", modDone: 0, modTotal: 59, want: 48},
		{name: "modules middle", phase: "vuln_module_rate_limit", modDone: 30, modTotal: 59, want: 71},
		{name: "modules complete", phase: "vuln_module_backup_archives", modDone: 59, modTotal: 59, want: 95},
		{name: "oast", phase: "oast_drain", want: 97},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scanProgressPercent(tt.phase, tt.crawled, tt.urlLimit, false, tt.paramDone, tt.paramTotal, tt.modDone, tt.modTotal)
			if got != tt.want {
				t.Fatalf("progress=%d, want %d", got, tt.want)
			}
		})
	}
}

func TestETAUsesWholeScanProgress(t *testing.T) {
	now := time.Now()
	cw := NewConsoleWriter()
	cw.startTime = now.Add(-2 * time.Minute)
	cw.progressPercent = 20
	cw.updateETALocked(now)
	if cw.eta != "00:08:00" {
		t.Fatalf("ETA=%q, want 00:08:00", cw.eta)
	}
}

func TestRunningStatusUsesPortableSingleLine(t *testing.T) {
	var output bytes.Buffer
	cw := NewConsoleWriter()
	cw.out = &output
	cw.interactive = true
	cw.scanActive = true
	cw.target = "http://example.test/"
	cw.urlLimit = 1000

	cw.writeRunningStatus()
	got := output.String()
	if !strings.Contains(got, "RUN") || !strings.Contains(got, "0/1000 URLs") {
		t.Fatalf("single-line scan status was not rendered: %q", got)
	}
	if strings.Contains(got, "\033[999;1H") || strings.Contains(got, "\n") {
		t.Fatalf("status line used a fixed region or multiple lines: %q", got)
	}
}

func TestTerminalTextStripsControlSequencesAndBidiOverrides(t *testing.T) {
	input := "safe\x1b[31m-red\x1b[0m\x1b]0;owned\x07\u202Etxt\nnext"
	got := safeTerminalText(input)
	if got != "safe-redtxt next" {
		t.Fatalf("unsafe terminal text was not normalized: %q", got)
	}
}

func TestBoxTextClampsWideUnicodeToPanelWidth(t *testing.T) {
	line := boxText("測試測試測試測試 and a very long terminal value", 16)
	if got := visibleLen(line); got != 20 {
		t.Fatalf("panel line width=%d, want 20: %q", got, line)
	}
}

func TestPanelsRespectNarrowTerminalWidth(t *testing.T) {
	previous := activeUIWidth
	activeUIWidth = minUIWidth
	defer func() { activeUIWidth = previous }()

	panel := oastCallbackPanel(map[string]interface{}{
		"protocol": "http", "vuln_class": "ssrf",
		"endpoint": "https://example.test/a/very/long/path/that/must/not/overflow?next=another-long-value",
	})
	for _, line := range strings.Split(strings.TrimSpace(panel), "\n") {
		if visibleLen(line) > minUIWidth+4 {
			t.Fatalf("narrow panel overflowed (%d columns): %q", visibleLen(line), line)
		}
	}
}

func TestNormalizeScanArgsSupportsFlagsAfterLeadingTarget(t *testing.T) {
	got := normalizeScanArgs([]string{"https://example.test", "--mode", "sql"})
	want := []string{"--url", "https://example.test", "--mode", "sql"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("normalized args=%v, want %v", got, want)
	}
}

func TestInteractiveEventsRenderWithoutFixedCursorMovement(t *testing.T) {
	var output bytes.Buffer
	cw := NewConsoleWriter()
	cw.out = &output
	cw.interactive = true
	cw.scanActive = true

	err := cw.WriteEvent(events.Event{
		Type:    "phase_started",
		Message: "crawling",
		Payload: map[string]interface{}{"phase": "crawling"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := output.String()
	if strings.Contains(got, "\033[999;1H") {
		t.Fatalf("legacy scrolling event moved to a fixed dashboard cursor: %q", got)
	}
	if !strings.Contains(got, "Crawling") {
		t.Fatalf("phase event was not rendered: %q", got)
	}
}

func TestTrafficAdjustmentUsesTitleCaseAndDeduplicates(t *testing.T) {
	text := trafficAdjustmentText(map[string]interface{}{
		"global_rate_limit":    3,
		"per_host_rate_limit":  1,
		"max_concurrency":      4,
		"per_host_concurrency": 1,
	})
	if text != "Rate 3/s  Host 1/s  Workers 4/1" {
		t.Fatalf("unexpected traffic text: %q", text)
	}
	cw := NewConsoleWriter()
	if !cw.acceptTrafficUpdate(text) || cw.acceptTrafficUpdate(text) {
		t.Fatal("identical traffic update must be printed exactly once")
	}
}

func TestBenchmarkCommandWritesObservedJSON(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "benchmark.json")
	code := runBenchmarkCommand([]string{
		"--db", filepath.Join(dir, "benchmark.db"),
		"--output", output,
		"--strict",
	})
	if code != 0 {
		t.Fatalf("benchmark command exited with %d", code)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Results []struct {
			Scenario  string `json:"scenario"`
			Synthetic bool   `json:"synthetic_fixture"`
			Requests  int    `json:"requests"`
		} `json:"results"`
		QualityGate struct {
			Passed    bool            `json:"passed"`
			Synthetic bool            `json:"synthetic"`
			Checks    map[string]bool `json:"checks"`
		} `json:"quality_gate"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Results) == 0 || payload.QualityGate.Synthetic || !payload.QualityGate.Passed {
		t.Fatalf("benchmark output is not observed: %+v", payload)
	}
	for _, check := range []string{"request_budget", "duration_budget", "determinism", "goroutine_leak", "report_schema"} {
		if !payload.QualityGate.Checks[check] {
			t.Fatalf("benchmark operational check failed or is missing: %s", check)
		}
	}
	var aggregateRequests int
	for _, result := range payload.Results {
		if result.Synthetic {
			t.Fatalf("synthetic result leaked into observed benchmark: %+v", result)
		}
		if result.Scenario == "aggregate" {
			aggregateRequests = result.Requests
		}
	}
	if aggregateRequests == 0 {
		t.Fatal("observed aggregate request count is missing")
	}
}

func TestWriteReportCreatesMissingParentDirectories(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "reports", "scan.json")
	want := []byte(`{"ok":true}`)
	if err := writeReport(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("report=%q, want %q", got, want)
	}
}

func TestSubcommandHelpDoesNotInitializeRuntime(t *testing.T) {
	if code := runReplayCommand([]string{"--help"}); code != 0 {
		t.Fatalf("replay help exit code=%d", code)
	}
	if code := runBenchmarkCommand([]string{"--help"}); code != 0 {
		t.Fatalf("benchmark help exit code=%d", code)
	}
}

func TestCLIEndToEndPassiveScanWritesReport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><title>test</title></head><body><a href="/next">next</a></body></html>`))
	}))
	defer srv.Close()

	previousDataDir, err := storage.ResolveDataDir()
	if err != nil {
		t.Fatal(err)
	}
	storage.SetDataDirOverride(t.TempDir())
	defer storage.SetDataDirOverride(previousDataDir)

	reportPath := filepath.Join(t.TempDir(), "reports", "passive.json")
	code := runScanCommand([]string{
		"--url", srv.URL,
		"--mode", "passive",
		"--max-pages", "1",
		"--max-endpoints", "8",
		"--crawler-budget", "20",
		"--request-budget", "100",
		"--output", reportPath,
		"--format", "json",
		"--quiet",
	})
	if code != 0 {
		t.Fatalf("passive CLI scan exit code=%d", code)
	}
	raw, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]interface{}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("generated report is invalid JSON: %v", err)
	}
	if _, ok := document["scope"]; !ok {
		t.Fatal("generated report omitted scan scope metadata")
	}
}
