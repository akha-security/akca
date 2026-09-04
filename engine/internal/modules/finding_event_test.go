package modules

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/verification"
)

type crossMethodProbeClient struct{}

func (crossMethodProbeClient) Do(_ context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	value := ""
	if strings.EqualFold(method, http.MethodGet) {
		if u, err := url.Parse(rawURL); err == nil {
			value = u.Query().Get("q")
		}
	} else {
		values, _ := url.ParseQuery(string(body))
		value = values.Get("q")
	}
	responseBody := "stable"
	if strings.Contains(value, "<svg") {
		responseBody = "reflected " + value
	}
	return httpclient.RequestResponse{
		Request: httpclient.RequestRecord{
			Method: method, URL: rawURL, Body: string(body), Headers: headers,
		},
		Response: httpclient.ResponseRecord{
			StatusCode: http.StatusOK, Body: responseBody,
			Headers: map[string]string{"Content-Type": "text/html"},
		},
	}, nil
}

func TestPersistFindingPublishesExactlyOneCanonicalEvent(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/module-finding-event.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureScan("scan-module-live"); err != nil {
		t.Fatal(err)
	}

	var events []map[string]interface{}
	runner := &Runner{
		scanID: "scan-module-live", db: db,
		emit: func(eventType, _ string, payload map[string]interface{}) error {
			if eventType == "finding_detected" {
				events = append(events, payload)
			}
			return nil
		},
	}
	finding := ModuleFinding{
		Title: "Advanced SQL injection", VulnClass: "sqli", Severity: "Critical",
		Description: "confirmed union signal", Endpoint: "https://example.test/items?id=1",
		Parameter: "id", Location: "query", Confidence: verification.Confirmed,
		Evidence: Evidence{
			Module: "sqli", Signal: "union_signal",
			Payload:  payloadgen.Payload{Value: "' UNION SELECT 1,2-- -", VulnClass: "sqli"},
			Request:  httpclient.RequestRecord{Method: "GET", URL: "https://example.test/items?id=1"},
			Response: httpclient.ResponseRecord{StatusCode: 200},
			Verification: verification.Result{
				Confidence: verification.Confirmed, Score: 0.95,
				ProofType:   verification.ProofDifferentialReplay,
				ProofPolicy: verification.CurrentProofPolicyVersion, ProofSatisfied: true,
				Observations: []verification.Observation{
					verification.NewHTTPObservation(
						"scan-module-live", "sqli", "https://example.test/items?id=1", "id", "query",
						verification.RolePositiveProbe, 1, "", "GET",
						"https://example.test/items?id=1", "", nil,
						verification.ResponseSnapshot{StatusCode: 200, Body: "union marker"},
					),
				},
			},
		},
	}
	if err := runner.persistFinding(finding); err != nil {
		t.Fatal(err)
	}

	findings, err := db.ListFindings("scan-module-live", 20, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || len(events) != 1 {
		t.Fatalf("persisted=%d live=%d, want exactly one of each", len(findings), len(events))
	}
	if events[0]["finding_id"] != findings[0].ID || events[0]["signal"] != "union_signal" {
		t.Fatalf("report/live mismatch: report=%+v live=%v", findings[0], events[0])
	}
}

func TestPersistFindingDeduplicatesPayloadVariantsOnSameSurface(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/module-finding-dedupe.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureScan("scan-module-dedupe"); err != nil {
		t.Fatal(err)
	}

	var events int
	runner := &Runner{
		scanID: "scan-module-dedupe", db: db,
		emit: func(eventType, _ string, _ map[string]interface{}) error {
			if eventType == "finding_detected" {
				events++
			}
			return nil
		},
	}
	base := ModuleFinding{
		Title: "OS Command Injection", VulnClass: "command_injection", Severity: "Critical",
		Description: "computed canary output", Endpoint: "https://example.test/rce/ping?host=127.0.0.1",
		Parameter: "host", Location: "form", Confidence: verification.HighConfidence,
		Evidence: Evidence{
			Module: "command_injection", Signal: "canary_output",
			Payload:   payloadgen.Payload{Value: ";printf AKCA_CMD_1", VulnClass: "command_injection"},
			Parameter: "host", Location: "form",
			Request:  httpclient.RequestRecord{Method: "POST", URL: "https://example.test/rce/ping?host=127.0.0.1"},
			Response: httpclient.ResponseRecord{StatusCode: 200},
			Verification: verification.Result{
				Confidence: verification.HighConfidence, Score: 0.80,
				ProofType:   verification.ProofDifferentialReplay,
				ProofPolicy: verification.CurrentProofPolicyVersion, ProofSatisfied: true,
				Observations: []verification.Observation{
					verification.NewHTTPObservation(
						"scan-module-dedupe", "command_injection", "https://example.test/rce/ping?host=127.0.0.1", "host", "form",
						verification.RolePositiveProbe, 1, "", "POST",
						"https://example.test/rce/ping?host=127.0.0.1", "host=;printf", nil,
						verification.ResponseSnapshot{StatusCode: 200, Body: "AKCA_CMD_1"},
					),
				},
			},
		},
	}
	if err := runner.persistFinding(base); err != nil {
		t.Fatal(err)
	}
	second := base
	second.Evidence.Payload.Value = "|printf AKCA_CMD_2"
	second.Evidence.Request.Body = "host=|printf"
	second.Evidence.Response.Body = "AKCA_CMD_2"
	second.Evidence.Verification.Observations = []verification.Observation{
		verification.NewHTTPObservation(
			"scan-module-dedupe", "command_injection", "https://example.test/rce/ping?host=127.0.0.1", "host", "form",
			verification.RolePositiveProbe, 2, "", "POST",
			"https://example.test/rce/ping?host=127.0.0.1", "host=|printf", nil,
			verification.ResponseSnapshot{StatusCode: 200, Body: "AKCA_CMD_2"},
		),
	}
	if err := runner.persistFinding(second); !errors.Is(err, errDuplicateFinding) {
		t.Fatalf("second payload error = %v, want duplicate sentinel", err)
	}

	findings, err := db.ListFindings("scan-module-dedupe", 20, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || events != 1 {
		t.Fatalf("persisted=%d live=%d, want one canonical finding/event", len(findings), events)
	}
	evidence, err := db.ListEvidenceRecords("scan-module-dedupe", 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) != 2 {
		t.Fatalf("evidence rows=%d, want canonical evidence plus payload variant", len(evidence))
	}
}

func TestPersistFindingDeduplicatesPayloadVariantsForParameterizedModules(t *testing.T) {
	for _, module := range []string{"sqli", "ssrf", "xss", "ssti"} {
		t.Run(module, func(t *testing.T) {
			db, err := storage.Open(t.TempDir() + "/module-surface-dedupe.db")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if err := db.Migrate(); err != nil {
				t.Fatal(err)
			}
			if err := db.EnsureScan("scan-surface-dedupe"); err != nil {
				t.Fatal(err)
			}
			runner := &Runner{scanID: "scan-surface-dedupe", db: db}
			first := testParameterizedFinding(module, "payload-one", "first_signal")
			if err := runner.persistFinding(first); err != nil {
				t.Fatal(err)
			}
			second := testParameterizedFinding(module, "payload-two", "second_signal")
			if err := runner.persistFinding(second); !errors.Is(err, errDuplicateFinding) {
				t.Fatalf("second %s payload error = %v, want duplicate sentinel", module, err)
			}
			findings, err := db.ListFindings("scan-surface-dedupe", 20, 0)
			if err != nil {
				t.Fatal(err)
			}
			if len(findings) != 1 {
				t.Fatalf("%s findings=%d, want one canonical finding", module, len(findings))
			}
		})
	}
}

func TestRecordFindingDoesNotInventPOSTMethodVariantAfterGETQueryFinding(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/module-cross-method.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureScan("scan-cross-method"); err != nil {
		t.Fatal(err)
	}

	payload := `"><svg/onload=alert(1)>`
	finding := ModuleFinding{
		Title: "Reflected XSS", VulnClass: "xss", Severity: "High",
		Description: "confirmed reflected xss", Endpoint: "https://example.test/search?q=1&lang=tr",
		Parameter: "q", Location: "query", Confidence: verification.HighConfidence,
		Evidence: Evidence{
			Module: "xss", Signal: "reflected",
			Payload:   payloadgen.Payload{Value: payload, VulnClass: "xss"},
			Parameter: "q", Location: "query",
			Request:  httpclient.RequestRecord{Method: http.MethodGet, URL: "https://example.test/search?q=" + url.QueryEscape(payload) + "&lang=tr"},
			Response: httpclient.ResponseRecord{StatusCode: http.StatusOK, Body: "reflected " + payload},
			Verification: verification.Result{
				Confidence: verification.HighConfidence, Score: 0.80,
				ProofType:   verification.ProofDifferentialReplay,
				ProofPolicy: verification.CurrentProofPolicyVersion, ProofSatisfied: true,
				Observations: []verification.Observation{
					verification.NewHTTPObservation(
						"scan-cross-method", "xss", "https://example.test/search?q=1&lang=tr", "q", "query",
						verification.RolePositiveProbe, 1, "", http.MethodGet,
						"https://example.test/search?q="+url.QueryEscape(payload)+"&lang=tr", "", nil,
						verification.ResponseSnapshot{StatusCode: http.StatusOK, Body: "reflected " + payload},
					),
				},
			},
		},
	}
	runner := &Runner{scanID: "scan-cross-method", db: db, client: crossMethodProbeClient{}}
	var out []ModuleFinding
	if !runner.recordFinding(context.Background(), &out, &finding, "xss", "reflected") {
		t.Fatal("expected finding to be recorded")
	}
	if len(out) != 1 {
		t.Fatalf("findings = %d, want one canonical GET finding", len(out))
	}
	if len(out[0].Evidence.MethodVariants) != 0 {
		t.Fatalf("method variants = %+v, want no fabricated POST form confirmation", out[0].Evidence.MethodVariants)
	}
}

func testParameterizedFinding(module, payloadValue, signal string) ModuleFinding {
	return ModuleFinding{
		Title: module + " finding", VulnClass: module, Severity: "High",
		Description: "confirmed parameterized module signal", Endpoint: "https://example.test/search?q=1",
		Parameter: "q", Location: "query", Confidence: verification.HighConfidence,
		Evidence: Evidence{
			Module: module, Signal: signal,
			Payload:   payloadgen.Payload{Value: payloadValue, VulnClass: module},
			Parameter: "q", Location: "query",
			Request:  httpclient.RequestRecord{Method: "GET", URL: "https://example.test/search?q=1"},
			Response: httpclient.ResponseRecord{StatusCode: 200},
			Verification: verification.Result{
				Confidence: verification.HighConfidence, Score: 0.80,
				ProofType:   verification.ProofDifferentialReplay,
				ProofPolicy: verification.CurrentProofPolicyVersion, ProofSatisfied: true,
				Observations: []verification.Observation{
					verification.NewHTTPObservation(
						"scan-surface-dedupe", module, "https://example.test/search?q=1", "q", "query",
						verification.RolePositiveProbe, 1, "", "GET",
						"https://example.test/search?q=1", "", nil,
						verification.ResponseSnapshot{StatusCode: 200, Body: payloadValue},
					),
				},
			},
		},
	}
}
