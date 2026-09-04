package modules

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/oast"
	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/verification"
)

func TestFinalizeOASTFindingsProcessesCallbacksBeyondFirstPage(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/oast-pages.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	const scanID = "scan-oast-pages"
	if err := db.EnsureScan(scanID); err != nil {
		t.Fatal(err)
	}

	registered := time.Now().UTC().Add(-time.Second)
	valid := oast.CallbackRecord{
		ScanID: scanID, PayloadID: "old-valid", Protocol: "http",
		Strength: oast.InteractionStrength("http"), ReceivedAt: time.Now().UTC(),
		Interaction: oast.Interaction{Protocol: "http", UniqueID: "old-token.oast.test"},
		Correlation: oast.Correlation{
			ScanID: scanID, PayloadID: "old-valid", CandidateID: "candidate-old",
			CorrelationToken: "old-token", Nonce: "nonce-old",
			EndpointURL: "https://target.test/fetch", Parameter: "url", Location: "query", VulnClass: "ssrf",
			CallbackURL: "https://old-token.oast.test/", RegisteredAt: registered,
		},
	}
	if err := db.SaveOASTCallback(scanID, valid.PayloadID, valid); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 500; i++ {
		_, err := db.Conn().Exec(`INSERT INTO oast_callbacks
(scan_id, payload_id, protocol, source_ip, callback_json, correlation_token, protocol_strength)
VALUES (?, ?, 'http', '', '{}', ?, 3)`, scanID, fmt.Sprintf("invalid-%d", i), fmt.Sprintf("invalid-token-%d", i))
		if err != nil {
			t.Fatal(err)
		}
	}

	findings, err := FinalizeOASTFindings(db, scanID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Evidence.Payload.Value == "" {
		t.Fatalf("old callback beyond first 500 rows was not finalized: %+v", findings)
	}
}

type oastDeliveryErrorClient struct {
	err error
}

func (c oastDeliveryErrorClient) Do(context.Context, string, string, []byte, map[string]string) (httpclient.RequestResponse, error) {
	return httpclient.RequestResponse{}, c.err
}

func TestStoredOASTCallbackRequiresFullCorrelation(t *testing.T) {
	registered := time.Now().UTC().Add(-time.Second)
	cb := oast.CallbackRecord{
		ScanID: "scan-1", PayloadID: "payload-1", Protocol: "dns", Strength: 1, ReceivedAt: time.Now().UTC(),
		Interaction: oast.Interaction{Protocol: "dns", UniqueID: "token-1.oast.test"},
		Correlation: oast.Correlation{
			ScanID: "scan-1", PayloadID: "payload-1", CandidateID: "candidate-1",
			CorrelationToken: "token-1", Nonce: "nonce-1",
			EndpointURL: "https://target.test/fetch", Location: "query", VulnClass: "ssrf",
			CallbackURL: "https://token-1.oast.test/", RegisteredAt: registered,
		},
	}
	rec := storage.OASTCallbackRecord{PayloadID: "payload-1", Protocol: "dns"}
	if !validStoredOASTCallback("scan-1", rec, cb) {
		t.Fatal("expected fully correlated callback to pass")
	}
	forged := cb
	forged.Correlation.ScanID = "scan-2"
	if validStoredOASTCallback("scan-1", rec, forged) {
		t.Fatal("cross-scan callback must be rejected")
	}
	forged = cb
	forged.Interaction.UniqueID = "unrelated.oast.test"
	if validStoredOASTCallback("scan-1", rec, forged) {
		t.Fatal("callback without the registered token must be rejected")
	}
}

func TestDNSOnlyOASTFindingIsDowngraded(t *testing.T) {
	cor := oast.Correlation{
		ScanID: "scan-1", PayloadID: "payload-1", EndpointURL: "https://target.test/fetch",
		Parameter: "url", VulnClass: "ssrf", CallbackURL: "https://token.oast.test/",
	}
	dns := buildOASTFinding(cor, storage.OASTCallbackRecord{Protocol: "dns"},
		oast.CallbackRecord{Protocol: "dns", ReceivedAt: time.Now().UTC()})
	httpFinding := buildOASTFinding(cor, storage.OASTCallbackRecord{Protocol: "http"},
		oast.CallbackRecord{Protocol: "http", ReceivedAt: time.Now().UTC()})
	if dns.Confidence != verification.HighConfidence || dns.Severity == "critical" {
		t.Fatalf("DNS-only SSRF must be downgraded: %+v", dns)
	}
	if httpFinding.Confidence != verification.Confirmed {
		t.Fatalf("HTTP callback should retain confirmed confidence: %+v", httpFinding)
	}
}

func TestOASTProbeFailureClassesAndNoticeDedup(t *testing.T) {
	if got := oastProbeFailureClass(errors.New("host circuit open until later")); got != "host_circuit_open" {
		t.Fatalf("unexpected failure class: %s", got)
	}
	if got := oastProbeFailureClass(&url.Error{Op: "Post", URL: "http://target.test/actuator", Err: io.EOF}); got != "connection_closed" {
		t.Fatalf("wrapped EOF failure class = %s, want connection_closed", got)
	}
	if got := oastProbeFailureClass(io.ErrUnexpectedEOF); got != "connection_closed" {
		t.Fatalf("unexpected EOF failure class = %s, want connection_closed", got)
	}
	if got := oastProbeFailureMessage("connection_closed"); got == "" || got == io.EOF.Error() {
		t.Fatalf("connection-close message must be human-readable: %q", got)
	}
	if oastProbeSafeToRetry("POST") {
		t.Fatal("POST OAST delivery must not be marked safe to retry")
	}
	if !oastProbeSafeToRetry("GET") {
		t.Fatal("GET OAST delivery should be marked safe to retry")
	}
	count := 0
	r := &Runner{
		notices: make(map[string]struct{}),
		emit: func(string, string, map[string]interface{}) error {
			count++
			return nil
		},
	}
	r.emitOnce("same", "coverage_gap", "message", nil)
	r.emitOnce("same", "coverage_gap", "message", nil)
	if count != 1 {
		t.Fatalf("duplicate notice should be emitted once, got %d", count)
	}
}

func TestSendOASTProbeReportsTargetEOFWithoutBlockingOAST(t *testing.T) {
	var eventType, message string
	var payload map[string]interface{}
	r := &Runner{
		client:  oastDeliveryErrorClient{err: &url.Error{Op: "Post", URL: "http://target.test/actuator", Err: io.EOF}},
		notices: make(map[string]struct{}),
		emit: func(gotType, gotMessage string, gotPayload map[string]interface{}) error {
			eventType, message, payload = gotType, gotMessage, gotPayload
			return nil
		},
	}
	r.sendOASTProbe(context.Background(), ScanTarget{
		EndpointURL: "http://target.test/actuator",
		Method:      "POST",
		Parameter:   "User-Agent",
		Location:    "header",
	}, "https://callback.oast.test/")

	if eventType != "oast_probe_failed" {
		t.Fatalf("event type = %q, want oast_probe_failed", eventType)
	}
	if payload["failure_scope"] != "target_delivery" || payload["failure_class"] != "connection_closed" {
		t.Fatalf("unexpected failure payload: %+v", payload)
	}
	if payload["method"] != "POST" || payload["safe_to_retry"] != false {
		t.Fatalf("POST retry policy was not preserved: %+v", payload)
	}
	if message == io.EOF.Error() || message == "" {
		t.Fatalf("delivery message must explain the coverage gap: %q", message)
	}
	if !strings.Contains(message, "automatic retry was skipped") {
		t.Fatalf("POST delivery message must explain retry policy: %q", message)
	}
	if r.oastDeliveryBlocked() {
		t.Fatal("one target EOF must not disable OAST delivery for the scan")
	}
}
