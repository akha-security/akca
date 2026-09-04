package oast

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/storage"
)

func TestInteractshFallbackUsesConfiguredOrderAndReportsSelection(t *testing.T) {
	var firstAttempts, secondAttempts int
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		firstAttempts++
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/register" {
			secondAttempts++
			_, _ = w.Write([]byte(`{"message":"registration successful"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer second.Close()

	var started map[string]interface{}
	listener, err := NewListener(nil, func(eventType, _ string, payload map[string]interface{}) error {
		if eventType == "oast_started" {
			started = payload
		}
		return nil
	}, Config{ServerURL: first.URL + "," + second.URL, PollInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer listener.Stop()

	if firstAttempts != 1 || secondAttempts != 1 {
		t.Fatalf("registration attempts = first:%d second:%d, want 1 each", firstAttempts, secondAttempts)
	}
	if got := started["active_server"]; got != second.URL {
		t.Fatalf("active server = %v, want %s", got, second.URL)
	}
	if got := started["selected_priority"]; got != 2 {
		t.Fatalf("selected priority = %v, want 2", got)
	}
	if got := started["fallback_used"]; got != true {
		t.Fatalf("fallback used = %v, want true", got)
	}
	if got := started["runtime_failover"]; got != false {
		t.Fatalf("runtime failover = %v, want false", got)
	}
}

func TestGenerateURLUniqueAndCorrelatable(t *testing.T) {
	p := NewLocalProvider()
	_ = p.Start()
	defer p.Stop()

	a, err := p.GenerateURL("payload-a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.GenerateURL("payload-b")
	if err != nil {
		t.Fatal(err)
	}
	if a.URL == b.URL {
		t.Fatal("urls must be unique")
	}
	if a.CorrelationToken == "" || b.CorrelationToken == "" {
		t.Fatal("expected correlation tokens")
	}
	c, err := p.GenerateURL("payload-a")
	if err != nil {
		t.Fatal(err)
	}
	if a.CorrelationToken == c.CorrelationToken {
		t.Fatal("repeated provider payload IDs must remain unique")
	}
}

func TestCallbackCorrelationAndPersistence(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/oast.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_ = db.Migrate()
	_ = db.EnsureScan("scan-o")
	_, _ = db.SaveFinding("scan-o", "blind ssrf", "Medium", "ssrf", "candidate", "http://example.com/fetch", "", 0.6, "")

	var received int
	listener, err := NewListener(db, func(eventType, _ string, _ map[string]interface{}) error {
		if eventType == "oast_callback_received" {
			received++
		}
		return nil
	}, Config{PollInterval: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := listener.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer listener.Stop()

	listener.SetScanID("scan-o")
	gen, err := listener.GenerateURL("pl-ssrf-1", "http://example.com/fetch", "url", "ssrf", 0)
	if err != nil {
		t.Fatal(err)
	}

	lp := listener.Provider().(*LocalProvider)
	lp.InjectInteraction(gen.CorrelationToken+"."+lp.Domain(), "dns", "10.0.0.5")

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		listener.pollOnce()
		if received > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if received == 0 {
		t.Fatal("expected oast_callback_received event")
	}

	count, err := db.CountOASTCallbacks("scan-o")
	if err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Fatal("expected persisted callback")
	}
}

func TestInteractshMockServerPolling(t *testing.T) {
	mock := NewMockInteractshServer()
	if err := mock.Start(); err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	provider := NewInteractshProvider(mock.URL)
	if err := provider.Start(); err != nil {
		t.Fatal(err)
	}
	defer provider.Stop()

	gen, err := provider.GenerateURL("xxe-1")
	if err != nil {
		t.Fatal(err)
	}
	mock.PushInteraction(Interaction{
		Protocol: "http", UniqueID: gen.CorrelationToken + "." + mock.Domain(),
		RemoteAddress: "203.0.113.1", Timestamp: time.Now().UTC(),
	})

	interactions, err := provider.Poll()
	if err != nil {
		t.Fatal(err)
	}
	if len(interactions) != 1 {
		t.Fatalf("expected 1 interaction, got %d", len(interactions))
	}
}

func TestMatchInteractionRejectsPayloadIDOnly(t *testing.T) {
	correlations := map[string]Correlation{
		"pl-1.corr": {PayloadID: "pl-1", ScanID: "scan-1"},
	}
	interaction := Interaction{UniqueID: "pl-1.other.oast.mock", Protocol: "dns"}
	c, ok := MatchInteraction(interaction, "oast.mock", correlations)
	if ok {
		t.Fatalf("payload ID alone must not correlate: %+v", c)
	}
}

func TestMatchInteractionRejectsWrongDomainSuffix(t *testing.T) {
	correlations := map[string]Correlation{
		"unique-token": {CorrelationToken: "unique-token", ScanID: "scan-1"},
	}
	interaction := Interaction{UniqueID: "unique-token.oast.mock.attacker.test", Protocol: "dns"}
	if c, ok := MatchInteraction(interaction, "oast.mock", correlations); ok {
		t.Fatalf("token on an attacker-controlled suffix must not correlate: %+v", c)
	}
}

func TestCallbackDoesNotUpgradeUnrelatedEndpointFinding(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/oast-up.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_ = db.Migrate()
	_ = db.EnsureScan("scan-u")
	_, _ = db.SaveFinding("scan-u", "blind xss", "Medium", "xss", "candidate", "http://example.com/q", "", 0.55, "")

	upgraded, err := db.UpgradeFindingConfidenceOAST(Correlation{
		ScanID: "scan-u", EndpointURL: "http://example.com/q", VulnClass: "xss", PayloadID: "pl-xss",
	})
	if err != nil {
		t.Fatal(err)
	}
	if upgraded {
		t.Fatal("callback without an exact finding and payload binding must not upgrade a finding")
	}
}

func TestBoundURLsRemainUniqueForRepeatedPayloadLabels(t *testing.T) {
	listener, err := NewListener(nil, func(string, string, map[string]interface{}) error { return nil }, Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.provider.Start(); err != nil {
		t.Fatal(err)
	}
	defer listener.provider.Stop()
	listener.SetScanID("scan-bound")
	binding := ProbeBinding{
		PayloadID: "same-payload", CandidateID: "candidate-a",
		EndpointURL: "https://target.test/a", Parameter: "url",
		Location: "header:x-forwarded-for", VulnClass: "ssrf",
	}
	first, err := listener.GenerateBoundURL(binding)
	if err != nil {
		t.Fatal(err)
	}
	binding.CandidateID = "candidate-b"
	binding.EndpointURL = "https://target.test/b"
	second, err := listener.GenerateBoundURL(binding)
	if err != nil {
		t.Fatal(err)
	}
	if first.CorrelationToken == second.CorrelationToken || first.Nonce == second.Nonce {
		t.Fatal("repeated payload labels must receive one-time correlation identities")
	}
	if listener.CorrelationCount() != 2 {
		t.Fatalf("expected two independent correlations, got %d", listener.CorrelationCount())
	}
}

func TestOldScanCallbackIsRejected(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/cross-scan.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	_ = db.EnsureScan("scan-old")
	_ = db.EnsureScan("scan-new")
	listener, _ := NewListener(db, func(string, string, map[string]interface{}) error { return nil }, Config{})
	if err := listener.provider.Start(); err != nil {
		t.Fatal(err)
	}
	defer listener.provider.Stop()
	listener.SetScanID("scan-old")
	gen, err := listener.GenerateBoundURL(ProbeBinding{
		PayloadID: "payload", CandidateID: "candidate", EndpointURL: "https://target.test/a",
		Parameter: "url", Location: "query", VulnClass: "ssrf",
	})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetScanID("scan-new")
	lp := listener.Provider().(*LocalProvider)
	lp.InjectInteraction(gen.CorrelationToken+"."+lp.Domain(), "http", "203.0.113.44")
	listener.pollOnce()
	count, err := db.CountOASTCallbacks("scan-new")
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("a delayed callback from a previous scan must not enter the active scan")
	}
}

func TestStrongerProtocolReplacesDNSCallback(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/strength.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	_ = db.EnsureScan("scan-strength")
	listener, _ := NewListener(db, func(string, string, map[string]interface{}) error { return nil }, Config{})
	if err := listener.provider.Start(); err != nil {
		t.Fatal(err)
	}
	defer listener.provider.Stop()
	listener.SetScanID("scan-strength")
	gen, err := listener.GenerateBoundURL(ProbeBinding{
		PayloadID: "payload", CandidateID: "candidate", EndpointURL: "https://target.test/a",
		Parameter: "url", Location: "query", VulnClass: "ssrf",
	})
	if err != nil {
		t.Fatal(err)
	}
	lp := listener.Provider().(*LocalProvider)
	identifier := gen.CorrelationToken + "." + lp.Domain()
	lp.InjectInteraction(identifier, "dns", "203.0.113.44")
	listener.pollOnce()
	lp.InjectInteraction(identifier, "http", "203.0.113.99")
	listener.pollOnce()
	records, err := db.ListOASTCallbackRecords("scan-strength", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Protocol != "http" {
		t.Fatalf("expected one strongest HTTP callback, got %+v", records)
	}
	if records[0].SourceIP != "203.0.113.0/24" {
		t.Fatalf("source IP was not privacy-redacted: %q", records[0].SourceIP)
	}
}

func TestDrainHonorsShortDeadline(t *testing.T) {
	listener, _ := NewListener(nil, func(string, string, map[string]interface{}) error { return nil },
		Config{PollInterval: time.Second})
	if err := listener.provider.Start(); err != nil {
		t.Fatal(err)
	}
	defer listener.provider.Stop()
	started := time.Now()
	listener.Drain(context.Background(), 30*time.Millisecond)
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("drain exceeded its configured deadline: %s", elapsed)
	}
}

func TestRemainingDrainDurationUsesNewestProbeTime(t *testing.T) {
	listener, _ := NewListener(nil, func(string, string, map[string]interface{}) error { return nil },
		Config{PollInterval: 150 * time.Millisecond})
	now := time.Now().UTC()
	if got := listener.RemainingDrainDuration(time.Minute); got != 0 {
		t.Fatalf("empty listener should not drain, got %s", got)
	}

	listener.RegisterCorrelation(Correlation{
		CorrelationToken: "recent",
		RegisteredAt:     now.Add(-55 * time.Second),
		ProbeSentAt:      now.Add(-50 * time.Second),
	})
	remaining := listener.RemainingDrainDuration(time.Minute)
	if remaining < 9*time.Second || remaining > 11*time.Second {
		t.Fatalf("remaining drain = %s, want about 10s", remaining)
	}

	listener.RegisterCorrelation(Correlation{
		CorrelationToken: "expired",
		RegisteredAt:     now.Add(-2 * time.Minute),
		ProbeSentAt:      now.Add(-90 * time.Second),
	})
	listener.mu.Lock()
	delete(listener.correlations, "recent")
	listener.mu.Unlock()
	remaining = listener.RemainingDrainDuration(time.Minute)
	if remaining <= 0 || remaining > 150*time.Millisecond {
		t.Fatalf("expired window should keep only one short final poll, got %s", remaining)
	}
}

func TestCallbackSanitizationPreservesRequestMetadata(t *testing.T) {
	correlation := sanitizeCorrelation(Correlation{
		EndpointURL: "https://target.test/fetch?token=endpoint-secret&view=1",
		Request: httpclient.RequestRecord{
			URL: "https://target.test/fetch?api_key=url-secret",
			Headers: map[string]string{
				"Cookie": "session=header-secret",
			},
			Body: `{"password":"body-secret"}`,
		},
	})
	serialized := correlation.EndpointURL + correlation.Request.URL +
		correlation.Request.Headers["Cookie"] + correlation.Request.Body
	for _, secret := range []string{"endpoint-secret", "url-secret", "header-secret", "body-secret"} {
		if !strings.Contains(serialized, secret) {
			t.Fatalf("callback correlation did not preserve %q", secret)
		}
	}
}

func TestInteractshSubdomainCorrelationMatching(t *testing.T) {
	correlations := map[string]Correlation{
		"ssrf-a1b2c3-nonce123": {PayloadID: "ssrf-a1b2c3", EndpointURL: "https://example.com/ssrf"},
		"ssrf-a1b2c3":          {PayloadID: "ssrf-a1b2c3", EndpointURL: "https://example.com/ssrf"},
	}

	interaction := Interaction{
		UniqueID: "c123456789",
		FullID:   "ssrf-a1b2c3-nonce123.c123456789",
		Protocol: "http",
	}

	c, ok := MatchInteraction(interaction, "c123456789.oast.fun", correlations)
	if !ok {
		t.Fatalf("MatchInteraction failed to match Interactsh subdomain callback")
	}
	if c.PayloadID != "ssrf-a1b2c3" {
		t.Fatalf("expected payload ID ssrf-a1b2c3, got %s", c.PayloadID)
	}
}
