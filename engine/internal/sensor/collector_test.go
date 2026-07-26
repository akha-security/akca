package sensor

import (
	"context"
	"testing"
	"time"
)

func runtimeEvent() Event {
	return Event{
		TraceID: "trace-1", RequestID: "req-1", ScanID: "scan-1", CandidateID: "candidate-1",
		Endpoint: "https://example.com/search", Parameter: "X-Forwarded-For", Platform: "node",
		Source:     Source{Kind: "header", Name: "X-Forwarded-For", Location: "header", Tainted: true},
		Sinks:      []Sink{{Type: "sql", Operation: "query", Tainted: true}},
		ObservedAt: time.Now().UTC(),
	}
}

func TestCollectorRequiresExactRequestCandidateBinding(t *testing.T) {
	collector := NewCollector("secret", nil)
	if err := collector.Register(Binding{
		RequestID: "req-1", ScanID: "scan-1", CandidateID: "candidate-1",
		Endpoint: "https://example.com/search", Parameter: "X-Forwarded-For", Location: "header",
	}); err != nil {
		t.Fatal(err)
	}
	assessment, err := collector.Ingest(runtimeEvent())
	if err != nil || !assessment.Vulnerable {
		t.Fatalf("expected correlated unsafe SQL sink: %+v %v", assessment, err)
	}
	crossScan := runtimeEvent()
	crossScan.ScanID = "scan-2"
	if _, err := collector.Ingest(crossScan); err == nil {
		t.Fatal("cross-scan runtime trace must be rejected")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	event, awaited, ok := collector.Await(ctx, "req-1")
	if !ok || !awaited.Vulnerable || event.Sinks[0].Target != "" {
		t.Fatalf("correlated trace was not available to the DAST verifier: %+v %+v", event, awaited)
	}
}

func TestParameterizedSQLIsSafeEvidence(t *testing.T) {
	event := runtimeEvent()
	event.Sinks[0].Parameterized = true
	assessment := Assess(event)
	if !assessment.Safe || assessment.Vulnerable {
		t.Fatalf("expected parameterized bind safe evidence: %+v", assessment)
	}
}

func TestSanitizedNonSQLSinkIsSafeEvidence(t *testing.T) {
	assessment := Assess(Event{
		Source: Source{Tainted: true},
		Sinks:  []Sink{{Type: "command", Tainted: true, Sanitized: true}},
	})
	if !assessment.Safe || assessment.Vulnerable || assessment.Sink == nil ||
		assessment.Sink.Type != "command" {
		t.Fatalf("sanitized command sink was not retained as safe typed evidence: %+v", assessment)
	}
}

func TestRuntimeTraceTargetAndStackAreRedacted(t *testing.T) {
	collector := NewCollector("secret", nil)
	if err := collector.Register(Binding{
		RequestID: "req-1", ScanID: "scan-1", CandidateID: "candidate-1",
		Endpoint: "https://example.com/search", Parameter: "X-Forwarded-For", Location: "header",
	}); err != nil {
		t.Fatal(err)
	}
	event := runtimeEvent()
	event.Sinks[0].Target = "SELECT * FROM audit WHERE ip='secret-payload'"
	event.Sinks[0].Stack = []string{"/srv/private/app.js:42"}
	if _, err := collector.Ingest(event); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	stored, _, ok := collector.Await(ctx, "req-1")
	if !ok || stored.Sinks[0].Target == event.Sinks[0].Target ||
		stored.Sinks[0].Stack[0] == event.Sinks[0].Stack[0] {
		t.Fatalf("sensitive runtime metadata was not redacted: %+v", stored.Sinks[0])
	}
}

func TestCollectorActivatesOnlyDiscoveredEndpointHost(t *testing.T) {
	collector := NewCollector("0123456789abcdef", nil)
	if collector.ActiveFor("https://app.test/search") {
		t.Fatal("collector must be inactive before agent discovery")
	}
	collector.ActivateEndpoint("https://app.test/")
	if !collector.ActiveFor("https://app.test/search") {
		t.Fatal("agent discovery should activate correlation for the same host")
	}
	if collector.ActiveFor("https://other.test/search") {
		t.Fatal("agent activation must remain host scoped")
	}
}
