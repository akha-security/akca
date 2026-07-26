package resilience

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/events"
	"github.com/akha-security/akca/engine/internal/session"
	"github.com/akha-security/akca/engine/internal/storage"
)

func TestFixtureScaleConstants(t *testing.T) {
	if len(GenerateEndpoints(TargetEndpoints)) != TargetEndpoints {
		t.Fatalf("expected %d endpoints", TargetEndpoints)
	}
}

func TestBulkEndpointPaginationAndSearch(t *testing.T) {
	if testing.Short() {
		t.Skip("massive fixture")
	}
	db, err := storage.Open(t.TempDir() + "/massive.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	urls := GenerateEndpoints(TargetEndpoints)
	if err := SeedEndpoints(db, "scan-ep", urls); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	var total int
	cursor := int64(0)
	for i := 0; i < 200; i++ {
		rows, next, err := db.ListEndpointsUI(storage.EndpointQuery{
			ScanID: "scan-ep", Limit: 500, Cursor: cursor,
		})
		if err != nil {
			t.Fatal(err)
		}
		total += len(rows)
		cursor = next
		if next == 0 {
			break
		}
	}
	if total < TargetEndpoints {
		t.Fatalf("paginated only %d endpoints", total)
	}
	searched, _, err := db.ListEndpointsUI(storage.EndpointQuery{
		ScanID: "scan-ep", Search: "resource/99999", Limit: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(searched) == 0 {
		t.Fatal("search should match endpoint")
	}
	if time.Since(start) > 60*time.Second {
		t.Fatalf("pagination too slow: %s", time.Since(start))
	}
}

func TestHighVolumeFuzzResults(t *testing.T) {
	if testing.Short() {
		t.Skip("massive fixture")
	}
	db, err := storage.Open(t.TempDir() + "/massive.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	const n = 50_000
	if err := SeedFuzzResults(db, "scan-fuzz", n); err != nil {
		t.Fatal(err)
	}
	rows, err := db.ListFuzzResultRecords("scan-fuzz", n+1)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != n {
		t.Fatalf("expected %d fuzz rows, got %d", n, len(rows))
	}
}

func TestEventStormBatching(t *testing.T) {
	if testing.Short() {
		t.Skip("massive fixture")
	}
	w := &countWriter{}
	b := events.NewBatcher(w, 500, 50*time.Millisecond)
	defer b.Close()

	for i := 0; i < TargetEvents; i++ {
		if err := b.Emit(events.Event{Type: "log", Message: "storm"}); err != nil {
			t.Fatal(err)
		}
	}
	_ = b.Flush()

	if w.totalEvents < TargetEvents {
		t.Fatalf("writer saw %d events, want %d", w.totalEvents, TargetEvents)
	}
	if w.batchCount == 0 {
		t.Fatal("expected batched event_batch emissions")
	}
	if w.batchCount >= TargetEvents {
		t.Fatalf("expected batching to reduce writes, got %d batches for %d events", w.batchCount, TargetEvents)
	}
}

func TestMalformedJSONEvents(t *testing.T) {
	raw := []string{
		`{broken`,
		`{"type":"log"}`,
		``,
		`{"ts":"x"}`,
		`{"type":"log","ts":"2026-01-01T00:00:00Z"}`,
		`not json at all`,
	}
	var valid, invalid int
	for _, line := range raw {
		if _, ok := ParseEventLine(line); ok {
			valid++
		} else {
			invalid++
		}
	}
	if valid != 1 {
		t.Fatalf("expected 1 valid event, got %d", valid)
	}
	if invalid != 5 {
		t.Fatalf("expected 5 invalid events, got %d", invalid)
	}
}

func TestBulkFindingPaginationAndFilter(t *testing.T) {
	if testing.Short() {
		t.Skip("massive fixture")
	}
	db, err := storage.Open(t.TempDir() + "/findings.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := SeedFindings(db, "scan-find", TargetFindings); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	var total int
	cursor := int64(0)
	for i := 0; i < 200; i++ {
		rows, next, err := db.ListFindingsUI(storage.FindingQuery{
			ScanID: "scan-find", Limit: 500, Cursor: cursor,
		})
		if err != nil {
			t.Fatal(err)
		}
		total += len(rows)
		cursor = next
		if next == 0 {
			break
		}
	}
	if total < TargetFindings {
		t.Fatalf("paginated only %d findings", total)
	}
	highOnly, _, err := db.ListFindingsUI(storage.FindingQuery{
		ScanID: "scan-find", Severities: []string{"high"}, Limit: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range highOnly {
		if row.Severity != "high" {
			t.Fatalf("filter leak: %s", row.Severity)
		}
	}
	searched, _, err := db.ListFindingsUI(storage.FindingQuery{
		ScanID: "scan-find", Search: "Finding 4242", Limit: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(searched) == 0 {
		t.Fatal("search should match finding title")
	}
	if time.Since(start) > 90*time.Second {
		t.Fatalf("finding pagination too slow: %s", time.Since(start))
	}
}

func TestOversizedPayloadBounded(t *testing.T) {
	payload := OversizedPayload(128 * 1024)
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > MaxPayloadBytes+4096 {
		t.Fatalf("payload exceeds bound: %d", len(raw))
	}
}

func TestSnapshotRecoveryAfterInterrupt(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.ScanID = "scan-snap"
	sess := session.NewScanSession(cfg)
	sess.Start()
	sess.SetPhase("crawling")
	sess.Increment("endpoints_discovered", 42_000)
	snap := sess.Snapshot()
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	var restored session.ScanSession
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.Phase != "crawling" {
		t.Fatalf("phase not restored: %s", restored.Phase)
	}
	if restored.Metrics["endpoints_discovered"] != 42_000 {
		t.Fatalf("metrics not restored: %v", restored.Metrics)
	}
}

func TestSlowSQLiteBackpressure(t *testing.T) {
	if testing.Short() {
		t.Skip("massive fixture")
	}
	db, err := storage.Open(t.TempDir() + "/slow.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	_ = db.EnsureScan("scan-slow")
	_, _ = db.Conn().Exec(`PRAGMA journal_mode = WAL`)
	var n int
	for i := 0; i < 4000; i++ {
		if err := db.SeedFindingForTest("scan-slow", "f", "low", "Potential", "xss", "d", fmt.Sprintf("https://x/%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	_ = db.Conn().QueryRow(`SELECT COUNT(*) FROM findings WHERE scan_id = 'scan-slow'`).Scan(&n)
	if n < 4000 {
		t.Fatalf("expected backpressure writes, got %d", n)
	}
}

type countWriter struct {
	totalEvents int
	batchCount  int
	mu          sync.Mutex
}

func (w *countWriter) WriteEvent(e events.Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if e.Type == "event_batch" {
		w.batchCount++
		if evts, ok := e.Payload["events"].([]events.Event); ok {
			w.totalEvents += len(evts)
			return nil
		}
	}
	w.totalEvents++
	return nil
}

func TestEvidenceLazyLoadNotEager(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/lazy.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	scanID := "scan-lazy"
	_ = db.EnsureScan(scanID)
	body := strings.Repeat("X", 32*1024)
	_, err = db.Conn().Exec(`INSERT INTO evidence (scan_id, evidence_type, evidence_json) VALUES (?, 'http', ?)`,
		scanID, `{"body":"`+body+`"}`)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := db.ListEvidenceLazy(scanID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("expected lazy list row")
	}
	for _, r := range rows {
		if len(r.Preview) > 200 {
			t.Fatal("lazy preview should be truncated")
		}
	}
}
