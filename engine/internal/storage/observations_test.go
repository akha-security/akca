package storage

import (
	"path/filepath"
	"testing"
	"time"
)

func TestVerificationObservationLedgerRoundTrip(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "observations.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Conn().Exec(`INSERT INTO scans(id,status,config_json) VALUES ('scan-1','running','{}')`); err != nil {
		t.Fatal(err)
	}
	item := VerificationObservationRecord{
		ID: "obs-1", ScanID: "scan-1", Module: "sqli", Endpoint: "https://target.test/search",
		Parameter: "q", Location: "query", Role: "native_baseline", Attempt: 1,
		RequestMethod: "GET", RequestURL: "https://target.test/search?q=x",
		RequestHash: "req", ResponseHash: "resp", NormalizedHash: "norm",
		StatusCode: 200, ContentType: "application/json", DurationMs: 12, CreatedAt: time.Now().UTC(),
	}
	if err := db.SaveVerificationObservation(0, item); err != nil {
		t.Fatal(err)
	}
	got, err := db.ListVerificationObservations("scan-1", 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != item.ID || got[0].Role != item.Role {
		t.Fatalf("unexpected observation round trip: %+v", got)
	}
}
