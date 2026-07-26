package checkpoint

import (
	"testing"

	"github.com/akha-security/akca/engine/internal/storage"
)

func TestCheckpointSaveLatest(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/akca.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	s := NewStore(db)
	_ = db.EnsureScan("scan-1")
	st := State{Phase: "crawling", Completed: []string{"bootstrap", "fingerprint"}}
	if err := s.Save("scan-1", st); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.Latest("scan-1")
	if err != nil || !ok {
		t.Fatalf("latest failed ok=%v err=%v", ok, err)
	}
	if got.Phase != "crawling" || got.Version != 1 {
		t.Fatalf("unexpected state: %+v", got)
	}
	if s.ResumeFromPhase(got) != "crawling" {
		t.Fatal("resume phase mismatch")
	}
}
