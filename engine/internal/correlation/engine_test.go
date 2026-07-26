package correlation

import (
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/storage"
)

func TestTemplateKey(t *testing.T) {
	got := templateKey("https://app.test/api/users/42/orders/7")
	if !strings.Contains(got, "{id}") {
		t.Fatalf("expected template id placeholder in %s", got)
	}
}

func TestCorrelationGroupsDuplicates(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/akca.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	scanID := "scan-corr"
	_ = db.EnsureScan(scanID)
	for _, ep := range []string{
		"https://app.test/users/1", "https://app.test/users/2", "https://app.test/users/3",
	} {
		if err := db.SeedFindingForTest(scanID, "IDOR", "high", "firm", "idor", "desc", ep); err != nil {
			t.Fatal(err)
		}
	}
	groups, err := NewEngine(db).Run(scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0].Count < 3 {
		t.Fatalf("expected one grouped root cause, got %+v", groups)
	}
}
