package stategraph

import (
	"path/filepath"
	"testing"

	"github.com/akha-security/akca/engine/internal/storage"
)

func TestGraphPersistsIdentityIsolatedStatesAndTransition(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "graph.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureScan("scan-1"); err != nil {
		t.Fatal(err)
	}
	graph := New(db)
	anonymous, err := graph.ObservePage("scan-1", "https://app.test/dashboard", `<p>login</p>`, "anonymous", nil)
	if err != nil {
		t.Fatal(err)
	}
	user, err := graph.ObservePage("scan-1", "https://app.test/dashboard", `<p nonce="random">hello user</p>`,
		"user-a", []string{"https://app.test/api/me"})
	if err != nil {
		t.Fatal(err)
	}
	if anonymous.ID == user.ID {
		t.Fatal("different identities must produce isolated state nodes")
	}
	if _, err := graph.AddTransition("scan-1", anonymous.ID, user.ID, "submit_login", map[string]string{"method": "POST"}, nil, nil, false); err != nil {
		t.Fatal(err)
	}
	var nodes, edges int
	if err := db.Conn().QueryRow(`SELECT COUNT(*) FROM application_states`).Scan(&nodes); err != nil {
		t.Fatal(err)
	}
	if err := db.Conn().QueryRow(`SELECT COUNT(*) FROM state_transitions`).Scan(&edges); err != nil {
		t.Fatal(err)
	}
	if nodes != 2 || edges != 1 {
		t.Fatalf("unexpected persisted graph: nodes=%d edges=%d", nodes, edges)
	}
}

func TestDOMFingerprintMasksVolatileValues(t *testing.T) {
	a := DOMFingerprint(`<div nonce="abc">2026-01-01T00:00:00Z</div>`)
	b := DOMFingerprint(`<div nonce="xyz">2026-02-02T00:00:00Z</div>`)
	if a != b {
		t.Fatal("volatile DOM values should not create different states")
	}
}
