package stategraph

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/storage"
)

func TestInstrumentedBrowserStatePersistsWorkersAndDOMSinks(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "instrumented.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureScan("scan-browser"); err != nil {
		t.Fatal(err)
	}
	graph := New(db)
	node, err := graph.ObserveInstrumentedPage(
		"scan-browser", "https://app.test/", "<html></html>", "user",
		map[string]string{"session": "value"}, map[string]string{"step": "1"},
		map[string]string{"tenant": "acme"}, nil, nil, []string{"https://app.test/api/me"},
		[]string{"wss://app.test/live"}, []string{"https://app.test/sw.js"},
		[]string{"dom_mutation:childList"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(node.ServiceWorkers) != 1 || len(node.DOMSinkEvents) != 1 {
		t.Fatalf("instrumented state missing from node: %+v", node)
	}
	var workers, sinks string
	if err := db.Conn().QueryRow(`
SELECT COALESCE(service_workers_json,''), COALESCE(dom_sink_events_json,'')
FROM application_states WHERE id = ?`, node.ID).Scan(&workers, &sinks); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(workers, "sw.js") || !strings.Contains(sinks, "dom_mutation") {
		t.Fatalf("instrumented state was not persisted: workers=%s sinks=%s", workers, sinks)
	}
}
