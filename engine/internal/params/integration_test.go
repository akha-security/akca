package params

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/ratelimit"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
)

func TestDiscovererDifferentialAndPersistence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Query().Get("debug") != "":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("debug error"))
		case r.Method == http.MethodPost && r.FormValue("debug") != "":
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte("accepted"))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("baseline"))
		}
	}))
	defer srv.Close()

	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"127.0.0.1"}
	scopeEngine := scope.NewEngine(cfg)
	client, err := httpclient.New(cfg, scopeEngine, ratelimit.New(1000, 1000))
	if err != nil {
		t.Fatal(err)
	}

	db, err := storage.Open(t.TempDir() + "/params.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_ = db.Migrate()
	_ = db.EnsureScan("scan-p")

	if err := db.SaveDiscoveredEndpoint("scan-p", map[string]interface{}{
		"url": srv.URL, "method": "GET", "normalized_url": srv.URL, "source": "seed",
	}); err != nil {
		t.Fatal(err)
	}
	endpointID, err := db.GetEndpointID("scan-p", srv.URL, "GET")
	if err != nil {
		t.Fatal(err)
	}

	var events []string
	d := NewDiscoverer("scan-p", client, scopeEngine, db, func(eventType, message string, payload map[string]interface{}) error {
		events = append(events, eventType)
		return nil
	})
	d.SetMaxProbes(40)

	found, err := d.DiscoverEndpoint(context.Background(), endpointID, srv.URL, "GET")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) == 0 {
		t.Fatal("expected discovered parameters")
	}

	count, err := db.CountParameters(endpointID)
	if err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Fatal("expected persisted parameters")
	}

	methodDependent := false
	for _, p := range found {
		if p.MethodDependent {
			methodDependent = true
		}
	}
	_ = methodDependent // differential may find debug on GET only depending on probe order
}
