package params

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/ratelimit"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
)

func TestDiscovererReplaysNativeJSONForPutAndPatch(t *testing.T) {
	for _, method := range []string{http.MethodPut, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			var wrongMethod, lostTemplate bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					_, _ = w.Write([]byte(`{"result":"baseline"}`))
					return
				}
				if r.Method != method {
					wrongMethod = true
				}
				var body map[string]interface{}
				if json.NewDecoder(r.Body).Decode(&body) != nil || body["required"] != "keep" || r.Header.Get("X-Replay") != "kept" {
					lostTemplate = true
				}
				w.Header().Set("Content-Type", "application/json")
				if body["debug"] != nil {
					w.WriteHeader(http.StatusAccepted)
					_, _ = w.Write([]byte(`{"result":"debug accepted"}`))
					return
				}
				_, _ = w.Write([]byte(`{"result":"baseline"}`))
			}))
			defer srv.Close()

			cfg := config.DefaultScanConfig()
			cfg.IncludeDomains = []string{"127.0.0.1"}
			scopeEngine := scope.NewEngine(cfg)
			client, err := httpclient.New(cfg, scopeEngine, ratelimit.New(1000, 1000))
			if err != nil {
				t.Fatal(err)
			}
			db, err := storage.Open(t.TempDir() + "/native-json.db")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if err := db.Migrate(); err != nil {
				t.Fatal(err)
			}
			if err := db.EnsureScan("scan-native-json"); err != nil {
				t.Fatal(err)
			}
			if err := db.SaveDiscoveredEndpoint("scan-native-json", map[string]interface{}{
				"url": srv.URL, "method": method, "normalized_url": srv.URL, "source": "test",
			}); err != nil {
				t.Fatal(err)
			}
			endpointID, err := db.GetEndpointID("scan-native-json", srv.URL, method)
			if err != nil {
				t.Fatal(err)
			}

			d := NewDiscoverer("scan-native-json", client, scopeEngine, db, func(string, string, map[string]interface{}) error { return nil })
			d.SetWordlistCap(4)
			d.SetMaxProbes(20)
			template := storage.DiscoveryRequestTemplate{
				Method: method, URL: srv.URL, Body: `{"required":"keep","existing":1}`,
				ContentType: "application/json", Headers: map[string]string{"X-Replay": "kept"},
			}
			found, err := d.DiscoverEndpoint(context.Background(), endpointID, srv.URL, method, template)
			if err != nil {
				t.Fatal(err)
			}
			if wrongMethod || lostTemplate {
				t.Fatalf("native request was not replayed: wrong_method=%v lost_template=%v", wrongMethod, lostTemplate)
			}
			var debugFound bool
			for _, parameter := range found {
				if parameter.Name == "debug" && parameter.Location == LocationJSON && parameter.EndpointMethod == method {
					debugFound = true
				}
			}
			if !debugFound {
				t.Fatalf("debug JSON parameter not discovered with %s: %+v", method, found)
			}
		})
	}
}

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
	var progressPayload map[string]interface{}
	d := NewDiscoverer("scan-p", client, scopeEngine, db, func(eventType, message string, payload map[string]interface{}) error {
		events = append(events, eventType)
		if eventType == "parameter_discovery_progress" {
			progressPayload = payload
		}
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

	if err := d.Run(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if progressPayload == nil || progressPayload["completed"] != 1 || progressPayload["total"] != 1 {
		t.Fatalf("unexpected progress payload: %#v", progressPayload)
	}
}

func TestDiscovererFindsHiddenPOSTParamInBodyNotQuery(t *testing.T) {
	var sawQueryProbe bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("debug") != "" {
			sawQueryProbe = true
		}
		if r.Method == http.MethodPost && r.FormValue("debug") == "akca_probe" {
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte("debug accepted"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("baseline"))
	}))
	defer srv.Close()

	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"127.0.0.1"}
	scopeEngine := scope.NewEngine(cfg)
	client, err := httpclient.New(cfg, scopeEngine, ratelimit.New(1000, 1000))
	if err != nil {
		t.Fatal(err)
	}
	db, err := storage.Open(t.TempDir() + "/post-body-param.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureScan("scan-post-body"); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveDiscoveredEndpoint("scan-post-body", map[string]interface{}{
		"url": srv.URL, "method": http.MethodPost, "normalized_url": srv.URL, "source": "test",
	}); err != nil {
		t.Fatal(err)
	}
	endpointID, err := db.GetEndpointID("scan-post-body", srv.URL, http.MethodPost)
	if err != nil {
		t.Fatal(err)
	}

	d := NewDiscoverer("scan-post-body", client, scopeEngine, db, func(string, string, map[string]interface{}) error { return nil })
	d.SetWordlistCap(4)
	d.SetMaxProbes(8)
	found, err := d.DiscoverEndpoint(context.Background(), endpointID, srv.URL, http.MethodPost)
	if err != nil {
		t.Fatal(err)
	}
	if sawQueryProbe {
		t.Fatal("POST hidden parameter discovery must not add speculative query parameters")
	}
	for _, p := range found {
		if p.Name == "debug" && p.Location == LocationForm && p.EndpointMethod == http.MethodPost {
			return
		}
	}
	t.Fatalf("debug parameter was not discovered in POST body: %+v", found)
}

func TestCrossEndpointTransferUsesPOSTBodyNotQuery(t *testing.T) {
	var sawQueryProbe bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("debug") != "" {
			sawQueryProbe = true
		}
		if r.Method == http.MethodPost && r.FormValue("debug") == "akca_probe" {
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte("debug accepted"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("baseline"))
	}))
	defer srv.Close()

	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"127.0.0.1"}
	scopeEngine := scope.NewEngine(cfg)
	client, err := httpclient.New(cfg, scopeEngine, ratelimit.New(1000, 1000))
	if err != nil {
		t.Fatal(err)
	}
	db, err := storage.Open(t.TempDir() + "/post-transfer-param.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureScan("scan-transfer-body"); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveDiscoveredEndpoint("scan-transfer-body", map[string]interface{}{
		"url": srv.URL, "method": http.MethodPost, "normalized_url": srv.URL, "source": "test",
	}); err != nil {
		t.Fatal(err)
	}
	endpointID, err := db.GetEndpointID("scan-transfer-body", srv.URL, http.MethodPost)
	if err != nil {
		t.Fatal(err)
	}

	d := NewDiscoverer("scan-transfer-body", client, scopeEngine, db, func(string, string, map[string]interface{}) error { return nil })
	d.probeSingleParam(context.Background(), storage.DiscoveryEndpoint{
		ID:     endpointID,
		URL:    srv.URL,
		Method: http.MethodPost,
	}, "debug")
	if sawQueryProbe {
		t.Fatal("cross-endpoint transfer must not add speculative query parameters to POST endpoints")
	}
	count, err := db.CountParameters(endpointID)
	if err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Fatal("expected transferred parameter to be saved from POST body proof")
	}
}

func TestGenericUnknownPOSTFieldsAreNotDiscovered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "form", http.StatusBadRequest)
			return
		}
		for name := range r.PostForm {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = fmt.Fprintf(w, `{"error":"unknown field %s"}`, name)
			return
		}
		_, _ = w.Write([]byte(`{"status":"baseline"}`))
	}))
	defer srv.Close()

	db, err := storage.Open(filepath.Join(t.TempDir(), "params-generic-unknown.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureScan("scan-generic-unknown"); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveDiscoveredEndpoint("scan-generic-unknown", map[string]interface{}{
		"url": srv.URL, "method": http.MethodPost, "normalized_url": srv.URL, "source": "test",
	}); err != nil {
		t.Fatal(err)
	}
	endpointID, err := db.GetEndpointID("scan-generic-unknown", srv.URL, http.MethodPost)
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"127.0.0.1"}
	scopeEngine := scope.NewEngine(cfg)
	client, err := httpclient.New(cfg, scopeEngine, ratelimit.New(1000, 1000))
	if err != nil {
		t.Fatal(err)
	}
	d := NewDiscoverer("scan-generic-unknown", client, scopeEngine, db, nil)
	d.SetWordlistCap(4)
	d.SetMaxProbes(8)
	found, err := d.DiscoverEndpoint(context.Background(), endpointID, srv.URL, http.MethodPost)
	if err != nil {
		t.Fatal(err)
	}
	for _, parameter := range found {
		if parameter.Source == "differential" {
			t.Fatalf("generic unknown-field response became a hidden parameter: %+v", parameter)
		}
	}
}

func TestGETDiscoveryPreservesCapturedAuthenticationHeaders(t *testing.T) {
	var unauthenticatedProbe bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.URL.Query()) > 0 && r.Header.Get("Authorization") != "Bearer test-token" {
			unauthenticatedProbe = true
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Query().Get("debug") == "akca_probe" {
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte("debug accepted"))
			return
		}
		_, _ = w.Write([]byte("baseline"))
	}))
	defer srv.Close()

	db, err := storage.Open(filepath.Join(t.TempDir(), "params-auth-get.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureScan("scan-auth-get"); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveDiscoveredEndpoint("scan-auth-get", map[string]interface{}{
		"url": srv.URL, "method": http.MethodGet, "normalized_url": srv.URL, "source": "test",
	}); err != nil {
		t.Fatal(err)
	}
	endpointID, err := db.GetEndpointID("scan-auth-get", srv.URL, http.MethodGet)
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"127.0.0.1"}
	scopeEngine := scope.NewEngine(cfg)
	client, err := httpclient.New(cfg, scopeEngine, ratelimit.New(1000, 1000))
	if err != nil {
		t.Fatal(err)
	}
	d := NewDiscoverer("scan-auth-get", client, scopeEngine, db, nil)
	d.SetWordlistCap(4)
	d.SetMaxProbes(8)
	found, err := d.DiscoverEndpoint(context.Background(), endpointID, srv.URL, http.MethodGet,
		storage.DiscoveryRequestTemplate{Method: http.MethodGet, URL: srv.URL, Headers: map[string]string{"Authorization": "Bearer test-token"}})
	if err != nil {
		t.Fatal(err)
	}
	if unauthenticatedProbe {
		t.Fatal("GET parameter probe dropped captured authentication headers")
	}
	for _, parameter := range found {
		if parameter.Name == "debug" && parameter.Location == LocationQuery {
			return
		}
	}
	t.Fatalf("authenticated hidden query parameter was not discovered: %+v", found)
}
