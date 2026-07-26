package storage

import (
	"path/filepath"
	"testing"
)

func TestShadowAPIObservationsAndDiffsPersist(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "shadow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveDiscoveredEndpoint("scan-shadow", map[string]interface{}{
		"url": "https://api.test/v1/users/{id}", "method": "GET", "source": "api_import",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveDiscoveredEndpoint("scan-shadow", map[string]interface{}{
		"url": "https://api.test/v1/users/{id}", "method": "GET", "source": "browser_xhr",
	}); err != nil {
		t.Fatal(err)
	}
	observations, err := db.ListEndpointObservations("scan-shadow")
	if err != nil || len(observations) != 2 {
		t.Fatalf("endpoint sources were not retained: %+v err=%v", observations, err)
	}
	if err := db.ReplaceShadowAPIDiffs("scan-shadow", []ShadowAPIDiff{{
		Kind: "method_drift", Method: "PUT", Path: "api.test/v1/users/{param}",
		DocumentedMethod: "GET", ObservedMethod: "PUT", Source: "browser_xhr", Detail: "drift",
	}}); err != nil {
		t.Fatal(err)
	}
	rows, err := db.ListShadowAPIDiffs("scan-shadow", "method_drift", 10)
	if err != nil || len(rows) != 1 || rows[0].ObservedMethod != "PUT" {
		t.Fatalf("shadow API diff was not persisted: %+v err=%v", rows, err)
	}
}
