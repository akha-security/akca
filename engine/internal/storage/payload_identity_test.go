package storage

import (
	"strings"
	"testing"
)

func TestGeneratedPayloadsAreIsolatedByFullTargetIdentity(t *testing.T) {
	db, err := Open(t.TempDir() + "/identity.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.Migrate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ scan, method, location, marker string }{{"a", "GET", "query", "a-get"}, {"a", "POST", "query", "a-post"}, {"a", "POST", "json", "a-json"}, {"b", "GET", "query", "b-get"}} {
		if err := db.SaveGeneratedPayloads(tc.scan, "https://target.test", "id", map[string]string{"method": tc.method, "parameter_location": tc.location, "marker": tc.marker}); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct{ scan, method, location, marker string }{{"a", "GET", "query", "a-get"}, {"a", "POST", "query", "a-post"}, {"a", "POST", "json", "a-json"}, {"b", "GET", "query", "b-get"}} {
		raw, err := db.LoadGeneratedPayloadsJSON(tc.scan, tc.method, "https://target.test", "id", tc.location)
		if err != nil || !strings.Contains(raw, tc.marker) {
			t.Fatalf("identity crossed: %s %v", raw, err)
		}
	}
	if raw, err := db.LoadGeneratedPayloadsJSON("c", "GET", "https://target.test", "id", "query"); err == nil || raw != "" {
		t.Fatal("unknown scan loaded legacy/global payload")
	}
}
