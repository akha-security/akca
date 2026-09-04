package storage

import "testing"

func TestSecondOrderMarkersPersistAndDedupe(t *testing.T) {
	db, err := Open(t.TempDir() + "/markers.db")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatalf("migrate db: %v", err)
	}
	if err := db.SaveSecondOrderMarker("scan-a", "https://example.com/profile", "bio", "akca-stored-1"); err != nil {
		t.Fatalf("save marker: %v", err)
	}
	if err := db.SaveSecondOrderMarker("scan-a", "https://example.com/profile", "bio", "akca-stored-1"); err != nil {
		t.Fatalf("save duplicate marker: %v", err)
	}
	markers, err := db.ListSecondOrderMarkers("scan-a")
	if err != nil {
		t.Fatalf("list markers: %v", err)
	}
	if len(markers) != 1 {
		t.Fatalf("expected one deduped marker, got %+v", markers)
	}
	if markers[0].EndpointURL != "https://example.com/profile" || markers[0].Parameter != "bio" ||
		markers[0].Marker != "akca-stored-1" {
		t.Fatalf("unexpected marker: %+v", markers[0])
	}
}
