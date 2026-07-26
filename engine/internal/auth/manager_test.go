package auth

import (
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/secrets"
	"github.com/akha-security/akca/engine/internal/storage"
)

func TestPersistProfilesEncrypted(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/akca.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	m := NewManager(db, secrets.NewStore("encrypted_disk", dataDir))
	cfg := config.DefaultScanConfig()
	cfg.ScanID = "scan-auth"
	cfg.EnableEncryptedSecretStorage = true
	cfg.AuthProfiles = []config.AuthProfile{{
		ID: "a1", Name: "admin", Headers: map[string]string{"Authorization": "Bearer secret-token"},
	}}
	if err := m.PersistProfiles(cfg.ScanID, cfg); err != nil {
		t.Fatal(err)
	}
	rows, err := db.ListAuthProfileRecords(cfg.ScanID, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("expected 1 profile, got %d err=%v", len(rows), err)
	}
	loaded, err := m.LoadProfile(cfg.ScanID, "a1")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Headers["Authorization"] != "Bearer secret-token" {
		t.Fatalf("expected decrypted token, got %q", loaded.Headers["Authorization"])
	}
}

func TestDetectSessionExpiry(t *testing.T) {
	m := NewManager(nil, nil)
	if !m.DetectSessionExpiry(401, "") {
		t.Fatal("401 should signal expiry")
	}
	if !m.DetectSessionExpiry(200, "Your session expired, please login") {
		t.Fatal("body should signal expiry")
	}
}

func TestEncryptedReferencesAreScopedPerIdentity(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/identity-secrets.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(db, secrets.NewStore("encrypted_disk", t.TempDir()))
	cfg := config.DefaultScanConfig()
	cfg.AuthProfiles = []config.AuthProfile{
		{ID: "alice", Headers: map[string]string{"Authorization": "Bearer alice"}},
		{ID: "bob", Headers: map[string]string{"Authorization": "Bearer bob"}},
	}
	if err := manager.PersistProfiles("scan-identities", cfg); err != nil {
		t.Fatal(err)
	}
	alice, err := manager.LoadProfile("scan-identities", "alice")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := manager.LoadProfile("scan-identities", "bob")
	if err != nil {
		t.Fatal(err)
	}
	if alice.Headers["Authorization"] != "Bearer alice" ||
		bob.Headers["Authorization"] != "Bearer bob" {
		t.Fatalf("identity secrets crossed: alice=%q bob=%q",
			alice.Headers["Authorization"], bob.Headers["Authorization"])
	}
}

func TestCompareRolesClassification(t *testing.T) {
	cmp := RoleComparison{StatusA: 200, StatusB: 403, AccessControl: "potential_idor_bola"}
	if cmp.AccessControl != "potential_idor_bola" {
		t.Fatal("unexpected classification")
	}
}
