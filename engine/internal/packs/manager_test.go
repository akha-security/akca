package packs

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/akha-security/akca/engine/internal/storage"
)

func TestPackInstallRollback(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/akca.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	m := NewManager(db)
	payload := validBundleJSON("sqli")
	man, err := m.Install("rule", "stable", "1.1.0", payload)
	if err != nil {
		t.Fatal(err)
	}
	if !man.Compatible || man.PayloadSHA256 == "" || man.SignatureVerified {
		t.Fatal("manifest incomplete")
	}
	if _, err := m.Install("rule", "stable", "1.0.0", validBundleJSON("xss")); err != nil {
		t.Fatal(err)
	}
	if err := m.Rollback("rule", "stable", "1.1.0"); err != nil {
		t.Fatalf("rollback to installed artifact failed: %v", err)
	}
	loaded, restored, err := m.LoadActive("rule", "stable", "1.8.0")
	if err != nil || loaded.Version != "1.1.0" || restored != payload {
		t.Fatalf("offline rollback artifact mismatch: %+v %v", loaded, err)
	}
	if err := m.Rollback("rule", "stable", "0.9.0"); err == nil {
		t.Fatal("rollback to missing artifact must fail")
	}
	if _, err := db.Conn().Exec(`
UPDATE pack_artifacts SET payload = payload || 'tampered'
WHERE pack_type = 'rule' AND channel = 'stable' AND active = 1`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.LoadActive("rule", "stable", "1.8.0"); err == nil {
		t.Fatal("corrupted offline artifact must be rejected")
	}
	rows, err := m.Current("rule")
	if err != nil || len(rows) == 0 {
		t.Fatalf("expected versions: %v", err)
	}
}

func TestCompatibility(t *testing.T) {
	m := NewManager(nil)
	if !m.CheckCompatibility("1.1.0", "1.0.0") {
		t.Fatal("expected compatible")
	}
	if m.CheckCompatibility("2.0.0", "1.9.0") {
		t.Fatal("different compatibility major must be rejected")
	}
}

func TestSignedPackInstallRejectsTampering(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/signed.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager(db)
	if err := manager.TrustKey("release", base64.StdEncoding.EncodeToString(publicKey)); err != nil {
		t.Fatal(err)
	}
	payload := validBundleJSON("sqli")
	manifest := Manifest{
		PackType: "rule", Channel: "stable", Version: "1.2.0", Compatibility: "1.0.0",
		PayloadSHA256: payloadDigest(payload), KeyID: "release",
	}
	manifest.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, manifestSigningBytes(manifest)))
	installed, err := manager.InstallSigned(manifest, payload, "1.5.0")
	if err != nil || !installed.SignatureVerified {
		t.Fatalf("signed install failed: %+v %v", installed, err)
	}
	if _, err := manager.InstallSigned(manifest, payload+" ", "1.5.0"); err == nil {
		t.Fatal("tampered payload must be rejected")
	}
}

func validBundleJSON(id string) string {
	return `{
	  "sdk_version":"1.0.0",
	  "modules":[{
	    "manifest":{"id":"` + id + `","name":"Test rule","version":"1.0.0","compatibility":"1.0.0"},
	    "preconditions":{"methods":["GET"],"locations":["query","header"]},
	    "payload_families":[{"id":"default","payloads":[{"id":"probe","value":"akca-canary","risk_level":"safe"}]}],
	    "proof_policy":{"allowed_proof_types":["differential"],"confirmation_rules":["baseline_probe_control"],"minimum_attempts":2,"requires_control":true},
	    "controls":[{"id":"negative","type":"negative","value":"akca-control"}],
	    "report":{"title":"Test finding","description":"Differential proof","impact":"Impact","remediation":"Remediation"},
	    "tests":[{"kind":"positive","name":"vulnerable"},{"kind":"negative","name":"safe"},{"kind":"control","name":"control"}]
	  }]
	}`
}
