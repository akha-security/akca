package config

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultAndValidateEnums(t *testing.T) {
	cfg := DefaultScanConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config invalid: %v", err)
	}
	if cfg.PayloadBudget != PayloadBudgetUnlimited {
		t.Fatalf("expected unlimited payload budget, got %q", cfg.PayloadBudget)
	}
	if cfg.CredentialStorageMode != CredentialStorageEncryptedDisk {
		t.Fatalf("expected encrypted_disk")
	}
	if !cfg.RedactionEnabled {
		t.Fatal("default scans must redact sensitive HTTP evidence")
	}

	cfg.UserAgentMode = "bad"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid user agent mode error")
	}
	cfg.UserAgentMode = UserAgentCustom
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected custom mode without user agents to fail")
	}
	cfg.UserAgents = []string{"UA"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("custom mode should pass: %v", err)
	}

	cfg.PayloadBudget = "bad"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid payload budget")
	}
	cfg.CredentialStorageMode = "bad"
	cfg.PayloadBudget = PayloadBudgetMedium
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid credential storage mode")
	}
}

func TestAuthorizationPolicyValidation(t *testing.T) {
	cfg := DefaultScanConfig()
	cfg.AuthProfiles = []AuthProfile{{ID: "user"}, {ID: "admin"}}
	cfg.AuthorizationPolicies = []AuthorizationPolicy{{
		ID: "admin-enable", URLContains: "/admin/enable", Method: "POST",
		LowRoleProfileID: "user", HighRoleProfileID: "admin",
		ExpectedRolePolicy: "admin only", StateURL: "https://example.com/state",
		CleanupURL: "https://example.com/admin/disable", CleanupMethod: "POST",
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid authorization policy rejected: %v", err)
	}
	cfg.AuthorizationPolicies[0].HighRoleProfileID = "user"
	if err := cfg.Validate(); err == nil {
		t.Fatal("same low/high role must be rejected")
	}
}

func TestObjectAuthorizationPolicyRequiresDistinctRolesAndAnonymousControl(t *testing.T) {
	cfg := DefaultScanConfig()
	cfg.AuthProfiles = []AuthProfile{{ID: "alice-auth"}, {ID: "bob-auth"}}
	cfg.RoleProfiles = []RoleProfile{
		{ID: "alice", AuthProfileID: "alice-auth"},
		{ID: "bob", AuthProfileID: "bob-auth"},
	}
	cfg.ObjectAuthorizationPolicies = []ObjectAuthorizationPolicy{{
		ID: "owner-only", URLContains: "/accounts/", Method: http.MethodGet,
		Parameter: "id", Location: "path", OwnerRoleProfileID: "alice", ForeignRoleProfileID: "bob",
		ResourceValues: []string{"acct-7"}, ExpectedPolicy: "owner only", RequireAnonymousDeny: true,
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid object authorization policy rejected: %v", err)
	}
	cfg.ObjectAuthorizationPolicies[0].ForeignRoleProfileID = "alice"
	if err := cfg.Validate(); err == nil {
		t.Fatal("same owner/foreign role must be rejected")
	}
}

func TestRuntimeSensorRequiresLoopbackAndEnvironmentSecret(t *testing.T) {
	cfg := DefaultScanConfig()
	cfg.EnableRuntimeSensor = true
	cfg.RuntimeSensorTokenEnv = "AKCA_TEST_SENSOR_TOKEN"
	t.Setenv("AKCA_TEST_SENSOR_TOKEN", "0123456789abcdef")
	cfg.RuntimeSensorListenAddr = "127.0.0.1:0"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid loopback sensor config rejected: %v", err)
	}
	cfg.RuntimeSensorListenAddr = "0.0.0.0:19091"
	if err := cfg.Validate(); err == nil {
		t.Fatal("public runtime collector bind must be rejected")
	}
	cfg.RuntimeSensorListenAddr = "127.0.0.1:19091"
	cfg.RuntimeSensorTokenEnv = "AKCA_MISSING_SENSOR_TOKEN"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("missing token should use an ephemeral per-scan secret: %v", err)
	}
}

func TestConfigPersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scan.json")
	cfg := DefaultScanConfig()
	cfg.ScanID = "scan-1"
	cfg.Targets = []string{"https://example.com"}
	cfg.TimeBudget = 2 * time.Minute
	cfg.UserAgentMode = UserAgentRandom

	if err := Save(path, cfg); err != nil {
		t.Fatalf("save failed: %v", err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if loaded.ScanID != cfg.ScanID {
		t.Fatalf("scan id mismatch")
	}
	if loaded.TimeBudget != cfg.TimeBudget {
		t.Fatalf("time budget mismatch")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// On Windows FAT/network filesystems chmod is a no-op; skip the perm check there.
	if info.Mode().Perm()&0o077 != 0 {
		t.Logf("note: config file permissions %o – FAT/network FS may not support 0600", info.Mode().Perm())
	}
}
