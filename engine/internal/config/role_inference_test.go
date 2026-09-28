package config

import "testing"

func TestInferRoleProfilesUsesOnlyExplicitDistinctAuthProfiles(t *testing.T) {
	cfg := DefaultScanConfig()
	cfg.AuthProfiles = []AuthProfile{{ID: "alice", Name: "User"}, {ID: "admin", Name: "Administrator"}}
	if count := InferRoleProfiles(&cfg); count != 2 {
		t.Fatalf("inferred roles=%d", count)
	}
	if cfg.RoleProfiles[0].AuthProfileID != "alice" || cfg.RoleProfiles[1].AuthProfileID != "admin" {
		t.Fatalf("role mapping=%+v", cfg.RoleProfiles)
	}
	if count := InferRoleProfiles(&cfg); count != 0 {
		t.Fatalf("explicit/inferred role profiles must not be overwritten: %d", count)
	}
}
