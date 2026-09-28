package config

import "strings"

// InferRoleProfiles converts distinct explicitly supplied authentication
// profiles into role identities when the operator has not duplicated them in
// role_profiles. It never invents credentials, privileges or ownership rules;
// those remain explicit proof contracts.
func InferRoleProfiles(cfg *ScanConfig) int {
	if cfg == nil || len(cfg.RoleProfiles) > 0 || len(cfg.AuthProfiles) < 2 {
		return 0
	}
	seen := make(map[string]struct{})
	for _, profile := range cfg.AuthProfiles {
		id := strings.TrimSpace(profile.ID)
		if id == "" {
			continue
		}
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		seen[id] = struct{}{}
		name := strings.TrimSpace(profile.Name)
		if name == "" {
			name = id
		}
		cfg.RoleProfiles = append(cfg.RoleProfiles, RoleProfile{ID: "role-" + id, Name: name, AuthProfileID: id})
	}
	return len(cfg.RoleProfiles)
}
