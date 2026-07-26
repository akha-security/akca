package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/secrets"
	"github.com/akha-security/akca/engine/internal/storage"
)

type Manager struct {
	db      *storage.DB
	secrets *secrets.Store
}

func NewManager(db *storage.DB, secretStore *secrets.Store) *Manager {
	return &Manager{db: db, secrets: secretStore}
}

type RoleComparison struct {
	URL           string `json:"url"`
	RoleA         string `json:"role_a"`
	RoleB         string `json:"role_b"`
	StatusA       int    `json:"status_a"`
	StatusB       int    `json:"status_b"`
	AccessControl string `json:"access_control"`
	Notes         string `json:"notes"`
}

func (m *Manager) PersistProfiles(scanID string, cfg config.ScanConfig) error {
	for _, p := range cfg.AuthProfiles {
		headers := map[string]string{}
		cookies := map[string]string{}
		for k, v := range p.Headers {
			if m.secrets != nil && cfg.EnableEncryptedSecretStorage && isSensitiveHeader(k) {
				secretKey := p.ID + ":header:" + k
				ref, err := m.secrets.Put(scanID+":"+secretKey, []byte(v))
				if err == nil {
					headers[k] = "[encrypted:" + secretKey + "]"
					_ = m.db.SaveEncryptedSecretRef(scanID, secretKey, ref)
				} else {
					headers[k] = m.secrets.RedactValue(v)
				}
			} else {
				headers[k] = v
			}
		}
		for k, v := range p.Cookies {
			if m.secrets != nil && cfg.EnableEncryptedSecretStorage {
				secretKey := p.ID + ":cookie:" + k
				ref, err := m.secrets.Put(scanID+":"+secretKey, []byte(v))
				if err == nil {
					cookies[k] = "[encrypted:" + secretKey + "]"
					_ = m.db.SaveEncryptedSecretRef(scanID, secretKey, ref)
				} else {
					cookies[k] = m.secrets.RedactValue(v)
				}
			} else {
				cookies[k] = v
			}
		}
		profile := map[string]interface{}{"headers": headers, "cookies": cookies}
		raw, _ := json.Marshal(profile)
		if err := m.db.SaveAuthProfile(scanID, p.ID, p.Name, string(raw)); err != nil {
			return err
		}
	}
	for _, r := range cfg.RoleProfiles {
		raw, _ := json.Marshal(r)
		if err := m.db.SaveRoleProfile(scanID, r.ID, r.Name, r.AuthProfileID, string(raw)); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) LoadProfile(scanID, profileID string) (config.AuthProfile, error) {
	if m == nil || m.db == nil {
		return config.AuthProfile{}, fmt.Errorf("auth manager unavailable")
	}
	rec, err := m.db.GetAuthProfileRecord(scanID, profileID)
	if err != nil {
		return config.AuthProfile{}, err
	}
	var stored struct {
		Headers map[string]string `json:"headers"`
		Cookies map[string]string `json:"cookies"`
	}
	if err := json.Unmarshal([]byte(rec.ProfileJSON), &stored); err != nil {
		return config.AuthProfile{}, err
	}
	profile := config.AuthProfile{
		ID:      rec.ID,
		Name:    rec.Name,
		Headers: map[string]string{},
		Cookies: map[string]string{},
	}
	for k, v := range stored.Headers {
		profile.Headers[k] = m.resolveStoredValue(scanID, k, v)
	}
	for k, v := range stored.Cookies {
		profile.Cookies[k] = m.resolveStoredValue(scanID, k, v)
	}
	return profile, nil
}

func (m *Manager) resolveStoredValue(scanID, key, value string) string {
	if m.secrets == nil || !strings.HasPrefix(value, "[encrypted") {
		return value
	}
	secretKey := key
	if strings.HasPrefix(value, "[encrypted:") && strings.HasSuffix(value, "]") {
		secretKey = strings.TrimSuffix(strings.TrimPrefix(value, "[encrypted:"), "]")
	}
	refJSON, err := m.db.LoadEncryptedSecretRef(scanID, secretKey)
	if err != nil && secretKey != key {
		// Backward compatibility for profiles persisted before identity-scoped
		// secret references were introduced.
		refJSON, err = m.db.LoadEncryptedSecretRef(scanID, key)
	}
	if err != nil {
		return value
	}
	var ref secrets.Ref
	if json.Unmarshal([]byte(refJSON), &ref) != nil {
		return value
	}
	plain, err := m.secrets.Get(ref)
	if err != nil {
		return value
	}
	return string(plain)
}

func (m *Manager) ApplyProfile(client *httpclient.Client, profile config.AuthProfile) {
	headers := map[string]string{}
	for k, v := range profile.Headers {
		headers[k] = v
	}
	client.SetSession(profile.Cookies, headers)
}

func (m *Manager) CompareRoles(ctx context.Context, client *httpclient.Client, url string, roleA, roleB config.AuthProfile) (RoleComparison, error) {
	rrA, errA := client.DoWithAuthProfile(ctx, "GET", url, nil, nil, roleA)
	rrB, errB := client.DoWithAuthProfile(ctx, "GET", url, nil, nil, roleB)
	if errA != nil || errB != nil {
		return RoleComparison{}, fmt.Errorf("role comparison failed: role A: %v; role B: %v", errA, errB)
	}

	cmp := RoleComparison{
		URL:     url,
		RoleA:   roleA.Name,
		RoleB:   roleB.Name,
		StatusA: rrA.Response.StatusCode,
		StatusB: rrB.Response.StatusCode,
	}
	switch {
	case rrA.Response.StatusCode == 200 && rrB.Response.StatusCode == 403:
		cmp.AccessControl = "expected_role_difference"
		cmp.Notes = "Role A can access a resource denied to Role B; no ownership violation was established"
	case rrA.Response.StatusCode == 403 && rrB.Response.StatusCode == 200:
		cmp.AccessControl = "expected_role_difference"
		cmp.Notes = "Role B can access a resource denied to Role A; no ownership violation was established"
	case rrA.Response.StatusCode == 200 && rrB.Response.StatusCode == 200:
		if len(rrA.Response.Body) != len(rrB.Response.Body) {
			cmp.AccessControl = "role_variant"
			cmp.Notes = "Both roles can access the endpoint with different views; no foreign-object proof was established"
		} else {
			cmp.AccessControl = "same_access"
		}
	default:
		cmp.AccessControl = "inconclusive"
	}
	return cmp, nil
}

func (m *Manager) DetectSessionExpiry(status int, body string) bool {
	if status == 401 || status == 403 {
		return true
	}
	lower := strings.ToLower(body)
	return strings.Contains(lower, "session expired") || strings.Contains(lower, "login required")
}

func isSensitiveHeader(k string) bool {
	switch strings.ToLower(k) {
	case "authorization", "cookie", "x-api-key", "x-auth-token":
		return true
	default:
		return false
	}
}

func SessionCaptureNote() string {
	return fmt.Sprintf("browser capture supported via worker pool; manual MFA login window timeout=%s", (5 * time.Minute).String())
}
