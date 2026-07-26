package app

import (
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
)

func TestBrowserSessionCarriesAuthenticatedScanContext(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.CustomHeaders = map[string]string{"X-Tenant": "acme"}
	cfg.Authentication = map[string]string{
		"Authorization": "Bearer token", "Cookie": "legacy=one; theme=dark",
	}
	cfg.SessionCookies = map[string]string{"session": "current"}
	cfg.ApiKeys = map[string]string{"X-API-Key": "key"}
	cfg.AuthProfiles = []config.AuthProfile{{
		Headers: map[string]string{"X-Role": "user"},
		Cookies: map[string]string{"profile": "selected"},
	}}
	headers, cookies := browserSession(cfg)
	for key, expected := range map[string]string{
		"X-Tenant": "acme", "Authorization": "Bearer token", "X-API-Key": "key", "X-Role": "user",
	} {
		if headers[key] != expected {
			t.Fatalf("browser header %s missing: %v", key, headers)
		}
	}
	for key, expected := range map[string]string{
		"legacy": "one", "theme": "dark", "session": "current", "profile": "selected",
	} {
		if cookies[key] != expected {
			t.Fatalf("browser cookie %s missing: %v", key, cookies)
		}
	}
}
