package config

import (
	"fmt"
	"net/url"
	"strings"
)

// NormalizeTargetURL canonicalizes a user-provided scan target.
func NormalizeTargetURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("empty target URL")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid target URL %q: %w", raw, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("invalid target URL %q: missing host", raw)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("invalid target URL %q: unsupported scheme", raw)
	}
	u.Host = strings.ToLower(u.Host)
	u.Fragment = ""
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), nil
}

// NormalizeTargets deduplicates and canonicalizes all configured targets.
func NormalizeTargets(targets []string) ([]string, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("no scan targets configured")
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(targets))
	for _, raw := range targets {
		norm, err := NormalizeTargetURL(raw)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[norm]; ok {
			continue
		}
		seen[norm] = struct{}{}
		out = append(out, norm)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no scan targets configured")
	}
	return out, nil
}
