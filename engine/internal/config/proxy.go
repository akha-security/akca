package config

import (
	"fmt"
	"net/url"
	"strings"
)

// NormalizeProxyURL accepts the common host:port shorthand while rejecting
// ambiguous or unsupported proxy URLs before a scan starts.
func NormalizeProxyURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid proxy URL: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "socks5":
	default:
		return "", fmt.Errorf("unsupported proxy scheme %q; use http, https, or socks5", u.Scheme)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("proxy URL must include a host")
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("proxy URL must not include a path")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("proxy URL must not include a query or fragment")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Path = ""
	return u.String(), nil
}

// SafeProxyURL removes credentials before a proxy address is logged or shown.
func SafeProxyURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "configured proxy"
	}
	u.User = nil
	return u.String()
}
