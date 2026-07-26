package crawler

import (
	"context"
	"net/http"
	"strings"
)

// extractLinkHeaderURLs parses RFC 5988 Link headers into absolute URLs.
func extractLinkHeaderURLs(baseURL string, headers map[string]string) []string {
	var raw string
	for k, v := range headers {
		if strings.EqualFold(k, "Link") {
			raw = v
			break
		}
	}
	if raw == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(part, "<") {
			continue
		}
		end := strings.Index(part, ">")
		if end <= 1 {
			continue
		}
		ref := strings.TrimSpace(part[1:end])
		resolved, err := ResolveReference(baseURL, ref)
		if err != nil || resolved == "" {
			continue
		}
		out = append(out, resolved)
	}
	return out
}

// probeSecurityHeaders sends lightweight variant requests with common override
// headers used in host-header / cache-poison testing during crawl.
func (c *Crawler) probeSecurityHeaders(ctx context.Context, rawURL, method string) {
	if method == "" {
		method = http.MethodGet
	}
	probes := []map[string]string{
		{"X-Forwarded-Host": "evil.akca-probe.local"},
		{"X-Original-URL": "/admin"},
		{"X-Rewrite-URL": "/admin"},
	}
	for _, hdrs := range probes {
		if ctx.Err() != nil {
			return
		}
		_, _ = c.client.Do(ctx, method, rawURL, nil, hdrs)
		c.mu.Lock()
		c.requestsMade++
		c.mu.Unlock()
	}
}
