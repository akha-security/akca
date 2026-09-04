package crawler

import (
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
