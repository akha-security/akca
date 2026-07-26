package jsanalyzer

import (
	"net/url"
	"regexp"
	"strings"
)

var stringLiteralRe = regexp.MustCompile(`"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|` + "`(?:\\\\.|[^`\\\\])*`")

// ExtractASTLite walks JavaScript string literals and extracts URL-like values near API call keywords.
func ExtractASTLite(js string) []ExtractedEndpoint {
	var out []ExtractedEndpoint
	literals := stringLiteralRe.FindAllString(js, -1)
	for _, lit := range literals {
		unquoted := strings.Trim(lit, `"'` + "`")
		if !looksLikeEndpoint(unquoted) {
			continue
		}
		method, why := inferMethodNear(js, lit)
		conf := ScoreEndpoint(unquoted, "ast", method)
		out = append(out, ExtractedEndpoint{
			URL: unquoted, Method: method, Template: NormalizeTemplate(unquoted),
			Source: "ast_literal", Extraction: "ast", Confidence: conf, Why: why,
		})
	}
	return out
}

func inferMethodNear(js, literal string) (string, string) {
	idx := strings.Index(js, literal)
	if idx < 0 {
		return "GET", "string literal url"
	}
	start := idx - 80
	if start < 0 {
		start = 0
	}
	ctx := strings.ToLower(js[start:idx])
	switch {
	case strings.Contains(ctx, "post"):
		return "POST", "ast literal near POST context"
	case strings.Contains(ctx, "put"):
		return "PUT", "ast literal near PUT context"
	case strings.Contains(ctx, "delete"):
		return "DELETE", "ast literal near DELETE context"
	case strings.Contains(ctx, "graphql"):
		return "POST", "ast literal near graphql context"
	default:
		return "GET", "ast string literal"
	}
}

func looksLikeEndpoint(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 2 {
		return false
	}
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "/") {
		return true
	}
	if strings.Contains(s, "/api/") || strings.Contains(s, "graphql") {
		return true
	}
	_, err := url.Parse(s)
	return err == nil && strings.Contains(s, "/")
}
