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
	literals := stringLiteralRe.FindAllStringIndex(js, -1)
	for _, span := range literals {
		lit := js[span[0]:span[1]]
		unquoted := strings.Trim(lit, `"'`+"`")
		if !looksLikeEndpoint(unquoted) {
			continue
		}
		// A nearby word such as postMessage does not establish an HTTP method.
		// AnalyzeContent's call parser supplies the actual method and body.
		method, why := "GET", "ast string literal"
		conf := ScoreEndpoint(unquoted, "ast", method)
		out = append(out, ExtractedEndpoint{
			URL: unquoted, Method: method, Template: NormalizeTemplate(unquoted),
			Source: "ast_literal", Extraction: "ast", Confidence: conf, Why: why,
		})
	}
	return out
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
