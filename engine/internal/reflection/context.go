package reflection

import (
	"html"
	"net/url"
	"strings"
)

func ClassifyContext(body, canary, contentType string) (ContextType, string) {
	idx := strings.Index(body, canary)
	if idx < 0 {
		enc := html.EscapeString(canary)
		idx = strings.Index(body, enc)
		if idx >= 0 {
			canary = enc
		}
	}
	if idx < 0 {
		lower := strings.ToLower(contentType)
		if strings.Contains(lower, "json") {
			return ContextJSON, "none"
		}
		if strings.Contains(lower, "xml") {
			return ContextXML, "none"
		}
		return ContextUnknown, "none"
	}

	before := body[:idx]
	after := body[idx+len(canary):]
	window := snippet(before, 120) + canary + snippet(after, 120)

	if inHTMLComment(before) {
		return ContextComment, detectQuote(before, after)
	}
	if inTagRegion(before, after) {
		if inScriptBlock(before) {
			return ContextJavaScript, detectQuote(before, after)
		}
		if inStyleBlock(before) {
			return ContextCSS, detectQuote(before, after)
		}
		if isURLReflection(window) {
			return ContextURL, detectQuote(before, after)
		}
		if isAttributeReflection(before, after) {
			return ContextAttribute, detectQuote(before, after)
		}
	}
	if strings.Contains(strings.ToLower(contentType), "json") || looksLikeJSON(window) {
		return ContextJSON, detectQuote(before, after)
	}
	if strings.Contains(strings.ToLower(contentType), "xml") || looksLikeXML(window) {
		return ContextXML, detectQuote(before, after)
	}
	return ContextHTML, detectQuote(before, after)
}

func ClassifyReflectionKind(body, canary string) ReflectionKind {
	if strings.Contains(body, canary) {
		return ReflectionRaw
	}
	if strings.Contains(body, html.EscapeString(canary)) {
		return ReflectionEncoded
	}
	if strings.Contains(body, url.QueryEscape(canary)) {
		return ReflectionEncoded
	}
	partial := canary
	for len(partial) > 4 {
		partial = partial[:len(partial)-1]
		if strings.Contains(body, partial) {
			return ReflectionPartial
		}
	}
	return ReflectionRemoved
}

func DetectCharAvailability(body, canary string) (available, blocked []string) {
	probes := []string{"<", ">", "\"", "'", "`", "(", ")", "{", "}", "/", "\\", "&", ";"}
	for _, ch := range probes {
		if strings.Contains(body, canary+ch) || strings.Contains(body, ch+canary) {
			available = append(available, ch)
		} else if strings.Contains(body, html.EscapeString(canary+ch)) {
			available = append(available, ch)
		} else {
			blocked = append(blocked, ch)
		}
	}
	return available, blocked
}

func detectQuote(before, after string) string {
	if strings.HasSuffix(strings.TrimSpace(before), `"`) || strings.HasPrefix(after, `"`) {
		return "double"
	}
	if strings.HasSuffix(strings.TrimSpace(before), `'`) || strings.HasPrefix(after, `'`) {
		return "single"
	}
	if strings.HasSuffix(strings.TrimSpace(before), "`") || strings.HasPrefix(after, "`") {
		return "backtick"
	}
	return "none"
}

func inHTMLComment(before string) bool {
	last := strings.LastIndex(before, "<!--")
	if last < 0 {
		return false
	}
	return strings.LastIndex(before[last:], "-->") < 0
}

func inScriptBlock(before string) bool {
	open := strings.LastIndex(strings.ToLower(before), "<script")
	if open < 0 {
		return false
	}
	close := strings.LastIndex(strings.ToLower(before), "</script>")
	return close < open
}

func inStyleBlock(before string) bool {
	open := strings.LastIndex(strings.ToLower(before), "<style")
	if open < 0 {
		return false
	}
	close := strings.LastIndex(strings.ToLower(before), "</style>")
	return close < open
}

func inTagRegion(before, after string) bool {
	lastOpen := strings.LastIndex(before, "<")
	lastClose := strings.LastIndex(before, ">")
	if lastOpen > lastClose {
		return true
	}
	return strings.Contains(after, ">") || strings.Contains(before, "<")
}

func isAttributeReflection(before, after string) bool {
	trim := strings.TrimSpace(before)
	return strings.HasSuffix(trim, "=") ||
		strings.HasSuffix(trim, `="`) || strings.HasSuffix(trim, `='`) ||
		strings.Contains(trim, `="`) || strings.Contains(trim, `='`)
}

func isURLReflection(window string) bool {
	lower := strings.ToLower(window)
	return strings.Contains(lower, "href=") || strings.Contains(lower, "src=") ||
		strings.Contains(lower, "url(") || strings.Contains(lower, "action=")
}

func looksLikeXML(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, "<?xml") || strings.HasPrefix(s, "<root") || strings.HasPrefix(s, "<item>")
}

func looksLikeJSON(s string) bool {
	s = strings.TrimSpace(s)
	return (strings.HasPrefix(s, "{") && strings.Contains(s, ":")) ||
		(strings.HasPrefix(s, "[") && strings.Contains(s, `"`))
}

func snippet(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
