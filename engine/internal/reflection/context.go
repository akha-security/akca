package reflection

import (
	"html"
	"net/url"
	"strings"
)

var contextPriority = map[ContextType]int{
	ContextJavaScript: 5,
	ContextCSS:        4,
	ContextAttribute:  3,
	ContextURL:        2,
	ContextHTML:       1,
	ContextJSON:       1,
	ContextXML:        1,
	ContextComment:    0,
	ContextUnknown:    -1,
}

func ClassifyContext(body, canary, contentType string) (ContextType, string) {
	if canary == "" || body == "" {
		return classifyNonReflected(contentType)
	}

	indices := allIndices(body, canary)
	if len(indices) == 0 {
		enc := html.EscapeString(canary)
		if enc != canary {
			indices = allIndices(body, enc)
			if len(indices) > 0 {
				canary = enc
			}
		}
	}
	if len(indices) == 0 {
		return classifyNonReflected(contentType)
	}

	bestContext := ContextUnknown
	bestQuote := "none"
	bestPriority := -2

	for _, idx := range indices {
		before := body[:idx]
		after := body[idx+len(canary):]
		ctxType, quote := classifySingleContext(before, after, canary, contentType)
		if contextPriority[ctxType] > bestPriority {
			bestPriority = contextPriority[ctxType]
			bestContext = ctxType
			bestQuote = quote
		}
	}

	return bestContext, bestQuote
}

func classifyNonReflected(contentType string) (ContextType, string) {
	lower := strings.ToLower(contentType)
	if strings.Contains(lower, "json") {
		return ContextJSON, "none"
	}
	if strings.Contains(lower, "xml") {
		return ContextXML, "none"
	}
	return ContextUnknown, "none"
}

func classifySingleContext(before, after, canary, contentType string) (ContextType, string) {
	window := snippet(before, 120) + canary + snippet(after, 120)

	if inHTMLComment(before) {
		return ContextComment, detectQuote(before, after)
	}
	if inScriptBlock(before) {
		return ContextJavaScript, detectQuote(before, after)
	}
	if inStyleBlock(before) {
		return ContextCSS, detectQuote(before, after)
	}
	if inTagRegion(before, after) {
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

func allIndices(s, substr string) []int {
	var indices []int
	offset := 0
	for {
		idx := strings.Index(s[offset:], substr)
		if idx < 0 {
			break
		}
		indices = append(indices, offset+idx)
		offset += idx + len(substr)
		if offset >= len(s) {
			break
		}
	}
	return indices
}

func ClassifyReflectionKind(body, canary string) ReflectionKind {
	if strings.Contains(body, canary) {
		return ReflectionRaw
	}
	if strings.Contains(body, html.EscapeString(canary)) && html.EscapeString(canary) != canary {
		return ReflectionEncoded
	}
	if strings.Contains(body, url.QueryEscape(canary)) && url.QueryEscape(canary) != canary {
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
		} else {
			blocked = append(blocked, ch)
		}
	}
	return available, blocked
}

func detectQuote(before, after string) string {
	localBefore := snippet(before, 20)
	localAfter := snippetPrefix(after, 20)
	if strings.HasSuffix(strings.TrimSpace(localBefore), `"`) || strings.HasPrefix(strings.TrimSpace(localAfter), `"`) {
		return "double"
	}
	if strings.HasSuffix(strings.TrimSpace(localBefore), `'`) || strings.HasPrefix(strings.TrimSpace(localAfter), `'`) {
		return "single"
	}
	if strings.HasSuffix(strings.TrimSpace(localBefore), "`") || strings.HasPrefix(strings.TrimSpace(localAfter), "`") {
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
	if lastOpen >= 0 && lastOpen > lastClose {
		// Inside an open tag (<tag attr=...)
		return true
	}
	return false
}

func isAttributeReflection(before, after string) bool {
	local := snippet(before, 60)
	trim := strings.TrimSpace(local)
	if strings.HasSuffix(trim, "=") || strings.HasSuffix(trim, `="`) || strings.HasSuffix(trim, `='`) {
		return true
	}
	// Check if within attribute value e.g. value="something CANARY
	lastEq := strings.LastIndex(local, "=")
	if lastEq >= 0 {
		afterEq := strings.TrimSpace(local[lastEq+1:])
		if strings.HasPrefix(afterEq, `"`) && !strings.Contains(afterEq[1:], `"`) {
			return true
		}
		if strings.HasPrefix(afterEq, `'`) && !strings.Contains(afterEq[1:], `'`) {
			return true
		}
	}
	return false
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

func snippetPrefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
