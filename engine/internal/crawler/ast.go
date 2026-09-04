package crawler

import (
	"fmt"
	"strings"
)

// ExtractASTFromJSBundle performs call-expression-aware endpoint extraction.
//
// Unlike the regex pass (ExtractFromJSBundle), this tokenizes the JavaScript
// (skipping comments and respecting string boundaries) and then matches real
// call sites: fetch(), axios()/axios.get(), XMLHttpRequest .open(), jQuery
// $.ajax()/$.get(), new WebSocket(), new EventSource(), and dynamic import().
// This catches multiline calls, template literals and object-config arguments
// (e.g. axios({ url, method })) that flat regexes miss.
func ExtractASTFromJSBundle(baseURL, js string) []DiscoveredEndpoint {
	toks := tokenizeJS(js)
	var out []DiscoveredEndpoint
	seen := map[string]struct{}{}

	add := func(raw, method string, source DiscoverySource, confidence float64, why string, tmpl *RequestTemplate) {
		if !looksLikeURLRef(raw) {
			return
		}
		resolved, err := ResolveReference(baseURL, NormalizeRouteTemplate(raw))
		if err != nil || resolved == "" {
			return
		}
		lower := strings.ToLower(resolved)
		if strings.Contains(lower, "graphql") {
			source = SourceGraphQL
		}
		if strings.HasPrefix(lower, "ws://") || strings.HasPrefix(lower, "wss://") {
			source = SourceWebSocket
		}
		key := method + " " + resolved
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		if tmpl != nil {
			if tmpl.URL == "" {
				tmpl.URL = resolved
			}
			if tmpl.Method == "" {
				tmpl.Method = method
			}
		}
		out = append(out, DiscoveredEndpoint{
			URL: resolved, Method: method, NormalizedURL: resolved, Kind: KindAPI, Source: source, Confidence: confidence, WhyDiscovered: why, RequestTemplate: tmpl,
		})
	}

	for k := 0; k < len(toks); k++ {
		t := toks[k]
		if t.kind != tokIdent {
			continue
		}
		id := t.val
		lid := strings.ToLower(id)

		// new WebSocket(...) / new EventSource(...)
		if k >= 1 && toks[k-1].kind == tokIdent && toks[k-1].val == "new" {
			switch lid {
			case "websocket":
				if s, ok := callFirstString(toks, k); ok {
					add(s, "GET", SourceWebSocket, 0.85, "new WebSocket() (ast)", nil)
				}
				continue
			case "eventsource":
				if s, ok := callFirstString(toks, k); ok {
					add(s, "GET", SourceEventSource, 0.7, "new EventSource() (ast)", nil)
				}
				continue
			case "xmlhttprequest":
				continue
			}
		}

		switch lid {
		case "fetch":
			if s, ok := callFirstString(toks, k); ok {
				method, headers, body, ct := parseFetchOptions(toks, k+3)
				if method == "" {
					method = "GET"
				}
				var tmpl *RequestTemplate
				if method != "GET" || len(headers) > 0 || body != "" {
					tmpl = &RequestTemplate{
						Method: method, URL: s, Headers: headers, Body: body, ContentType: ct,
					}
				}
				add(s, method, SourceJSBundle, 0.8, "fetch() (ast)", tmpl)
			}
			continue
		case "import":
			if s, ok := callFirstString(toks, k); ok {
				add(s, "GET", SourceJSBundle, 0.7, "dynamic import() (ast)", nil)
			}
			continue
		case "axios":
			// axios.get("...") / axios.post("...", data) ...
			if isPunct(toks, k+1, ".") && k+2 < len(toks) && toks[k+2].kind == tokIdent {
				m := strings.ToUpper(toks[k+2].val)
				if isHTTPMethod(m) {
					if s, ok := callFirstString(toks, k+2); ok {
						body, ct := parseCallSecondArgBody(toks, k+4)
						var tmpl *RequestTemplate
						if m != "GET" || body != "" {
							tmpl = &RequestTemplate{
								Method: m, URL: s, Body: body, ContentType: ct,
							}
						}
						add(s, m, SourceJSBundle, 0.8, "axios."+strings.ToLower(m)+"() (ast)", tmpl)
					}
					continue
				}
			}
			// axios("...") or axios({ url, method, data })
			if isPunct(toks, k+1, "(") {
				if s, ok := stringAt(toks, k+2); ok {
					add(s, "GET", SourceJSBundle, 0.75, "axios() (ast)", nil)
					continue
				}
				if u, m, headers, body, ct := objURLMethodFull(toks, k); u != "" {
					var tmpl *RequestTemplate
					if m != "GET" || len(headers) > 0 || body != "" {
						tmpl = &RequestTemplate{
							Method: m, URL: u, Headers: headers, Body: body, ContentType: ct,
						}
					}
					add(u, m, SourceJSBundle, 0.75, "axios({}) (ast)", tmpl)
				}
			}
			continue
		case "open":
			// xhr.open("GET", "/url")
			if k >= 1 && isPunct(toks, k-1, ".") && isPunct(toks, k+1, "(") {
				if m, okm := stringAt(toks, k+2); okm && isPunct(toks, k+3, ",") {
					if u, oku := stringAt(toks, k+4); oku && isHTTPMethod(strings.ToUpper(m)) {
						method := strings.ToUpper(m)
						var tmpl *RequestTemplate
						if method != "GET" {
							tmpl = &RequestTemplate{Method: method, URL: u}
						}
						add(u, method, SourceJSBundle, 0.8, "XMLHttpRequest.open() (ast)", tmpl)
					}
				}
			}
			continue
		}

		// jQuery: $.ajax({url}), $.get("..."), $.post("...", data), $.getJSON("...")
		if id == "$" || lid == "jquery" {
			if isPunct(toks, k+1, ".") && k+2 < len(toks) && toks[k+2].kind == tokIdent {
				switch strings.ToLower(toks[k+2].val) {
				case "get", "getjson":
					if s, ok := callFirstString(toks, k+2); ok {
						add(s, "GET", SourceJSBundle, 0.7, "jQuery.get() (ast)", nil)
					}
				case "post":
					if s, ok := callFirstString(toks, k+2); ok {
						body, ct := parseCallSecondArgBody(toks, k+4)
						tmpl := &RequestTemplate{Method: "POST", URL: s, Body: body, ContentType: ct}
						add(s, "POST", SourceJSBundle, 0.7, "jQuery.post() (ast)", tmpl)
					}
				case "ajax":
					if u, m, headers, body, ct := objURLMethodFull(toks, k+2); u != "" {
						var tmpl *RequestTemplate
						if m != "GET" || len(headers) > 0 || body != "" {
							tmpl = &RequestTemplate{
								Method: m, URL: u, Headers: headers, Body: body, ContentType: ct,
							}
						}
						add(u, m, SourceJSBundle, 0.7, "jQuery.ajax() (ast)", tmpl)
					}
				}
			}
			continue
		}

		// Generic HTTP client: <recv>.get/post/put/delete/patch("...")
		if lid == "get" || lid == "post" || lid == "put" || lid == "delete" || lid == "patch" {
			if k >= 2 && isPunct(toks, k-1, ".") && toks[k-2].kind == tokIdent {
				recv := strings.ToLower(toks[k-2].val)
				if recv == "http" || recv == "$http" || strings.Contains(recv, "api") ||
					strings.Contains(recv, "http") || strings.Contains(recv, "client") ||
					strings.Contains(recv, "request") {
					if s, ok := callFirstString(toks, k); ok {
						method := strings.ToUpper(lid)
						var tmpl *RequestTemplate
						if method != "GET" {
							tmpl = &RequestTemplate{Method: method, URL: s}
						}
						add(s, method, SourceJSBundle, 0.65, recv+"."+lid+"() (ast)", tmpl)
					}
				}
			}
			continue
		}
	}
	return out
}

func isHTTPMethod(m string) bool {
	switch m {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS":
		return true
	}
	return false
}

// looksLikeURLRef keeps only string args that plausibly reference a URL/path.
func looksLikeURLRef(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 2 {
		return false
	}
	lower := strings.ToLower(s)
	switch {
	case strings.HasPrefix(s, "/"):
		return true
	case strings.HasPrefix(lower, "http://"), strings.HasPrefix(lower, "https://"):
		return true
	case strings.HasPrefix(lower, "ws://"), strings.HasPrefix(lower, "wss://"):
		return true
	case strings.HasPrefix(s, "./"), strings.HasPrefix(s, "../"):
		return true
	case strings.Contains(s, "/") && !strings.Contains(s, " "):
		return true
	}
	return false
}

// --- token helpers ---

func stringAt(toks []token, k int) (string, bool) {
	if k < 0 || k >= len(toks) || toks[k].kind != tokString {
		return "", false
	}
	return toks[k].val, true
}

func isPunct(toks []token, k int, s string) bool {
	return k >= 0 && k < len(toks) && toks[k].kind == tokPunct && toks[k].val == s
}

// callFirstString expects toks[k+1] == "(" and toks[k+2] to be a string literal.
func callFirstString(toks []token, k int) (string, bool) {
	if !isPunct(toks, k+1, "(") {
		return "", false
	}
	return stringAt(toks, k+2)
}

// objURLMethod parses a config object argument like ({ url: "...", method: "..." })
// starting where toks[k] is the call's identifier and toks[k+1] == "(".
func objURLMethod(toks []token, k int) (url, method string) {
	u, m, _, _, _ := objURLMethodFull(toks, k)
	return u, m
}

func objURLMethodFull(toks []token, k int) (rawURL, method string, headers map[string]string, body string, ct string) {
	method = "GET"
	if !isPunct(toks, k+1, "(") || !isPunct(toks, k+2, "{") {
		return "", method, nil, "", ""
	}
	depth := 0
	bodyKeys := []string{}
	for i := k + 2; i < len(toks); i++ {
		switch {
		case toks[i].kind == tokPunct && toks[i].val == "{":
			depth++
		case toks[i].kind == tokPunct && toks[i].val == "}":
			depth--
			if depth == 0 {
				if len(bodyKeys) > 0 && body == "" {
					body = buildObjectTemplate(bodyKeys)
					if ct == "" {
						ct = "application/json"
					}
				}
				return rawURL, method, headers, body, ct
			}
		case depth == 1:
			key := ""
			if toks[i].kind == tokIdent {
				key = strings.ToLower(strings.Trim(toks[i].val, `"'`))
			} else if toks[i].kind == tokString {
				key = strings.ToLower(toks[i].val)
			}
			if (key == "url" || key == "uri" || key == "endpoint") && isPunct(toks, i+1, ":") {
				if s, ok := stringAt(toks, i+2); ok {
					rawURL = s
				}
			}
			if (key == "method" || key == "type") && isPunct(toks, i+1, ":") {
				if s, ok := stringAt(toks, i+2); ok && isHTTPMethod(strings.ToUpper(s)) {
					method = strings.ToUpper(s)
				}
			}
			if (key == "data" || key == "body" || key == "params") && isPunct(toks, i+1, ":") {
				if isPunct(toks, i+2, "{") {
					keys, _ := parseObjectLiteralKeys(toks, i+2)
					bodyKeys = append(bodyKeys, keys...)
				} else if s, ok := stringAt(toks, i+2); ok {
					body = s
				}
			}
		}
	}
	if len(bodyKeys) > 0 && body == "" {
		body = buildObjectTemplate(bodyKeys)
		if ct == "" {
			ct = "application/json"
		}
	}
	return rawURL, method, headers, body, ct
}

func parseFetchOptions(toks []token, start int) (method string, headers map[string]string, body string, ct string) {
	method = "GET"
	// Find opening brace of options
	braceIdx := -1
	for i := start; i < len(toks) && i < start+5; i++ {
		if isPunct(toks, i, "{") {
			braceIdx = i
			break
		}
	}
	if braceIdx == -1 {
		return method, nil, "", ""
	}
	depth := 0
	bodyKeys := []string{}
	headers = make(map[string]string)
	for i := braceIdx; i < len(toks); i++ {
		switch {
		case toks[i].kind == tokPunct && toks[i].val == "{":
			depth++
		case toks[i].kind == tokPunct && toks[i].val == "}":
			depth--
			if depth == 0 {
				if len(bodyKeys) > 0 && body == "" {
					body = buildObjectTemplate(bodyKeys)
					if ct == "" {
						ct = "application/json"
					}
				}
				return method, headers, body, ct
			}
		case depth == 1:
			key := ""
			if toks[i].kind == tokIdent {
				key = strings.ToLower(strings.Trim(toks[i].val, `"'`))
			} else if toks[i].kind == tokString {
				key = strings.ToLower(toks[i].val)
			}
			if key == "method" && isPunct(toks, i+1, ":") {
				if s, ok := stringAt(toks, i+2); ok && isHTTPMethod(strings.ToUpper(s)) {
					method = strings.ToUpper(s)
				}
			}
			if key == "body" && isPunct(toks, i+1, ":") {
				if isPunct(toks, i+2, "{") {
					keys, _ := parseObjectLiteralKeys(toks, i+2)
					bodyKeys = append(bodyKeys, keys...)
				} else if s, ok := stringAt(toks, i+2); ok {
					body = s
				}
			}
		}
	}
	if len(bodyKeys) > 0 && body == "" {
		body = buildObjectTemplate(bodyKeys)
		if ct == "" {
			ct = "application/json"
		}
	}
	return method, headers, body, ct
}

func parseCallSecondArgBody(toks []token, start int) (body string, ct string) {
	if start >= len(toks) {
		return "", ""
	}
	// Look for object literal `{ field1, field2 }`
	braceIdx := -1
	for i := start; i < len(toks) && i < start+4; i++ {
		if isPunct(toks, i, "{") {
			braceIdx = i
			break
		}
	}
	if braceIdx != -1 {
		keys, _ := parseObjectLiteralKeys(toks, braceIdx)
		if len(keys) > 0 {
			return buildObjectTemplate(keys), "application/json"
		}
	}
	return "", ""
}

func parseObjectLiteralKeys(toks []token, braceIdx int) ([]string, int) {
	if !isPunct(toks, braceIdx, "{") {
		return nil, braceIdx
	}
	var keys []string
	depth := 0
	for i := braceIdx; i < len(toks); i++ {
		if toks[i].kind == tokPunct && toks[i].val == "{" {
			depth++
		} else if toks[i].kind == tokPunct && toks[i].val == "}" {
			depth--
			if depth == 0 {
				return keys, i
			}
		} else if depth == 1 {
			if toks[i].kind == tokIdent {
				k := strings.TrimSpace(toks[i].val)
				if k != "" && !isReservedJSKeyword(k) {
					keys = append(keys, k)
				}
			} else if toks[i].kind == tokString {
				k := strings.TrimSpace(toks[i].val)
				if k != "" {
					keys = append(keys, k)
				}
			}
		}
	}
	return keys, len(toks)
}

func buildObjectTemplate(keys []string) string {
	if len(keys) == 0 {
		return "{}"
	}
	seen := map[string]bool{}
	var parts []string
	for _, k := range keys {
		if seen[k] || k == "" {
			continue
		}
		seen[k] = true
		parts = append(parts, fmt.Sprintf(`"%s":"test"`, k))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func isReservedJSKeyword(s string) bool {
	switch s {
	case "var", "let", "const", "function", "return", "if", "else", "for", "while", "class", "import", "export", "true", "false", "null", "undefined":
		return true
	}
	return false
}

// --- minimal JS tokenizer ---

type tokKind int

const (
	tokIdent tokKind = iota
	tokString
	tokPunct
	tokOther
)

type token struct {
	kind tokKind
	val  string
}

func tokenizeJS(src string) []token {
	var toks []token
	n := len(src)
	for i := 0; i < n; {
		c := src[i]
		// comments
		if c == '/' && i+1 < n {
			if src[i+1] == '/' {
				j := i + 2
				for j < n && src[j] != '\n' {
					j++
				}
				i = j
				continue
			}
			if src[i+1] == '*' {
				j := i + 2
				for j+1 < n && !(src[j] == '*' && src[j+1] == '/') {
					j++
				}
				i = j + 2
				continue
			}
		}
		// string / template literals
		if c == '"' || c == '\'' || c == '`' {
			val, j := readJSString(src, i)
			toks = append(toks, token{tokString, val})
			i = j
			continue
		}
		// identifiers / keywords
		if isIdentStart(c) {
			j := i + 1
			for j < n && isIdentPart(src[j]) {
				j++
			}
			toks = append(toks, token{tokIdent, src[i:j]})
			i = j
			continue
		}
		// punctuation of interest
		switch c {
		case '(', ')', '.', ',', '{', '}', ':', '[', ']':
			toks = append(toks, token{tokPunct, string(c)})
		}
		i++
	}
	return toks
}

// readJSString reads a quoted string starting at i. For template literals it
// replaces ${...} interpolation expressions with {param} placeholders and preserves the entire URL path.
func readJSString(src string, i int) (string, int) {
	quote := src[i]
	n := len(src)
	var sb strings.Builder
	j := i + 1
	for j < n {
		c := src[j]
		if c == '\\' && j+1 < n {
			// keep the escaped char literally enough for URL purposes
			sb.WriteByte(src[j+1])
			j += 2
			continue
		}
		if quote == '`' && c == '$' && j+1 < n && src[j+1] == '{' {
			sb.WriteString("{param}")
			// skip expression inside ${...}
			k := j + 2
			depth := 1
			for k < n && depth > 0 {
				if src[k] == '\\' && k+1 < n {
					k += 2
					continue
				}
				if src[k] == '{' {
					depth++
				} else if src[k] == '}' {
					depth--
				}
				k++
			}
			j = k
			continue
		}
		if c == quote {
			return sb.String(), j + 1
		}
		sb.WriteByte(c)
		j++
	}
	return sb.String(), n
}

func isIdentStart(c byte) bool {
	return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}
