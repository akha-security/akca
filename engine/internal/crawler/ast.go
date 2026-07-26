package crawler

import "strings"

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

	add := func(raw, method string, source DiscoverySource, confidence float64, why string) {
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
		out = append(out, DiscoveredEndpoint{
			URL: resolved, Method: method, Source: source, Confidence: confidence, WhyDiscovered: why,
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
					add(s, "GET", SourceWebSocket, 0.85, "new WebSocket() (ast)")
				}
				continue
			case "eventsource":
				if s, ok := callFirstString(toks, k); ok {
					add(s, "GET", SourceEventSource, 0.7, "new EventSource() (ast)")
				}
				continue
			case "xmlhttprequest":
				continue
			}
		}

		switch lid {
		case "fetch":
			if s, ok := callFirstString(toks, k); ok {
				add(s, "GET", SourceJSBundle, 0.8, "fetch() (ast)")
			}
			continue
		case "import":
			if s, ok := callFirstString(toks, k); ok {
				add(s, "GET", SourceJSBundle, 0.7, "dynamic import() (ast)")
			}
			continue
		case "axios":
			// axios.get("...") / axios.post("...") ...
			if isPunct(toks, k+1, ".") && k+2 < len(toks) && toks[k+2].kind == tokIdent {
				m := strings.ToUpper(toks[k+2].val)
				if isHTTPMethod(m) {
					if s, ok := callFirstString(toks, k+2); ok {
						add(s, m, SourceJSBundle, 0.8, "axios."+strings.ToLower(m)+"() (ast)")
					}
					continue
				}
			}
			// axios("...") or axios({ url, method })
			if isPunct(toks, k+1, "(") {
				if s, ok := stringAt(toks, k+2); ok {
					add(s, "GET", SourceJSBundle, 0.75, "axios() (ast)")
					continue
				}
				if u, m := objURLMethod(toks, k); u != "" {
					add(u, m, SourceJSBundle, 0.75, "axios({}) (ast)")
				}
			}
			continue
		case "open":
			// xhr.open("GET", "/url")
			if k >= 1 && isPunct(toks, k-1, ".") && isPunct(toks, k+1, "(") {
				if m, okm := stringAt(toks, k+2); okm && isPunct(toks, k+3, ",") {
					if u, oku := stringAt(toks, k+4); oku && isHTTPMethod(strings.ToUpper(m)) {
						add(u, strings.ToUpper(m), SourceJSBundle, 0.8, "XMLHttpRequest.open() (ast)")
					}
				}
			}
			continue
		}

		// jQuery: $.ajax({url}), $.get("..."), $.post("..."), $.getJSON("...")
		if id == "$" || lid == "jquery" {
			if isPunct(toks, k+1, ".") && k+2 < len(toks) && toks[k+2].kind == tokIdent {
				switch strings.ToLower(toks[k+2].val) {
				case "get", "getjson":
					if s, ok := callFirstString(toks, k+2); ok {
						add(s, "GET", SourceJSBundle, 0.7, "jQuery.get() (ast)")
					}
				case "post":
					if s, ok := callFirstString(toks, k+2); ok {
						add(s, "POST", SourceJSBundle, 0.7, "jQuery.post() (ast)")
					}
				case "ajax":
					if u, m := objURLMethod(toks, k+2); u != "" {
						add(u, m, SourceJSBundle, 0.7, "jQuery.ajax() (ast)")
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
						add(s, strings.ToUpper(lid), SourceJSBundle, 0.65, recv+"."+lid+"() (ast)")
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
	method = "GET"
	if !isPunct(toks, k+1, "(") || !isPunct(toks, k+2, "{") {
		return "", method
	}
	depth := 0
	for i := k + 2; i < len(toks); i++ {
		switch {
		case toks[i].kind == tokPunct && toks[i].val == "{":
			depth++
		case toks[i].kind == tokPunct && toks[i].val == "}":
			depth--
			if depth == 0 {
				return url, method
			}
		case depth == 1 && toks[i].kind == tokIdent:
			key := strings.ToLower(strings.Trim(toks[i].val, `"'`))
			if (key == "url" || key == "uri" || key == "endpoint") && isPunct(toks, i+1, ":") {
				if s, ok := stringAt(toks, i+2); ok {
					url = s
				}
			}
			if key == "method" && isPunct(toks, i+1, ":") {
				if s, ok := stringAt(toks, i+2); ok && isHTTPMethod(strings.ToUpper(s)) {
					method = strings.ToUpper(s)
				}
			}
		case depth == 1 && toks[i].kind == tokString:
			// object keys may be quoted: "url": "..."
			key := strings.ToLower(toks[i].val)
			if (key == "url" || key == "uri" || key == "endpoint") && isPunct(toks, i+1, ":") {
				if s, ok := stringAt(toks, i+2); ok {
					url = s
				}
			}
			if key == "method" && isPunct(toks, i+1, ":") {
				if s, ok := stringAt(toks, i+2); ok && isHTTPMethod(strings.ToUpper(s)) {
					method = strings.ToUpper(s)
				}
			}
		}
	}
	return url, method
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
// returns the static prefix before the first ${ interpolation. Returns the
// unquoted content and the index just past the closing quote.
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
			// stop at interpolation; static prefix is enough for discovery
			return sb.String(), skipToStringEnd(src, j, quote)
		}
		if c == quote {
			return sb.String(), j + 1
		}
		sb.WriteByte(c)
		j++
	}
	return sb.String(), n
}

// skipToStringEnd advances to just past the terminating quote, used after we
// stop early at a template interpolation.
func skipToStringEnd(src string, i int, quote byte) int {
	n := len(src)
	depth := 0
	for j := i; j < n; j++ {
		c := src[j]
		if c == '\\' {
			j++
			continue
		}
		if c == '{' {
			depth++
		} else if c == '}' {
			depth--
		} else if c == quote && depth <= 0 {
			return j + 1
		}
	}
	return n
}

func isIdentStart(c byte) bool {
	return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}
