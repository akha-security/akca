package params

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// volatileHeaders change on every response regardless of request input (dates,
// request IDs, cache validators, CDN trace IDs). Including them in the response
// fingerprint made every probe look "different" from the baseline, which flooded
// parameter discovery with false positives and starved the real parameters.
var volatileHeaders = map[string]struct{}{
	"date": {}, "set-cookie": {}, "age": {}, "expires": {},
	"last-modified": {}, "etag": {}, "keep-alive": {}, "connection": {},
	"x-request-id": {}, "x-requestid": {}, "request-id": {}, "x-correlation-id": {},
	"x-trace-id": {}, "cf-ray": {}, "x-amz-cf-id": {}, "x-amz-request-id": {},
	"x-runtime": {}, "x-response-time": {}, "report-to": {}, "nel": {},
	"x-served-by": {}, "x-cache": {}, "x-timer": {}, "via": {},
}

var (
	reInputName  = regexp.MustCompile(`(?i)<input[^>]+name=["']([^"']+)["']`)
	reInputID    = regexp.MustCompile(`(?i)<input[^>]+id=["']([^"']+)["']`)
	reHidden     = regexp.MustCompile(`(?i)<input[^>]+type=["']hidden["'][^>]+name=["']([^"']+)["']`)
	reDataAttr   = regexp.MustCompile(`(?i)\sdata-([a-z0-9_-]+)=`)
	reOAuthParam = regexp.MustCompile(`(?i)(code|state|redirect_uri|client_id|scope)=`)
	reGraphQLVar = regexp.MustCompile(`(?i)"variables"\s*:\s*\{([^}]+)\}`)
	reJSParam    = regexp.MustCompile(`(?i)(?:params|query|data)\s*:\s*\{([^}]{1,500})\}`)
	reStateBlob  = regexp.MustCompile(`(?i)__INITIAL_STATE__|window\.__STATE__|__PRELOADED_STATE__`)
)

// ExtractPassive discovers parameters from response content without active probing.
func ExtractPassive(endpointURL, method, contentType, body string, headers map[string]string) []DiscoveredParameter {
	var out []DiscoveredParameter
	add := func(name string, loc Location, priority int, source string) {
		if name == "" {
			return
		}
		out = append(out, DiscoveredParameter{
			Name: name, Location: loc, Priority: priority, Confidence: 0.85,
			Source: source, EndpointURL: endpointURL, EndpointMethod: method,
		})
	}

	// Parameters that literally appear in the discovered URL's query string are
	// real, attacker-controllable inputs — give them the highest priority so they
	// are never crowded out of the (limited) reflection/module budget by
	// speculative wordlist or path guesses.
	if u := parseQueryParams(endpointURL); len(u) > 0 {
		for k := range u {
			add(k, LocationQuery, 96, "passive")
		}
	}

	for _, m := range reInputName.FindAllStringSubmatch(body, -1) {
		add(m[1], LocationForm, 75, "passive")
	}
	for _, m := range reHidden.FindAllStringSubmatch(body, -1) {
		add(m[1], LocationHidden, 80, "passive")
	}
	for _, m := range reInputID.FindAllStringSubmatch(body, -1) {
		add(m[1], LocationHTMLAttr, 60, "passive")
	}
	for _, m := range reDataAttr.FindAllStringSubmatch(body, -1) {
		add("data-"+m[1], LocationDataAttr, 65, "passive")
	}

	ct := strings.ToLower(contentType)
	trimmed := strings.TrimSpace(body)
	lowerTrim := strings.ToLower(trimmed)
	if strings.Contains(ct, "json") || strings.HasPrefix(trimmed, "{") {
		for k := range extractJSONKeys(body) {
			add(k, LocationJSON, 75, "passive")
		}
	}
	// Only treat the body as XML for genuine XML responses. HTML documents also
	// start with "<" but parsing them as XML turned every tag (html, body, h1…)
	// into a bogus "parameter".
	looksHTML := strings.Contains(ct, "html") ||
		strings.HasPrefix(lowerTrim, "<!doctype html") || strings.HasPrefix(lowerTrim, "<html")
	if strings.Contains(ct, "xml") || (strings.HasPrefix(trimmed, "<") && !looksHTML) {
		for k := range extractXMLKeys(body) {
			add(k, LocationXML, 70, "passive")
		}
	}
	if strings.Contains(ct, "multipart") {
		for k := range extractMultipartNames(body) {
			add(k, LocationMultipart, 70, "passive")
		}
	}

	for k := range headers {
		if isInterestingHeader(k) {
			add(k, LocationHeader, 55, "passive")
		}
	}
	// Universal header injection surfaces — backends and proxies often parse these.
	for _, h := range []string{"User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host", "X-Original-URL", "X-Custom-IP-Authorization"} {
		add(h, LocationHeader, 72, "synthetic_header")
	}

	if reGraphQLVar.MatchString(body) {
		add("variables", LocationGraphQL, 85, "passive")
	}
	if strings.Contains(strings.ToLower(endpointURL), "callback") || reOAuthParam.MatchString(endpointURL) {
		for _, p := range []string{"code", "state", "redirect_uri", "client_id", "scope"} {
			add(p, LocationOAuth, 80, "passive")
		}
	}
	if strings.HasPrefix(strings.ToLower(endpointURL), "ws://") || strings.HasPrefix(strings.ToLower(endpointURL), "wss://") {
		add("message", LocationWebSocket, 70, "passive")
	}
	for _, m := range reJSParam.FindAllStringSubmatch(body, -1) {
		for _, part := range strings.Split(m[1], ",") {
			kv := strings.Split(strings.TrimSpace(part), ":")
			if len(kv) > 0 {
				key := strings.Trim(kv[0], `"' `)
				add(key, LocationJSBuilder, 72, "passive")
			}
		}
	}
	if reStateBlob.MatchString(body) {
		add("__state__", LocationStateBlob, 68, "passive")
	}

	if seg := extractPathParamHints(endpointURL); seg != "" {
		add(seg, LocationPath, 78, "passive")
	}
	return out
}

func parseQueryParams(rawURL string) map[string]struct{} {
	out := map[string]struct{}{}
	idx := strings.Index(rawURL, "?")
	if idx < 0 {
		return out
	}
	q := rawURL[idx+1:]
	for _, part := range strings.Split(q, "&") {
		kv := strings.SplitN(part, "=", 2)
		if kv[0] != "" {
			out[kv[0]] = struct{}{}
		}
	}
	return out
}

func extractJSONKeys(body string) map[string]struct{} {
	out := map[string]struct{}{}
	var data interface{}
	if json.Unmarshal([]byte(body), &data) != nil {
		return out
	}
	collectJSONPaths(data, "", out)
	return out
}

func collectJSONPaths(value interface{}, prefix string, out map[string]struct{}) {
	switch node := value.(type) {
	case map[string]interface{}:
		for key, child := range node {
			path := key
			if prefix != "" {
				path = prefix + "." + key
			}
			out[path] = struct{}{}
			collectJSONPaths(child, path, out)
		}
	case []interface{}:
		for i, child := range node {
			path := strconv.Itoa(i)
			if prefix != "" {
				path = prefix + "." + path
			}
			collectJSONPaths(child, path, out)
			if prefix != "" {
				collectJSONPaths(child, prefix, out)
			}
			if i >= 2 {
				break
			}
		}
	}
}

func extractXMLKeys(body string) map[string]struct{} {
	out := map[string]struct{}{}
	decoder := xml.NewDecoder(strings.NewReader(body))
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		if se, ok := tok.(xml.StartElement); ok {
			out[se.Name.Local] = struct{}{}
		}
	}
	return out
}

func extractMultipartNames(body string) map[string]struct{} {
	out := map[string]struct{}{}
	re := regexp.MustCompile(`(?i)name="([^"]+)"`)
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		out[m[1]] = struct{}{}
	}
	return out
}

func isInterestingHeader(name string) bool {
	switch strings.ToLower(name) {
	case "x-api-key", "x-auth-token", "authorization", "cookie", "x-csrf-token", "x-requested-with",
		"user-agent", "referer", "x-forwarded-for", "x-forwarded-host", "x-original-url":
		return true
	default:
		return false
	}
}

func extractPathParamHints(rawURL string) string {
	// Inspect only the URL path. The previous version scanned the whole raw URL,
	// so a host/port that begins with a digit (e.g. 127.0.0.1:8899) produced a
	// spurious "path_segment" parameter on every single endpoint.
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	for _, p := range strings.Split(u.Path, "/") {
		if len(p) > 0 && p[0] >= '0' && p[0] <= '9' {
			return "path_segment"
		}
	}
	return ""
}

func Fingerprint(status int, body string, durationMs int64, headers map[string]string) ResponseFingerprint {
	h := sha256.Sum256([]byte(body))
	// Build a deterministic, stable header signature: drop volatile headers and
	// sort the rest so the same response always hashes identically (Go map
	// iteration order is random, which previously made identical headers hash
	// differently on every call).
	keys := make([]string, 0, len(headers))
	for k := range headers {
		if _, vol := volatileHeaders[strings.ToLower(strings.TrimSpace(k))]; vol {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var hb strings.Builder
	for _, k := range keys {
		hb.WriteString(strings.ToLower(k))
		hb.WriteByte(':')
		hb.WriteString(headers[k])
		hb.WriteByte('\n')
	}
	hh := sha256.Sum256([]byte(hb.String()))
	return ResponseFingerprint{
		StatusCode: status,
		BodyLength: len(body),
		BodyHash:   hex.EncodeToString(h[:]),
		DurationMs: durationMs,
		HeaderHash: hex.EncodeToString(hh[:]),
	}
}

// Differs reports whether a probe response meaningfully differs from the
// baseline for parameter-discovery purposes. It deliberately ignores response
// timing (network jitter is not evidence of a parameter) and relies on status
// code, body, and the volatile-filtered header signature.
func Differs(a, b ResponseFingerprint) bool {
	if a.StatusCode != b.StatusCode {
		return true
	}
	lenDiff := abs(a.BodyLength - b.BodyLength)
	if lenDiff > 64 {
		return true
	}
	if a.BodyHash != b.BodyHash && a.BodyLength < 256 && lenDiff > 0 {
		return true
	}
	if a.HeaderHash != b.HeaderHash {
		return true
	}
	return false
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// ExtractFromTemplateBody extracts parameter names from a request template body (form urlencoded or JSON).
func ExtractFromTemplateBody(endpointURL, method, contentType, body string) []DiscoveredParameter {
	var out []DiscoveredParameter
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return nil
	}
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "json") || strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		for k := range extractJSONKeys(body) {
			out = append(out, DiscoveredParameter{
				Name: k, Location: LocationJSON, Priority: 95, Confidence: 0.98,
				Source: "form_template", EndpointURL: endpointURL, EndpointMethod: method,
			})
		}
		if len(out) > 0 {
			return out
		}
	}
	if parsed, err := url.ParseQuery(trimmed); err == nil && len(parsed) > 0 {
		for k := range parsed {
			k = strings.TrimSpace(k)
			if k != "" {
				out = append(out, DiscoveredParameter{
					Name: k, Location: LocationForm, Priority: 95, Confidence: 0.98,
					Source: "form_template", EndpointURL: endpointURL, EndpointMethod: method,
				})
			}
		}
	}
	return out
}
