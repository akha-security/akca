package verification

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type DOMStructure struct {
	TagCount   int `json:"tag_count"`
	MaxDepth   int `json:"max_depth"`
	ScriptTags int `json:"script_tags"`
}

type SemanticDelta struct {
	ChangedSchema      bool     `json:"changed_schema"`
	ChangedStatus      bool     `json:"changed_status"`
	ChangedHeaders     bool     `json:"changed_headers,omitempty"`
	ChangedDOM         bool     `json:"changed_dom"`
	AddedSensitiveData []string `json:"added_sensitive_data,omitempty"`
	AddedErrorSignals  []string `json:"added_error_signals,omitempty"`
	Similarity         float64  `json:"similarity"`
	DynamicOnly        bool     `json:"dynamic_only"`
	SecurityRelevant   bool     `json:"security_relevant"`
}

func AnalyzeDOMStructure(html string) DOMStructure {
	re := regexp.MustCompile(`<(/?)([a-zA-Z][a-zA-Z0-9]*)`)
	matches := re.FindAllStringSubmatch(html, -1)
	depth := 0
	maxDepth := 0
	scripts := 0
	for _, m := range matches {
		if len(m) < 3 {
			continue
		}
		if m[1] == "/" {
			if depth > 0 {
				depth--
			}
			continue
		}
		depth++
		if depth > maxDepth {
			maxDepth = depth
		}
		if strings.EqualFold(m[2], "script") {
			scripts++
		}
	}
	return DOMStructure{TagCount: len(matches), MaxDepth: maxDepth, ScriptTags: scripts}
}

func CompareDOMStructure(a, b DOMStructure) bool {
	if a.TagCount == 0 && b.TagCount == 0 {
		return true
	}
	return abs(a.TagCount-b.TagCount) <= 2 &&
		abs(a.MaxDepth-b.MaxDepth) <= 1 &&
		a.ScriptTags == b.ScriptTags
}

func ExtractJSONKeyPaths(body string) []string {
	var raw interface{}
	if err := json.Unmarshal([]byte(body), &raw); err != nil {
		return nil
	}
	var paths []string
	collectJSONPaths("", raw, &paths)
	return paths
}

func collectJSONPaths(prefix string, v interface{}, out *[]string) {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, val := range t {
			path := k
			if prefix != "" {
				path = prefix + "." + k
			}
			*out = append(*out, path)
			collectJSONPaths(path, val, out)
		}
	case []interface{}:
		for i, val := range t {
			path := prefix + "[" + strconv.Itoa(i) + "]"
			collectJSONPaths(path, val, out)
		}
	}
}

func CompareJSONKeyPaths(aBody, bBody string) bool {
	a := ExtractJSONKeyPaths(aBody)
	b := ExtractJSONKeyPaths(bBody)
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	if len(a) != len(b) {
		return false
	}
	am := map[string]struct{}{}
	for _, p := range a {
		am[p] = struct{}{}
	}
	for _, p := range b {
		if _, ok := am[p]; !ok {
			return false
		}
	}
	return true
}

var errorKeywords = []string{
	"sql syntax", "mysql", "postgresql", "sqlite", "ora-", "syntax error",
	"stack trace", "exception", "fatal error", "undefined index", "warning:",
}

func ContainsErrorKeywords(body string) bool {
	lower := strings.ToLower(body)
	for _, kw := range errorKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func SemanticDiffers(base, probe ResponseSnapshot) bool {
	return CompareSemantic(base, probe).SecurityRelevant
}

func CompareSemantic(base, probe ResponseSnapshot) SemanticDelta {
	baseBody := NormalizeVolatileFields(base.Body)
	probeBody := NormalizeVolatileFields(probe.Body)
	delta := SemanticDelta{
		ChangedStatus: base.StatusCode != probe.StatusCode,
		Similarity:    textSimilarity(baseBody, probeBody),
		DynamicOnly:   base.Body != probe.Body && baseBody == probeBody,
	}
	baseType := strings.ToLower(base.ContentType)
	probeType := strings.ToLower(probe.ContentType)
	isJSON := strings.Contains(baseType, "json") || strings.Contains(probeType, "json")
	isHTML := strings.Contains(baseType, "html") || strings.Contains(probeType, "html") ||
		strings.Contains(baseBody, "<")
	isBinary := isBinaryContentType(baseType) || isBinaryContentType(probeType)

	if isJSON {
		delta.ChangedSchema = !CompareJSONKeyPaths(baseBody, probeBody)
		delta.AddedSensitiveData = addedSensitiveJSONPaths(baseBody, probeBody)
	} else if isHTML && !isBinary {
		delta.ChangedDOM = !CompareDOMStructure(AnalyzeDOMStructure(baseBody), AnalyzeDOMStructure(probeBody))
	}
	delta.AddedErrorSignals = addedErrorSignals(baseBody, probeBody)
	delta.SecurityRelevant = delta.ChangedStatus || delta.ChangedSchema || delta.ChangedDOM ||
		len(delta.AddedSensitiveData) > 0 || len(delta.AddedErrorSignals) > 0
	if delta.DynamicOnly {
		delta.SecurityRelevant = false
	}
	return delta
}

func SignificantHeaderDiff(base, probe ResponseSnapshot) bool {
	baseHeaders := significantHeaders(base.Headers)
	probeHeaders := significantHeaders(probe.Headers)
	if len(baseHeaders) != len(probeHeaders) {
		return true
	}
	for key, probeValue := range probeHeaders {
		if baseHeaders[key] != probeValue {
			return true
		}
	}
	return false
}

func significantHeaders(headers map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range headers {
		lower := strings.ToLower(strings.TrimSpace(key))
		switch {
		case lower == "location",
			lower == "x-akca-crlf",
			lower == "x-injected",
			strings.HasPrefix(lower, "access-control-"):
			out[lower] = strings.ToLower(strings.TrimSpace(value))
		}
	}
	return out
}

func addedErrorSignals(base, probe string) []string {
	base = strings.ToLower(base)
	probe = strings.ToLower(probe)
	var out []string
	for _, keyword := range errorKeywords {
		if strings.Contains(probe, keyword) && !strings.Contains(base, keyword) {
			out = append(out, keyword)
		}
	}
	return out
}

func addedSensitiveJSONPaths(baseBody, probeBody string) []string {
	var base, probe interface{}
	if json.Unmarshal([]byte(baseBody), &base) != nil || json.Unmarshal([]byte(probeBody), &probe) != nil {
		return nil
	}
	baseValues := make(map[string]string)
	probeValues := make(map[string]string)
	collectSensitiveValues("", base, baseValues)
	collectSensitiveValues("", probe, probeValues)
	var out []string
	for path, value := range probeValues {
		if value != "" && baseValues[path] != value {
			out = append(out, path)
		}
	}
	sort.Strings(out)
	return out
}

var sensitiveJSONKeyRE = regexp.MustCompile(`(?i)(password|secret|token|api[_-]?key|ssn|credit|card|email|phone|address|role|permission)`)

func collectSensitiveValues(prefix string, value interface{}, out map[string]string) {
	switch typed := value.(type) {
	case map[string]interface{}:
		for key, child := range typed {
			path := key
			if prefix != "" {
				path = prefix + "." + key
			}
			if sensitiveJSONKeyRE.MatchString(key) {
				raw, _ := json.Marshal(child)
				out[path] = string(raw)
			}
			collectSensitiveValues(path, child, out)
		}
	case []interface{}:
		for index, child := range typed {
			collectSensitiveValues(prefix+"["+strconv.Itoa(index)+"]", child, out)
		}
	}
}

func textSimilarity(a, b string) float64 {
	if a == b {
		return 1
	}
	if a == "" || b == "" {
		return 0
	}
	aTokens := strings.Fields(a)
	bTokens := strings.Fields(b)
	if len(aTokens) == 0 || len(bTokens) == 0 {
		return 0
	}
	counts := make(map[string]int, len(aTokens))
	for _, token := range aTokens {
		counts[token]++
	}
	common := 0
	for _, token := range bTokens {
		if counts[token] > 0 {
			counts[token]--
			common++
		}
	}
	return 2 * float64(common) / float64(len(aTokens)+len(bTokens))
}

func isBinaryContentType(contentType string) bool {
	return strings.Contains(contentType, "image/") || strings.Contains(contentType, "audio/") ||
		strings.Contains(contentType, "video/") || strings.Contains(contentType, "application/pdf") ||
		strings.Contains(contentType, "application/octet-stream")
}
