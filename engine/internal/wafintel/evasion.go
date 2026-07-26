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
}

type LearningProfile struct {
	Domain           string         `json:"domain"`
	StrategyScores   map[string]int `json:"strategy_scores"`
	TechniqueScores  map[string]int `json:"technique_scores,omitempty"`
	BlockedEncodings []string       `json:"blocked_encodings"`
	LastSuccessful   string         `json:"last_successful"`
	LastTechnique    string         `json:"last_technique,omitempty"`
}

func NewLearningProfile(domain string) LearningProfile {
	return LearningProfile{Domain: domain, StrategyScores: map[string]int{}, TechniqueScores: map[string]int{}}
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
	out := payload
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
		}
	}
	out = MutatePayload(out)
	return out, headers
}

func ApplyEncoding(s, enc string) string {
	switch enc {
	case "url":
		return url.QueryEscape(s)
	case "double_url":
		return url.QueryEscape(url.QueryEscape(s))
	case "unicode":
		return unicodeEscape(s)
	case "html_entity":
		return htmlEntityEncode(s)
	case "hex":
		return hexEncode(s)
	case "octal":
		return octalEncode(s)
	case "mixed":
		if len(s) == 0 {
			return s
		}
		return url.QueryEscape(string(s[0])) + htmlEntityEncode(s[1:])
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
