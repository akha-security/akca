package modules

import (
	"encoding/base64"
	"net/url"
	"regexp"
	"strings"
)

var (
	uuidRe    = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	emailRe   = regexp.MustCompile(`(?i)^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$`)
	numericRe = regexp.MustCompile(`^\d+$`)
	b64Re     = regexp.MustCompile(`^[A-Za-z0-9+/=_-]{16,}={0,2}$`)
)

var idParamNames = []string{
	"id", "uid", "user_id", "userid", "account_id", "account", "invoice", "invoice_id",
	"invoice_num", "order_id", "order", "uuid", "guid", "ref", "reference", "doc_id",
	"document_id", "resource_id", "object_id", "profile_id", "customer_id", "member_id",
}

var workflowEarly = []string{"checkout", "cart", "payment", "billing", "shipping", "wizard", "step", "register", "signup", "verify", "onboard"}
var workflowLate = []string{"receipt", "confirm", "confirmation", "complete", "success", "finalize", "done", "thank", "summary"}

// IDCandidate is a parameter or path segment that may reference an object identity.
type IDCandidate struct {
	Name  string
	Value string
	Kind  string // numeric, uuid, email, base64, path_segment, named_param
}

func classifyIDValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	switch {
	case uuidRe.MatchString(v):
		return "uuid"
	case emailRe.MatchString(v):
		return "email"
	case numericRe.MatchString(v):
		return "numeric"
	case b64Re.MatchString(v) && len(v) >= 16:
		if _, err := base64.StdEncoding.DecodeString(v); err == nil {
			return "base64"
		}
		if _, err := base64.RawURLEncoding.DecodeString(v); err == nil {
			return "base64"
		}
	}
	return ""
}

func extractIDCandidates(endpointURL, param string) []IDCandidate {
	u, err := url.Parse(endpointURL)
	if err != nil {
		return nil
	}
	seen := map[string]struct{}{}
	var out []IDCandidate
	add := func(name, value, kind string) {
		if value == "" || kind == "" {
			return
		}
		key := name + "|" + value
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, IDCandidate{Name: name, Value: value, Kind: kind})
	}

	if param != "" {
		for _, v := range u.Query()[param] {
			if kind := classifyIDValue(v); kind != "" {
				add(param, v, kind)
			}
		}
	}
	for name, vals := range u.Query() {
		lower := strings.ToLower(name)
		for _, hint := range idParamNames {
			if lower == hint || strings.Contains(lower, hint) {
				for _, v := range vals {
					if kind := classifyIDValue(v); kind != "" {
						add(name, v, kind)
					}
				}
			}
		}
	}

	segs := strings.Split(strings.Trim(u.Path, "/"), "/")
	for i, seg := range segs {
		if kind := classifyIDValue(seg); kind != "" {
			add("path_segment_"+itoa(i), seg, kind)
		}
	}
	return out
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [12]byte
	n := len(b)
	v := i
	for v > 0 {
		n--
		b[n] = byte('0' + v%10)
		v /= 10
	}
	return string(b[n:])
}

func idSwapValues(kind, original string) []string {
	switch kind {
	case "numeric":
		return []string{"1", "2", "3", "100", "999", "0", "-1"}
	case "uuid":
		return []string{
			"00000000-0000-0000-0000-000000000001",
			"00000000-0000-0000-0000-000000000002",
			"11111111-1111-1111-1111-111111111111",
		}
	case "email":
		return []string{"victim@example.com", "admin@example.com", "other@test.local"}
	case "base64":
		return []string{
			base64.StdEncoding.EncodeToString([]byte("admin")),
			base64.StdEncoding.EncodeToString([]byte("2")),
		}
	default:
		return []string{"2", "admin", "test"}
	}
}

func buildStepSkipURLs(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	pathLower := strings.ToLower(u.Path)
	if !containsAny(pathLower, workflowEarly...) {
		return nil
	}
	segs := strings.Split(strings.Trim(u.Path, "/"), "/")
	var out []string
	seen := map[string]struct{}{}
	add := func(path string) {
		if path == "" {
			return
		}
		nu := *u
		nu.Path = path
		nu.RawQuery = u.RawQuery
		s := nu.String()
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}

	for i, seg := range segs {
		lower := strings.ToLower(seg)
		if !containsAny(lower, workflowEarly...) {
			continue
		}
		for _, late := range workflowLate {
			mutated := append(append([]string{}, segs[:i]...), late)
			if i+1 < len(segs) {
				mutated = append(mutated, segs[i+1:]...)
			}
			add("/" + strings.Join(mutated, "/"))
			add("/api/v1/" + late)
			add("/api/" + late)
		}
	}
	return out
}

func containsAny(s string, parts ...string) bool {
	for _, p := range parts {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

func stepSkipQueryVariants(rawQuery string) []string {
	if rawQuery == "" {
		return []string{
			"step=3&step=1",
			"state=complete&state=pending",
			"token=&token=skip",
			"confirmed=true&confirmed=false",
		}
	}
	vals, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil
	}
	var out []string
	for key := range vals {
		lower := strings.ToLower(key)
		if containsAny(lower, "step", "state", "token", "stage", "phase", "confirm") {
			out = append(out, key+"=final&"+key+"=skip")
			out = append(out, key+"=3&"+key+"=1")
		}
	}
	return out
}
