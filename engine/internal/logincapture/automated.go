package logincapture

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// LoginRequest describes credentials for automated form login.
type LoginRequest struct {
	LoginURL      string            `json:"login_url"`
	Username      string            `json:"username"`
	Password      string            `json:"password"`
	UsernameField string            `json:"username_field,omitempty"`
	PasswordField string            `json:"password_field,omitempty"`
	ExtraFields   map[string]string `json:"extra_fields,omitempty"`
	Steps         []LoginStep       `json:"steps,omitempty"`
	ForceHTTP1    bool              `json:"force_http1"`
}

type LoginStep struct {
	URL     string            `json:"url"`
	Method  string            `json:"method,omitempty"`
	Fields  map[string]string `json:"fields,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

var (
	inputNameRe  = regexp.MustCompile(`(?i)<input[^>]+name=["']([^"']+)["'][^>]*>`)
	formActionRe = regexp.MustCompile(`(?i)<form[^>]*action=["']([^"']*)["']`)
)

// AutomatedLogin performs a browser-like form login over HTTP/1.1 and returns captured session data.
func AutomatedLogin(ctx context.Context, req LoginRequest) (Session, error) {
	if strings.TrimSpace(req.LoginURL) == "" {
		return Session{}, fmt.Errorf("login_url is required")
	}
	loginURL, err := url.Parse(req.LoginURL)
	if err != nil {
		return Session{}, err
	}

	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return Session{}, err
	}

	transport := httpTransport(req.ForceHTTP1)
	client := &http.Client{
		Timeout:   45 * time.Second,
		Jar:       jar,
		Transport: transport,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, req.LoginURL, nil)
	if err != nil {
		return Session{}, err
	}
	getReq.Header.Set("User-Agent", defaultUserAgent())
	getResp, err := client.Do(getReq)
	if err != nil {
		return Session{}, fmt.Errorf("fetch login page: %w", err)
	}
	pageBody, err := io.ReadAll(io.LimitReader(getResp.Body, 2<<20))
	getResp.Body.Close()
	if err != nil {
		return Session{}, err
	}

	actionURL, fields := parseLoginForm(string(pageBody), loginURL)
	userField := req.UsernameField
	passField := req.PasswordField
	if userField == "" {
		userField = guessUsernameField(fields)
	}
	if passField == "" {
		passField = guessPasswordField(fields)
	}
	if userField == "" || passField == "" {
		return Session{}, fmt.Errorf("could not detect login form fields; specify username_field and password_field")
	}

	form := url.Values{}
	for k, v := range fields {
		form.Set(k, v)
	}
	for k, v := range req.ExtraFields {
		form.Set(k, v)
	}
	form.Set(userField, req.Username)
	form.Set(passField, req.Password)

	postReq, err := http.NewRequestWithContext(ctx, http.MethodPost, actionURL, strings.NewReader(form.Encode()))
	if err != nil {
		return Session{}, err
	}
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("User-Agent", defaultUserAgent())
	postReq.Header.Set("Referer", req.LoginURL)
	postReq.Header.Set("Origin", originOf(loginURL))

	postResp, err := client.Do(postReq)
	if err != nil {
		return Session{}, fmt.Errorf("submit login: %w", err)
	}
	postBody, _ := io.ReadAll(io.LimitReader(postResp.Body, 1<<20))
	postResp.Body.Close()
	responses := []capturedLoginResponse{{response: postResp, body: postBody}}
	lastURL := postResp.Request.URL

	for index, step := range req.Steps {
		method := strings.ToUpper(strings.TrimSpace(step.Method))
		if method == "" {
			method = http.MethodPost
		}
		stepURL := strings.TrimSpace(step.URL)
		if stepURL == "" && lastURL != nil {
			stepURL = lastURL.String()
		} else if lastURL != nil {
			stepURL = resolveURL(lastURL, stepURL)
		}
		form := url.Values{}
		for key, value := range step.Fields {
			form.Set(key, value)
		}
		var bodyReader io.Reader
		if method != http.MethodGet && method != http.MethodHead {
			bodyReader = strings.NewReader(form.Encode())
		} else if len(form) > 0 {
			parsed, parseErr := url.Parse(stepURL)
			if parseErr != nil {
				return Session{}, fmt.Errorf("login step %d URL: %w", index+1, parseErr)
			}
			query := parsed.Query()
			for key, values := range form {
				for _, value := range values {
					query.Add(key, value)
				}
			}
			parsed.RawQuery = query.Encode()
			stepURL = parsed.String()
		}
		stepReq, requestErr := http.NewRequestWithContext(ctx, method, stepURL, bodyReader)
		if requestErr != nil {
			return Session{}, fmt.Errorf("login step %d: %w", index+1, requestErr)
		}
		stepReq.Header.Set("User-Agent", defaultUserAgent())
		if bodyReader != nil {
			stepReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		for key, value := range step.Headers {
			stepReq.Header.Set(key, value)
		}
		stepResp, stepErr := client.Do(stepReq)
		if stepErr != nil {
			return Session{}, fmt.Errorf("login step %d request: %w", index+1, stepErr)
		}
		stepBody, _ := io.ReadAll(io.LimitReader(stepResp.Body, 1<<20))
		stepResp.Body.Close()
		responses = append(responses, capturedLoginResponse{response: stepResp, body: stepBody})
		lastURL = stepResp.Request.URL
		if stepResp.StatusCode >= 400 {
			return Session{}, fmt.Errorf("login step %d returned HTTP %d", index+1, stepResp.StatusCode)
		}
	}

	sess := NewSession()
	sess.MergeCookies(cookiesFromJar(jar, loginURL))
	for _, u := range []*url.URL{loginURL, lastURL} {
		if u != nil {
			sess.MergeCookies(cookiesFromJar(jar, u))
		}
	}
	for _, captured := range responses {
		mergeLoginResponse(&sess, captured)
	}
	if len(sess.Cookies) == 0 && !hasAuthenticationHeader(sess.Headers) {
		return sess, fmt.Errorf("login submitted but no session cookies or authentication tokens were captured")
	}
	if postResp.StatusCode >= 400 {
		sess.Notes = fmt.Sprintf("login POST returned HTTP %d; cookies captured anyway", postResp.StatusCode)
	}
	return sess, nil
}

func hasAuthenticationHeader(headers map[string]string) bool {
	for key, value := range headers {
		if isAuthHeader(key) && strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

type capturedLoginResponse struct {
	response *http.Response
	body     []byte
}

func mergeLoginResponse(session *Session, captured capturedLoginResponse) {
	if captured.response == nil {
		return
	}
	for key, values := range captured.response.Header {
		if strings.EqualFold(key, "set-cookie") {
			for _, value := range values {
				session.MergeCookies(parseSetCookie(value))
			}
		}
		if isAuthHeader(key) && len(values) > 0 {
			session.MergeHeaders(map[string]string{key: values[0]})
		}
	}
	var object map[string]interface{}
	if json.Unmarshal(captured.body, &object) != nil {
		return
	}
	for _, key := range []string{"access_token", "token", "id_token"} {
		if token, ok := object[key].(string); ok && strings.TrimSpace(token) != "" {
			session.MergeHeaders(map[string]string{"Authorization": "Bearer " + strings.TrimSpace(token)})
			return
		}
	}
}

func httpTransport(forceHTTP1 bool) *http.Transport {
	tr := &http.Transport{
		ForceAttemptHTTP2: !forceHTTP1,
	}
	if forceHTTP1 {
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	return tr
}

func parseLoginForm(html string, base *url.URL) (string, map[string]string) {
	fields := map[string]string{}
	action := base.String()
	if m := formActionRe.FindStringSubmatch(html); len(m) == 2 {
		action = resolveURL(base, m[1])
	}
	for _, m := range inputNameRe.FindAllStringSubmatch(html, -1) {
		if len(m) != 2 {
			continue
		}
		name := m[0]
		fieldName := m[1]
		lower := strings.ToLower(name)
		switch {
		case strings.Contains(lower, `type="password"`):
			fields[fieldName] = ""
		case strings.Contains(lower, `type="hidden"`):
			if val := extractInputValue(name); val != "" {
				fields[fieldName] = val
			}
		case strings.Contains(lower, `type="submit"`), strings.Contains(lower, `type="button"`):
			continue
		default:
			fields[fieldName] = ""
		}
	}
	return action, fields
}

var inputValueRe = regexp.MustCompile(`(?i)value=["']([^"']*)["']`)

func extractInputValue(tag string) string {
	if m := inputValueRe.FindStringSubmatch(tag); len(m) == 2 {
		return m[1]
	}
	return ""
}

func guessUsernameField(fields map[string]string) string {
	for name := range fields {
		lower := strings.ToLower(name)
		if strings.Contains(lower, "user") || strings.Contains(lower, "email") || strings.Contains(lower, "login") {
			return name
		}
	}
	for name := range fields {
		return name
	}
	return ""
}

func guessPasswordField(fields map[string]string) string {
	for name := range fields {
		if strings.Contains(strings.ToLower(name), "pass") {
			return name
		}
	}
	return ""
}

func resolveURL(base *url.URL, ref string) string {
	if ref == "" {
		return base.String()
	}
	u, err := base.Parse(ref)
	if err != nil {
		return base.String()
	}
	return u.String()
}

func originOf(u *url.URL) string {
	if u == nil {
		return ""
	}
	scheme := u.Scheme
	if scheme == "" {
		scheme = "https"
	}
	return scheme + "://" + u.Host
}

func cookiesFromJar(jar *cookiejar.Jar, u *url.URL) map[string]string {
	out := map[string]string{}
	if jar == nil || u == nil {
		return out
	}
	for _, c := range jar.Cookies(u) {
		if c.Name != "" {
			out[c.Name] = c.Value
		}
	}
	return out
}

func defaultUserAgent() string {
	return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
}
