package logincapture

import (
	"strings"
	"sync"

	"github.com/akha-security/akca/engine/internal/workflow"
)

// Session holds cookies and headers captured during login.
type Session struct {
	Cookies  map[string]string    `json:"cookies"`
	Headers  map[string]string    `json:"headers"`
	Notes    string               `json:"notes,omitempty"`
	Workflow *workflow.Definition `json:"workflow,omitempty"`
}

func NewSession() Session {
	return Session{
		Cookies: map[string]string{},
		Headers: map[string]string{},
	}
}

func (s *Session) MergeCookies(cookies map[string]string) {
	if len(cookies) == 0 {
		return
	}
	if s.Cookies == nil {
		s.Cookies = map[string]string{}
	}
	for k, v := range cookies {
		if k != "" && v != "" {
			s.Cookies[k] = v
		}
	}
}

func (s *Session) MergeHeaders(headers map[string]string) {
	if len(headers) == 0 {
		return
	}
	if s.Headers == nil {
		s.Headers = map[string]string{}
	}
	for k, v := range headers {
		if k != "" && v != "" {
			s.Headers[k] = v
		}
	}
}

// CookieJar accumulates Set-Cookie and Cookie header values from proxy traffic.
type CookieJar struct {
	mu      sync.Mutex
	cookies map[string]string
	headers map[string]string
}

func NewCookieJar() *CookieJar {
	return &CookieJar{
		cookies: map[string]string{},
		headers: map[string]string{},
	}
}

func (j *CookieJar) IngestRequestHeaders(h map[string]string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for k, v := range h {
		if strings.EqualFold(k, "cookie") {
			for ck, cv := range parseCookieHeader(v) {
				j.cookies[ck] = cv
			}
		}
		if isAuthHeader(k) {
			j.headers[k] = v
		}
	}
}

func (j *CookieJar) IngestSetCookie(raw string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for ck, cv := range parseSetCookie(raw) {
		j.cookies[ck] = cv
	}
}

func (j *CookieJar) Snapshot() Session {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := NewSession()
	for k, v := range j.cookies {
		out.Cookies[k] = v
	}
	for k, v := range j.headers {
		out.Headers[k] = v
	}
	return out
}

func parseCookieHeader(raw string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(raw, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 && kv[0] != "" {
			out[kv[0]] = kv[1]
		}
	}
	return out
}

func parseSetCookie(raw string) map[string]string {
	out := map[string]string{}
	kv := strings.SplitN(strings.TrimSpace(raw), ";", 2)
	if len(kv) == 0 {
		return out
	}
	nameVal := strings.SplitN(strings.TrimSpace(kv[0]), "=", 2)
	if len(nameVal) == 2 && nameVal[0] != "" {
		out[nameVal[0]] = nameVal[1]
	}
	return out
}

func isAuthHeader(k string) bool {
	switch strings.ToLower(k) {
	case "authorization", "x-api-key", "x-auth-token", "x-csrf-token", "x-xsrf-token":
		return true
	default:
		return false
	}
}
