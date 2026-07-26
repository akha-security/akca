package testlab

import (
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/akha-security/akca/engine/internal/testfixtures"
)

const DefaultDomain = "lab.akca.test"

// Server simulates a vulnerable bug-bounty target for end-to-end scans.
type Server struct {
	Host   string
	Server *httptest.Server
	Mode   Mode

	mu          sync.Mutex
	raceClaims  atomic.Int32
	rateHits    map[string]int
	oastSink    func(string)
	profileRole string
}

type Mode int

const (
	ModeFull Mode = iota
	ModeV1
	ModeV2
)

func NewServer(mode Mode) *Server {
	lab := &Server{
		Mode:        mode,
		rateHits:    map[string]int{},
		profileRole: "user",
	}
	lab.Server = httptest.NewServer(http.HandlerFunc(lab.handle))
	u, _ := url.Parse(lab.Server.URL)
	lab.Host = u.Host
	return lab
}

func (s *Server) Close() {
	if s.Server != nil {
		s.Server.Close()
	}
}

func (s *Server) BaseURL() string {
	return s.Server.URL + "/"
}

func (s *Server) ScopeDomain() string {
	host := s.Host
	if idx := strings.Index(host, ":"); idx >= 0 {
		return host[:idx]
	}
	return host
}

func (s *Server) SetOASTInteractionSink(sink func(string)) {
	s.mu.Lock()
	s.oastSink = sink
	s.mu.Unlock()
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.setWAFHeaders(w)
	path := r.URL.Path

	switch {
	case path == "/":
		s.serveIndex(w)
	case strings.HasPrefix(path, "/parity/safe/"):
		s.serveParitySafe(w, r)
	case path == "/parity/auth/jwt":
		s.serveParityJWT(w, r)
	case path == "/parity/oauth/authorize":
		s.serveParityOAuth(w, r)
	case path == "/parity/auth/forgot":
		s.serveParityAccountEnum(w, r)
	case path == "/parity/auth/login":
		s.serveParityRateLimit(w, r)
	case path == "/parity/api/profile":
		s.serveParityProfile(w, r)
	case path == "/auth/profile":
		s.serveAuthProfile(w, r)
	case path == "/search":
		s.serveSearch(w, r)
	case strings.HasPrefix(path, "/api/users"):
		s.serveUsers(w, r)
	case strings.HasPrefix(path, "/api/fetch"):
		s.serveFetch(w, r)
	case path == "/download":
		s.serveDownload(w, r)
	case path == "/xml":
		s.serveXML(w, r)
	case path == "/redirect":
		s.serveRedirect(w, r)
	case path == "/admin":
		s.serveAdmin(w, r)
	case path == "/actuator/health":
		s.serveActuator(w)
	case path == "/backup.tar.gz":
		s.serveArchive(w)
	case path == "/static/app.js":
		s.serveAppJS(w)
	case path == "/graphql":
		s.serveGraphQL(w, r)
	case path == "/waf-probe":
		s.serveWAFProbe(w, r)
	case path == "/coupon/claim":
		s.serveRace(w, r)
	case path == "/rate-limit":
		s.serveRateLimit(w, r)
	case path == "/profile":
		s.serveProfile(w)
	case strings.Contains(r.URL.RawQuery, ".oast.akca.local") || strings.Contains(readBody(r), ".oast.akca.local"):
		s.serveOASTAck(w)
	default:
		if r.Method == http.MethodGet && r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.NotFound(w, r)
	}
}

func (s *Server) setWAFHeaders(w http.ResponseWriter) {
	w.Header().Set("Server", "cloudflare")
	w.Header().Set("CF-RAY", "akca-lab-test")
}

func (s *Server) serveIndex(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, `<!doctype html><html><body>
<h1>Akca Lab Target</h1>
<a href="/search?q=hello">search</a>
<a href="/api/users?id=1">users</a>
<a href="/redirect?url=/home">redirect</a>
<a href="/admin">admin</a>
<a href="/actuator/health">actuator</a>
<a href="/backup.tar.gz">backup</a>
<a href="/static/app.js">app.js</a>
<a href="/graphql">graphql</a>
<a href="/waf-probe?x=test">waf</a>
<a href="/coupon/claim?claim=bonus">race</a>
<a href="/profile">profile</a>
<a href="/api/fetch?url=http://example.com">fetch</a>
<a href="/download?file=index.html">download</a>
<a href="https://offscope.evil/secret">offscope</a>
</body></html>`)
}

func (s *Server) serveSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	switch s.Mode {
	case ModeV2:
		_, _ = io.WriteString(w, "<html><body>results: "+html.EscapeString(q)+"</body></html>")
	default:
		_, _ = io.WriteString(w, "<html><body>results: "+q+"</body></html>")
	}
}

func (s *Server) serveUsers(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	unbalancedQuote := strings.Count(id, "'")%2 == 1 || strings.Count(id, `"`)%2 == 1
	if s.Mode == ModeV2 || unbalancedQuote {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":"You have an error in your SQL syntax near '`+id+`'"}`)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"id":`+id+`,"name":"alice"}`)
}

// serveFetch simulates a server-side fetch primitive vulnerable to SSRF. In V2
// the SSRF is patched (allowlist), so internal targets are not fetched.
func (s *Server) serveFetch(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	w.Header().Set("Content-Type", "text/plain")
	low := strings.ToLower(target)
	if s.Mode != ModeV2 {
		if parsed, err := url.Parse(target); err == nil && strings.Contains(strings.ToLower(parsed.Hostname()), ".oast.akca.local") {
			s.mu.Lock()
			sink := s.oastSink
			s.mu.Unlock()
			if sink != nil {
				sink(parsed.Hostname())
			}
		}
		switch {
		case strings.Contains(low, "169.254.169.254") || strings.Contains(low, "2852039166"):
			_, _ = io.WriteString(w, "ami-id: ami-0akcatest\ninstance-id: i-0lab\nmetadata leaked")
			return
		case strings.Contains(low, "metadata.google.internal"):
			_, _ = io.WriteString(w, "computeMetadata instance metadata project akca")
			return
		case strings.Contains(low, "127.0.0.1") || strings.Contains(low, "localhost"):
			_, _ = io.WriteString(w, "internal service reached at 127.0.0.1 (metadata)")
			return
		}
	}
	_, _ = io.WriteString(w, "fetched: "+html.EscapeString(target))
}

func (s *Server) serveAuthProfile(w http.ResponseWriter, r *http.Request) {
	authenticated := false
	if cookie, err := r.Cookie("akca_session"); err == nil && cookie.Value == "valid" {
		authenticated = true
	}
	if s.Mode == ModeV2 && !authenticated {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"profile":{"account":"AC-1042","billing":"active","orders":[101,102]},"session":"valid"}`)
}

func (s *Server) serveParitySafe(w http.ResponseWriter, r *http.Request) {
	path := strings.ToLower(r.URL.Path)
	index, _ := strconv.Atoi(strings.TrimLeft(path[strings.LastIndex(path, "/")+1:], "0"))
	variant := index % 4
	switch {
	case strings.Contains(path, "/search/"):
		q := r.URL.Query().Get("q")
		if variant == 3 && strings.Contains(q, "<") {
			http.Error(w, "request rejected by policy", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if variant == 2 {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		}
		_, _ = io.WriteString(w, "<html><body>results: "+html.EscapeString(q)+"</body></html>")
	case strings.Contains(path, "/api/users/"):
		id := html.EscapeString(r.URL.Query().Get("id"))
		w.Header().Set("Content-Type", "application/json")
		switch variant {
		case 1:
			_, _ = io.WriteString(w, `{"error":"validation failed","request_id":"safe-`+id+`"}`)
		case 2:
			http.Error(w, "temporary upstream error", http.StatusInternalServerError)
		default:
			_, _ = io.WriteString(w, `{"id":"`+id+`","name":"public user"}`)
		}
	case strings.Contains(path, "/api/fetch/"):
		target := html.EscapeString(r.URL.Query().Get("url"))
		w.Header().Set("Content-Type", "text/plain")
		switch variant {
		case 1:
			http.Error(w, "URL rejected by allowlist", http.StatusBadRequest)
		case 2:
			http.Error(w, "upstream gateway unavailable", http.StatusBadGateway)
		default:
			_, _ = io.WriteString(w, "validated URL: "+target)
		}
	case strings.Contains(path, "/download/"):
		file := html.EscapeString(r.URL.Query().Get("file"))
		w.Header().Set("Content-Type", "text/plain")
		switch variant {
		case 1:
			http.NotFound(w, r)
		case 2:
			_, _ = io.WriteString(w, "documentation index")
		default:
			_, _ = io.WriteString(w, "requested filename: "+file)
		}
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) serveParityJWT(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	header, claims, ok := decodeLabJWT(token)
	if !ok {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	accepted := token == LabValidJWT()
	if s.Mode != ModeV2 && strings.EqualFold(stringValue(header["alg"]), "none") {
		accepted = true
	}
	if !accepted {
		http.Error(w, "invalid or expired token", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"sub": stringValue(claims["sub"]), "role": stringValue(claims["role"]),
	})
}

func (s *Server) serveParityOAuth(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	parsed, err := url.Parse(redirectURI)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	if s.Mode == ModeV2 && redirectURI != "https://client.example/callback" {
		http.Error(w, "redirect_uri mismatch", http.StatusBadRequest)
		return
	}
	values := parsed.Query()
	values.Set("code", "akca-code")
	values.Set("state", state)
	parsed.RawQuery = values.Encode()
	w.Header().Set("Location", parsed.String())
	w.WriteHeader(http.StatusFound)
}

func (s *Server) serveParityAccountEnum(w http.ResponseWriter, r *http.Request) {
	account := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("email")))
	w.Header().Set("Content-Type", "application/json")
	if s.Mode != ModeV2 && account != "known@example.com" {
		_, _ = io.WriteString(w, `{"error":"no account found"}`)
		return
	}
	_, _ = io.WriteString(w, `{"message":"If the account exists, reset instructions will be sent"}`)
}

func (s *Server) serveParityRateLimit(w http.ResponseWriter, r *http.Request) {
	account := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("username")))
	s.mu.Lock()
	s.rateHits["login:"+account]++
	hits := s.rateHits["login:"+account]
	s.mu.Unlock()
	if s.Mode == ModeV2 && account == "known@example.com" && hits > 3 {
		http.Error(w, "too many attempts; try again later", http.StatusTooManyRequests)
		return
	}
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = io.WriteString(w, "invalid credentials")
}

func (s *Server) serveParityProfile(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		role := s.profileRole
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"name": "alice", "role": role})
	case http.MethodPost:
		var body map[string]interface{}
		if json.Unmarshal([]byte(readBody(r)), &body) != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		role := "user"
		if supplied := stringValue(body["role"]); supplied != "" && s.Mode != ModeV2 {
			role = supplied
		}
		s.mu.Lock()
		s.profileRole = role
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"updated": true, "role": role})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func stringValue(value interface{}) string {
	text, _ := value.(string)
	return text
}

// serveDownload simulates a file-download endpoint vulnerable to path traversal.
func (s *Server) serveDownload(w http.ResponseWriter, r *http.Request) {
	file := r.URL.Query().Get("file")
	w.Header().Set("Content-Type", "text/plain")
	low := strings.ToLower(file)
	if s.Mode != ModeV2 && (strings.Contains(low, "etc/passwd") || strings.Contains(low, "etc%2fpasswd")) {
		_, _ = io.WriteString(w, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin/nologin")
		return
	}
	if file == "" || strings.Contains(low, "index.html") {
		_, _ = io.WriteString(w, "welcome to akca lab downloads")
		return
	}
	_, _ = io.WriteString(w, "file content: "+html.EscapeString(file))
}

// serveXML simulates an XML parser vulnerable to XXE entity expansion.
func (s *Server) serveXML(w http.ResponseWriter, r *http.Request) {
	body := readBody(r)
	w.Header().Set("Content-Type", "application/xml")
	if s.Mode != ModeV2 && strings.Contains(body, `<!ENTITY xxe "AKCA_XXE_TEST">`) && strings.Contains(body, "&xxe;") {
		_, _ = io.WriteString(w, "<result>AKCA_XXE_TEST</result>")
		return
	}
	_, _ = io.WriteString(w, "<result>ok</result>")
}

func (s *Server) serveRedirect(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	if s.Mode != ModeV2 &&
		(strings.Contains(target, "evil.example") || strings.HasPrefix(target, "//evil.example")) {
		w.Header().Set("Location", target)
		w.WriteHeader(http.StatusFound)
		return
	}
	http.Redirect(w, r, "/home", http.StatusFound)
}

func (s *Server) serveAdmin(w http.ResponseWriter, r *http.Request) {
	if s.Mode != ModeV2 &&
		(r.Header.Get("X-Original-URL") == "/admin" || r.Header.Get("X-Rewrite-URL") == "/admin") {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"admin":true,"users":[{"id":1,"role":"admin"}]}`)
		return
	}
	w.WriteHeader(http.StatusForbidden)
	_, _ = io.WriteString(w, "forbidden access denied")
}

func (s *Server) serveActuator(w http.ResponseWriter) {
	if s.Mode == ModeV2 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.spring-boot.actuator.v2+json")
	_, _ = io.WriteString(w, `{"status":"UP","components":{"diskSpace":{"status":"UP"},"actuator":{"details":"exposed"}}}`)
}

func (s *Server) serveArchive(w http.ResponseWriter) {
	if s.Mode == ModeV2 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x62, 0x61, 0x63, 0x6b, 0x75, 0x70})
}

func (s *Server) serveAppJS(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/javascript")
	if s.Mode == ModeV2 {
		_, _ = io.WriteString(w, `const apiBase="/api/v1"; console.log("safe application bundle");`)
		return
	}
	_, _ = io.WriteString(w, `fetch("/graphql",{method:"POST",body:JSON.stringify({query:"{__typename}"})});
const apiBase="/api/v1";
const cfg={baseURL:"/api/internal/v2"};
axios.get("/api/v1/profile");
const ghToken="`+testfixtures.GitHubShortToken()+`";
const awsKey="`+testfixtures.AWSExampleAccessKey()+`";
const googleKey="`+testfixtures.GoogleAPIKey()+`";
const stripeKey="`+testfixtures.StripeSecretKey()+`";
import("./admin/secret-module.js");
//# sourceMappingURL=app.js.map`)
}

func (s *Server) serveGraphQL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if s.Mode == ModeV2 {
		_, _ = io.WriteString(w, `{"data":{"__typename":"Query"}}`)
		return
	}
	_, _ = io.WriteString(w, `{"data":{"__schema":{"types":[{"name":"User","fields":[{"name":"password"},{"name":"email"}]}]}}}`)
}

func (s *Server) serveWAFProbe(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.RawQuery
	decoded, _ := url.QueryUnescape(raw)
	probe := strings.ToLower(raw + " " + decoded)
	if strings.Contains(probe, "<script") && !strings.Contains(probe, "%3c") && !strings.Contains(probe, "%3C") {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, "request blocked by waf")
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "waf bypass ok")
}

func (s *Server) serveRace(w http.ResponseWriter, r *http.Request) {
	claim := r.URL.Query().Get("claim")
	if claim == "akca-race-base" {
		s.raceClaims.Store(0)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "single success")
		return
	}
	if claim == "" {
		claim = "bonus"
	}
	n := s.raceClaims.Add(1)
	w.Header().Set("Content-Type", "text/plain")
	if n <= 10 {
		_, _ = io.WriteString(w, "bonus claimed success")
		return
	}
	_, _ = io.WriteString(w, "single success")
}

func (s *Server) serveRateLimit(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.rateHits[r.RemoteAddr]++
	hits := s.rateHits[r.RemoteAddr]
	s.mu.Unlock()
	if hits > 2 {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, "rate limit exceeded")
		return
	}
	_, _ = io.WriteString(w, "ok")
}

func (s *Server) serveProfile(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html")
	if s.Mode == ModeV2 {
		_, _ = io.WriteString(w, `<html><body>public profile</body></html>`)
		return
	}
	_, _ = io.WriteString(w, `<html><body>patient ssn 123-45-6789 date of birth 1990-01-01</body></html>`)
}

func (s *Server) serveOASTAck(w http.ResponseWriter) {
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "oast seen")
}

func readBody(r *http.Request) string {
	if r.Body == nil {
		return ""
	}
	b, _ := io.ReadAll(r.Body)
	_ = r.Body.Close()
	r.Body = io.NopCloser(strings.NewReader(string(b)))
	return string(b)
}

// ComparisonTargets returns paired v1/v2 lab servers for diff scans.
func ComparisonTargets() (v1, v2 *Server) {
	v1 = NewServer(ModeV1)
	v2 = NewServer(ModeV2)
	return v1, v2
}
