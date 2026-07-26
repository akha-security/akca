package httpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/ratelimit"
	"github.com/akha-security/akca/engine/internal/scope"
)

var sensitiveHeaders = map[string]struct{}{
	"authorization":       {},
	"cookie":              {},
	"set-cookie":          {},
	"x-api-key":           {},
	"x-auth-token":        {},
	"x-akca-sensor-token": {},
}

type RequestRecord struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body,omitempty"`
}

type ResponseRecord struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body,omitempty"`
	Duration   time.Duration     `json:"duration"`
}

type RequestResponse struct {
	Request  RequestRecord  `json:"request"`
	Response ResponseRecord `json:"response"`
}

type Client struct {
	httpClient   *http.Client
	scope        *scope.Engine
	limiter      *ratelimit.Limiter
	cfg          config.ScanConfig
	sessionMu    sync.RWMutex
	uaMu         sync.Mutex
	uaIndex      int
	blockMu      sync.Mutex
	hostBlocks   map[string]int
	blockedUntil map[string]time.Time
	OnRequest    func(err bool)
}

func New(cfg config.ScanConfig, scopeEngine *scope.Engine, limiter *ratelimit.Limiter) (*Client, error) {
	proxyURL, err := config.NormalizeProxyURL(cfg.ProxyURL)
	if err != nil {
		return nil, err
	}
	cfg.ProxyURL = proxyURL
	transport := cfg.TestRoundTripper
	if transport == nil {
		base := &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 20 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			ForceAttemptHTTP2:     !cfg.ForceHTTP1,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: cfg.InsecureSkipVerify,
				MinVersion:         tls.VersionTLS12,
				// Use strong cipher suites
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_AES_128_GCM_SHA256,
				},
			},
		}
		if cfg.ForceHTTP1 {
			base.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		}
		transport = base
		if cfg.ProxyURL != "" {
			u, err := url.Parse(cfg.ProxyURL)
			if err != nil {
				return nil, err
			}
			base.Proxy = http.ProxyURL(u)
		}
	}
	return &Client{
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if !cfg.FollowRedirects {
					return http.ErrUseLastResponse
				}
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				// Never follow a redirect to an out-of-scope host; keep the
				// last (3xx) response so callers can still inspect Location.
				if scopeEngine != nil && !scopeEngine.IsInScope(req.URL.String()) {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		scope:        scopeEngine,
		limiter:      limiter,
		cfg:          cfg,
		hostBlocks:   make(map[string]int),
		blockedUntil: make(map[string]time.Time),
	}, nil
}

func (c *Client) SetSession(cookies map[string]string, headers map[string]string) {
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()
	if cookies != nil {
		c.cfg.SessionCookies = cloneStringMap(cookies)
	}
	if headers != nil {
		c.cfg.CustomHeaders = cloneStringMap(headers)
	}
}

func (c *Client) Do(ctx context.Context, method, rawURL string, body []byte, headers map[string]string) (RequestResponse, error) {
	return c.do(ctx, method, rawURL, body, headers, true, false)
}

// DoWithoutSession executes a request without configured authentication headers
// or cookies. Authentication checks use this to produce a genuinely anonymous
// comparison instead of an authenticated request with an empty Cookie header.
func (c *Client) DoWithoutSession(ctx context.Context, method, rawURL string, body []byte, headers map[string]string) (RequestResponse, error) {
	return c.do(ctx, method, rawURL, body, headers, false, false)
}

// DoWithAuthProfile applies authentication only to this request. It never
// mutates the shared client session used by concurrent scanner workers.
func (c *Client) DoWithAuthProfile(ctx context.Context, method, rawURL string, body []byte, headers map[string]string,
	profile config.AuthProfile) (RequestResponse, error) {
	explicit := cloneStringMap(headers)
	for key, value := range profile.Headers {
		explicit[key] = value
	}
	if len(profile.Cookies) > 0 {
		parts := make([]string, 0, len(profile.Cookies))
		for key, value := range profile.Cookies {
			parts = append(parts, key+"="+value)
		}
		explicit["Cookie"] = strings.Join(parts, "; ")
	}
	return c.do(ctx, method, rawURL, body, explicit, false, true)
}

func (c *Client) do(ctx context.Context, method, rawURL string, body []byte, headers map[string]string,
	includeSession, allowExplicitAuth bool) (RequestResponse, error) {
	if !c.scope.IsInScope(rawURL) {
		return RequestResponse{}, fmt.Errorf("scope blocked: %s", c.scope.Explain(rawURL))
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return RequestResponse{}, err
	}
	if until, blocked := c.circuitOpen(u.Hostname()); blocked {
		return RequestResponse{}, fmt.Errorf("host circuit open until %s after repeated WAF/rate-limit blocks", until.UTC().Format(time.RFC3339))
	}
	if err := c.limiter.WaitContext(ctx, u.Hostname()); err != nil {
		return RequestResponse{}, err
	}

	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, bodyReader)
	if err != nil {
		return RequestResponse{}, err
	}

	c.sessionMu.RLock()
	customHeaders := cloneStringMap(c.cfg.CustomHeaders)
	sessionCookies := cloneStringMap(c.cfg.SessionCookies)
	c.sessionMu.RUnlock()
	for k, v := range customHeaders {
		if !includeSession && isAuthenticationHeader(k) {
			continue
		}
		req.Header.Set(k, v)
	}
	for k, v := range headers {
		if !includeSession && !allowExplicitAuth && isAuthenticationHeader(k) {
			continue
		}
		req.Header.Set(k, v)
	}
	if includeSession {
		for k, v := range sessionCookies {
			req.AddCookie(&http.Cookie{Name: k, Value: v})
		}
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "*/*")
	}
	if req.Header.Get("Accept-Language") == "" {
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	}

	start := time.Now()
	var resp *http.Response

	for attempt := 0; attempt < 3; attempt++ {
		if ctx.Err() != nil {
			return RequestResponse{}, ctx.Err()
		}

		req.Header.Set("User-Agent", c.pickUserAgent())
		if c.cfg.EnableWAFBypassHeaders {
			c.applyWafBypassHeaders(req)
		}

		resp, err = c.httpClient.Do(req)
		if c.OnRequest != nil {
			c.OnRequest(err != nil)
		}

		if err != nil {
			if isTimeoutErr(err) || !isSafeMethod(method) || attempt == 2 {
				return RequestResponse{}, c.proxyError(err)
			}
			time.Sleep(500 * time.Millisecond)
			continue
		}

		// Handle WAF rate limiting / blocks
		if resp.StatusCode == http.StatusTooManyRequests {
			cooldown := retryAfterDuration(resp.Header.Get("Retry-After"), 5*time.Second)
			c.recordHostBlock(u.Hostname(), cooldown)
			resp.Body.Close()
			if until, blocked := c.circuitOpen(u.Hostname()); blocked {
				return RequestResponse{}, fmt.Errorf("rate limited; host circuit open until %s", until.UTC().Format(time.RFC3339))
			}
			c.limiter.SetWAFSlowDown(5.0)

			sleepDur := cooldown

			select {
			case <-ctx.Done():
				return RequestResponse{}, ctx.Err()
			case <-time.After(sleepDur):
			}
			continue
		}

		if resp.StatusCode >= 520 && resp.StatusCode <= 527 {
			c.recordHostBlock(u.Hostname(), 15*time.Second)
			resp.Body.Close()
			if until, blocked := c.circuitOpen(u.Hostname()); blocked {
				return RequestResponse{}, fmt.Errorf("CDN/WAF failures; host circuit open until %s", until.UTC().Format(time.RFC3339))
			}
			c.limiter.SetWAFSlowDown(3.0)

			select {
			case <-ctx.Done():
				return RequestResponse{}, ctx.Err()
			case <-time.After(3 * time.Second):
			}
			continue
		}

		break
	}

	if err != nil {
		return RequestResponse{}, c.proxyError(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 400 {
		c.clearHostBlocks(u.Hostname())
		c.limiter.DecayWAFSlowDown(0.10)
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return RequestResponse{}, err
	}

	rr := RequestResponse{
		Request: RequestRecord{
			Method:  method,
			URL:     rawURL,
			Headers: cloneHeaders(req.Header),
			Body:    string(body),
		},
		Response: ResponseRecord{
			StatusCode: resp.StatusCode,
			Headers:    cloneHeaders(resp.Header),
			Body:       string(respBody),
			Duration:   time.Since(start),
		},
	}
	if c.cfg.RedactionEnabled {
		rr = Redact(rr)
	}
	return rr, nil
}

func cloneStringMap(input map[string]string) map[string]string {
	out := make(map[string]string, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func (c *Client) proxyError(err error) error {
	if err == nil || strings.TrimSpace(c.cfg.ProxyURL) == "" {
		return err
	}
	return fmt.Errorf("proxy request via %s failed: %w", config.SafeProxyURL(c.cfg.ProxyURL), err)
}

func (c *Client) circuitOpen(host string) (time.Time, bool) {
	c.blockMu.Lock()
	defer c.blockMu.Unlock()
	until := c.blockedUntil[host]
	if until.IsZero() || !time.Now().Before(until) {
		delete(c.blockedUntil, host)
		return time.Time{}, false
	}
	return until, true
}

func (c *Client) recordHostBlock(host string, cooldown time.Duration) {
	c.blockMu.Lock()
	defer c.blockMu.Unlock()
	c.hostBlocks[host]++
	if c.hostBlocks[host] < 3 && cooldown < 30*time.Second {
		return
	}
	if cooldown < 30*time.Second {
		cooldown = 30 * time.Second
	}
	if cooldown > 15*time.Minute {
		cooldown = 15 * time.Minute
	}
	c.blockedUntil[host] = time.Now().Add(cooldown)
}

func (c *Client) clearHostBlocks(host string) {
	c.blockMu.Lock()
	delete(c.hostBlocks, host)
	delete(c.blockedUntil, host)
	c.blockMu.Unlock()
}

func retryAfterDuration(raw string, fallback time.Duration) time.Duration {
	raw = strings.TrimSpace(raw)
	if secs := parseSecs(raw); secs > 0 {
		return clampCooldown(time.Duration(secs) * time.Second)
	}
	if when, err := http.ParseTime(raw); err == nil {
		if wait := time.Until(when); wait > 0 {
			return clampCooldown(wait)
		}
	}
	return fallback
}

func clampCooldown(wait time.Duration) time.Duration {
	if wait > 15*time.Minute {
		return 15 * time.Minute
	}
	return wait
}

func isAuthenticationHeader(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "authorization", "cookie", "proxy-authorization", "x-api-key", "x-auth-token":
		return true
	default:
		return false
	}
}

func (c *Client) applyWafBypassHeaders(req *http.Request) {
	c.uaMu.Lock()
	idx := c.uaIndex
	c.uaMu.Unlock()

	randIP := fmt.Sprintf("%d.%d.%d.%d", 100+(idx%100), 20+(idx%100), 30+(idx%100), 40+(idx%100))

	bypassHeaders := []string{
		"X-Forwarded-For",
		"X-Originating-IP",
		"X-Remote-IP",
		"X-Remote-Addr",
		"Client-IP",
		"X-Client-IP",
		"X-Real-IP",
		"True-Client-IP",
		"CF-Connecting-IP",
	}

	for _, h := range bypassHeaders {
		req.Header.Set(h, randIP)
	}
}

func parseSecs(raw string) int {
	var val int
	for i := 0; i < len(raw); i++ {
		if raw[i] >= '0' && raw[i] <= '9' {
			val = val*10 + int(raw[i]-'0')
		} else {
			break
		}
	}
	return val
}

func (c *Client) pickUserAgent() string {
	switch c.cfg.UserAgentMode {
	case config.UserAgentCustom:
		if len(c.cfg.UserAgents) > 0 {
			return c.cfg.UserAgents[0]
		}
	case config.UserAgentRandom:
		agents := defaultUserAgents()
		c.uaMu.Lock()
		c.uaIndex = (c.uaIndex + 1) % len(agents)
		idx := c.uaIndex
		c.uaMu.Unlock()
		return agents[idx]
	}
	return defaultUserAgents()[0]
}

// isTimeoutErr reports whether err is a context deadline or a network timeout,
// for which an immediate retry would only waste another full timeout window.
func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return false
}

func isSafeMethod(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

func cloneHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, vals := range h {
		out[k] = strings.Join(vals, ", ")
	}
	return out
}

func defaultUserAgents() []string {
	return []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
	}
}

func Redact(rr RequestResponse) RequestResponse {
	rr.Request.Headers = redactMap(rr.Request.Headers)
	rr.Response.Headers = redactMap(rr.Response.Headers)
	return rr
}

func redactMap(headers map[string]string) map[string]string {
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		if _, ok := sensitiveHeaders[strings.ToLower(k)]; ok {
			out[k] = "[REDACTED]"
		} else {
			out[k] = v
		}
	}
	return out
}
