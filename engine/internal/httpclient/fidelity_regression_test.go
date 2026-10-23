package httpclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/ratelimit"
	"github.com/akha-security/akca/engine/internal/scope"
)

type fidelityTransport func(*http.Request) (*http.Response, error)

func (f fidelityTransport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func fidelityClient(t *testing.T, cfg config.ScanConfig, transport fidelityTransport) *Client {
	t.Helper()
	cfg.IncludeDomains = []string{"https://target.test"}
	cfg.EnableWAFBypassHeaders = false
	c, err := New(cfg, scope.NewEngine(cfg), ratelimit.New(1000, 1000))
	if err != nil {
		t.Fatal(err)
	}
	c.httpClient.Transport = transport
	return c
}

func fidelityResponse(req *http.Request, status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: req}
}

func TestAuthProfileOverridesCapturedHeaderRegardlessOfCase(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.CustomHeaders = map[string]string{"authorization": "Bearer ambient"}
	c := fidelityClient(t, cfg, func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Authorization") != "Bearer user" || req.Header.Get("Cookie") != "sid=user" {
			t.Fatalf("wrong role: %v", req.Header)
		}
		return fidelityResponse(req, 200, "ok"), nil
	})
	for i := 0; i < 100; i++ {
		_, err := c.DoWithAuthProfile(context.Background(), "GET", "https://target.test", nil, map[string]string{"authorization": "Bearer admin", "cookie": "sid=admin"}, config.AuthProfile{Headers: map[string]string{"Authorization": "Bearer user"}, Cookies: map[string]string{"sid": "user"}})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestExplicitUserAgentAndCookieWinOverSession(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.SessionCookies = map[string]string{"sid": "original", "theme": "dark"}
	c := fidelityClient(t, cfg, func(req *http.Request) (*http.Response, error) {
		if req.UserAgent() != "probe-marker" {
			t.Fatalf("UA overwritten: %q", req.UserAgent())
		}
		seen := map[string]int{}
		for _, cookie := range req.Cookies() {
			seen[cookie.Name]++
			if cookie.Name == "sid" && cookie.Value != "mutated" {
				t.Fatal("original sid reintroduced")
			}
		}
		if seen["sid"] != 1 || seen["theme"] != 1 {
			t.Fatalf("cookies: %v", req.Cookies())
		}
		return fidelityResponse(req, 200, "ok"), nil
	})
	if _, err := c.Do(context.Background(), "GET", "https://target.test", nil, map[string]string{"User-Agent": "probe-marker", "Cookie": "sid=mutated"}); err != nil {
		t.Fatal(err)
	}
}

func Test520DoesNotReplayPostAndKeepsLastResponseBody(t *testing.T) {
	for _, method := range []string{"POST", "GET"} {
		t.Run(method, func(t *testing.T) {
			calls := 0
			c := fidelityClient(t, config.DefaultScanConfig(), func(req *http.Request) (*http.Response, error) {
				calls++
				if method == "GET" && calls < 3 {
					return nil, errors.New("temporary")
				}
				return fidelityResponse(req, 520, "original gateway evidence"), nil
			})
			rr, err := c.Do(context.Background(), method, "https://target.test", []byte("action=once"), nil)
			if err != nil || rr.Response.Body != "original gateway evidence" {
				t.Fatalf("evidence lost: %+v %v", rr, err)
			}
			want := 1
			if method == "GET" {
				want = 3
			}
			if calls != want {
				t.Fatalf("calls=%d want=%d", calls, want)
			}
		})
	}
}
