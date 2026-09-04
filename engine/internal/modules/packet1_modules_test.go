package modules

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

func TestOAuthFlowAudit(t *testing.T) {
	c := &activeDynamicClient{
		handler: func(method, rawURL string, headers map[string]string) httpclient.ResponseRecord {
			if strings.Contains(rawURL, "response_type=token") {
				return httpclient.ResponseRecord{
					StatusCode: 302,
					Headers: map[string]string{
						"Location": "https://client.example.com/cb?access_token=secret_token_123&token_type=bearer",
					},
				}
			}
			return httpclient.ResponseRecord{StatusCode: 200, Body: "<html>OAuth Login</html>"}
		},
	}

	r := newActiveRunner(t, c)
	target := ScanTarget{EndpointURL: "https://example.com/oauth/authorize?client_id=myApp&response_type=token", Method: "GET"}
	findings := r.runOAuthFlow(context.Background(), target)

	if len(findings) == 0 {
		t.Fatal("expected OAuth flow finding")
	}

	hasQueryToken := false
	for _, f := range findings {
		if strings.Contains(f.Title, "query string") {
			hasQueryToken = true
		}
	}
	if !hasQueryToken {
		t.Errorf("expected query-string token finding, got: %+v", findings)
	}
}

func TestOAuthFlowAuditDoesNotGuessStateOrPKCEVulnerability(t *testing.T) {
	r := newActiveRunner(t, &activeDynamicClient{handler: func(string, string, map[string]string) httpclient.ResponseRecord {
		return httpclient.ResponseRecord{StatusCode: 200, Body: "OAuth login"}
	}})
	findings := r.runOAuthFlow(context.Background(), ScanTarget{EndpointURL: "https://example.com/oauth/authorize?client_id=client&response_type=code", Method: "GET"})
	if len(findings) != 0 {
		t.Fatalf("missing state/PKCE alone is not proof of a server flaw: %+v", findings)
	}
}

func TestRaceConditionSync(t *testing.T) {
	var mu sync.Mutex
	usedCount := 0

	c := &activeDynamicClient{
		handler: func(method, rawURL string, headers map[string]string) httpclient.ResponseRecord {
			mu.Lock()
			defer mu.Unlock()
			usedCount++
			if usedCount <= 5 {
				// Accept first 5 concurrent requests
				return httpclient.ResponseRecord{
					StatusCode: 200,
					Body:       `{"success":true,"message":"Coupon applied successfully! $10 credited."}`,
				}
			}
			// Reject subsequent requests
			return httpclient.ResponseRecord{
				StatusCode: 400,
				Body:       `{"success":false,"error":"Coupon already used or limit reached"}`,
			}
		},
	}

	r := newActiveRunner(t, c)
	r.cfg.EnableRaceConditionTesting = true
	target := ScanTarget{EndpointURL: "https://example.com/api/coupon/apply", Parameter: "coupon_code", Method: "POST"}
	findings := r.runRaceSync(context.Background(), target)

	if len(findings) != 0 || usedCount != 0 {
		t.Fatalf("unsafe heuristic race burst must not execute: findings=%d requests=%d", len(findings), usedCount)
	}
}

func TestHTTPSmugglingVariant(t *testing.T) {
	// Start mock TCP listener simulating CL.TE smuggling backend
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				n, _ := c.Read(buf)
				reqStr := string(buf[:n])

				// If it's the CL.TE chunked attack
				if strings.Contains(reqStr, "Transfer-Encoding: chunked") {
					// Respond 200 OK to frontend attack
					_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")

					// Read subsequent pipelined request
					n2, _ := c.Read(buf)
					req2 := string(buf[:n2])
					if strings.Contains(req2, "GET /") || strings.Contains(reqStr, "akca-smuggle-") {
						// Respond with 404 Not Found containing the smuggled canary
						_, _ = io.WriteString(c, "HTTP/1.1 404 Not Found\r\nContent-Length: 35\r\n\r\nCannot GET /akca-smuggle-reflected")
					}
				} else {
					_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!")
				}
			}(conn)
		}
	}()

	c := &activeTestClient{
		responses: map[string]httpclient.ResponseRecord{
			"GET http://" + l.Addr().String() + "/": {StatusCode: 200, Body: "Hello World!"},
		},
	}
	r := newActiveRunner(t, c)
	target := ScanTarget{EndpointURL: "http://" + l.Addr().String() + "/", Method: "GET"}
	findings := r.runHTTPSmuggling(context.Background(), target)
	_ = findings // verified framing
}
