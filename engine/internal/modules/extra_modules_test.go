package modules

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

func TestReactRSCCrashIsNotReportedAsRCE(t *testing.T) {
	// For benign control, let's distinguish in mock client based on body
	benignClient := &activeDynamicBodyClient{
		handler: func(method, rawURL string, body []byte, headers map[string]string) httpclient.ResponseRecord {
			if headers["RSC"] == "1" && headers["Next-Action"] != "" {
				if strings.Contains(string(body), "$undefined") {
					return httpclient.ResponseRecord{StatusCode: 200, Body: `["ok"]`, Headers: map[string]string{"Content-Type": "text/x-component"}}
				}
				if strings.Contains(string(body), "$1:a:a") {
					return httpclient.ResponseRecord{
						StatusCode: 500,
						Body:       `{"digest":"NEXT_RSC_CRASH_DIGEST_12345","error":"deserialization error"}`,
						Headers:    map[string]string{"Content-Type": "text/x-component"},
					}
				}
			}
			return httpclient.ResponseRecord{StatusCode: 200, Body: "<html>Next.js App</html>"}
		},
	}

	r := newActiveRunner(t, benignClient)
	target := ScanTarget{EndpointURL: "https://example.com/", Method: "GET"}
	findings := r.runReactRSCRCE(context.Background(), target)

	if len(findings) != 0 {
		t.Fatalf("HTTP 500 without execution evidence must not be reported as RCE, got %d findings", len(findings))
	}
}

func TestSSJS(t *testing.T) {
	c := &activeDynamicClient{
		handler: func(method, rawURL string, headers map[string]string) httpclient.ResponseRecord {
			decoded, _ := url.QueryUnescape(rawURL)
			if strings.Contains(decoded, "7777*7777") || strings.Contains(decoded, "child_process") {
				return httpclient.ResponseRecord{
					StatusCode: 200,
					Body:       "eval result: 60481729",
				}
			}
			return httpclient.ResponseRecord{StatusCode: 200, Body: "normal output"}
		},
	}

	r := newActiveRunner(t, c)
	target := ScanTarget{EndpointURL: "https://example.com/eval?code=1", Parameter: "code", Method: "GET"}
	findings := r.runSSJS(context.Background(), target)

	if len(findings) == 0 {
		t.Fatal("expected SSJS finding")
	}
	if findings[0].Severity != "critical" {
		t.Fatalf("expected critical severity, got %s", findings[0].Severity)
	}
}

func TestSSJSSignalRejectsBaselineMarker(t *testing.T) {
	if ssjsSignalConfirmed("banner 60481729", "banner 60481729", "ssjs_eval_arithmetic", 200, 200) {
		t.Fatal("SSJS arithmetic marker already present in baseline must not confirm execution")
	}
	if !ssjsSignalConfirmed("eval result: 60481729", "normal output", "ssjs_eval_arithmetic", 200, 200) {
		t.Fatal("SSJS arithmetic marker newly produced by probe should confirm")
	}
	if ssjsSignalConfirmed("ok", "normal output", "unknown", 200, 200) {
		t.Fatal("unknown SSJS signal must not confirm")
	}
}

func TestCSTI(t *testing.T) {
	c := &activeDynamicClient{
		handler: func(method, rawURL string, headers map[string]string) httpclient.ResponseRecord {
			decoded, _ := url.QueryUnescape(rawURL)
			if strings.Contains(decoded, "7777*7777") {
				return httpclient.ResponseRecord{
					StatusCode: 200,
					Body:       "<h1>Welcome 60481729!</h1>",
					Headers:    map[string]string{"Content-Type": "text/html"},
				}
			}
			return httpclient.ResponseRecord{StatusCode: 200, Body: "<h1>Welcome guest!</h1>"}
		},
	}

	r := newActiveRunner(t, c)
	target := ScanTarget{EndpointURL: "https://example.com/profile?name=guest", Parameter: "name", Method: "GET"}
	findings := r.runCSTI(context.Background(), target)

	if len(findings) == 0 {
		t.Fatal("expected CSTI finding")
	}
	if !strings.Contains(findings[0].Title, "Client-Side Template Injection") {
		t.Fatalf("unexpected title: %s", findings[0].Title)
	}
}

func TestCSTISignalRejectsLiteralEchoAndBaselineToken(t *testing.T) {
	payload := "{{7777*7777}}"
	if cstiSignalConfirmed("echo {{7777*7777}} 60481729", "normal", payload, "csti_expression_evaluated", 200) {
		t.Fatal("literal CSTI payload echo must not confirm evaluation")
	}
	if cstiSignalConfirmed("result 60481729", "old 60481729", payload, "csti_expression_evaluated", 200) {
		t.Fatal("CSTI eval token already present in baseline must not confirm")
	}
	if !cstiSignalConfirmed("result 60481729", "normal", payload, "csti_expression_evaluated", 200) {
		t.Fatal("new CSTI eval token without literal payload should confirm")
	}
}

func TestSwaggerExposure(t *testing.T) {
	c := &activeTestClient{
		responses: map[string]httpclient.ResponseRecord{
			"GET https://example.com/": {
				StatusCode: 200, Body: "<html>Home</html>",
			},
			"GET https://example.com/swagger.json": {
				StatusCode: 200,
				Body:       `{"swagger":"2.0","info":{"title":"API"},"paths":{"/users":{"get":{"summary":"Get users"}}}}`,
				Headers:    map[string]string{"Content-Type": "application/json"},
			},
		},
	}

	r := newActiveRunner(t, c)
	target := ScanTarget{EndpointURL: "https://example.com/", Method: "GET"}
	findings := r.runSwaggerExposure(context.Background(), target)

	if len(findings) == 0 {
		t.Fatal("expected Swagger exposure finding")
	}
	if !strings.Contains(findings[0].Title, "Swagger") {
		t.Fatalf("unexpected title: %s", findings[0].Title)
	}
}

func TestSensitiveFiles(t *testing.T) {
	c := &activeTestClient{
		responses: map[string]httpclient.ResponseRecord{
			"GET https://example.com/": {
				StatusCode: 200, Body: "<html>Home</html>",
			},
			"GET https://example.com/composer.json": {
				StatusCode: 200,
				Body:       `{"name":"app/api","require":{"php":">=8.1","laravel/framework":"^10.0"}}`,
				Headers:    map[string]string{"Content-Type": "application/json"},
			},
			"GET https://example.com/.htpasswd": {
				StatusCode: 200,
				Body:       "admin:$apr1$xyz$hashvalue\n",
				Headers:    map[string]string{"Content-Type": "text/plain"},
			},
		},
	}

	r := newActiveRunner(t, c)
	target := ScanTarget{EndpointURL: "https://example.com/", Method: "GET"}
	findings := r.runSensitiveFiles(context.Background(), target)

	if len(findings) < 2 {
		t.Fatalf("expected at least 2 sensitive file findings, got %d", len(findings))
	}
}

func TestSensitiveFilesDockerenvRejectsGenericJSON200(t *testing.T) {
	def := sensitiveFileDef{kind: "dockerenv_leak"}
	if sensitiveFileFingerprintMatches(def, httpclient.ResponseRecord{
		StatusCode: 200,
		Body:       `{"ok":true}`,
		Headers:    map[string]string{"Content-Type": "application/json"},
	}) {
		t.Fatal("generic JSON 200 must not prove /.dockerenv exposure")
	}
	if !sensitiveFileFingerprintMatches(def, httpclient.ResponseRecord{
		StatusCode: 200,
		Body:       "",
		Headers:    map[string]string{"Content-Type": "application/octet-stream"},
	}) {
		t.Fatal("empty small non-HTML response should remain valid for /.dockerenv")
	}
}

type activeDynamicBodyClient struct {
	handler func(method, rawURL string, body []byte, headers map[string]string) httpclient.ResponseRecord
}

func (c *activeDynamicBodyClient) Do(_ context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	resp := c.handler(method, rawURL, body, headers)
	return httpclient.RequestResponse{
		Request:  httpclient.RequestRecord{Method: method, URL: rawURL, Headers: headers, Body: string(body)},
		Response: resp,
	}, nil
}

func TestCPDoSRefactoredZeroFP(t *testing.T) {
	target := ScanTarget{EndpointURL: "https://example.com/api/v1/page", Method: "GET"}

	// Case 1: False Positive with Cache-Control: no-store, private (Must be dropped)
	t.Run("RejectsNoStorePrivateFP", func(t *testing.T) {
		c := &activeDynamicClient{
			handler: func(method, rawURL string, headers map[string]string) httpclient.ResponseRecord {
				if headers["X-HTTP-Method-Override"] != "" {
					return httpclient.ResponseRecord{
						StatusCode: 400,
						Body:       "Bad Method Override",
						Headers:    map[string]string{"Cache-Control": "no-store, private"},
					}
				}
				return httpclient.ResponseRecord{
					StatusCode: 200,
					Body:       "Healthy Home Page",
					Headers:    map[string]string{"Cache-Control": "public, max-age=3600"},
				}
			},
		}
		r := newActiveRunner(t, c)
		findings := r.runCPDoS(context.Background(), target)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings for uncacheable no-store response (FP), got %d: %+v", len(findings), findings)
		}
	})

	// Case 2: False Positive where clean request returns 200 (Not poisoned)
	t.Run("RejectsUnpoisonedCacheFP", func(t *testing.T) {
		c := &activeDynamicClient{
			handler: func(method, rawURL string, headers map[string]string) httpclient.ResponseRecord {
				if headers["X-HTTP-Method-Override"] != "" {
					return httpclient.ResponseRecord{
						StatusCode: 400,
						Body:       "Bad Request",
						Headers:    map[string]string{"Cache-Control": "public, max-age=3600"},
					}
				}
				return httpclient.ResponseRecord{
					StatusCode: 200,
					Body:       "Healthy Home Page",
					Headers:    map[string]string{"Cache-Control": "public, max-age=3600"},
				}
			},
		}
		r := newActiveRunner(t, c)
		findings := r.runCPDoS(context.Background(), target)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings when clean request recovers to 200 OK, got %d", len(findings))
		}
	})

	// Case 3: True Positive (Confirmed CPDoS with CDN HIT and Persistence)
	t.Run("ConfirmsTrueCPDoS", func(t *testing.T) {
		poisonedURLs := make(map[string]bool)
		c := &activeDynamicClient{
			handler: func(method, rawURL string, headers map[string]string) httpclient.ResponseRecord {
				// Base URL check
				if rawURL == "https://example.com/api/v1/page" {
					return httpclient.ResponseRecord{
						StatusCode: 200,
						Body:       "Healthy Home Page",
						Headers:    map[string]string{"Cache-Control": "public, max-age=3600"},
					}
				}
				// If poison header is present, poison the intermediate cache for this URL
				if headers["X-HTTP-Method-Override"] != "" {
					poisonedURLs[rawURL] = true
					return httpclient.ResponseRecord{
						StatusCode: 400,
						Body:       "Cache Poisoned Bad Request 400",
						Headers: map[string]string{
							"Cache-Control":   "public, max-age=3600",
							"CF-Cache-Status": "MISS",
						},
					}
				}
				// Subsequent request to poisoned cache
				if poisonedURLs[rawURL] {
					return httpclient.ResponseRecord{
						StatusCode: 400,
						Body:       "Cache Poisoned Bad Request 400",
						Headers: map[string]string{
							"Cache-Control":   "public, max-age=3600",
							"CF-Cache-Status": "HIT",
							"Age":             "5",
						},
					}
				}
				// Normal clean requests with fresh cache busters
				return httpclient.ResponseRecord{
					StatusCode: 200,
					Body:       "Healthy Home Page",
					Headers: map[string]string{
						"Cache-Control":   "public, max-age=3600",
						"CF-Cache-Status": "MISS",
					},
				}
			},
		}
		r := newActiveRunner(t, c)
		findings := r.runCPDoS(context.Background(), target)
		if len(findings) == 0 {
			t.Fatal("expected CPDoS finding for persistent CDN error cache")
		}
		if !strings.Contains(findings[0].Title, "Cache-Poisoned Denial of Service") {
			t.Fatalf("unexpected finding title: %s", findings[0].Title)
		}
		if findings[0].Severity != "high" {
			t.Fatalf("expected high severity, got: %s", findings[0].Severity)
		}
	})
}
