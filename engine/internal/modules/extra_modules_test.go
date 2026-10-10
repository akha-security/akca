package modules

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/verification"
)

func TestReactRSCCrashIsReportedAsDecoderDifferentialNotRCE(t *testing.T) {
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

	if len(findings) != 1 || findings[0].Severity != "medium" || strings.Contains(strings.ToLower(findings[0].Title), "remote code execution") {
		t.Fatalf("expected one non-RCE decoder differential, got %+v", findings)
	}
}

type archiveCountingClient struct {
	mu        sync.Mutex
	calls     map[string]int
	rangeSeen bool
}

func (c *archiveCountingClient) Do(_ context.Context, method, rawURL string, _ []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	c.mu.Lock()
	c.calls[rawURL]++
	if rawURL != "https://example.com" && headers["Range"] == "bytes=0-511" {
		c.rangeSeen = true
	}
	c.mu.Unlock()
	status := 404
	body := "not found"
	if rawURL == "https://example.com" {
		status, body = 200, "<html>home</html>"
	}
	return httpclient.RequestResponse{
		Request:  httpclient.RequestRecord{Method: method, URL: rawURL, Headers: headers},
		Response: httpclient.ResponseRecord{StatusCode: status, Body: body, Headers: map[string]string{"Content-Type": "text/plain"}},
	}, nil
}

func TestBackupArchivesDoesNotRepeatRootDictionaryPerPrefix(t *testing.T) {
	client := &archiveCountingClient{calls: make(map[string]int)}
	runner := newActiveRunner(t, client)
	runner.runBackupArchives(context.Background(), ScanTarget{EndpointURL: "https://example.com/news/article", Method: "GET"})
	client.mu.Lock()
	firstCalls := len(client.calls)
	rootCalls := client.calls["https://example.com/backup.zip"]
	client.mu.Unlock()
	if rootCalls != 1 {
		t.Fatalf("root archive candidate called %d times after first prefix", rootCalls)
	}
	if firstCalls > archiveRootCanaryProbes+1 {
		t.Fatalf("uniform 404 origin exceeded canary stage: calls=%d", firstCalls)
	}
	if !client.rangeSeen {
		t.Fatal("archive probes must request only the signature byte range")
	}
	for _, candidate := range []string{
		"https://example.com/example.com.zip",
		"https://example.com/database.sql.gz",
		"https://example.com/news/article.bak",
	} {
		if client.calls[candidate] != 1 {
			t.Fatalf("diversified archive canary missed %s", candidate)
		}
	}
	runner.runBackupArchives(context.Background(), ScanTarget{EndpointURL: "https://example.com/blog/post", Method: "POST"})
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.calls["https://example.com/backup.zip"] != 1 {
		t.Fatalf("root archive dictionary repeated across prefixes/methods: %d", client.calls["https://example.com/backup.zip"])
	}
	if len(client.calls)-firstCalls >= firstCalls {
		t.Fatalf("second prefix repeated the origin dictionary: first=%d additional=%d", firstCalls, len(client.calls)-firstCalls)
	}
}

type archiveBlockedClient struct {
	mu           sync.Mutex
	archiveCalls int
}

func (c *archiveBlockedClient) Do(_ context.Context, method, rawURL string, _ []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	status, body := 200, "<html>home</html>"
	if rawURL != "https://example.com" {
		c.mu.Lock()
		c.archiveCalls++
		c.mu.Unlock()
		status, body = 429, "too many requests"
	}
	return httpclient.RequestResponse{
		Request:  httpclient.RequestRecord{Method: method, URL: rawURL, Headers: headers},
		Response: httpclient.ResponseRecord{StatusCode: status, Body: body, Headers: map[string]string{"Content-Type": "text/plain"}},
	}, nil
}

func TestBackupArchivesStopsAtFirstPressureSignal(t *testing.T) {
	client := &archiveBlockedClient{}
	runner := newActiveRunner(t, client)
	findings := runner.runBackupArchives(context.Background(), ScanTarget{EndpointURL: "https://example.com/news/article", Method: "GET"})
	if len(findings) != 0 {
		t.Fatalf("rate-limited archive scan produced findings: %+v", findings)
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.archiveCalls != 1 {
		t.Fatalf("archive queue continued after pressure signal: calls=%d", client.archiveCalls)
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

func TestSSJSTimingRejectsHTTP200WAFBlockPage(t *testing.T) {
	blockPage := "<title>Request Rejected</title>The requested URL was rejected. Please consult with your administrator. Your support ID is: 123"
	if ssjsSignalConfirmed(blockPage, "normal", "ssjs_time_delay", 200, 200) {
		t.Fatal("HTTP 200 WAF rejection page confirmed SSJS timing")
	}
	c := &activeDynamicClient{handler: func(method, rawURL string, headers map[string]string) httpclient.ResponseRecord {
		decoded, _ := url.QueryUnescape(rawURL)
		if strings.Contains(decoded, "while(b-a<5000)") {
			return httpclient.ResponseRecord{StatusCode: 200, Body: blockPage, Duration: 5500 * time.Millisecond}
		}
		return httpclient.ResponseRecord{StatusCode: 200, Body: "normal", Duration: 100 * time.Millisecond}
	}}
	findings := newActiveRunner(t, c).runSSJS(context.Background(), ScanTarget{
		EndpointURL: "https://example.com/robots.txt?public=1", Parameter: "public", Method: "GET",
	})
	if len(findings) != 0 {
		t.Fatalf("WAF rejection produced SSJS finding: %+v", findings)
	}
}

func TestSSJSTimingRequiresThreeMatchedDelayedControls(t *testing.T) {
	c := &activeDynamicClient{handler: func(method, rawURL string, headers map[string]string) httpclient.ResponseRecord {
		decoded, _ := url.QueryUnescape(rawURL)
		switch {
		case strings.Contains(decoded, "while(b-a<5000)"):
			return httpclient.ResponseRecord{StatusCode: 200, Body: "normal", Duration: 5100 * time.Millisecond}
		case strings.Contains(decoded, "while(b-a<0)"):
			return httpclient.ResponseRecord{StatusCode: 200, Body: "normal", Duration: 100 * time.Millisecond}
		default:
			return httpclient.ResponseRecord{StatusCode: 200, Body: "normal", Duration: 100 * time.Millisecond}
		}
	}}
	findings := newActiveRunner(t, c).runSSJS(context.Background(), ScanTarget{
		EndpointURL: "https://example.com/eval?code=1", Parameter: "code", Method: "GET",
	})
	if len(findings) != 1 {
		t.Fatalf("matched timing proof produced %d findings, want 1", len(findings))
	}
	proof := findings[0].Evidence.Verification
	if !proof.TimingConfirmed || proof.ProofType != verification.ProofTiming {
		t.Fatalf("SSJS timing finding lacked timing proof: %+v", proof)
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

	if len(findings) != 0 {
		t.Fatal("HTTP arithmetic output does not prove client-side execution")
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
