package storage

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEvidencePreservesCapturedRawTransactions(t *testing.T) {
	request := "POST /submit HTTP/1.1\r\nHost: example.test\r\nContent-Type: text/plain\r\n\r\nfirst\nlast\n\n"
	response := "HTTP/2 200 OK\r\nContent-Type: text/html\r\n\r\n" + strings.Repeat("response line\n", 9000) + "END\n\n"
	for _, nested := range []bool{false, true} {
		value := map[string]interface{}{
			"method": "POST", "url": "https://example.test/submit",
			"raw_request": request, "raw_response": response, "body_truncated": true,
		}
		if nested {
			value["raw_request"], value["raw_response"] = "stale request", "stale response"
			value["body_truncated"] = false
			value["request"] = map[string]interface{}{"raw": request, "body": "shorter fallback"}
			value["response"] = map[string]interface{}{"raw": response, "status_code": 200, "body": "shorter fallback", "body_truncated": true}
		}
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		body := ParseEvidenceBody(string(raw))
		if body.RawRequest != request || body.RawResponse != response {
			t.Fatalf("nested=%v: raw transaction was rebuilt or truncated", nested)
		}
		if !body.BodyTruncated || body.Method != "POST" || body.URL != "https://example.test/submit" {
			t.Fatalf("nested=%v: evidence metadata lost", nested)
		}
	}
}

func TestEvidenceStructuredFallbackPreservesBodiesAndRepeatedHeaders(t *testing.T) {
	body := ParseEvidenceBody(`{"request":{"method":"POST","url":"https://example.test/submit","headers":{"host":"example.test","Content-Type":"text/plain"},"body":"request\n\n"},"response":{"status_code":200,"headers":{"Set-Cookie":["first=one","second=two"]},"body":"response\n\n"}}`)
	if strings.Count(strings.ToLower(body.RawRequest), "host:") != 1 {
		t.Fatalf("duplicated Host header: %q", body.RawRequest)
	}
	if !strings.HasSuffix(body.RawRequest, "\n\nrequest\n\n") || !strings.HasSuffix(body.RawResponse, "\n\nresponse\n\n") {
		t.Fatal("structured fallback lost body whitespace or header/body separator")
	}
	if !strings.Contains(body.RawResponse, "Set-Cookie: first=one\nSet-Cookie: second=two") {
		t.Fatal("structured fallback lost repeated response headers")
	}
}

func TestBuildRawRequest_BurpSuiteStyle(t *testing.T) {
	// 1. GET with no headers: must generate full Burp Suite style headers
	raw := buildRawRequest("GET", "https://api.example.com/api/query", "", "")
	for _, expected := range []string{
		"GET /api/query HTTP/1.1\n",
		"Host: api.example.com\n",
		"User-Agent: Mozilla/5.0",
		"Accept: */*\n",
		"Accept-Language: en-US,en;q=0.9\n",
		"Accept-Encoding: gzip, deflate\n",
		"Connection: close\n",
	} {
		if !strings.Contains(raw, expected) {
			t.Fatalf("minimal request omitted %q in raw:\n%s", expected, raw)
		}
	}

	// 2. POST with body: must include Content-Type, Content-Length, and body
	postBody := "username=admin&password=secret_password"
	rawPost := buildRawRequest("POST", "https://api.example.com/login", "", postBody)
	for _, expected := range []string{
		"POST /login HTTP/1.1\n",
		"Host: api.example.com\n",
		"Content-Type: application/x-www-form-urlencoded\n",
		"Content-Length: 39\n",
		"Connection: close\n",
		"\n\n" + postBody,
	} {
		if !strings.Contains(rawPost, expected) {
			t.Fatalf("POST request omitted %q in raw:\n%s", expected, rawPost)
		}
	}

	// 3. Request with custom headers and cookies: must preserve them
	customH := "Cookie: session=xyz123\nAuthorization: Bearer token456\nUser-Agent: CustomBot/1.0"
	rawCustom := buildRawRequest("GET", "https://api.example.com/user", customH, "")
	for _, expected := range []string{
		"User-Agent: CustomBot/1.0\n",
		"Cookie: session=xyz123\n",
		"Authorization: Bearer token456\n",
	} {
		if !strings.Contains(rawCustom, expected) {
			t.Fatalf("custom request omitted %q in raw:\n%s", expected, rawCustom)
		}
	}
	// Must not duplicate User-Agent
	if strings.Count(rawCustom, "User-Agent:") != 1 {
		t.Fatalf("User-Agent was duplicated: %s", rawCustom)
	}
}
