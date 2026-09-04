package reflection

import (
	"strings"
	"testing"
)

func TestBuildProbeRequestReplacesTemplatedPathParameter(t *testing.T) {
	rawURL, _, _, err := BuildProbeRequest(
		"https://api.test/orders/{id}", "GET", "id", "path", "ord-9",
	)
	if err != nil {
		t.Fatal(err)
	}
	if rawURL != "https://api.test/orders/ord-9" {
		t.Fatalf("path probe URL = %q", rawURL)
	}
}

func TestBuildProbeRequestMutatesConcretePathSegment(t *testing.T) {
	rawURL, _, _, err := BuildProbeRequest(
		"https://api.test/orders/ord-7", "GET", "id", "path", "ord-9",
	)
	if err != nil {
		t.Fatal(err)
	}
	if rawURL != "https://api.test/orders/ord-9" || strings.Contains(rawURL, "ord-7/ord-9") {
		t.Fatalf("concrete path probe URL = %q", rawURL)
	}
}

func TestBuildProbeRequestPreservesJSONScalarTypes(t *testing.T) {
	_, body, _, err := BuildProbeRequestWithTemplate(
		"https://api.test/orders", "POST", "quantity", "json", "2",
		`{"quantity":1,"active":true,"name":"old"}`,
	)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"active":true,"name":"old","quantity":2}` {
		t.Fatalf("typed JSON mutation changed schema: %s", body)
	}
	_, fallbackBody, _, fallbackErr := BuildProbeRequestWithTemplate(
		"https://api.test/orders", "POST", "quantity", "json", "' OR 1=1",
		`{"quantity":1,"active":true}`,
	)
	if fallbackErr != nil {
		t.Fatal(fallbackErr)
	}
	if string(fallbackBody) != `{"active":true,"quantity":"' OR 1=1"}` && string(fallbackBody) != `{"quantity":"' OR 1=1"}` {
		t.Fatalf("string injection payload failed to produce valid JSON body: %s", fallbackBody)
	}
}

func TestMutateRequestPreservesMethodHeadersAndSiblingJSONFields(t *testing.T) {
	req, err := MutateRequest(RequestTemplate{
		Method: "PATCH",
		URL:    "https://api.test/orders/7?expand=owner",
		Headers: map[string]string{
			"Authorization": "Bearer test-token",
			"X-Tenant":      "acme",
		},
		Body:        `{"order":{"quantity":1,"sku":"A-1"},"csrf":"kept"}`,
		ContentType: "application/json; charset=utf-8",
	}, "order.quantity", "json", "2")
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != "PATCH" || req.URL != "https://api.test/orders/7?expand=owner" {
		t.Fatalf("request identity changed: %+v", req)
	}
	if req.Headers["Authorization"] != "Bearer test-token" || req.Headers["X-Tenant"] != "acme" ||
		req.Headers["Content-Type"] != "application/json; charset=utf-8" {
		t.Fatalf("request headers were not preserved: %#v", req.Headers)
	}
	if string(req.Body) != `{"csrf":"kept","order":{"quantity":2,"sku":"A-1"}}` {
		t.Fatalf("JSON siblings changed: %s", req.Body)
	}
}

func TestMutateRequestQueryAndCookieKeepOriginalBody(t *testing.T) {
	template := RequestTemplate{
		Method: "PUT", URL: "https://api.test/profile?view=full",
		Headers: map[string]string{"Cookie": "session=abc; theme=dark", "X-Replay": "kept"},
		Body:    `{"display_name":"Caner"}`, ContentType: "application/json",
	}
	queryReq, err := MutateRequest(template, "view", "query", "compact")
	if err != nil {
		t.Fatal(err)
	}
	if queryReq.Method != "PUT" || !strings.Contains(queryReq.URL, "view=compact") || string(queryReq.Body) != template.Body {
		t.Fatalf("query mutation lost request fidelity: %+v", queryReq)
	}
	cookieReq, err := MutateRequest(template, "theme", "cookie", "light")
	if err != nil {
		t.Fatal(err)
	}
	if cookieReq.Headers["Cookie"] != "session=abc; theme=light" || string(cookieReq.Body) != template.Body {
		t.Fatalf("cookie mutation lost request fidelity: %+v", cookieReq)
	}
}
