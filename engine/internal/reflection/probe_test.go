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
	if _, _, _, err := BuildProbeRequestWithTemplate(
		"https://api.test/orders", "POST", "quantity", "json", "' OR 1=1",
		`{"quantity":1,"active":true}`,
	); err == nil {
		t.Fatal("string injection must not silently change a numeric JSON field into a string")
	}
}
