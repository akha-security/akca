package findingtext

import "testing"

func TestHumanTitle(t *testing.T) {
	if HumanTitle("sqli") != "SQL Injection" {
		t.Fatal("sqli title")
	}
	if HumanTitle("ssti") != "Server-Side Template Injection" {
		t.Fatal("ssti title")
	}
}

func TestDisplayTitleTechnical(t *testing.T) {
	got := DisplayTitle("sqli", "SQLI (union_signal) on template")
	if got != "SQL Injection" {
		t.Fatalf("got %q", got)
	}
}

func TestHumanDescription(t *testing.T) {
	desc := HumanDescription("sqli", "union_signal", "id", "https://ex.com/api", "' OR 1=1--", "union", "query")
	if desc == "" || !containsAll(desc, "SQL Injection", "id", "' OR 1=1--") {
		t.Fatalf("bad desc: %s", desc)
	}
}

func containsAll(s string, parts ...string) bool {
	for _, p := range parts {
		if !contains(s, p) {
			return false
		}
	}
	return true
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
