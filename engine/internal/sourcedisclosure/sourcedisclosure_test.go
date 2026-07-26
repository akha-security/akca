package sourcedisclosure

import "testing"

func TestLooksLikeSourceCodePHP(t *testing.T) {
	if !LooksLikeSourceCode(`<?php $db="localhost";`, "text/html") {
		t.Fatal("expected php source detection")
	}
}

func TestAnalyzeSecretsAndInternalIP(t *testing.T) {
	body := `api_key="AKIAIOSFODNN7EXAMPLE"; if (debug == true) { } // 10.0.0.5`
	findings := Analyze(body)
	if len(findings) < 2 {
		t.Fatalf("expected multiple findings, got %v", findings)
	}
}

func TestCandidateURLs(t *testing.T) {
	urls := CandidateURLs("http://example.com/app/login.php")
	if len(urls) == 0 {
		t.Fatal("expected candidate urls")
	}
	found := false
	for _, u := range urls {
		if contains(u, ".bak") || contains(u, ".php") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected backup variants, got %v", urls)
	}
}

func TestCandidateURLsPreserveQuerySeparators(t *testing.T) {
	urls := CandidateURLs("http://example.com/app/login.php?next=/home")
	for _, u := range urls {
		if u == "http://example.com/app/login.php.bak?next=/home" {
			return
		}
	}
	t.Fatalf("expected query-preserving backup candidate, got %v", urls)
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
