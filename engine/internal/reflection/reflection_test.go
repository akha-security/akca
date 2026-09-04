package reflection

import "testing"

func TestClassifyAllContexts(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		canary string
		ctype  string
		want   ContextType
	}{
		{
			name:   "Simple HTML body",
			body:   `<html><body>hello akca1239z world</body></html>`,
			canary: "akca1239z",
			ctype:  "text/html",
			want:   ContextHTML,
		},
		{
			name:   "Realistic HTML body with header and meta attributes",
			body:   `<html lang="en"><head><meta charset="utf-8"><title>Test</title></head><body><div class="results">You searched for: akca1239z</div></body></html>`,
			canary: "akca1239z",
			ctype:  "text/html",
			want:   ContextHTML,
		},
		{
			name:   "Attribute reflection",
			body:   `<input value="akca1239z">`,
			canary: "akca1239z",
			ctype:  "text/html",
			want:   ContextAttribute,
		},
		{
			name:   "JavaScript block reflection",
			body:   `<script>var x="akca1239z";</script>`,
			canary: "akca1239z",
			ctype:  "text/html",
			want:   ContextJavaScript,
		},
		{
			name:   "CSS style block reflection",
			body:   `<style>.x{background:url(akca1239z)}</style>`,
			canary: "akca1239z",
			ctype:  "text/html",
			want:   ContextCSS,
		},
		{
			name:   "URL attribute reflection",
			body:   `<a href="https://x.test/?q=akca1239z">link</a>`,
			canary: "akca1239z",
			ctype:  "text/html",
			want:   ContextURL,
		},
		{
			name:   "JSON response",
			body:   `{"name":"akca1239z"}`,
			canary: "akca1239z",
			ctype:  "application/json",
			want:   ContextJSON,
		},
		{
			name:   "HTML comment reflection",
			body:   `<!-- akca1239z -->`,
			canary: "akca1239z",
			ctype:  "text/html",
			want:   ContextComment,
		},
		{
			name:   "XML document",
			body:   `<root><item>akca1239z</item></root>`,
			canary: "akca1239z",
			ctype:  "application/xml",
			want:   ContextXML,
		},
		{
			name:   "Multiple reflections prioritizes JavaScript over HTML body",
			body:   `<html><body><div>akca1239z</div><script>var search = "akca1239z";</script></body></html>`,
			canary: "akca1239z",
			ctype:  "text/html",
			want:   ContextJavaScript,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := ClassifyContext(tc.body, tc.canary, tc.ctype)
			if got != tc.want {
				t.Fatalf("body=%q got %q want %q", tc.body, got, tc.want)
			}
		})
	}
}

func TestReflectionKinds(t *testing.T) {
	canary := "akcaabcd9z"
	if ClassifyReflectionKind("prefix "+canary+" suffix", canary) != ReflectionRaw {
		t.Fatal("expected raw")
	}
	if ClassifyReflectionKind("no marker", canary) != ReflectionRemoved {
		t.Fatal("expected removed")
	}
	if ClassifyReflectionKind("prefix akcaabcd suffix", canary) != ReflectionPartial {
		t.Fatal("expected partial")
	}
}

func TestQuoteDetection(t *testing.T) {
	_, quote := ClassifyContext(`<input value="akca1239z">`, "akca1239z", "text/html")
	if quote != "double" {
		t.Fatalf("expected double quote, got %q", quote)
	}
}

func TestCanaryMarker(t *testing.T) {
	_, value := NewCanary()
	if !IsCanaryMarker(value) {
		t.Fatalf("expected canary marker %q", value)
	}
	if IsCanaryMarker("akca123") {
		t.Fatal("short canary marker should not pass")
	}
	if IsCanaryMarker("other123456789z") {
		t.Fatal("wrong prefix canary marker should not pass")
	}
}

func TestEvaluateCharSentinels(t *testing.T) {
	// Simulated response where < and " are allowed raw, but > is encoded to &gt;
	body := "prefix AK<BK EK\"FK CK&gt;DK suffix"
	avail, blocked, hasEnc := evaluateCharSentinels(body)

	hasLt := false
	hasQuote := false
	for _, c := range avail {
		if c == "<" {
			hasLt = true
		}
		if c == "\"" {
			hasQuote = true
		}
	}
	if !hasLt || !hasQuote {
		t.Fatalf("expected < and \" to be available, got %v", avail)
	}
	if !hasEnc {
		t.Fatal("expected hasEncoded to be true due to CK&gt;DK")
	}
	hasGtBlocked := false
	for _, c := range blocked {
		if c == ">" {
			hasGtBlocked = true
		}
	}
	if !hasGtBlocked {
		t.Fatalf("expected > to be in blocked list, got %v", blocked)
	}
}
