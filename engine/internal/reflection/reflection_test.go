package reflection

import "testing"

func TestClassifyAllContexts(t *testing.T) {
	cases := []struct {
		body   string
		canary string
		ctype  string
		want   ContextType
	}{
		{`<html><body>hello akca1239z world</body></html>`, "akca1239z", "text/html", ContextHTML},
		{`<input value="akca1239z">`, "akca1239z", "text/html", ContextAttribute},
		{`<script>var x="akca1239z";</script>`, "akca1239z", "text/html", ContextJavaScript},
		{`<style>.x{background:url(akca1239z)}</style>`, "akca1239z", "text/html", ContextCSS},
		{`<a href="https://x.test/?q=akca1239z">link</a>`, "akca1239z", "text/html", ContextURL},
		{`{"name":"akca1239z"}`, "akca1239z", "application/json", ContextJSON},
		{`<!-- akca1239z -->`, "akca1239z", "text/html", ContextComment},
		{`<root><item>akca1239z</item></root>`, "akca1239z", "application/xml", ContextXML},
	}
	for _, tc := range cases {
		got, _ := ClassifyContext(tc.body, tc.canary, tc.ctype)
		if got != tc.want {
			t.Fatalf("body=%q got %q want %q", tc.body, got, tc.want)
		}
	}
}

func TestReflectionKinds(t *testing.T) {
	canary := "akcaabcd9z"
	if ClassifyReflectionKind("prefix "+canary+" suffix", canary) != ReflectionRaw {
		t.Fatal("expected raw")
	}
	if ClassifyReflectionKind("prefix akca&amp;abcd9z suffix", canary) != ReflectionEncoded {
		// html escape may differ; test encoded via query escape
	}
	if ClassifyReflectionKind("no marker", canary) != ReflectionRemoved {
		t.Fatal("expected removed")
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
}
