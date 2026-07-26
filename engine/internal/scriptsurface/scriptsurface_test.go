package scriptsurface

import "testing"

const sampleHTML = `
<html><head>
<link rel="stylesheet" href="https://cdn.vendor.com/app.css">
<script src="https://cdn.vendor.com/app.js"></script>
<script src="/local.js"></script>
<iframe src="https://widgets.example.net/frame"></iframe>
<a href="https://github.com/acme-corp">GitHub</a>
</head></html>`

func TestExtractFromHTML(t *testing.T) {
	res := ExtractFromHTML(sampleHTML, "https://example.com/page")
	if len(res) < 3 {
		t.Fatalf("expected external resources, got %d", len(res))
	}
}

func TestIsThirdParty(t *testing.T) {
	if !IsThirdParty("cdn.vendor.com", "example.com") {
		t.Fatal("expected third party")
	}
	if IsThirdParty("cdn.example.com", "example.com") {
		t.Fatal("expected same registrable domain treated as first-party subdomain")
	}
}

func TestAnalyzeBrokenCDN(t *testing.T) {
	ok, sig := AnalyzeResponse(404, "There isn't a GitHub Pages site here.")
	if !ok || sig != "broken_cdn_takeover" {
		t.Fatalf("got ok=%v sig=%q", ok, sig)
	}
}
