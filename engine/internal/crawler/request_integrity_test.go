package crawler

import (
	"net/url"
	"path/filepath"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
)

func TestHTMLGETFormsRetainRequestTemplate(t *testing.T) {
	for _, markup := range []string{
		`<form action="/search"><input name="q" value="books"></form>`,
		`<a href="/search?q=books">search</a><form action="/search"><input name="q" value="books"></form>`,
		`<a href="/search">search</a><form action="/search"></form>`,
	} {
		found := false
		for _, endpoint := range ExtractFromHTML("https://example.test/", markup) {
			if endpoint.Source == SourceForm && endpoint.Method == "GET" {
				found = true
				if endpoint.RequestTemplate == nil || endpoint.RequestTemplate.URL != endpoint.URL {
					t.Fatalf("form lost replay shape: %+v", endpoint)
				}
			}
		}
		if !found {
			t.Fatalf("GET form was shadowed: %s", markup)
		}
	}
}

func TestPOSTFormDoesNotInventGETAction(t *testing.T) {
	for _, endpoint := range ExtractFromHTML("https://example.test/", `<form action="/save" method="POST"><input name="id" value="1"></form>`) {
		if endpoint.URL == "https://example.test/save" && endpoint.Method != "POST" {
			t.Fatalf("invented method: %+v", endpoint)
		}
	}
}

func TestFormDefaultsPreserveEmptyAndSelectedValues(t *testing.T) {
	forms := extractForms("https://example.test/base", `<form action="" method="">
<input name="token" value=""><input name="ignored" disabled="" value="x">
<input name="check" type="checkbox" checked=""><input name="no" type="checkbox">
<textarea name="notes">  keep  </textarea><textarea name="empty"></textarea>
<select name="first"><option disabled value="bad">Bad</option><optgroup><option value="one">One</option></optgroup></select>
<select name="blank"><option value="" selected>Choose</option></select>
<select name="multi" multiple><option value="x">X</option></select>
<select name="group"><optgroup disabled><option selected value="bad">Bad</option></optgroup><option value="good">Good</option></select>
</form>`)
	if len(forms) != 1 {
		t.Fatalf("forms=%+v", forms)
	}
	u, err := url.Parse(forms[0].URL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	for name, want := range map[string]string{"token": "", "check": "on", "notes": "  keep  ", "empty": "", "first": "one", "blank": "", "group": "good"} {
		if _, exists := q[name]; !exists || q.Get(name) != want {
			t.Errorf("%s=%q, want %q (present=%v)", name, q[name], want, exists)
		}
	}
	for _, name := range []string{"ignored", "no", "multi"} {
		if _, exists := q[name]; exists {
			t.Errorf("unexpected successful control %q", name)
		}
	}
	if u.Path != "/base" {
		t.Fatalf("empty action changed path: %s", u)
	}
}

func TestNormalizeURLPreservesRequestDistinctions(t *testing.T) {
	for _, pair := range [][2]string{
		{"https://example.test/a", "https://example.test/a/"},
		{"https://example.test/a?x=1&x=2", "https://example.test/a?x=2&x=1"},
		{"https://example.test/a%2Fb/", "https://example.test/a/b/"},
	} {
		a, err := NormalizeURL(pair[0])
		if err != nil {
			t.Fatal(err)
		}
		b, err := NormalizeURL(pair[1])
		if err != nil {
			t.Fatal(err)
		}
		if a == b {
			t.Fatalf("distinct requests collapsed: %q and %q", pair[0], pair[1])
		}
	}
}

func TestDuplicateCandidateRetainsCapturedRequest(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "request-integrity.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureScan("request-integrity"); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"example.test"}
	c := New("request-integrity", cfg, nil, scope.NewEngine(cfg), db, nil)
	// Avoid unrelated linked-host expansion in this focused test.
	c.linkedHostsSeen["example.test"] = struct{}{}
	rawURL := "https://example.test/api/save"
	c.enqueueCandidate(rawURL, "POST", 1, SourceAST, .9, "static hint", Budget{}, nil, "")
	template := &RequestTemplate{Method: "POST", URL: rawURL, Body: `{"token":"keep"}`, ContentType: "application/json", Headers: map[string]string{"Authorization": "Bearer test"}}
	c.enqueueCandidate(rawURL, "POST", 1, SourceBrowserXHR, .99, "captured request", Budget{}, template, "")
	endpoints, err := db.ListDiscoveryEndpoints("request-integrity", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(endpoints) != 1 || endpoints[0].RequestTemplate.Body != template.Body || endpoints[0].RequestTemplate.Headers["Authorization"] != "Bearer test" {
		t.Fatalf("captured request lost: %+v", endpoints)
	}
	if c.q.Len() != 0 {
		t.Fatal("unsafe request was actively queued")
	}
	if c.runtimeFound != 1 {
		t.Fatalf("runtime observation lost: %d", c.runtimeFound)
	}
}
