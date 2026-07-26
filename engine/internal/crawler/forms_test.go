package crawler

import (
	"net/http"
	"strings"
	"testing"
)

func TestExtractFormsPOSTWithBody(t *testing.T) {
	html := `<html><body>
<form action="/login" method="post">
  <input type="text" name="username" value="admin">
  <input type="password" name="password">
  <input type="submit" value="Login">
</form>
</body></html>`
	eps := extractForms("https://example.com/", html)
	if len(eps) != 1 {
		t.Fatalf("expected 1 form, got %d", len(eps))
	}
	ep := eps[0]
	if ep.Method != http.MethodPost {
		t.Fatalf("method=%q want POST", ep.Method)
	}
	if ep.Source != SourceForm {
		t.Fatalf("source=%q", ep.Source)
	}
	if ep.RequestTemplate == nil {
		t.Fatal("expected request template")
	}
	if !strings.Contains(ep.RequestTemplate.Body, "username=admin") {
		t.Fatalf("body=%q", ep.RequestTemplate.Body)
	}
	if ep.RequestTemplate.ContentType != "application/x-www-form-urlencoded" {
		t.Fatalf("content-type=%q", ep.RequestTemplate.ContentType)
	}
}

func TestExtractFormsGETQuery(t *testing.T) {
	html := `<form action="/search" method="get">
  <input type="text" name="q" value="test">
</form>`
	eps := extractForms("https://example.com/", html)
	if len(eps) != 1 {
		t.Fatalf("expected 1 form, got %d", len(eps))
	}
	if eps[0].Method != http.MethodGet {
		t.Fatalf("method=%q", eps[0].Method)
	}
	if !strings.Contains(eps[0].RequestTemplate.URL, "q=test") {
		t.Fatalf("url=%q", eps[0].RequestTemplate.URL)
	}
}

func TestExtractFormsDefaultGET(t *testing.T) {
	html := `<form action="/submit"><input name="id" value="1"></form>`
	eps := extractForms("https://example.com/page", html)
	if len(eps) != 1 || eps[0].Method != http.MethodGet {
		t.Fatalf("expected default GET, got %+v", eps)
	}
}

func TestExtractFormsHandlesHTML5Controls(t *testing.T) {
	raw := `<form action="/profile" method="post">
<textarea name="bio">hello world</textarea>
<select name="role"><option value="user">User</option><option value="admin" selected>Admin</option></select>
<input type="checkbox" name="notify" value="yes" checked>
<input type="checkbox" name="ignored" value="yes">
<input name="disabled_field" disabled value="x">
</form>`
	eps := extractForms("https://example.com/", raw)
	if len(eps) != 1 || eps[0].RequestTemplate == nil {
		t.Fatalf("expected parsed form template, got %+v", eps)
	}
	body := eps[0].RequestTemplate.Body
	for _, expected := range []string{"bio=hello+world", "role=admin", "notify=yes"} {
		if !strings.Contains(body, expected) {
			t.Fatalf("missing %q in %q", expected, body)
		}
	}
	if strings.Contains(body, "ignored=") || strings.Contains(body, "disabled_field=") {
		t.Fatalf("unchecked or disabled controls must be skipped: %q", body)
	}
}
