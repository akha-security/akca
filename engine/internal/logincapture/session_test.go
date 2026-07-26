package logincapture

import (
	"net/url"
	"strings"
	"testing"
)

func TestParseCookieHeader(t *testing.T) {
	got := parseCookieHeader("session=abc; path=/; HttpOnly")
	if got["session"] != "abc" {
		t.Fatalf("expected session=abc, got %v", got)
	}
}

func TestParseSetCookie(t *testing.T) {
	got := parseSetCookie("token=xyz; Path=/; Secure; HttpOnly")
	if got["token"] != "xyz" {
		t.Fatalf("expected token=xyz, got %v", got)
	}
}

func TestCookieJarMerge(t *testing.T) {
	j := NewCookieJar()
	j.IngestSetCookie("a=1; Path=/")
	j.IngestRequestHeaders(map[string]string{"Cookie": "b=2"})
	s := j.Snapshot()
	if s.Cookies["a"] != "1" || s.Cookies["b"] != "2" {
		t.Fatalf("unexpected cookies: %v", s.Cookies)
	}
}

func TestGuessFields(t *testing.T) {
	fields := map[string]string{"username": "", "password": ""}
	if guessUsernameField(fields) != "username" {
		t.Fatal("expected username field")
	}
	if guessPasswordField(fields) != "password" {
		t.Fatal("expected password field")
	}
}

func TestParseLoginForm(t *testing.T) {
	html := `<form action="/login" method="post">
	<input type="hidden" name="csrf" value="tok123"/>
	<input type="text" name="email"/>
	<input type="password" name="password"/>
	</form>`
	u, _ := parseLoginForm(html, mustURL(t, "https://app.example.com/signin"))
	if !strings.Contains(u, "/login") {
		t.Fatalf("unexpected action: %s", u)
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
