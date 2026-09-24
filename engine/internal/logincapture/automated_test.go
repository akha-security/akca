package logincapture

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAutomatedLoginSupportsMultiStepBearerSession(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte(`<form action="/login"><input name="email"><input type="password" name="password"><input type="hidden" name="csrf" value="page-token"></form>`))
				return
			}
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.Form.Get("email") != "scanner@example.test" || r.Form.Get("password") != "secret" ||
				r.Form.Get("csrf") != "override-token" || r.Form.Get("tenant") != "security" {
				t.Errorf("unexpected login form: %#v", r.Form)
			}
			http.SetCookie(w, &http.Cookie{Name: "login_stage", Value: "ready", Path: "/"})
			_, _ = w.Write([]byte(`{"next":"/select"}`))
		case "/select":
			cookie, err := r.Cookie("login_stage")
			if err != nil || cookie.Value != "ready" {
				t.Errorf("follow-up request did not preserve cookie: %v", err)
			}
			if err := r.ParseForm(); err != nil || r.Form.Get("account") != "red-team" {
				t.Errorf("unexpected follow-up form: %#v (%v)", r.Form, err)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "stage-token"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	session, err := AutomatedLogin(context.Background(), LoginRequest{
		LoginURL: srv.URL + "/login", Username: "scanner@example.test", Password: "secret",
		ExtraFields: map[string]string{"csrf": "override-token", "tenant": "security"},
		Steps:       []LoginStep{{URL: "/select", Fields: map[string]string{"account": "red-team"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.Headers["Authorization"] != "Bearer stage-token" {
		t.Fatalf("bearer token was not captured: %#v", session.Headers)
	}
	if session.Cookies["login_stage"] != "ready" {
		t.Fatalf("login cookie was not captured: %#v", session.Cookies)
	}
}

func TestAutomatedLoginAcceptsTokenOnlySession(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<form><input name="username"><input type="password" name="password"></form>`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"token-only"}`))
	}))
	defer srv.Close()

	session, err := AutomatedLogin(context.Background(), LoginRequest{LoginURL: srv.URL, Username: "user", Password: "pass"})
	if err != nil {
		t.Fatal(err)
	}
	if session.Headers["Authorization"] != "Bearer token-only" {
		t.Fatalf("token-only session was not accepted: %#v", session)
	}
}
