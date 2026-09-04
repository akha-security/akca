package oast

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestStartFallsBackToLocalWhenRemoteRegisterFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"domain":"","secret":"","correlation_id":""}`))
	}))
	defer srv.Close()

	var fallback bool
	listener, err := NewListener(nil, func(eventType, _ string, _ map[string]interface{}) error {
		if eventType == "oast_fallback" {
			fallback = true
		}
		return nil
	}, Config{ServerURL: srv.URL, PollInterval: time.Second, AllowLocalFallback: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.Start(context.Background()); err != nil {
		t.Fatalf("expected local fallback start, got %v", err)
	}
	defer listener.Stop()
	if !fallback {
		t.Fatal("expected oast_fallback event")
	}
	if _, ok := listener.provider.(*LocalProvider); !ok {
		t.Fatal("expected local provider after fallback")
	}
	if listener.provider.Domain() == "" {
		t.Fatal("expected local domain")
	}
}

func TestInteractshPollFailsOverAtRuntime(t *testing.T) {
	var firstRecovered atomic.Bool
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/register":
			_, _ = w.Write([]byte(`{"message":"registration successful"}`))
		case "/poll":
			if !firstRecovered.Load() {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte(`{"data":[{"protocol":"dns","unique-id":"old-server-callback"}]}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/register":
			_, _ = w.Write([]byte(`{"message":"registration successful"}`))
		case "/poll":
			_, _ = w.Write([]byte(`{"data":[]}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer second.Close()

	provider := NewInteractshProvider(first.URL + "," + second.URL)
	if err := provider.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Poll(); err != nil {
		t.Fatalf("runtime failover did not recover polling: %v", err)
	}
	active, _, priority := provider.ServerSelection()
	if active != second.URL || priority != 2 {
		t.Fatalf("runtime failover selection = %q priority %d", active, priority)
	}
	firstRecovered.Store(true)
	interactions, err := provider.Poll()
	if err != nil {
		t.Fatalf("polling recovered registrations failed: %v", err)
	}
	foundOldCallback := false
	for _, interaction := range interactions {
		if interaction.UniqueID == "old-server-callback" {
			foundOldCallback = true
		}
	}
	if !foundOldCallback {
		t.Fatal("callback issued against the pre-failover server was lost")
	}
}
