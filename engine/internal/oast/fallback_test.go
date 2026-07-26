package oast

import (
	"context"
	"net/http"
	"net/http/httptest"
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
