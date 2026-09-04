package app

import (
	"net/http"
	"testing"
)

func TestPreflightFailsFastOnBadGateway(t *testing.T) {
	if err := preflightStatusError(http.StatusBadGateway, false); err == nil {
		t.Fatal("HTTP 502 must stop the scan")
	}
}

func TestPreflightOnlyTreatsAuthStatusAsFatalWhenAuthConfigured(t *testing.T) {
	if err := preflightStatusError(http.StatusUnauthorized, false); err != nil {
		t.Fatalf("public 401 target should remain scannable: %v", err)
	}
	if err := preflightStatusError(http.StatusUnauthorized, true); err == nil {
		t.Fatal("configured authentication must be validated")
	}
}
