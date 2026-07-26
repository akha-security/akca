package app

import (
	"net/http"
	"testing"
)

func TestReplayBlocksMutationWithoutCleanupPlan(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		if safeReplayMethod(method) {
			t.Fatalf("%s replay must require a recorded cleanup plan", method)
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		if !safeReplayMethod(method) {
			t.Fatalf("%s should be safe to replay", method)
		}
	}
}
