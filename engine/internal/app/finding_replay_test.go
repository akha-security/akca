package app

import (
	"context"
	"encoding/json"
	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/modules"
	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/verification"
	"net/http/httptest"
	"sync/atomic"

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

func TestReplayRedirectChangesFromVulnerableToFixed(t *testing.T) {
	var fixed atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		location := "/safe"
		if r.URL.Query().Get("next") == "external" && !fixed.Load() {
			location = "https://external.invalid/"
		}
		w.Header().Set("Location", location)
		w.WriteHeader(302)
	}))
	defer server.Close()
	db, err := storage.Open(t.TempDir() + "/replay.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.Migrate(); err != nil {
		t.Fatal(err)
	}
	scanID := "replay-test"
	if err = db.EnsureScan(scanID); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultScanConfig()
	cfg.Targets = []string{server.URL}
	cfg.FollowRedirects = false
	raw, _ := json.Marshal(cfg)
	if err = db.UpdateScanConfig(scanID, string(raw)); err != nil {
		t.Fatal(err)
	}
	var observations []verification.Observation
	var steps []modules.ReplayStep
	for i, role := range []verification.ObservationRole{verification.RoleNativeBaseline, verification.RolePositiveProbe} {
		requestURL := server.URL + "?next=safe"
		location := "/safe"
		if i == 1 {
			requestURL = server.URL + "?next=external"
			location = "https://external.invalid/"
		}
		o := verification.NewHTTPObservation(scanID, "open_redirect", server.URL, "next", "query", role, 1, "", "GET", requestURL, "", nil, verification.ResponseSnapshot{StatusCode: 302, Headers: map[string]string{"Location": location}})
		observations = append(observations, o)
		steps = append(steps, modules.ReplayStep{Role: role, Request: httpclient.RequestRecord{Method: "GET", URL: requestURL}, ExpectedNormalizedHash: o.NormalizedHash})
	}
	raw, _ = json.Marshal(map[string]interface{}{"replay_plan": steps, "verification": map[string]string{"proof_type": string(verification.ProofHeaderEvidence)}})
	id, err := db.SaveFinding(scanID, "redirect", "medium", "open_redirect", "test", server.URL, "next", 1, string(raw))
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range observations {
		b, _ := json.Marshal(o)
		var record storage.VerificationObservationRecord
		json.Unmarshal(b, &record)
		if err = db.SaveVerificationObservation(id, record); err != nil {
			t.Fatal(err)
		}
	}
	e := &Engine{db: db}
	result, err := e.ReplayFinding(context.Background(), id)
	if err != nil || result.Status != "still_vulnerable" {
		t.Fatalf("before fix: %+v %v", result, err)
	}
	fixed.Store(true)
	result, err = e.ReplayFinding(context.Background(), id)
	if err != nil || result.Status != "fixed" {
		t.Fatalf("after fix: %+v %v", result, err)
	}
}
