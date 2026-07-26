package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"github.com/akha-security/akca/engine/internal/checkpoint"
	"github.com/akha-security/akca/engine/internal/events"
	"github.com/akha-security/akca/engine/internal/storage"
)

type mockEventsWriter struct{}

func (m *mockEventsWriter) WriteEvent(e events.Event) error {
	return nil
}

type mockErrorTransport struct{}

func (t *mockErrorTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("mock network error")
}

func TestHandleQuery_ParamsParseError(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/query_err.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	eng, err := NewWithDB(&mockEventsWriter{}, db)
	if err != nil {
		t.Fatal(err)
	}

	// Pass completely invalid JSON for Params
	input := CommandInput{
		RequestID: "req-1",
		Query:     "endpoints",
		Params:    json.RawMessage(`{invalid_json}`),
	}

	err = eng.HandleQuery(input)
	if err == nil {
		t.Fatal("expected error for malformed params JSON, but got nil")
	}

	if !strings.Contains(err.Error(), "validation error") {
		t.Fatalf("expected validation error message, got %v", err)
	}
	if !strings.Contains(err.Error(), "req-1") {
		t.Fatalf("expected request_id in error message, got %v", err)
	}
}

func TestHandleQuery_ValidateAPIKey_ErrorPropagation(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/query_api.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	eng, err := NewWithDB(&mockEventsWriter{}, db)
	if err != nil {
		t.Fatal(err)
	}
	eng.initPlatform(t.TempDir())

	// Use reflection to mock the unexported Client transport inside apikeyvalidator.Validator
	// to guarantee a hard network failure and test error propagation.
	val := reflect.ValueOf(eng.platform.apiKeys).Elem()
	clientField := val.FieldByName("client")
	mockClient := &http.Client{
		Transport: &mockErrorTransport{},
	}
	reflect.NewAt(clientField.Type(), unsafe.Pointer(clientField.UnsafeAddr())).Elem().Set(reflect.ValueOf(mockClient))

	input := CommandInput{
		RequestID: "req-2",
		Query:     "validate_api_key",
		Params:    json.RawMessage(`{"token":"ghp_testtesttoken123"}`),
	}

	err = eng.HandleQuery(input)
	if err == nil {
		t.Fatal("expected error for api key validation failure, but got nil")
	}

	if !strings.Contains(err.Error(), "failed to validate API key") {
		t.Fatalf("expected API key validation error propagation, got %v", err)
	}
}

func TestScanPipeline_PhaseCompletionMark(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/query_phase.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	eng, err := NewWithDB(&mockEventsWriter{}, db)
	if err != nil {
		t.Fatal(err)
	}
	eng.initPlatform(t.TempDir())

	// Ensure the scan ID exists in the scans table to avoid ForeignKeyConstraintError
	if err := db.EnsureScan("scan-test"); err != nil {
		t.Fatal(err)
	}

	completedList := []string{"bootstrap"}
	status := map[string]string{
		"fingerprint": "success",
		"crawling":    "failed",
	}

	// Call checkpoint.Save directly to ensure persistence and test that crawl status is failed
	err = eng.platform.checkpoint.Save("scan-test", checkpoint.State{
		Phase: "crawling", Completed: completedList, PhaseStatus: status,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Fetch checkpoint from store
	st, ok, err := eng.platform.checkpoint.Latest("scan-test")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected checkpoint to be found")
	}

	// crawling should NOT be in completed list since it failed
	hasCrawling := false
	for _, p := range st.Completed {
		if p == "crawling" {
			hasCrawling = true
		}
	}
	if hasCrawling {
		t.Fatal("failed phase 'crawling' should NOT be marked as completed")
	}

	if st.PhaseStatus["crawling"] != "failed" {
		t.Fatalf("expected crawling status to be failed, got %s", st.PhaseStatus["crawling"])
	}
	if st.PhaseStatus["fingerprint"] != "success" {
		t.Fatalf("expected fingerprint status to be success, got %s", st.PhaseStatus["fingerprint"])
	}
}
