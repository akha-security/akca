package modules

import (
	"context"
	"net/http"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/verification"
)

type failedUploadCleanupClient struct {
	uploaded      bool
	cleanupCalled bool
}

func (c *failedUploadCleanupClient) Do(_ context.Context, method, rawURL string, body []byte,
	headers map[string]string) (httpclient.RequestResponse, error) {
	status, responseBody := http.StatusOK, "stable upload form"
	switch method {
	case http.MethodPost:
		c.uploaded = true
		status, responseBody = http.StatusInternalServerError, "late storage error"
	case http.MethodDelete:
		c.cleanupCalled = true
		c.uploaded = false
		status, responseBody = http.StatusNoContent, ""
	}
	return httpclient.RequestResponse{
		Request:  httpclient.RequestRecord{Method: method, URL: rawURL, Body: string(body), Headers: headers},
		Response: httpclient.ResponseRecord{StatusCode: status, Body: responseBody},
	}, nil
}

func TestFileUploadCleansUpEvenWhenUploadReturnsError(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"example.com"}
	cfg.FileUploadProofPolicies = []config.FileUploadProofPolicy{{
		ID: "deterministic-cleanup", URLContains: "/upload", CleanupMethod: http.MethodDelete,
		CleanupURL: "http://example.com/files/{{filename}}",
	}}
	client := &failedUploadCleanupClient{}
	runner := NewRunner("upload-cleanup", client, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil), nil, nil, cfg)
	findings := runner.runFileUpload(context.Background(), ScanTarget{
		EndpointURL: "http://example.com/upload", Method: http.MethodPost, Parameter: "file",
	})
	if len(findings) != 0 {
		t.Fatalf("failed upload must not produce a finding, got %d", len(findings))
	}
	if !client.cleanupCalled || client.uploaded {
		t.Fatalf("failed upload path did not clean up: called=%v uploaded=%v", client.cleanupCalled, client.uploaded)
	}
}
