package apikeyvalidator

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/testfixtures"
)

type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("network unavailable")
}

func TestDetectService(t *testing.T) {
	v := New(nil)
	if v.DetectService(testfixtures.GitHubHintToken()) != "github" {
		t.Fatal("github prefix")
	}
	if v.DetectService(testfixtures.AWSExampleAccessKey()) != "aws" {
		t.Fatal("aws prefix")
	}
	if v.DetectService("random") != "unknown" {
		t.Fatal("unknown service")
	}
}

func TestHintPreservesRawToken(t *testing.T) {
	if hint("abcd") != "abcd" {
		t.Fatal("short token should be preserved")
	}
	h := hint(testfixtures.GitHubHintToken())
	if h != testfixtures.GitHubHintToken() {
		t.Fatalf("unexpected hint: %s", h)
	}
}

func TestValidateMarksTransportFailureAsNetworkError(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/akca.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	v := New(db)
	v.client = &http.Client{Transport: failingTransport{}}
	result, err := v.Validate(context.Background(), "scan-network", testfixtures.GitHubHintToken())
	if err == nil {
		t.Fatal("expected transport error")
	}
	if result.Status != "network-error" {
		t.Fatalf("status = %q, want network-error", result.Status)
	}
}
