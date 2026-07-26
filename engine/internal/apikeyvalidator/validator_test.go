package apikeyvalidator

import (
	"testing"

	"github.com/akha-security/akca/engine/internal/testfixtures"
)

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

func TestHintRedaction(t *testing.T) {
	if hint("abcd") == "abcd" {
		t.Fatal("short token should redact")
	}
	h := hint(testfixtures.GitHubHintToken())
	if h == "" || len(h) > 20 {
		t.Fatalf("unexpected hint: %s", h)
	}
}
