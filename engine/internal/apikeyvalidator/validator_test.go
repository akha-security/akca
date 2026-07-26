package apikeyvalidator

import (
	"testing"
)

func TestDetectService(t *testing.T) {
	v := New(nil)
	if v.DetectService("ghp_abc123") != "github" {
		t.Fatal("github prefix")
	}
	if v.DetectService("AKIAIOSFODNN7EXAMPLE") != "aws" {
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
	h := hint("ghp_abcdefghijklmnop")
	if h == "" || len(h) > 20 {
		t.Fatalf("unexpected hint: %s", h)
	}
}
