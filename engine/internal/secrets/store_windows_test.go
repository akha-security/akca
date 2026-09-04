//go:build windows

package secrets

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestDiskMasterKeyIsDPAPIProtectedAtRest(t *testing.T) {
	dir := t.TempDir()
	key, err := loadOrCreateDiskKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(filepath.Join(dir, "secrets", diskMasterKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, key) || !bytes.HasPrefix(stored, dpapiDiskKeyPrefix) {
		t.Fatal("Windows disk master key was not protected with DPAPI")
	}
}

func TestDPAPIRoundTripCopiesOutputBeforeFree(t *testing.T) {
	refID, err := protectOS("dpapi-test", []byte("sensitive-value"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := unprotectOS(refID)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "sensitive-value" {
		t.Fatalf("unexpected plaintext: %q", plaintext)
	}
	noise := make([]byte, 1<<20)
	for i := range noise {
		noise[i] = 0xa5
	}
	if string(plaintext) != "sensitive-value" {
		t.Fatal("plaintext referenced freed DPAPI memory")
	}
}

func TestDPAPIEmptyValuesDoNotPanic(t *testing.T) {
	refID, err := protectOS("dpapi-empty", nil)
	if err == nil {
		plaintext, err := unprotectOS(refID)
		if err != nil {
			t.Fatal(err)
		}
		if len(plaintext) != 0 {
			t.Fatalf("expected empty plaintext, got %q", plaintext)
		}
	}
	if _, err := unprotectOS(""); err == nil {
		t.Fatal("empty DPAPI reference should be rejected")
	}
}
