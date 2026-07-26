package secrets

import (
	"testing"

	"github.com/akha-security/akca/engine/internal/testfixtures"
)

func TestEncryptDecryptDisk(t *testing.T) {
	dir := t.TempDir()
	ct, err := encryptDisk(dir, []byte("super-secret-token"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := decryptDisk(dir, ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "super-secret-token" {
		t.Fatalf("unexpected plaintext: %s", plain)
	}
}

func TestStorePutGetEncryptedDisk(t *testing.T) {
	dir := t.TempDir()
	s := NewStore("encrypted_disk", dir)
	raw := testfixtures.GitHubQueryToken()
	ref, err := s.Put("api_key", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if ref.Ciphertext == "" {
		t.Fatal("expected ciphertext")
	}
	got, err := s.Get(ref)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != raw {
		t.Fatalf("unexpected: %s", got)
	}
}

func TestRedactValue(t *testing.T) {
	s := NewStore("encrypted_disk", t.TempDir())
	if s.RedactValue("ab") != "****" {
		t.Fatal("short redact failed")
	}
	if s.RedactValue("abcdef") == "abcdef" {
		t.Fatal("expected redaction")
	}
}
