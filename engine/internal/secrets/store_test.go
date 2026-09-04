package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"runtime"
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

func TestDecryptDiskReadsLegacyCiphertext(t *testing.T) {
	dir := t.TempDir()
	block, err := aes.NewCipher(legacyDiskKey(dir))
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatal(err)
	}
	legacyCiphertext := base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte("legacy-secret"), nil))
	plaintext, err := decryptDisk(dir, legacyCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "legacy-secret" {
		t.Fatalf("legacy plaintext mismatch: %q", plaintext)
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
	if len(ref.Ciphertext) < len(diskCipherV2Prefix) || ref.Ciphertext[:len(diskCipherV2Prefix)] != diskCipherV2Prefix {
		t.Fatalf("expected versioned ciphertext, got %q", ref.Ciphertext)
	}
	got, err := s.Get(ref)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != raw {
		t.Fatalf("unexpected: %s", got)
	}
}

func TestDiskMasterKeyIsRandomAndPersisted(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	keyA, err := loadOrCreateDiskKey(dirA)
	if err != nil {
		t.Fatal(err)
	}
	keyAAgain, err := loadOrCreateDiskKey(dirA)
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := loadOrCreateDiskKey(dirB)
	if err != nil {
		t.Fatal(err)
	}
	if string(keyA) != string(keyAAgain) {
		t.Fatal("master key was not persisted")
	}
	if string(keyA) == string(keyB) || string(keyA) == string(legacyDiskKey(dirA)) {
		t.Fatal("disk master key is predictable or reused")
	}
	info, err := os.Stat(filepath.Join(dirA, "secrets", diskMasterKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("master key permissions are too broad: %o", info.Mode().Perm())
	}
}

func TestOSKeychainFailureDoesNotFallBackToDisk(t *testing.T) {
	if _, err := protectOS("probe", []byte("secret")); err == nil {
		t.Skip("OS keychain is available on this platform")
	}
	dir := t.TempDir()
	store := NewStore("os_keychain", dir)
	if _, err := store.Put("api_key", []byte("secret")); err == nil {
		t.Fatal("os_keychain failure silently fell back to encrypted_disk")
	}
	if _, err := os.Stat(filepath.Join(dir, "secrets", diskMasterKeyFile)); !os.IsNotExist(err) {
		t.Fatalf("fallback unexpectedly created a disk key: %v", err)
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
