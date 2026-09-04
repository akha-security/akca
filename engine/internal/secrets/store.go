package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	diskCipherV2Prefix = "v2:"
	diskMasterKeySize  = 32
	diskMasterKeyFile  = "master.key"
)

type Ref struct {
	Key         string `json:"key"`
	StorageMode string `json:"storage_mode"`
	Ciphertext  string `json:"ciphertext,omitempty"`
	RefID       string `json:"ref_id,omitempty"`
}

type Store struct {
	mode    string
	dataDir string
}

func NewStore(mode, dataDir string) *Store {
	return &Store{mode: mode, dataDir: dataDir}
}

func (s *Store) Put(key string, plaintext []byte) (Ref, error) {
	switch s.mode {
	case "os_keychain":
		refID, err := protectOS(key, plaintext)
		if err != nil {
			return Ref{}, fmt.Errorf("os keychain storage requested but unavailable: %w", err)
		}
		return Ref{Key: key, StorageMode: "os_keychain", RefID: refID}, nil
	case "encrypted_disk", "":
		ct, err := encryptDisk(s.dataDir, plaintext)
		if err != nil {
			return Ref{}, err
		}
		return Ref{Key: key, StorageMode: "encrypted_disk", Ciphertext: ct}, nil
	default:
		return Ref{}, fmt.Errorf("unsupported credential storage mode %q", s.mode)
	}
}

func (s *Store) Get(ref Ref) ([]byte, error) {
	switch ref.StorageMode {
	case "os_keychain":
		return unprotectOS(ref.RefID)
	case "encrypted_disk", "":
		return decryptDisk(s.dataDir, ref.Ciphertext)
	default:
		return nil, fmt.Errorf("unsupported credential storage mode %q", ref.StorageMode)
	}
}

func (s *Store) RedactValue(value string) string {
	if len(value) <= 4 {
		return "****"
	}
	return value[:2] + "****" + value[len(value)-2:]
}

func MarshalRef(ref Ref) string {
	b, _ := json.Marshal(ref)
	return string(b)
}

// legacyDiskKey exists only to decrypt records written before the random
// master-key format was introduced. New ciphertext must never use it.
func legacyDiskKey(dataDir string) []byte {
	host, _ := os.Hostname()
	sum := sha256.Sum256([]byte(dataDir + "|" + host + "|akca-secrets"))
	return sum[:]
}

func loadOrCreateDiskKey(dataDir string) ([]byte, error) {
	if err := EnsureDataDir(dataDir); err != nil {
		return nil, err
	}
	keyPath := filepath.Join(dataDir, "secrets", diskMasterKeyFile)
	readKey := func() ([]byte, error) {
		encodedKey, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, err
		}
		key, err := decodeDiskMasterKey(encodedKey)
		if err != nil {
			return nil, fmt.Errorf("decode disk master key: %w", err)
		}
		if len(key) != diskMasterKeySize {
			return nil, fmt.Errorf("invalid disk master key length: got %d", len(key))
		}
		_ = os.Chmod(keyPath, 0o600)
		return key, nil
	}
	if key, err := readKey(); err == nil {
		return key, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	key := make([]byte, diskMasterKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate disk master key: %w", err)
	}
	encodedKey, err := encodeDiskMasterKey(key)
	if err != nil {
		return nil, fmt.Errorf("encode disk master key: %w", err)
	}
	f, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if os.IsExist(err) {
		return readKey()
	}
	if err != nil {
		return nil, fmt.Errorf("create disk master key: %w", err)
	}
	written := false
	defer func() {
		_ = f.Close()
		if !written {
			_ = os.Remove(keyPath)
		}
	}()
	if _, err := f.Write(encodedKey); err != nil {
		return nil, fmt.Errorf("write disk master key: %w", err)
	}
	if err := f.Sync(); err != nil {
		return nil, fmt.Errorf("sync disk master key: %w", err)
	}
	written = true
	return key, nil
}

func encryptDisk(dataDir string, plaintext []byte) (string, error) {
	key, err := loadOrCreateDiskKey(dataDir)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, plaintext, nil)
	return diskCipherV2Prefix + base64.StdEncoding.EncodeToString(ct), nil
}

func decryptDisk(dataDir string, encoded string) ([]byte, error) {
	key := legacyDiskKey(dataDir)
	if strings.HasPrefix(encoded, diskCipherV2Prefix) {
		var err error
		key, err = loadOrCreateDiskKey(dataDir)
		if err != nil {
			return nil, err
		}
		encoded = strings.TrimPrefix(encoded, diskCipherV2Prefix)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(raw) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}

func EnsureDataDir(dataDir string) error {
	dir := filepath.Join(dataDir, "secrets")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700)
}
