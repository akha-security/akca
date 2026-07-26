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
)

type Ref struct {
	Key         string `json:"key"`
	StorageMode string `json:"storage_mode"`
	Ciphertext  string `json:"ciphertext,omitempty"`
	RefID       string `json:"ref_id,omitempty"`
}

type Store struct {
	mode   string
	dataDir string
}

func NewStore(mode, dataDir string) *Store {
	return &Store{mode: mode, dataDir: dataDir}
}

func (s *Store) Put(key string, plaintext []byte) (Ref, error) {
	switch s.mode {
	case "os_keychain":
		refID, err := protectOS(key, plaintext)
		if err == nil {
			return Ref{Key: key, StorageMode: "os_keychain", RefID: refID}, nil
		}
		fallthrough
	default:
		ct, err := encryptDisk(s.dataDir, plaintext)
		if err != nil {
			return Ref{}, err
		}
		return Ref{Key: key, StorageMode: "encrypted_disk", Ciphertext: ct}, nil
	}
}

func (s *Store) Get(ref Ref) ([]byte, error) {
	switch ref.StorageMode {
	case "os_keychain":
		return unprotectOS(ref.RefID)
	default:
		return decryptDisk(s.dataDir, ref.Ciphertext)
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

func diskKey(dataDir string) []byte {
	host, _ := os.Hostname()
	sum := sha256.Sum256([]byte(dataDir + "|" + host + "|akca-secrets"))
	return sum[:]
}

func encryptDisk(dataDir string, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(diskKey(dataDir))
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
	return base64.StdEncoding.EncodeToString(ct), nil
}

func decryptDisk(dataDir string, encoded string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(diskKey(dataDir))
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
	return os.MkdirAll(filepath.Join(dataDir, "secrets"), 0o700)
}
