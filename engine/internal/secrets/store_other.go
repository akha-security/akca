//go:build !windows

package secrets

import "fmt"

func encodeDiskMasterKey(key []byte) ([]byte, error) {
	return append([]byte(nil), key...), nil
}

func decodeDiskMasterKey(encoded []byte) ([]byte, error) {
	return append([]byte(nil), encoded...), nil
}

func protectOS(key string, plaintext []byte) (string, error) {
	return "", fmt.Errorf("os keychain unavailable")
}

func unprotectOS(refID string) ([]byte, error) {
	return nil, fmt.Errorf("os keychain unavailable")
}
