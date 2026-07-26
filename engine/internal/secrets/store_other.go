//go:build !windows

package secrets

import "fmt"

func protectOS(key string, plaintext []byte) (string, error) {
	return "", fmt.Errorf("os keychain unavailable")
}

func unprotectOS(refID string) ([]byte, error) {
	return nil, fmt.Errorf("os keychain unavailable")
}
