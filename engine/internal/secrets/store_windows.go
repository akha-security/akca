//go:build windows

package secrets

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"syscall"
	"unsafe"
)

var dpapiDiskKeyPrefix = []byte("dpapi:")

func encodeDiskMasterKey(key []byte) ([]byte, error) {
	refID, err := protectOS("disk-master-key", key)
	if err != nil {
		return nil, err
	}
	return append(append([]byte(nil), dpapiDiskKeyPrefix...), []byte(refID)...), nil
}

func decodeDiskMasterKey(encoded []byte) ([]byte, error) {
	if !bytes.HasPrefix(encoded, dpapiDiskKeyPrefix) {
		return nil, fmt.Errorf("disk master key is not DPAPI protected")
	}
	return unprotectOS(string(bytes.TrimPrefix(encoded, dpapiDiskKeyPrefix)))
}

var (
	crypt32                = syscall.NewLazyDLL("crypt32.dll")
	procCryptProtectData   = crypt32.NewProc("CryptProtectData")
	procCryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func protectOS(key string, plaintext []byte) (string, error) {
	var plaintextPtr *byte
	if len(plaintext) > 0 {
		plaintextPtr = &plaintext[0]
	}
	in := dataBlob{cbData: uint32(len(plaintext)), pbData: plaintextPtr}
	var out dataBlob
	desc, _ := syscall.UTF16PtrFromString("akca:" + key)
	r, _, err := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(&in)), uintptr(unsafe.Pointer(desc)), 0, 0, 0, 0, uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return "", fmt.Errorf("CryptProtectData: %w", err)
	}
	defer syscall.LocalFree(syscall.Handle(uintptr(unsafe.Pointer(out.pbData))))
	buf := unsafe.Slice(out.pbData, out.cbData)
	encoded := base64.StdEncoding.EncodeToString(buf)
	return encoded, nil
}

func unprotectOS(refID string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(refID)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("CryptUnprotectData: empty protected value")
	}
	in := dataBlob{cbData: uint32(len(raw)), pbData: &raw[0]}
	var out dataBlob
	r, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&in)), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptUnprotectData: %w", err)
	}
	defer syscall.LocalFree(syscall.Handle(uintptr(unsafe.Pointer(out.pbData))))
	if out.cbData == 0 || out.pbData == nil {
		return []byte{}, nil
	}
	// CryptUnprotectData owns the output allocation. Copy it before LocalFree;
	// returning unsafe.Slice directly would expose freed memory to the caller.
	plaintext := append([]byte(nil), unsafe.Slice(out.pbData, out.cbData)...)
	return plaintext, nil
}
