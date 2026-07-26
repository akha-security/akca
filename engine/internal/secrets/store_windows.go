//go:build windows

package secrets

import (
	"encoding/base64"
	"fmt"
	"syscall"
	"unsafe"
)

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
	in := dataBlob{cbData: uint32(len(plaintext)), pbData: &plaintext[0]}
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
	in := dataBlob{cbData: uint32(len(raw)), pbData: &raw[0]}
	var out dataBlob
	r, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&in)), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptUnprotectData: %w", err)
	}
	defer syscall.LocalFree(syscall.Handle(uintptr(unsafe.Pointer(out.pbData))))
	return unsafe.Slice(out.pbData, out.cbData), nil
}
