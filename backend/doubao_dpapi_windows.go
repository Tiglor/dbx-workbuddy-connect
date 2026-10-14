//go:build windows

// Windows DPAPI (CurrentUser) unwrap of the Chromium os_crypt master key.

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

type dataBlob struct {
	size uint32
	data *byte
}

var (
	crypt32                = syscall.NewLazyDLL("crypt32.dll")
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procCryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
	procLocalFree          = kernel32.NewProc("LocalFree")
)

// dpapiUnprotect runs CryptUnprotectData over the given ciphertext.
func dpapiUnprotect(encrypted []byte) ([]byte, error) {
	if len(encrypted) == 0 {
		return nil, fmt.Errorf("dpapi: empty input")
	}
	in := dataBlob{size: uint32(len(encrypted)), data: &encrypted[0]}
	var out dataBlob
	ret, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&out)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("dpapi: CryptUnprotectData failed: %w", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.data)))
	result := make([]byte, out.size)
	copy(result, unsafe.Slice(out.data, out.size))
	return result, nil
}
