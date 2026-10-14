//go:build !windows

package main

import "fmt"

// dpapiUnprotect is Windows-only; Doubao cookie decryption is unavailable here.
func dpapiUnprotect(encrypted []byte) ([]byte, error) {
	return nil, fmt.Errorf("dpapi: unsupported on this platform")
}
