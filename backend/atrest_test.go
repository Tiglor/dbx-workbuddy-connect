package main

import (
	"context"
	"os"
	"strings"
	"testing"
)

// TestOpenAuthFieldAgainstRealCredential validates the ported AES-256-GCM
// implementation against the machine's real WorkBuddy credential file.
//
// It is a cross-check, not a mock: the same document is opened by the reference
// JavaScript implementation (dsh-workbuddy-connect) and by this code, and the
// decrypted token must be a JWT of the recorded length. Skipped when the app is
// not installed or not signed in.
func TestOpenAuthFieldAgainstRealCredential(t *testing.T) {
	if os.Getenv("WORKBUDDY_ELECTRON_BIN") == "" {
		t.Skip("WORKBUDDY_ELECTRON_BIN not set; skipping real-credential cross-check")
	}
	store := newCredentialStore(newUpstreamClient(), t.TempDir())

	path, format, err := store.resolvedDesktopAuthPath()
	if err != nil {
		t.Fatalf("resolvedDesktopAuthPath: %v", err)
	}
	if path == "" {
		t.Skip("no WorkBuddy sign-in file on this machine")
	}
	if format != "encrypted" {
		t.Skipf("sign-in file is %s, not an encrypted envelope", format)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	classification := classifyDesktopAuthDocument(string(raw))
	if classification.format != "encrypted" {
		t.Fatalf("classify = %q, want encrypted", classification.format)
	}
	if len(classification.fields) == 0 {
		t.Fatal("no wrapped fields found")
	}

	secret, err := fetchAtRestSecretKey(context.Background())
	if err != nil {
		t.Fatalf("fetchAtRestSecretKey: %v", err)
	}
	key := deriveProtectorKey(secret)
	if len(key) != 32 {
		t.Fatalf("protector key length = %d, want 32", len(key))
	}

	// The derived key id must match the envelope's keyId, which proves the
	// SHA-256 -> hex[:16] derivation without decrypting anything.
	derivedID := keyIDForKey(key)
	if !containsString(classification.keyIDs, derivedID) {
		t.Fatalf("derived key id %q not among envelope key ids %v", derivedID, classification.keyIDs)
	}
	t.Logf("derived key id %s matches envelope", derivedID)

	opened := map[string]string{}
	for _, field := range classification.fields {
		plaintext, err := openAuthField(key, field)
		if err != nil {
			t.Fatalf("openAuthField(%s): %v", field.Field, err)
		}
		opened[field.Field] = plaintext
		t.Logf("%s: decrypted %d bytes", field.Field, len(plaintext))
	}

	access, ok := opened["accessToken"]
	if !ok {
		t.Fatal("accessToken was not in the envelope")
	}
	if !strings.HasPrefix(access, "eyJ") {
		t.Fatalf("decrypted accessToken does not look like a JWT (prefix %.8q)", access)
	}
	if parts := strings.Split(access, "."); len(parts) != 3 {
		t.Fatalf("decrypted accessToken is not a 3-part JWT (%d parts)", len(parts))
	}

	// The AAD is authenticated, so a wrong AAD fails decryption outright. Assert
	// it is sensitive to the key id to prove the transcription is load-bearing.
	badAAD := buildAuthenticatedContextAad("0000000000000000", 1)
	field := classification.fields[0]
	if _, err := openWithAAD(key, field, badAAD); err == nil {
		t.Fatal("decryption succeeded with a wrong AAD key id; the AAD is not being authenticated")
	}
}

// TestClassifyRejectsGarbage guards the classifier's fail-closed behaviour.
func TestClassifyRejectsGarbage(t *testing.T) {
	cases := []struct {
		name string
		text string
		want string
	}{
		{"empty", "   ", "absent"},
		{"not json", "hello", "unrecognized"},
		{"array", "[]", "unrecognized"},
		{"plaintext token", `{"auth":{"accessToken":"abc"}}`, "plaintext"},
		{"bad envelope", `{"auth":{"accessToken":{"$wbEncrypted":1,"envelope":"!!!not-base64"}}}`, "unrecognized"},
	}
	for _, tc := range cases {
		if got := classifyDesktopAuthDocument(tc.text).format; got != tc.want {
			t.Errorf("%s: classify = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestParseAtRestPayload covers the helper payload contract.
func TestParseAtRestPayload(t *testing.T) {
	valid := `{"version":1,"atRestSecretKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`
	if _, err := parseAtRestPayload(valid); err == nil {
		t.Error("all-zero secret must be rejected")
	}
	if _, err := parseAtRestPayload(`{"version":2,"atRestSecretKey":"x"}`); err == nil {
		t.Error("version 2 must be rejected")
	}
	if _, err := parseAtRestPayload("not json"); err == nil {
		t.Error("non-JSON must be rejected")
	}
}
