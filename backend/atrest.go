// Package main implements the WorkBuddy Connect DBX plugin sidecar.
//
// This file ports the WorkBuddy 5.6 "at rest" credential envelope opener. The
// scheme was reverse-engineered from the DSH plugin dsh-workbuddy-connect
// (Apache-2.0) and verified against a real credential file:
//
//	protectorKey = SHA256(atRestSecretKey)                    // 32 bytes, AES-256
//	keyId        = hex(SHA256(protectorKey))[:16]
//	plaintext    = AES-256-GCM(key = protectorKey,
//	                           nonce = base64decode(envelope.nonce),  // 12 bytes
//	                           aad   = buildAuthenticatedContextAad(keyId, suite),
//	                           ct    = base64decode(envelope.ciphertext) || base64decode(envelope.authTag))
//
// The protector key itself is NOT derivable from any file on disk: WorkBuddy
// holds it in an Electron private binding and only exposes it to its own
// binary. Obtaining it therefore requires running the installed WorkBuddy
// executable with a one-line helper script (see keyhelper.go).
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// authFields are the credential fields carried inside the envelope.
var authFields = []string{"accessToken", "refreshToken"}

// encryptedField is one wrapped credential field.
type encryptedField struct {
	Field string
	Suite uint32
	KeyID string
	// Envelope holds the raw decoded envelope document.
	Envelope encryptedEnvelope
}

// encryptedEnvelope is the decoded `envelope` JSON document.
//
// Observed on WorkBuddy 5.6.x:
//
//	{"suite":1,"keyId":"9127dea1b44020a7","nonce":"<base64 12B>",
//	 "authTag":"<base64 16B>","ciphertext":"<base64url>","z":"..."}
type encryptedEnvelope struct {
	Suite      uint32 `json:"suite"`
	KeyID      string `json:"keyId"`
	Nonce      string `json:"nonce"`
	AuthTag    string `json:"authTag"`
	Ciphertext string `json:"ciphertext"`
}

// wrappedFieldMarker is the sentinel value marking an encrypted field.
const wrappedFieldMarker = 1

// classifyResult is the outcome of inspecting one auth document.
type classifyResult struct {
	format  string // "absent" | "plaintext" | "encrypted" | "unrecognized"
	fields  []encryptedField
	keyIDs  []string
	rawText string
}

// classifyDesktopAuthDocument decides whether a document is plaintext, an
// encrypted envelope, or unreadable, mirroring the reference implementation.
func classifyDesktopAuthDocument(text string) classifyResult {
	if len(trimSpace(text)) == 0 {
		return classifyResult{format: "absent", rawText: text}
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		return classifyResult{format: "unrecognized", rawText: text}
	}
	auth := parsed
	if nested, ok := parsed["auth"].(map[string]any); ok {
		auth = nested
	}

	var fields []encryptedField
	var keyIDs []string
	for _, name := range authFields {
		value, present := auth[name]
		if !present {
			continue
		}
		// A plaintext string is the legacy (pre-5.6) shape.
		if _, isString := value.(string); isString {
			continue
		}
		object, isObject := value.(map[string]any)
		if !isObject {
			return classifyResult{format: "unrecognized", rawText: text}
		}
		marker, _ := object["$wbEncrypted"].(float64)
		encoded, _ := object["envelope"].(string)
		if marker != wrappedFieldMarker || encoded == "" {
			return classifyResult{format: "unrecognized", rawText: text}
		}
		env, err := decodeEnvelope(encoded)
		if err != nil {
			return classifyResult{format: "unrecognized", rawText: text}
		}
		fields = append(fields, encryptedField{
			Field:    name,
			Suite:    env.Suite,
			KeyID:    env.KeyID,
			Envelope: env,
		})
		keyIDs = append(keyIDs, env.KeyID)
	}
	if len(fields) == 0 {
		return classifyResult{format: "plaintext", rawText: text}
	}
	return classifyResult{format: "encrypted", fields: fields, keyIDs: keyIDs, rawText: text}
}

func decodeEnvelope(encoded string) (encryptedEnvelope, error) {
	raw, err := decodeBase64Variants(encoded)
	if err != nil {
		return encryptedEnvelope{}, err
	}
	var env encryptedEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return encryptedEnvelope{}, err
	}
	return env, nil
}

// decodeBase64Variants accepts the encodings the app has been observed to use:
// padded or unpadded standard base64, then their base64url counterparts.
func decodeBase64Variants(value string) ([]byte, error) {
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	var lastErr error
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(value)
		if err == nil {
			return decoded, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// buildAuthenticatedContextAad transcribes the app bundle's
// buildAuthenticatedContextAad. Credential fields are always suite 1 under the
// `field` framing (WBEV1).
func buildAuthenticatedContextAad(keyID string, suite uint32) []byte {
	lengthPrefixed := func(value string) []byte {
		bytes := []byte(value)
		header := make([]byte, 4)
		binary.BigEndian.PutUint32(header, uint32(len(bytes)))
		return append(header, bytes...)
	}
	suiteBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(suiteBytes, suite)

	out := []byte("WB-AAD\x00")
	out = append(out, 1)
	out = append(out, lengthPrefixed("WBEV1")...)
	out = append(out, lengthPrefixed("sym-v1")...)
	out = append(out, suiteBytes...)
	out = append(out, lengthPrefixed(keyID)...)
	out = append(out, 2, 0, 0)
	return out
}

// deriveProtectorKey turns the app's at-rest secret into the AES-256 key.
// The secret is hashed as its UTF-8 string form, not as decoded bytes.
func deriveProtectorKey(atRestSecretKey string) []byte {
	sum := sha256.Sum256([]byte(atRestSecretKey))
	return sum[:]
}

// keyIDForKey is the public identifier of a protector key.
func keyIDForKey(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:])[:16]
}

// openAuthField decrypts one wrapped field. Any failure is reported without
// echoing ciphertext or key material.
func openAuthField(key []byte, field encryptedField) (string, error) {
	return openWithAAD(key, field, buildAuthenticatedContextAad(field.Envelope.KeyID, field.Suite))
}

// openWithAAD is openAuthField with an explicit associated-data value, so tests
// can prove the AAD is actually authenticated.
func openWithAAD(key []byte, field encryptedField, aad []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("at-rest key is not usable for AES-256: %w", err)
	}
	gcm, err := cipher.NewGCMWithTagSize(block, 16)
	if err != nil {
		return "", err
	}

	// The app writes standard base64 (with '+', '/' and padding) for all three
	// envelope members; base64url is accepted as a fallback for builds that
	// differ. Observed on 5.6.x: nonce and authTag are padded base64, and the
	// ciphertext is standard base64 without padding.
	nonce, err := decodeBase64Variants(field.Envelope.Nonce)
	if err != nil {
		return "", fmt.Errorf("%s envelope nonce is not base64: %w", field.Field, err)
	}
	tag, err := decodeBase64Variants(field.Envelope.AuthTag)
	if err != nil {
		return "", fmt.Errorf("%s envelope authTag is not base64: %w", field.Field, err)
	}
	ciphertext, err := decodeBase64Variants(field.Envelope.Ciphertext)
	if err != nil {
		return "", fmt.Errorf("%s envelope ciphertext is not base64: %w", field.Field, err)
	}

	sealed := make([]byte, 0, len(ciphertext)+len(tag))
	sealed = append(sealed, ciphertext...)
	sealed = append(sealed, tag...)

	plaintext, err := gcm.Open(nil, nonce, sealed, aad)
	if err != nil {
		return "", errors.New("the encrypted desktop credential's " + field.Field +
			" could not be decrypted; the WorkBuddy app may hold a different at-rest key — open it once to reseal the sign-in")
	}
	return string(plaintext), nil
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && isSpace(s[start]) {
		start++
	}
	for end > start && isSpace(s[end-1]) {
		end--
	}
	return s[start:end]
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}
