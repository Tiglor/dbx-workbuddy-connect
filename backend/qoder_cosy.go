// Qoder COSY request signing and body encoding.
//
// Ported (MIT, (c) 2026 Sliverkiss / mmqz — see NOTICE) from
// mmqz/cpa-multi-plugins plugins/qoder (sign.go, encoding.go). The algorithm is
// RSA-wrapped AES session key + AES-128-CBC encrypted identity + MD5 request
// signature; the body encoding is Qoder's custom base64 variant.

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// qoderServerPubKeyPEM is Qoder's RSA public key, hardcoded in the official
// desktop client. It wraps the per-session AES key.
const qoderServerPubKeyPEM = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDA8iMH5c02LilrsERw9t6Pv5Nc
4k6Pz1EaDicBMpdpxKduSZu5OANqUq8er4GM95omAGIOPOh+Nx0spthYA2BqGz+l
6HRkPJ7S236FZz73In/KVuLnwI8JJ2CbuJap8kvheCCZpmAWpb/cPx/3Vr/J6I17
XcW+ML9FoCI6AOvOzwIDAQAB
-----END PUBLIC KEY-----`

var qoderServerPubKey *rsa.PublicKey

func init() {
	block, _ := pem.Decode([]byte(qoderServerPubKeyPEM))
	if block == nil {
		panic("qoder: bad server pubkey PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	qoderServerPubKey = parsed.(*rsa.PublicKey)
}

// qoderCosySession holds the per-credential signing state.
type qoderCosySession struct {
	MachineID    string `json:"machineId"`
	MachineToken string `json:"machineToken"`
	MachineType  string `json:"machineType"`
	TempKey      string `json:"-"`
	CosyKey      string `json:"cosyKey"`
	Info         string `json:"info"`
}

// qoderCosyIdentity is the plaintext sealed inside Info.
type qoderCosyIdentity struct {
	Name               string
	AID                string
	UID                string
	YxUID              string
	OrganizationID     string
	OrganizationName   string
	UserType           string
	SecurityOauthToken string
	RefreshToken       string
}

// qoderJSONSortedCompact marshals with sorted keys and no whitespace, the
// compact form the gateway recomputes when verifying the signature.
func qoderJSONSortedCompact(m map[string]string) []byte {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	sb.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		vb, _ := json.Marshal(m[k])
		sb.Write(kb)
		sb.WriteByte(':')
		sb.Write(vb)
	}
	sb.WriteByte('}')
	return []byte(sb.String())
}

// qoderAESCBCEncrypt encrypts with AES-128-CBC where key == iv == tempKey.
func qoderAESCBCEncrypt(plain, tempKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(tempKey)
	if err != nil {
		return nil, err
	}
	padLen := aes.BlockSize - len(plain)%aes.BlockSize
	padded := make([]byte, len(plain)+padLen)
	copy(padded, plain)
	for i := len(plain); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, tempKey).CryptBlocks(out, padded)
	return out, nil
}

// newQoderCosySession builds a fresh signing session for one identity.
func newQoderCosySession(id qoderCosyIdentity, machineID string) (*qoderCosySession, error) {
	if machineID == "" {
		machineID = uuid.NewString()
	}
	seed := []byte(uuid.NewString() + uuid.NewString())
	if len(seed) > 50 {
		seed = seed[:50]
	}
	machineToken := base64.RawURLEncoding.EncodeToString(seed)
	machineType := strings.ReplaceAll(uuid.NewString(), "-", "")[:18]
	tempKey := strings.ReplaceAll(uuid.NewString(), "-", "")[:16]

	wrapped, err := rsa.EncryptPKCS1v15(rand.Reader, qoderServerPubKey, []byte(tempKey))
	if err != nil {
		return nil, fmt.Errorf("qoder cosy: rsa encrypt: %w", err)
	}
	identity := map[string]string{
		"name":                 id.Name,
		"aid":                  id.AID,
		"uid":                  id.UID,
		"yx_uid":               id.YxUID,
		"organization_id":      id.OrganizationID,
		"organization_name":    id.OrganizationName,
		"user_type":            id.UserType,
		"security_oauth_token": id.SecurityOauthToken,
		"refresh_token":        id.RefreshToken,
	}
	sealed, err := qoderAESCBCEncrypt(qoderJSONSortedCompact(identity), []byte(tempKey))
	if err != nil {
		return nil, fmt.Errorf("qoder cosy: aes encrypt: %w", err)
	}
	return &qoderCosySession{
		MachineID:    machineID,
		MachineToken: machineToken,
		MachineType:  machineType,
		TempKey:      tempKey,
		CosyKey:      base64.StdEncoding.EncodeToString(wrapped),
		Info:         base64.StdEncoding.EncodeToString(sealed),
	}, nil
}

// bearer builds the Authorization value for one signed request. pathSig is the
// URL path with the "/algo" prefix stripped; body is the already-encoded body.
func (s *qoderCosySession) bearer(body, rawURL string) (string, string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", err
	}
	pathSig := u.Path
	if strings.HasPrefix(pathSig, "/algo") {
		pathSig = pathSig[len("/algo"):]
	}
	payload := map[string]string{
		"cosyVersion": "0.1.43",
		"ideVersion":  "",
		"info":        s.Info,
		"requestId":   uuid.NewString(),
		"version":     "v1",
	}
	payloadB64 := base64.StdEncoding.EncodeToString(qoderJSONSortedCompact(payload))
	date := fmt.Sprintf("%d", time.Now().Unix())
	sum := md5.Sum([]byte(payloadB64 + "\n" + s.CosyKey + "\n" + date + "\n" + body + "\n" + pathSig))
	return "Bearer COSY." + payloadB64 + "." + hex.EncodeToString(sum[:]), date, nil
}

// headers returns the full header set for one gateway request.
func (s *qoderCosySession) headers(uid, body, rawURL, accept string, sse bool) (map[string]string, error) {
	bearer, date, err := s.bearer(body, rawURL)
	if err != nil {
		return nil, err
	}
	h := map[string]string{
		"cosy-data-policy":  "AGREE",
		"content-type":      "application/json",
		"cosy-machinetype":  s.MachineType,
		"cosy-clienttype":   "5",
		"cosy-date":         date,
		"cosy-user":         uid,
		"cosy-key":          s.CosyKey,
		"accept":            accept,
		"cosy-clientip":     "169.254.198.161",
		"authorization":     bearer,
		"accept-encoding":   "identity",
		"cosy-version":      "0.1.43",
		"cosy-machineid":    s.MachineID,
		"cosy-machinetoken": s.MachineToken,
		"login-version":     "v2",
		"user-agent":        "Go-http-client/2.0",
	}
	if sse {
		h["cache-control"] = "no-cache"
	}
	return h, nil
}

// Qoder body encoding: a custom base64 variant.
const (
	qoderCustomAlphabet = "_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!"
	qoderStdAlphabet    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	qoderCustomPad      = '$'
)

var (
	qoderS2C [128]byte
	qoderC2S [128]byte
)

func init() {
	for i := 0; i < 64; i++ {
		qoderS2C[qoderStdAlphabet[i]] = qoderCustomAlphabet[i]
		qoderC2S[qoderCustomAlphabet[i]] = qoderStdAlphabet[i]
	}
	qoderS2C['='] = qoderCustomPad
	qoderC2S[qoderCustomPad] = '='
}

// qoderEncode encodes plaintext to Qoder's custom base64 variant.
func qoderEncode(plain []byte) string {
	std := base64.StdEncoding.EncodeToString(plain)
	n := len(std)
	a := n / 3
	rearranged := std[n-a:] + std[a:n-a] + std[:a]
	var sb strings.Builder
	sb.Grow(n)
	for i := 0; i < n; i++ {
		c := rearranged[i]
		if c >= 128 || qoderS2C[c] == 0 {
			sb.WriteByte(c)
			continue
		}
		sb.WriteByte(qoderS2C[c])
	}
	return sb.String()
}
