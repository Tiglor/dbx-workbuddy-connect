// Qoder CN device-authorization login and token store.
//
// Qoder keeps no user token on disk (see docs/sources-recon.md), so the only
// legitimate channel is to run the official desktop client's device-
// authorization flow ourselves: build the PKCE selectAccounts URL, let the user
// approve it in a browser, then poll /api/v1/deviceToken/poll for the grant.
// Protocol constants ported (MIT, (c) 2026 Sliverkiss / mmqz — see NOTICE) from
// mmqz/cpa-multi-plugins plugins/qoder (oauth.go), which derived them from
// official desktop client v0.4.3 asar forensics.

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	qoderRegionCN   = "cn"
	qoderRegionIntl = "intl"

	// qoderDesktopClientID is the single client_id both the CN and Intl
	// official desktop clients send on /device/selectAccounts.
	qoderDesktopClientID = "732aef47-9cf2-46a2-95fe-4cebb5d0d1fa"

	qoderWebsiteCN     = "https://qoder.cn"
	qoderRedirectURICN = "" // omitted from the selectAccounts URL
	qoderOpenAPICN     = "https://openapi.qoder.com.cn"
	qoderGatewayCN     = "https://gateway.qoder.com.cn"

	qoderWebsiteIntl     = "https://qoder.com"
	qoderRedirectURIIntl = "qoder-app://"
	qoderOpenAPIIntl     = "https://openapi.qoder.sh"
	qoderGatewayIntl     = "https://api3.qoder.sh"

	qoderLoginTTL = 10 * time.Minute
)

func qoderWebsiteFor(region string) string {
	if region == qoderRegionIntl {
		return qoderWebsiteIntl
	}
	return qoderWebsiteCN
}

func qoderRedirectURIFor(region string) string {
	if region == qoderRegionIntl {
		return qoderRedirectURIIntl
	}
	return qoderRedirectURICN
}

func qoderOpenAPIFor(region string) string {
	if region == qoderRegionIntl {
		return qoderOpenAPIIntl
	}
	return qoderOpenAPICN
}

func qoderGatewayFor(region string) string {
	if region == qoderRegionIntl {
		return qoderGatewayIntl
	}
	return qoderGatewayCN
}

// qoderToken is the persisted device grant.
type qoderToken struct {
	AccessToken        string `json:"accessToken"`  // dt-...
	RefreshToken       string `json:"refreshToken"` // drt-...
	ExpiresAtMs        int64  `json:"expiresAtMs"`
	RefreshExpiresAtMs int64  `json:"refreshExpiresAtMs"`
	UID                string `json:"uid"`
	Nickname           string `json:"nickname"`
	UserType           string `json:"userType"`
	Region             string `json:"region"`
	MachineID          string `json:"machineId"`
}

func (t *qoderToken) needsRefresh() bool {
	if t.ExpiresAtMs == 0 {
		return false
	}
	return time.Now().UnixMilli() > t.ExpiresAtMs-int64((5*time.Minute)/time.Millisecond)
}

// qoderDeviceTokenResponse mirrors /api/v1/deviceToken/{poll,refresh}.
// expires_in fields are milliseconds.
type qoderDeviceTokenResponse struct {
	Token                 string `json:"token"`
	DeviceToken           string `json:"device_token"`
	RefreshToken          string `json:"refresh_token"`
	UserID                string `json:"user_id"`
	ExpiresAt             string `json:"expires_at"`
	ExpiresIn             int64  `json:"expires_in"`
	RefreshTokenExpiresAt string `json:"refresh_token_expires_at"`
	RefreshTokenExpiresIn int64  `json:"refresh_token_expires_in"`
}

func (d *qoderDeviceTokenResponse) accessToken() string {
	if d.Token != "" {
		return d.Token
	}
	return d.DeviceToken
}

// qoderLoginState is one in-flight device authorization.
type qoderLoginState struct {
	verifier string
	nonce    string
	region   string
	expires  time.Time
}

// qoderAuth owns the login flow and the persisted grant.
type qoderAuth struct {
	path      string
	machineID string

	mu     sync.Mutex
	cached *qoderToken
	states map[string]*qoderLoginState
}

func newQoderAuth(dataDir string) *qoderAuth {
	return &qoderAuth{
		path:   filepath.Join(dataDir, "qoder-token.json"),
		states: map[string]*qoderLoginState{},
	}
}

// qoderRegion selects the realm; defaults to CN, overridable for testing.
func qoderRegion() string {
	if r := strings.ToLower(strings.TrimSpace(os.Getenv("QODER_REGION"))); r == qoderRegionIntl {
		return qoderRegionIntl
	}
	return qoderRegionCN
}

// machineID returns a stable per-install machine identity, persisted so
// device-targeted upstream rows stay consistent across restarts.
func (a *qoderAuth) machineIdentity() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.machineID != "" {
		return a.machineID
	}
	idPath := filepath.Join(filepath.Dir(a.path), "qoder-machine-id")
	if raw, err := os.ReadFile(idPath); err == nil {
		if id := strings.TrimSpace(string(raw)); id != "" {
			a.machineID = id
			return id
		}
	}
	id := uuid.NewString()
	_ = os.MkdirAll(filepath.Dir(idPath), 0o700)
	_ = os.WriteFile(idPath, []byte(id), 0o600)
	a.machineID = id
	return id
}

// qoderMakePKCE returns (verifier, challenge) per RFC 7636 (S256).
func qoderMakePKCE() (string, string) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	raw := make([]byte, 64)
	if _, err := rand.Read(raw); err != nil {
		s := uuid.NewString() + uuid.NewString()
		sum := sha256.Sum256([]byte(s))
		v := base64.RawURLEncoding.EncodeToString(sum[:])
		return v, v
	}
	verifier := make([]byte, 64)
	for i, b := range raw {
		verifier[i] = alphabet[int(b)%len(alphabet)]
	}
	sum := sha256.Sum256(verifier)
	return string(verifier), base64.RawURLEncoding.EncodeToString(sum[:])
}

// StartLogin builds the device-authorization URL the user must approve.
func (a *qoderAuth) StartLogin() (authURL, state string, err error) {
	region := qoderRegion()
	verifier, challenge := qoderMakePKCE()
	nonce := uuid.NewString()
	if region == qoderRegionIntl {
		nonce = strings.ReplaceAll(nonce, "-", "")
	}

	q := url.Values{}
	q.Set("challenge", challenge)
	q.Set("challenge_method", "S256")
	q.Set("nonce", nonce)
	q.Set("machine_id", a.machineIdentity())
	q.Set("client_id", qoderDesktopClientID)
	if r := qoderRedirectURIFor(region); r != "" {
		q.Set("redirect_uri", r)
	}
	inner := qoderWebsiteFor(region) + "/device/selectAccounts?" + q.Encode()
	authURL = qoderWebsiteFor(region) + "/users/sign-in?biz_variant=qoder&oauth_callback=" + url.QueryEscape(inner)

	state = fmt.Sprintf("qw-%d", time.Now().UnixNano())
	a.mu.Lock()
	a.states[state] = &qoderLoginState{verifier: verifier, nonce: nonce, region: region, expires: time.Now().Add(qoderLoginTTL)}
	a.mu.Unlock()
	return authURL, state, nil
}

// PollLogin performs one poll; pending=true means the user has not approved yet.
func (a *qoderAuth) PollLogin(ctx context.Context, state string) (*qoderToken, bool, error) {
	a.mu.Lock()
	lc, ok := a.states[state]
	a.mu.Unlock()
	if !ok {
		return nil, false, fmt.Errorf("qoder: unknown login state (restart login)")
	}
	if time.Now().After(lc.expires) {
		a.mu.Lock()
		delete(a.states, state)
		a.mu.Unlock()
		return nil, false, fmt.Errorf("qoder: login expired (%v timeout)", qoderLoginTTL)
	}

	tok, pending, err := qoderPollDeviceToken(ctx, lc.nonce, lc.verifier, lc.region)
	if err != nil {
		return nil, false, err
	}
	if pending || tok == nil {
		return nil, true, nil
	}
	cred := a.tokenFromDeviceResponse(tok, lc.region)
	if err := a.save(cred); err != nil {
		return nil, false, err
	}
	a.mu.Lock()
	delete(a.states, state)
	a.cached = cred
	a.mu.Unlock()
	return cred, false, nil
}

func (a *qoderAuth) tokenFromDeviceResponse(tok *qoderDeviceTokenResponse, region string) *qoderToken {
	cred := &qoderToken{
		AccessToken:  tok.accessToken(),
		RefreshToken: tok.RefreshToken,
		UID:          tok.UserID,
		Region:       region,
		MachineID:    a.machineIdentity(),
	}
	if tok.ExpiresIn > 0 {
		cred.ExpiresAtMs = time.Now().UnixMilli() + tok.ExpiresIn
	} else if t, err := time.Parse(time.RFC3339, tok.ExpiresAt); err == nil {
		cred.ExpiresAtMs = t.UnixMilli()
	} else {
		cred.ExpiresAtMs = time.Now().Add(30 * 24 * time.Hour).UnixMilli()
	}
	if tok.RefreshTokenExpiresIn > 0 {
		cred.RefreshExpiresAtMs = time.Now().UnixMilli() + tok.RefreshTokenExpiresIn
	} else if t, err := time.Parse(time.RFC3339, tok.RefreshTokenExpiresAt); err == nil {
		cred.RefreshExpiresAtMs = t.UnixMilli()
	}
	if len(cred.UID) > 8 {
		cred.Nickname = "u" + cred.UID[len(cred.UID)-8:]
	} else {
		cred.Nickname = "u" + cred.UID
	}
	return cred
}

// qoderPollDeviceToken performs one GET against /api/v1/deviceToken/poll.
func qoderPollDeviceToken(ctx context.Context, nonce, verifier, region string) (*qoderDeviceTokenResponse, bool, error) {
	q := url.Values{}
	q.Set("nonce", nonce)
	q.Set("verifier", verifier)
	q.Set("challenge_method", "S256")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		qoderOpenAPIFor(region)+"/api/v1/deviceToken/poll?"+q.Encode(), nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "QoderWork")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusAccepted {
		return nil, true, nil
	}
	if resp.StatusCode >= 400 {
		return nil, false, fmt.Errorf("qoder deviceToken poll: http %d", resp.StatusCode)
	}
	var out qoderDeviceTokenResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, false, fmt.Errorf("qoder deviceToken poll parse: %w", err)
	}
	if out.accessToken() == "" {
		return nil, true, nil
	}
	return &out, false, nil
}

// qoderRefreshDeviceToken calls POST /api/v1/deviceToken/refresh with a drt-.
func qoderRefreshDeviceToken(ctx context.Context, drt, region string) (*qoderDeviceTokenResponse, error) {
	body, _ := json.Marshal(map[string]string{"refresh_token": drt})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		qoderOpenAPIFor(region)+"/api/v1/deviceToken/refresh", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "QoderWork")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("qoder deviceToken refresh: http %d", resp.StatusCode)
	}
	var out qoderDeviceTokenResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("qoder deviceToken refresh parse: %w", err)
	}
	if out.accessToken() == "" || out.RefreshToken == "" {
		return nil, fmt.Errorf("qoder deviceToken refresh: incomplete token pair")
	}
	return &out, nil
}

// Resolve returns a grant ready to sign requests, refreshing when needed.
func (a *qoderAuth) Resolve(ctx context.Context) (*qoderToken, error) {
	cred, err := a.current()
	if err != nil {
		return nil, err
	}
	if cred == nil {
		return nil, errQoderNotSignedIn
	}
	if !cred.needsRefresh() {
		return cred, nil
	}
	tok, err := qoderRefreshDeviceToken(ctx, cred.RefreshToken, cred.Region)
	if err != nil {
		// Still usable while unexpired: avoid a refresh storm mid-flight.
		if cred.ExpiresAtMs == 0 || time.Now().UnixMilli() < cred.ExpiresAtMs {
			return cred, nil
		}
		return nil, fmt.Errorf("qoder: refresh failed (%w); re-login required", err)
	}
	refreshed := a.tokenFromDeviceResponse(tok, cred.Region)
	refreshed.Nickname = cred.Nickname
	refreshed.UserType = cred.UserType
	if err := a.save(refreshed); err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.cached = refreshed
	a.mu.Unlock()
	return refreshed, nil
}

var errQoderNotSignedIn = fmt.Errorf("qoder: 未登录——请在工作台点「登录 Qoder」完成设备授权")

// current reads the persisted grant without refreshing.
func (a *qoderAuth) current() (*qoderToken, error) {
	a.mu.Lock()
	cached := a.cached
	a.mu.Unlock()
	if cached != nil {
		return cached, nil
	}
	raw, err := os.ReadFile(a.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var cred qoderToken
	if err := json.Unmarshal(raw, &cred); err != nil || cred.AccessToken == "" {
		return nil, nil
	}
	a.mu.Lock()
	a.cached = &cred
	a.mu.Unlock()
	return &cred, nil
}

func (a *qoderAuth) save(cred *qoderToken) error {
	payload, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(a.path), 0o700); err != nil {
		return err
	}
	// Owner-only: this file holds a live bearer token.
	return os.WriteFile(a.path, payload, 0o600)
}

// signedIn reports whether a grant is present (no network).
func (a *qoderAuth) signedIn() bool {
	cred, err := a.current()
	return err == nil && cred != nil
}

// Logout clears the persisted grant and any in-flight login states.
func (a *qoderAuth) Logout() error {
	a.mu.Lock()
	a.cached = nil
	a.states = map[string]*qoderLoginState{}
	a.mu.Unlock()
	if err := os.Remove(a.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
