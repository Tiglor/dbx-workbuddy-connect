// Trae CN login and token store.
//
// Trae keeps no user token on disk, so the plugin runs the official desktop
// client's OAuth flow itself: it binds a loopback listener on
// http://127.0.0.1:<port>/authorize (the authorization page hard-requires that
// exact callback shape), opens the authorization URL for the user, receives the
// auth code on the listener, then exchanges it for a Cloud-IDE-JWT access token.
//
// A device key pair is generated once and persisted: ExchangeToken rejects an
// empty DevicePublicKey (business code 20405) and the server binds/caps devices
// per account, so the same identity must be reused across logins.
//
// Protocol constants and flow ported (MIT, (c) 2026 Sliverkiss / mmqz — see
// NOTICE) from mmqz/cpa-multi-plugins plugins/trae. Only the CN realm and the
// legacy (unsigned) refresh path are implemented; the device-signed bound
// refresh is not needed for chat.

package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
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
	traeClientID     = "ono9krqynydwx5"
	traeAppID        = "6eefa01c-1036-4c7e-9ca5-d891f63bfcd8"
	traeIdeVersion   = "0.1.61"
	traeVersionCode  = "20260820"
	traeDeviceBrand  = "83DG"
	traeOSVersion    = "Windows 11 Pro"
	traeAgentHost    = "https://trae-api-cn.mchost.guru"
	traeExchangeHost = "https://api.trae.cn"
	traeLegacyHost   = "https://api.trae.com.cn"
	traePluginVer    = "1.0.0"
	traeUA           = "Trae/" + traeIdeVersion
	traeLoginUA      = "Trae/1.0.0 antigravity-cockpit-tools"

	traeLoginTTL = 10 * time.Minute
)

// traeDeviceIdentity is the stable per-install device identity.
type traeDeviceIdentity struct {
	DeviceID  string `json:"deviceId"`
	MachineID string `json:"machineId"`
	PubPEM    string `json:"devicePublicKey"`
	PrivPEM   string `json:"devicePrivateKey"`
}

// traeToken is the persisted access grant.
type traeToken struct {
	AccessToken        string `json:"accessToken"`
	RefreshToken       string `json:"refreshToken"`
	ExpiresAtMs        int64  `json:"expiresAtMs"`
	RefreshExpiresAtMs int64  `json:"refreshExpiresAtMs"`
	UID                string `json:"uid"`
	Nickname           string `json:"nickname"`
}

func (t *traeToken) needsRefresh() bool {
	if t.ExpiresAtMs == 0 {
		return false
	}
	return time.Now().UnixMilli() > t.ExpiresAtMs-int64((24*time.Hour)/time.Millisecond)
}

// traeLoginState is one in-flight authorization, holding the loopback listener
// and the channel the callback params arrive on.
type traeLoginState struct {
	verifier  string
	challenge string
	traceID   string
	port      int
	listener  net.Listener
	callback  chan url.Values
	expires   time.Time

	mu     sync.Mutex
	result *traeToken
	err    error
	done   bool
}

type traeAuth struct {
	dir string

	mu     sync.Mutex
	dev    *traeDeviceIdentity
	cached *traeToken
	states map[string]*traeLoginState
}

func newTraeAuth(dataDir string) *traeAuth {
	return &traeAuth{
		dir:    dataDir,
		states: map[string]*traeLoginState{},
	}
}

func (a *traeAuth) tokenPath() string  { return filepath.Join(a.dir, "trae-token.json") }
func (a *traeAuth) devicePath() string { return filepath.Join(a.dir, "trae-device.json") }

// device loads (or creates and persists) the stable device identity.
func (a *traeAuth) device() (*traeDeviceIdentity, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.dev != nil {
		return a.dev, nil
	}
	if raw, err := os.ReadFile(a.devicePath()); err == nil {
		var id traeDeviceIdentity
		if json.Unmarshal(raw, &id) == nil && id.DeviceID != "" && id.PrivPEM != "" {
			a.dev = &id
			return a.dev, nil
		}
	}
	id, err := newTraeDeviceIdentity()
	if err != nil {
		return nil, err
	}
	if err := writePrivateJSON(a.devicePath(), id); err != nil {
		return nil, err
	}
	a.dev = id
	return a.dev, nil
}

func newTraeDeviceIdentity() (*traeDeviceIdentity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}))

	// device_id: 16 digits, first non-zero. machine_id: dashed UUID v4.
	var digits [16]byte
	if _, err := rand.Read(digits[:]); err != nil {
		return nil, err
	}
	deviceID := fmt.Sprintf("%d", 1+digits[0]%9)
	for _, d := range digits[1:] {
		deviceID += fmt.Sprintf("%d", d%10)
	}
	return &traeDeviceIdentity{
		DeviceID:  deviceID,
		MachineID: uuid.NewString(),
		PubPEM:    pubPEM,
		PrivPEM:   privPEM,
	}, nil
}

// StartLogin binds the loopback listener and returns the authorization URL.
func (a *traeAuth) StartLogin() (authURL, state string, err error) {
	dev, err := a.device()
	if err != nil {
		return "", "", err
	}
	verifierBytes := make([]byte, 48)
	if _, err := rand.Read(verifierBytes); err != nil {
		return "", "", err
	}
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	challenge := traePKCEChallenge(verifier)
	traceID := uuid.NewString()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", "", fmt.Errorf("trae: cannot bind loopback listener: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	callbackURL := fmt.Sprintf("http://127.0.0.1:%d/authorize", port)

	loginHost := traeResolveLoginHost(traceID)

	q := url.Values{}
	q.Set("login_version", "1")
	q.Set("auth_from", "trae")
	q.Set("login_channel", "native_ide")
	q.Set("plugin_version", traePluginVer)
	q.Set("auth_type", "local")
	q.Set("client_id", traeClientID)
	q.Set("redirect", "0")
	q.Set("login_trace_id", traceID)
	// The authorization page validates this against
	// ^http://127.0.0.1:(\d+)/authorize$ and must see it unencoded.
	authURL = "https://" + loginHost + "/authorization?" + q.Encode() +
		"&auth_callback_url=" + callbackURL +
		"&machine_id=" + url.QueryEscape(dev.MachineID) +
		"&device_id=" + url.QueryEscape(dev.DeviceID) +
		"&x_device_id=" + url.QueryEscape(dev.DeviceID) +
		"&x_machine_id=" + url.QueryEscape(dev.MachineID) +
		"&x_device_brand=" + url.QueryEscape(traeDeviceBrand) +
		"&x_device_type=windows" +
		"&x_os_version=" + url.QueryEscape(traeOSVersion) +
		"&x_env=prod" +
		"&x_app_version=" + url.QueryEscape(traeIdeVersion) +
		"&x_app_type=trae" +
		"&code_challenge=" + url.QueryEscape(challenge) +
		"&code_challenge_method=S256"

	st := &traeLoginState{
		verifier:  verifier,
		challenge: challenge,
		traceID:   traceID,
		port:      port,
		listener:  listener,
		callback:  make(chan url.Values, 1),
		expires:   time.Now().Add(traeLoginTTL),
	}
	state = "tw-" + fmt.Sprint(time.Now().UnixNano())
	a.mu.Lock()
	a.states[state] = st
	a.mu.Unlock()

	go a.serveCallback(st)
	return authURL, state, nil
}

func traePKCEChallenge(verifier string) string {
	// challenge = base64url-nopad(SHA256(verifier))
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// serveCallback accepts a single authorization redirect on the loopback listener.
func (a *traeAuth) serveCallback(st *traeLoginState) {
	defer st.listener.Close()
	for {
		conn, err := st.listener.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
			req, err := http.ReadRequest(bufio.NewReader(c))
			if err != nil {
				return
			}
			body := "<html><body><h3>Trae 登录完成，请回到工作台。</h3></body></html>"
			fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
			select {
			case st.callback <- req.URL.Query():
			default:
			}
		}(conn)
	}
}

// PollLogin performs one non-blocking check of an in-flight login.
func (a *traeAuth) PollLogin(ctx context.Context, state string) (*traeToken, bool, error) {
	a.mu.Lock()
	st, ok := a.states[state]
	a.mu.Unlock()
	if !ok {
		return nil, false, fmt.Errorf("trae: unknown login state (restart login)")
	}

	st.mu.Lock()
	if st.done {
		tok, err := st.result, st.err
		st.mu.Unlock()
		a.forgetState(state)
		return tok, false, err
	}
	st.mu.Unlock()

	if time.Now().After(st.expires) {
		a.forgetState(state)
		return nil, false, fmt.Errorf("trae: login expired (%v timeout)", traeLoginTTL)
	}

	select {
	case params := <-st.callback:
		authCode := traePickParam(params, "authCode", "auth_code", "AuthCode", "authorization_code", "code")
		if authCode == "" {
			if info := traePickParam(params, "authCodeInfo", "auth_code_info", "AuthCodeInfo"); info != "" {
				authCode = traeAuthCodeFromInfo(info)
			}
		}
		if authCode == "" {
			reason := traePickParam(params, "error", "error_code", "err", "errorCode")
			st.listener.Close()
			a.forgetState(state)
			if reason != "" {
				return nil, false, fmt.Errorf("trae: authorization failed (%s)", reason)
			}
			return nil, false, fmt.Errorf("trae: callback carried no auth code")
		}
		tok, err := a.exchangeAuthCode(ctx, authCode, st.verifier)
		if err != nil {
			st.listener.Close()
			a.forgetState(state)
			return nil, false, err
		}
		if err := a.save(tok); err != nil {
			return nil, false, err
		}
		a.mu.Lock()
		a.cached = tok
		a.mu.Unlock()
		a.forgetState(state)
		return tok, false, nil
	default:
		return nil, true, nil
	}
}

func (a *traeAuth) forgetState(state string) {
	a.mu.Lock()
	if st, ok := a.states[state]; ok {
		st.listener.Close()
		delete(a.states, state)
	}
	a.mu.Unlock()
}

func traePickParam(v url.Values, keys ...string) string {
	for _, k := range keys {
		if s := strings.TrimSpace(v.Get(k)); s != "" {
			return s
		}
	}
	return ""
}

// traeAuthCodeFromInfo unwraps an authCode carried in a (possibly URL-encoded)
// JSON blob.
func traeAuthCodeFromInfo(info string) string {
	if decoded, err := url.QueryUnescape(info); err == nil {
		info = decoded
	}
	var m map[string]any
	if json.Unmarshal([]byte(info), &m) != nil {
		return ""
	}
	for _, k := range []string{"authCode", "auth_code", "AuthCode", "authorization_code", "code"} {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// exchangeAuthCode trades the authorization code for an access token.
func (a *traeAuth) exchangeAuthCode(ctx context.Context, authCode, verifier string) (*traeToken, error) {
	dev, err := a.device()
	if err != nil {
		return nil, err
	}
	body := map[string]any{
		"ClientID":     traeClientID,
		"AuthCode":     authCode,
		"CodeVerifier": verifier,
		"DeviceInfo": map[string]any{
			"DeviceID":        dev.DeviceID,
			"MachineID":       dev.MachineID,
			"PlatformCode":    "IDE_PC",
			"DeviceType":      "PC",
			"DeviceName":      "DESKTOP-DBX",
			"DeviceModel":     traeDeviceBrand,
			"ClientVersion":   traeIdeVersion,
			"DevicePublicKey": dev.PubPEM,
			"DeviceBrand":     "Microsoft",
			"DeviceCPU":       "",
			"OSInfo":          "windows",
			"OSVersion":       traeOSVersion,
		},
		"IDEVersion": traeIdeVersion,
	}
	res, err := traeExchangeRequest(ctx, traeExchangeHost+"/trae/api/v3/oauth/ExchangeToken", body, "")
	if err != nil {
		return nil, err
	}
	tok, err := a.tokenFromResult(res)
	if err != nil {
		return nil, err
	}
	a.fetchUserInfo(ctx, tok)
	return tok, nil
}

// refresh uses the legacy unsigned path, which still yields chat-working tokens.
func (a *traeAuth) refresh(ctx context.Context, rt string) (*traeToken, error) {
	body := map[string]any{
		"ClientID":     traeClientID,
		"RefreshToken": rt,
		"ClientSecret": "-",
		"UserID":       "",
	}
	res, err := traeExchangeRequest(ctx, traeLegacyHost+"/cloudide/api/v3/trae/oauth/ExchangeToken", body, "")
	if err != nil {
		return nil, err
	}
	return a.tokenFromResult(res)
}

// traeExchangeRequest POSTs an ExchangeToken-family body and returns the Result.
func traeExchangeRequest(ctx context.Context, endpoint string, body map[string]any, accessToken string) (map[string]any, error) {
	payload, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(payload)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", traeLoginUA)
	if accessToken != "" {
		req.Header.Set("Authorization", "Cloud-IDE-JWT "+accessToken)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("trae exchange http %d: %s", resp.StatusCode, traeErrorSummary(raw))
	}
	var env map[string]any
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("trae exchange parse: %w", err)
	}
	if rm, ok := env["ResponseMetadata"].(map[string]any); ok {
		if e, ok := rm["Error"].(map[string]any); ok {
			return nil, fmt.Errorf("trae exchange error %v: %v", e["Code"], e["Message"])
		}
	}
	result, _ := env["Result"].(map[string]any)
	if result == nil {
		return nil, fmt.Errorf("trae exchange: no Result in response")
	}
	return result, nil
}

func traeErrorSummary(raw []byte) string {
	var env map[string]any
	if json.Unmarshal(raw, &env) == nil {
		if rm, ok := env["ResponseMetadata"].(map[string]any); ok {
			if e, ok := rm["Error"].(map[string]any); ok {
				return fmt.Sprintf("%v: %v", e["Code"], e["Message"])
			}
		}
	}
	return firstLine(raw)
}

func (a *traeAuth) tokenFromResult(result map[string]any) (*traeToken, error) {
	access := traeFirstString(result, "AccessToken", "accessToken", "Token", "token")
	refresh := traeFirstString(result, "RefreshToken", "refreshToken")
	if access == "" {
		return nil, fmt.Errorf("trae exchange: response carried no access token")
	}
	tok := &traeToken{AccessToken: access, RefreshToken: refresh}
	if v := traeNumber(result, "TokenExpireAt"); v > 0 {
		if v > 1e12 {
			v /= 1000
		}
		tok.ExpiresAtMs = int64(v) * 1000
	} else if d := traeNumber(result, "TokenExpireDuration"); d > 0 {
		tok.ExpiresAtMs = time.Now().Add(time.Duration(d) * time.Second).UnixMilli()
	}
	if v := traeNumber(result, "RefreshExpireAt"); v > 0 {
		if v > 1e12 {
			v /= 1000
		}
		tok.RefreshExpiresAtMs = int64(v) * 1000
	}
	if uid := traeFirstString(result, "UserID", "userId", "uid"); uid != "" {
		tok.UID = uid
	}
	if name := traeFirstString(result, "ScreenName", "screenName", "Nickname"); name != "" {
		tok.Nickname = name
	}
	return tok, nil
}

func (a *traeAuth) fetchUserInfo(ctx context.Context, tok *traeToken) {
	body := map[string]any{"ReqSource": "IDE", "IDEVersion": traeIdeVersion}
	payload, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		traeLegacyHost+"/cloudide/api/v3/trae/GetUserInfo", strings.NewReader(string(payload)))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", traeUA)
	req.Header.Set("X-Cloudide-Token", tok.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	var env map[string]any
	if json.NewDecoder(resp.Body).Decode(&env) != nil {
		return
	}
	result, _ := env["Result"].(map[string]any)
	if result == nil {
		return
	}
	if uid := traeFirstString(result, "UserID", "userId", "uid"); uid != "" {
		tok.UID = uid
	}
	if name := traeFirstString(result, "ScreenName", "screenName", "Nickname"); name != "" {
		tok.Nickname = name
	}
}

// Resolve returns a grant ready to send, refreshing when near expiry.
func (a *traeAuth) Resolve(ctx context.Context) (*traeToken, error) {
	cred, err := a.current()
	if err != nil {
		return nil, err
	}
	if cred == nil {
		return nil, errTraeNotSignedIn
	}
	if !cred.needsRefresh() {
		return cred, nil
	}
	if cred.RefreshToken == "" {
		return cred, nil
	}
	refreshed, err := a.refresh(ctx, cred.RefreshToken)
	if err != nil {
		if cred.ExpiresAtMs == 0 || time.Now().UnixMilli() < cred.ExpiresAtMs {
			return cred, nil
		}
		return nil, fmt.Errorf("trae: refresh failed (%w); re-login required", err)
	}
	if refreshed.UID == "" {
		refreshed.UID = cred.UID
	}
	if refreshed.Nickname == "" {
		refreshed.Nickname = cred.Nickname
	}
	if err := a.save(refreshed); err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.cached = refreshed
	a.mu.Unlock()
	return refreshed, nil
}

var errTraeNotSignedIn = fmt.Errorf("trae: 未登录——请在工作台点「登录 Trae」完成授权")

func (a *traeAuth) current() (*traeToken, error) {
	a.mu.Lock()
	cached := a.cached
	a.mu.Unlock()
	if cached != nil {
		return cached, nil
	}
	raw, err := os.ReadFile(a.tokenPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var cred traeToken
	if json.Unmarshal(raw, &cred) != nil || cred.AccessToken == "" {
		return nil, nil
	}
	a.mu.Lock()
	a.cached = &cred
	a.mu.Unlock()
	return &cred, nil
}

func (a *traeAuth) save(cred *traeToken) error {
	return writePrivateJSON(a.tokenPath(), cred)
}

func (a *traeAuth) signedIn() bool {
	cred, err := a.current()
	return err == nil && cred != nil
}

func (a *traeAuth) Logout() error {
	a.mu.Lock()
	a.cached = nil
	for state := range a.states {
		if st := a.states[state]; st != nil {
			st.listener.Close()
		}
		delete(a.states, state)
	}
	a.mu.Unlock()
	if err := os.Remove(a.tokenPath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// headers builds the Cloud-IDE-JWT header set for a chat/models request.
func (a *traeAuth) headers(tok *traeToken, dev *traeDeviceIdentity, accept string) map[string]string {
	h := map[string]string{
		"Content-Type":         "application/json",
		"Accept":               accept,
		"User-Agent":           traeUA,
		"Authorization":        "Cloud-IDE-JWT " + tok.AccessToken,
		"X-Cloudide-Token":     tok.AccessToken,
		"X-Ide-Token":          tok.AccessToken,
		"X-App-Id":             traeAppID,
		"X-App-Version":        "default",
		"X-Ide-Version":        traeIdeVersion,
		"X-Ide-Version-Code":   traeVersionCode,
		"X-App-Version-Code":   traeVersionCode,
		"X-Ide-Version-Type":   "stable",
		"X-Device-Type":        "windows",
		"X-OS-Version":         traeOSVersion,
		"X-Device-Brand":       traeDeviceBrand,
		"Request-Traffic-Type": "prod",
	}
	if tok.UID != "" {
		h["X-Uid"] = tok.UID
	}
	if dev != nil {
		if dev.MachineID != "" {
			h["X-Machine-Id"] = dev.MachineID
		}
		if dev.DeviceID != "" {
			h["X-Device-Id"] = dev.DeviceID
		}
	}
	return h
}

// traeResolveLoginHost asks GetLoginGuidance for the login host, falling back to
// the default CN host when every candidate fails.
func traeResolveLoginHost(traceID string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	body, _ := json.Marshal(map[string]string{"loginTraceID": traceID, "login_trace_id": traceID})
	candidates := []string{
		"https://api.trae.cn/cloudide/api/v3/trae/GetLoginGuidance",
		"https://api.trae.com.cn/cloudide/api/v3/trae/GetLoginGuidance",
		"https://www.trae.cn/cloudide/api/v3/trae/GetLoginGuidance",
	}
	for _, endpoint := range candidates {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", traeLoginUA)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			continue
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		resp.Body.Close()
		if host := traeExtractLoginHost(raw); host != "" {
			return host
		}
	}
	return "www.trae.cn"
}

func traeExtractLoginHost(raw []byte) string {
	var env map[string]any
	if json.Unmarshal(raw, &env) != nil {
		return ""
	}
	for _, key := range []string{"LoginHost", "loginHost", "LoginURL", "login_url"} {
		if host := traeHostString(env[key]); host != "" {
			return host
		}
	}
	for _, wrap := range []string{"Result", "result", "data"} {
		if m, ok := env[wrap].(map[string]any); ok {
			for _, key := range []string{"LoginHost", "loginHost", "LoginURL", "login_url"} {
				if host := traeHostString(m[key]); host != "" {
					return host
				}
			}
		}
	}
	return ""
}

func traeHostString(v any) string {
	s, _ := v.(string)
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimSuffix(s, "/")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return s
}

func traeFirstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

func traeNumber(m map[string]any, key string) float64 {
	switch v := m[key].(type) {
	case float64:
		return v
	case json.Number:
		f, _ := v.Float64()
		return f
	case string:
		var f float64
		fmt.Sscanf(v, "%f", &f)
		return f
	}
	return 0
}

// writePrivateJSON persists a credential/identity file owner-only.
func writePrivateJSON(path string, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, payload, 0o600)
}
