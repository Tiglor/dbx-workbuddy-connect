// Credential store: reads the WorkBuddy desktop sign-in, opens the at-rest
// envelope when present, and refreshes the session on demand.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// refreshMargin is how long before expiry a token is refreshed.
const refreshMargin = 5 * time.Minute

// credential is the usable sign-in state.
type credential struct {
	AccessToken        string `json:"accessToken"`
	RefreshToken       string `json:"refreshToken"`
	ExpiresAtMs        int64  `json:"expiresAtMs"`
	RefreshExpiresAtMs int64  `json:"refreshExpiresAtMs"`
	Domain             string `json:"domain"`
	UID                string `json:"uid"`
	EnterpriseID       string `json:"enterpriseId"`
	Source             string `json:"source"`
}

func (c credential) expired() bool {
	if c.ExpiresAtMs == 0 {
		return false
	}
	return time.Now().UnixMilli() > c.ExpiresAtMs
}

func (c credential) needsRefresh() bool {
	if c.ExpiresAtMs == 0 {
		return false
	}
	return time.Now().UnixMilli() > c.ExpiresAtMs-int64(refreshMargin/time.Millisecond)
}

// authStatus is the read-only sign-in summary surfaced to the UI.
type authStatus struct {
	State              string `json:"state"`
	Reason             string `json:"reason,omitempty"`
	ReasonCode         string `json:"reasonCode,omitempty"`
	ExpiresAtMs        int64  `json:"expiresAtMs,omitempty"`
	RefreshExpiresAtMs int64  `json:"refreshExpiresAtMs,omitempty"`
	Domain             string `json:"domain,omitempty"`
	Source             string `json:"source,omitempty"`
	UID                string `json:"uid,omitempty"`
	DesktopAuthPath    string `json:"desktopAuthPath,omitempty"`
	AuthFormat         string `json:"authFormat,omitempty"`
}

// credentialStore owns credential reads and the single-flight refresh.
type credentialStore struct {
	client   *upstreamClient
	ownPath  string
	mu       sync.Mutex
	inflight *refreshCall
	cached   *credential

	// atRest caches the opened protector key. Obtaining it means launching the
	// WorkBuddy binary, which costs several seconds, so it must happen at most
	// once per process — the same caching the reference implementation does.
	atRest      []byte
	atRestKeyID string
}

type refreshCall struct {
	done chan struct{}
	cred *credential
	err  error
}

func newCredentialStore(client *upstreamClient, dataDir string) *credentialStore {
	return &credentialStore{
		client:  client,
		ownPath: filepath.Join(dataDir, "credential.json"),
	}
}

// resolvedDesktopAuthPath reports which candidate file actually answers.
func (s *credentialStore) resolvedDesktopAuthPath() (string, string, error) {
	var firstErr error
	for _, candidate := range desktopAuthCandidates() {
		raw, err := os.ReadFile(candidate)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			if firstErr == nil {
				firstErr = fmt.Errorf("cannot read %s: %w", candidate, err)
			}
			continue
		}
		text := string(raw)
		if trimSpace(text) == "" {
			continue
		}
		classification := classifyDesktopAuthDocument(text)
		return candidate, classification.format, nil
	}
	if firstErr != nil {
		return "", "", firstErr
	}
	return "", "absent", nil
}

// current reads the freshest credential without refreshing.
//
// The in-memory credential is reused while it is still valid for long enough:
// re-opening the envelope would re-verify the at-rest key, and that check can
// only be satisfied by launching the WorkBuddy binary. When the file changes —
// a fresh sign-in — the cached token is replaced on the next read.
func (s *credentialStore) current(ctx context.Context) (*credential, error) {
	if cached := s.usableCached(); cached != nil {
		return cached, nil
	}
	path, format, err := s.resolvedDesktopAuthPath()
	if err != nil {
		return nil, err
	}
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		switch format {
		case "plaintext":
			cred, err := parsePlaintextCredential(string(raw), "desktop")
			if err != nil {
				return nil, err
			}
			return s.remember(cred), nil
		case "encrypted":
			cred, err := s.openEncrypted(ctx, string(raw))
			if err != nil {
				return nil, err
			}
			return s.remember(cred), nil
		default:
			return nil, fmt.Errorf("the desktop auth file at %s exists but is unreadable (neither a plaintext credential nor a decodable WorkBuddy 5.6 envelope)", path)
		}
	}
	// Fall back to the plugin-owned copy from an earlier refresh.
	if own, err := s.readOwn(); err == nil && own != nil {
		return own, nil
	}
	return nil, nil
}

// usableCached returns the memoised credential while it is comfortably valid.
func (s *credentialStore) usableCached() *credential {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cached == nil {
		return nil
	}
	// Refresh margin doubles as the reuse window: never hand out a token that
	// is inside the refresh window, or a caller could start work with one that
	// expires mid-flight.
	if s.cached.needsRefresh() {
		return nil
	}
	return s.cached
}

// remember stores a freshly read credential for reuse.
func (s *credentialStore) remember(cred *credential) *credential {
	if cred == nil {
		return nil
	}
	s.mu.Lock()
	s.cached = cred
	s.mu.Unlock()
	return cred
}

// resolve returns a credential ready to send upstream, refreshing if needed.
func (s *credentialStore) resolve(ctx context.Context) (*credential, error) {
	cred, err := s.current(ctx)
	if err != nil {
		return nil, err
	}
	if cred == nil {
		return nil, errors.New("no signed-in WorkBuddy account was found; sign in once in the WorkBuddy desktop app")
	}
	if !cred.needsRefresh() {
		return cred, nil
	}
	return s.refreshSingleFlight(ctx, cred)
}

// refreshSingleFlight collapses concurrent refreshes into one upstream call.
func (s *credentialStore) refreshSingleFlight(ctx context.Context, cred *credential) (*credential, error) {
	s.mu.Lock()
	if s.inflight != nil {
		call := s.inflight
		s.mu.Unlock()
		select {
		case <-call.done:
			if call.err != nil {
				// A failed refresh still returns a usable unexpired token.
				if !cred.expired() {
					return cred, nil
				}
				return nil, call.err
			}
			return call.cred, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	call := &refreshCall{done: make(chan struct{})}
	s.inflight = call
	s.mu.Unlock()

	refreshed, err := s.client.refreshToken(ctx, cred)

	s.mu.Lock()
	s.inflight = nil
	s.mu.Unlock()

	if err != nil {
		call.err = err
		close(call.done)
		if !cred.expired() {
			return cred, nil
		}
		return nil, err
	}
	call.cred = refreshed
	close(call.done)
	_ = s.saveOwn(refreshed)
	// Publish the refreshed credential so the reuse path sees it immediately.
	s.mu.Lock()
	s.cached = refreshed
	s.mu.Unlock()
	return refreshed, nil
}

// protectorKey returns the at-rest key, launching the WorkBuddy binary only the
// first time.
//
// The reference implementation caches this for the same reason: the spawn costs
// seconds, and reading the credential happens on every catalog refresh. Without
// the cache the workbench re-launched WorkBuddy on every panel load.
func (s *credentialStore) protectorKey(ctx context.Context, envelopeKeyIDs []string) ([]byte, error) {
	s.mu.Lock()
	if s.atRest != nil && containsString(envelopeKeyIDs, s.atRestKeyID) {
		key := s.atRest
		s.mu.Unlock()
		return key, nil
	}
	s.mu.Unlock()

	secret, err := fetchAtRestSecretKey(ctx)
	if err != nil {
		return nil, err
	}
	key := deriveProtectorKey(secret)
	keyID := keyIDForKey(key)

	s.mu.Lock()
	s.atRest, s.atRestKeyID = key, keyID
	s.mu.Unlock()
	return key, nil
}

// openEncrypted decrypts a 5.6 envelope document into the credential shape.
func (s *credentialStore) openEncrypted(ctx context.Context, text string) (*credential, error) {
	classification := classifyDesktopAuthDocument(text)
	if classification.format != "encrypted" {
		return nil, fmt.Errorf("desktop auth document is %s, not encrypted", classification.format)
	}
	key, err := s.protectorKey(ctx, classification.keyIDs)
	if err != nil {
		return nil, err
	}
	if got := keyIDForKey(key); !containsString(classification.keyIDs, got) {
		return nil, fmt.Errorf("WorkBuddy's current at-rest key (id %s) does not match the credential's envelope (id %s); the desktop credential was sealed by a different WorkBuddy installation",
			got, strings.Join(classification.keyIDs, " or "))
	}
	opened := make(map[string]string, len(classification.fields))
	for _, field := range classification.fields {
		plaintext, err := openAuthField(key, field)
		if err != nil {
			return nil, err
		}
		opened[field.Field] = plaintext
	}
	return credentialFromDocument(text, opened, "desktop")
}

// credentialFromDocument builds a credential from either the plaintext fields
// or the decrypted field values.
func credentialFromDocument(text string, opened map[string]string, source string) (*credential, error) {
	return parseDocument(text, opened, source)
}

func parsePlaintextCredential(text string, source string) (*credential, error) {
	return parseDocument(text, nil, source)
}

// parseDocument reads the document's non-secret fields and merges the token
// values, which are either inline strings (legacy) or decrypted (5.6).
func parseDocument(text string, opened map[string]string, source string) (*credential, error) {
	var doc map[string]any
	if err := json.Unmarshal([]byte(text), &doc); err != nil {
		return nil, fmt.Errorf("desktop auth document is not JSON: %w", err)
	}
	auth := doc
	if nested, ok := doc["auth"].(map[string]any); ok {
		auth = nested
	}

	value := func(field string) string {
		if opened != nil {
			if v, ok := opened[field]; ok {
				return v
			}
		}
		if v, ok := auth[field].(string); ok {
			return v
		}
		return ""
	}

	cred := &credential{
		AccessToken:  value("accessToken"),
		RefreshToken: value("refreshToken"),
		Domain:       stringField(auth, "domain"),
		Source:       source,
	}
	cred.ExpiresAtMs = timeFieldMs(auth, "expiresAt")
	cred.RefreshExpiresAtMs = timeFieldMs(auth, "refreshExpiresAt")

	// expiresIn/refreshExpiresIn are seconds-until when absolute times are absent.
	if cred.ExpiresAtMs == 0 {
		if secs := numberField(auth, "expiresIn"); secs > 0 {
			cred.ExpiresAtMs = time.Now().UnixMilli() + int64(secs)*1000
		}
	}
	if cred.RefreshExpiresAtMs == 0 {
		if secs := numberField(auth, "refreshExpiresIn"); secs > 0 {
			cred.RefreshExpiresAtMs = time.Now().UnixMilli() + int64(secs)*1000
		}
	}
	if cred.Domain == "" {
		cred.Domain = "www.workbuddy.cn"
	}
	cred.UID = accountUID(doc, auth)
	cred.EnterpriseID = accountEnterpriseID(doc, auth)

	if cred.AccessToken == "" {
		return nil, errors.New("the WorkBuddy sign-in document carries no access token")
	}
	return cred, nil
}

// accountUID finds the account identity, which lives outside `auth`.
func accountUID(doc, auth map[string]any) string {
	for _, source := range []map[string]any{doc, auth} {
		if account, ok := source["account"].(map[string]any); ok {
			if uid := stringField(account, "uid"); uid != "" {
				return uid
			}
		}
	}
	return ""
}

// accountEnterpriseID reads the enterprise/tenant id, when the account has one.
func accountEnterpriseID(doc, auth map[string]any) string {
	for _, source := range []map[string]any{doc, auth} {
		if account, ok := source["account"].(map[string]any); ok {
			for _, key := range []string{"enterpriseId", "enterprise_id", "tenantId"} {
				if value := stringField(account, key); value != "" {
					return value
				}
			}
		}
		if value := stringField(source, "enterpriseId"); value != "" {
			return value
		}
	}
	return ""
}

func stringField(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func numberField(m map[string]any, key string) float64 {
	switch v := m[key].(type) {
	case float64:
		return v
	case json.Number:
		f, _ := v.Float64()
		return f
	}
	return 0
}

// timeFieldMs accepts either epoch milliseconds or an ISO-8601 string.
func timeFieldMs(m map[string]any, key string) int64 {
	switch v := m[key].(type) {
	case float64:
		return normalizeEpochMs(int64(v))
	case json.Number:
		f, _ := v.Int64()
		return normalizeEpochMs(f)
	case string:
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t.UnixMilli()
		}
	}
	return 0
}

// normalizeEpochMs accepts seconds or milliseconds.
func normalizeEpochMs(v int64) int64 {
	if v > 0 && v < 1e11 {
		return v * 1000
	}
	return v
}

func (s *credentialStore) readOwn() (*credential, error) {
	raw, err := os.ReadFile(s.ownPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var cred credential
	if err := json.Unmarshal(raw, &cred); err != nil {
		return nil, nil
	}
	if cred.AccessToken == "" {
		return nil, nil
	}
	return &cred, nil
}

func (s *credentialStore) saveOwn(cred *credential) error {
	payload, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.ownPath), 0o700); err != nil {
		return err
	}
	// Owner-only: this file holds a live bearer token.
	return os.WriteFile(s.ownPath, payload, 0o600)
}

func (s *credentialStore) status(ctx context.Context) authStatus {
	path, format, err := s.resolvedDesktopAuthPath()
	status := authStatus{DesktopAuthPath: path, AuthFormat: format, State: "signed-out"}
	if err != nil {
		status.Reason = err.Error()
		status.ReasonCode = "credentials-unreadable"
		return status
	}
	if path == "" {
		status.Reason = "no WorkBuddy sign-in file was found; sign in once in the WorkBuddy desktop app"
		status.ReasonCode = "auth-file-absent"
		return status
	}
	cred, err := s.current(ctx)
	if err != nil {
		status.Reason = err.Error()
		status.ReasonCode = "credentials-unreadable"
		return status
	}
	if cred == nil {
		status.Reason = "no usable credential in the WorkBuddy sign-in file"
		status.ReasonCode = "credentials-empty"
		return status
	}
	status.State = "signed-in"
	status.ExpiresAtMs = cred.ExpiresAtMs
	status.RefreshExpiresAtMs = cred.RefreshExpiresAtMs
	status.Domain = cred.Domain
	status.Source = cred.Source
	status.UID = cred.UID
	return status
}

func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
