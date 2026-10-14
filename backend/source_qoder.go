// Qoder CN source.
//
// Two operating modes:
//
//   - Signed in (device authorization, see qoder_auth.go): the real catalog is
//     read from the gateway and chat turns are forwarded with COSY signing.
//   - Signed out: only the model keys Qoder's own history shows it using are
//     reported, and chat refuses with an actionable message pointing at the
//     workbench login button.
//
// Protocol constants and the COSY/encoding algorithm are ported (MIT,
// (c) 2026 Sliverkiss / mmqz — see NOTICE) from mmqz/cpa-multi-plugins
// plugins/qoder.

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/google/uuid"
)

const qoderSourceID = "qoder"

type qoderSource struct {
	auth *qoderAuth
}

func newQoderSource(auth *qoderAuth) *qoderSource { return &qoderSource{auth: auth} }

func (s *qoderSource) ID() string   { return qoderSourceID }
func (s *qoderSource) Name() string { return "Qoder CN" }

// qoderMessageDB is the app's own state database (catalog fallback).
func qoderMessageDB() string {
	if runtime.GOOS != "windows" {
		return ""
	}
	roaming := os.Getenv("APPDATA")
	if roaming == "" {
		return ""
	}
	return filepath.Join(roaming, "com.qodercn.app.stable", "main.sqlite")
}

// qoderLegacyDB is the shared client's local cache (catalog fallback).
func qoderLegacyDB() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".qoder-cn", "shared_client", "cache", "db", "local.db")
}

func (s *qoderSource) Status(ctx context.Context) sourceStatus {
	status := sourceStatus{ID: s.ID(), Name: s.Name()}

	if s.auth.signedIn() {
		status.Installed = true
		status.Callable = true
		status.State = "signed-in"
		status.CredentialPath = s.auth.path
		status.Detail = "已通过设备授权登录，可代理对话。"
		return status
	}

	var existing []string
	for _, candidate := range []string{qoderMessageDB(), qoderLegacyDB()} {
		if candidate != "" {
			if _, err := os.Stat(candidate); err == nil {
				existing = append(existing, candidate)
			}
		}
	}
	if len(existing) == 0 {
		status.State = "not-installed"
		status.Detail = "本机未找到 Qoder CN 的数据目录。"
		return status
	}
	status.Installed = true
	status.CredentialPath = existing[0]
	status.State = "not-signed-in"
	status.Detail = "Qoder CN 不把用户令牌写入磁盘；点工作台「登录 Qoder」完成设备授权后即可代理对话。"
	return status
}

// qoderModelListRow is one entry of the gateway's chat scene.
type qoderModelListRow struct {
	Key            string  `json:"key"`
	DisplayName    string  `json:"display_name"`
	Enable         bool    `json:"enable"`
	IsReasoning    bool    `json:"is_reasoning"`
	IsVL           bool    `json:"is_vl"`
	MaxInputTokens int64   `json:"max_input_tokens"`
	PriceFactor    float64 `json:"price_factor"`
}

// Models returns the live gateway catalog when signed in, otherwise the model
// keys Qoder's own history shows it using.
func (s *qoderSource) Models(ctx context.Context) ([]modelRow, error) {
	if s.auth.signedIn() {
		if rows, err := s.liveModels(ctx); err == nil && len(rows) > 0 {
			return rows, nil
		}
	}
	return s.historyModels()
}

func (s *qoderSource) liveModels(ctx context.Context) ([]modelRow, error) {
	cred, err := s.auth.Resolve(ctx)
	if err != nil {
		return nil, err
	}
	region := cred.Region
	rawURL := qoderGatewayFor(region) + "/algo/api/v2/model/list?Encode=1"
	// The COSY signature covers the request body, so the body signed must be the
	// body sent; model/list accepts an empty JSON object.
	encodedBody := qoderEncode([]byte("{}"))

	session, err := newQoderCosySession(qoderCosyIdentity{
		Name:               cred.Nickname,
		UID:                cred.UID,
		UserType:           qoderUserTypeOr(cred.UserType),
		SecurityOauthToken: cred.AccessToken,
		RefreshToken:       cred.RefreshToken,
	}, cred.MachineID)
	if err != nil {
		return nil, err
	}
	headers, err := session.headers(cred.UID, encodedBody, rawURL, "application/json", false)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, strings.NewReader(encodedBody))
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("qoder model/list: http %d", resp.StatusCode)
	}
	var apiResp map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("qoder model/list parse: %w", err)
	}
	chatRaw, ok := apiResp["chat"]
	if !ok {
		return nil, fmt.Errorf("qoder model/list: no chat scene")
	}
	var models []qoderModelListRow
	if err := json.Unmarshal(chatRaw, &models); err != nil {
		return nil, fmt.Errorf("qoder model/list chat parse: %w", err)
	}
	var out []modelRow
	for _, m := range models {
		if !m.Enable {
			continue
		}
		ctxWindow := int(180000)
		if m.MaxInputTokens > 0 {
			ctxWindow = int(m.MaxInputTokens)
		}
		out = append(out, modelRow{
			ID:             namespaceModel(s.ID(), m.Key),
			RemoteID:       m.Key,
			Source:         s.ID(),
			Name:           m.DisplayName,
			ContextWindow:  ctxWindow,
			MaxTokens:      8192,
			SupportsImages: m.IsVL,
			Vendor:         "qoder",
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("qoder model/list: no enabled chat models")
	}
	return out, nil
}

func qoderUserTypeOr(t string) string {
	if t == "" {
		return "personal_professional_trial"
	}
	return t
}

// modelKeyPattern matches the model keys Qoder records in its session rows.
var modelKeyPattern = regexp.MustCompile(`"(?:model_key|model)"\s*:\s*"([^"]{1,64})"`)

// historyModels reports the model keys Qoder's own history shows it using.
func (s *qoderSource) historyModels() ([]modelRow, error) {
	seen := map[string]struct{}{}

	if path := qoderMessageDB(); path != "" {
		rows, err := querySQLite(path,
			`select model_key from chat_model_preferences where model_key is not null and model_key <> ''`)
		if err == nil {
			for _, row := range rows {
				if len(row) > 0 && row[0] != "" {
					seen[row[0]] = struct{}{}
				}
			}
		}
		if len(seen) == 0 {
			if rows, err := querySQLite(path, `select model from chat_sessions where model is not null and model <> ''`); err == nil {
				for _, row := range rows {
					if len(row) > 0 && row[0] != "" {
						seen[row[0]] = struct{}{}
					}
				}
			}
		}
	}

	if path := qoderLegacyDB(); path != "" {
		if rows, err := querySQLite(path,
			`select distinct model_info from chat_message where model_info is not null and model_info <> ''`); err == nil {
			for _, row := range rows {
				if len(row) == 0 {
					continue
				}
				for _, match := range modelKeyPattern.FindAllStringSubmatch(row[0], -1) {
					seen[match[1]] = struct{}{}
				}
			}
		}
	}

	if len(seen) == 0 {
		return nil, fmt.Errorf("Qoder CN 的模型清单不可读(其目录为加密或尚未写入)")
	}

	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	out := make([]modelRow, 0, len(ids))
	for _, id := range ids {
		out = append(out, modelRow{
			ID:       namespaceModel(s.ID(), id),
			RemoteID: id,
			Source:   s.ID(),
			Name:     id,
		})
	}
	return out, nil
}

// SendChat forwards one chat turn to the gateway with COSY signing, translating
// the gateway's envelope SSE into plain OpenAI SSE frames.
func (s *qoderSource) SendChat(ctx context.Context, remoteModelID string, preparedBody string) (*chatResponse, error) {
	cred, err := s.auth.Resolve(ctx)
	if err != nil {
		if err == errQoderNotSignedIn {
			return refusal("Qoder CN 未登录：请在工作台点「登录 Qoder」，在浏览器完成设备授权后即可代理对话。"), nil
		}
		return nil, err
	}

	body, err := buildQoderChatBody(preparedBody, remoteModelID, cred.UserType)
	if err != nil {
		return nil, err
	}
	encodedBody := qoderEncode(body)
	rawURL := qoderGatewayFor(cred.Region) +
		"/algo/api/v2/service/pro/sse/agent_chat_generation?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1"

	session, err := newQoderCosySession(qoderCosyIdentity{
		Name:               cred.Nickname,
		UID:                cred.UID,
		UserType:           qoderUserTypeOr(cred.UserType),
		SecurityOauthToken: cred.AccessToken,
		RefreshToken:       cred.RefreshToken,
	}, cred.MachineID)
	if err != nil {
		return nil, err
	}
	headers, err := session.headers(cred.UID, encodedBody, rawURL, "text/event-stream", true)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(encodedBody))
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, fmt.Errorf("qoder chat: http %d body=%s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return &chatResponse{
		StatusCode:  resp.StatusCode,
		ContentType: "text/event-stream",
		Body:        newQoderSSETranslator(resp.Body),
	}, nil
}

// buildQoderChatBody renders the gateway's agent_chat_generation body. The
// upstream needs no template system prompt or tools when the client supplies
// its own system message, so a minimal body is sent.
func buildQoderChatBody(preparedBody, modelKey, userType string) ([]byte, error) {
	var req struct {
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal([]byte(preparedBody), &req); err != nil {
		return nil, fmt.Errorf("the chat request body is not valid JSON: %w", err)
	}

	prompt := ""
	var messages []any
	for _, m := range req.Messages {
		role := m.Role
		if role == "developer" {
			role = "system"
		}
		text := qoderMessageText(m.Content)
		if role == "user" && text != "" {
			prompt = text
		}
		messages = append(messages, map[string]any{"role": role, "content": text})
	}
	if prompt == "" {
		return nil, fmt.Errorf("qoder: no user message in request")
	}

	nid := uuid.NewString()
	body := map[string]any{
		"request_id":       nid,
		"chat_record_id":   nid,
		"request_set_id":   uuid.NewString(),
		"session_id":       uuid.NewString(),
		"stream":           true,
		"aliyun_user_type": qoderUserTypeOr(userType),
		"agent_id":         "agent_common",
		"model_config": map[string]any{
			"key":          modelKey,
			"is_reasoning": true,
			"source":       "system",
		},
		"chat_context": map[string]any{
			"text": map[string]any{"text": prompt},
			"extra": map[string]any{
				"originalContent": map[string]any{"text": prompt},
				"modelConfig":     map[string]any{"key": modelKey, "is_reasoning": true},
			},
		},
		"messages": messages,
	}
	return json.Marshal(body)
}

// qoderMessageText flattens a message content (string or parts array) to text.
func qoderMessageText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &parts); err != nil {
		return ""
	}
	var sb strings.Builder
	for _, p := range parts {
		if p.Type == "text" {
			sb.WriteString(p.Text)
		}
	}
	return sb.String()
}

// qoderSSETranslator unwraps the gateway's nested envelope SSE
// (data:{"body":"<inner openai chunk>","statusCodeValue":N}) into plain OpenAI
// SSE frames as it streams, so DBX sees a standard chunk stream.
type qoderSSETranslator struct {
	pr     *io.PipeReader
	cancel context.CancelFunc
	once   sync.Once
}

func newQoderSSETranslator(upstream io.ReadCloser) *qoderSSETranslator {
	ctx, cancel := context.WithCancel(context.Background())
	pr, pw := io.Pipe()
	t := &qoderSSETranslator{pr: pr, cancel: cancel}

	go func() {
		defer upstream.Close()
		defer pw.Close()
		scanner := bufio.NewScanner(upstream)
		scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
		for scanner.Scan() {
			if ctx.Err() != nil {
				return
			}
			line := strings.TrimSpace(scanner.Text())
			if line == "event:error" || line == "event: error" {
				pw.Write([]byte("data: {\"error\":{\"message\":\"qoder upstream error event\"}}\n\n"))
				return
			}
			if !strings.HasPrefix(line, "data:") {
				continue
			}
			payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			var outer struct {
				Body   json.RawMessage `json:"body"`
				Status int             `json:"statusCodeValue"`
			}
			if json.Unmarshal([]byte(payload), &outer) != nil {
				continue
			}
			body := payload
			if len(outer.Body) > 0 {
				inner := string(outer.Body)
				var unquoted string
				if json.Unmarshal(outer.Body, &unquoted) == nil {
					body = unquoted
				} else {
					body = inner
				}
			}
			if strings.TrimSpace(body) == "[DONE]" {
				pw.Write([]byte("data: [DONE]\n\n"))
				return
			}
			var probe struct {
				Error   json.RawMessage `json:"error"`
				Choices json.RawMessage `json:"choices"`
				Usage   json.RawMessage `json:"usage"`
			}
			if json.Unmarshal([]byte(body), &probe) != nil {
				continue
			}
			if outer.Status >= 400 || (len(probe.Error) > 0 && string(probe.Error) != "null") {
				pw.Write([]byte("data: " + body + "\n\n"))
				return
			}
			// Bare gateway timing metadata carries neither choices nor usage.
			if len(probe.Choices) == 0 && len(probe.Usage) == 0 {
				continue
			}
			if _, err := pw.Write([]byte("data: " + body + "\n\n")); err != nil {
				return
			}
		}
	}()
	return t
}

func (t *qoderSSETranslator) Read(p []byte) (int, error) { return t.pr.Read(p) }

func (t *qoderSSETranslator) Close() error {
	t.once.Do(func() {
		t.cancel()
		t.pr.Close()
	})
	return nil
}

// describeQoderBlockers is used by the workbench diagnostics panel.
func describeQoderBlockers() string {
	parts := []string{"用户令牌不落盘，需走设备授权登录"}
	parts = append(parts, "推理网关需 COSY 签名")
	return strings.Join(parts, "; ")
}
