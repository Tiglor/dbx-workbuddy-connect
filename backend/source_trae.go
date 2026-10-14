// Trae CN source.
//
// Two operating modes:
//
//   - Signed in (OAuth via a loopback listener, see trae_auth.go): the catalog
//     is read from the agent host and chat turns are forwarded with the
//     Cloud-IDE-JWT header set, translating Trae's event-stream into OpenAI SSE.
//   - Signed out: the model list Trae caches on disk is reported for display,
//     and chat refuses with an actionable message pointing at the login button.
//
// Protocol constants ported (MIT, (c) 2026 Sliverkiss / mmqz — see NOTICE) from
// mmqz/cpa-multi-plugins plugins/trae.

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
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const traeSourceID = "trae"

type traeSource struct {
	auth *traeAuth
}

func newTraeSource(auth *traeAuth) *traeSource { return &traeSource{auth: auth} }

func (s *traeSource) ID() string   { return traeSourceID }
func (s *traeSource) Name() string { return "Trae CN" }

// traeStateDB is the VSCode-compatible global storage (catalog fallback).
func traeStateDB() string {
	if runtime.GOOS != "windows" {
		return ""
	}
	roaming := os.Getenv("APPDATA")
	if roaming == "" {
		return ""
	}
	return filepath.Join(roaming, "Trae CN", "User", "globalStorage", "state.vscdb")
}

// traeModelListKeySuffix identifies the model-list row; the full key carries a
// per-user id prefix that changes between machines.
const traeModelListKeySuffix = "_AI.agent.model.model_list_map"

// envTraeAppPath lets a user point at a non-standard install, mirroring the
// WorkBuddy source's WORKBUDDY_ELECTRON_BIN convention.
const envTraeAppPath = "TRAE_APP_PATH"

func traeAppPath() string {
	if runtime.GOOS != "windows" {
		return ""
	}
	// An explicit path is authoritative and never falls back.
	if explicit := os.Getenv(envTraeAppPath); explicit != "" {
		if _, err := os.Stat(explicit); err == nil {
			return explicit
		}
	}
	// Standard install locations, in probe order.
	var candidates []string
	if local := os.Getenv("LOCALAPPDATA"); local != "" {
		candidates = append(candidates, filepath.Join(local, "Programs", "Trae CN", "Trae CN.exe"))
	}
	if pf := os.Getenv("ProgramFiles"); pf != "" {
		candidates = append(candidates, filepath.Join(pf, "Trae CN", "Trae CN.exe"))
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

func (s *traeSource) Status(ctx context.Context) sourceStatus {
	status := sourceStatus{ID: s.ID(), Name: s.Name()}

	if s.auth.signedIn() {
		status.Installed = true
		status.Callable = true
		status.State = "signed-in"
		status.CredentialPath = s.auth.tokenPath()
		status.Detail = "已通过 OAuth 登录，可代理对话。"
		if app := traeAppPath(); app != "" {
			status.AppPath = app
		}
		return status
	}

	path := traeStateDB()
	if path == "" {
		status.State = "not-signed-in"
		status.Detail = "点工作台「登录 Trae」完成授权后即可代理对话。"
		return status
	}
	if _, err := os.Stat(path); err != nil {
		status.State = "not-signed-in"
		status.Detail = "本机未找到 Trae CN 数据目录；仍可点「登录 Trae」授权后代理对话。"
		return status
	}
	status.Installed = true
	status.CredentialPath = path
	if app := traeAppPath(); app != "" {
		status.AppPath = app
	}
	status.State = "not-signed-in"
	status.Detail = "Trae CN 不把令牌写入磁盘；点工作台「登录 Trae」完成授权后即可代理对话（未登录时仅显示磁盘缓存的模型清单）。"
	return status
}

// Models returns the live catalog when signed in, otherwise Trae's cached list.
func (s *traeSource) Models(ctx context.Context) ([]modelRow, error) {
	if s.auth.signedIn() {
		if rows, err := s.liveModels(ctx); err == nil && len(rows) > 0 {
			return rows, nil
		}
	}
	return s.cachedModels()
}

// traeConfigEntry is one row of get_detail_param's config_info_list.
type traeConfigEntry struct {
	ConfigName       string `json:"config_name"`
	ConfigSwitch     bool   `json:"config_switch"`
	InvisibleToUser  bool   `json:"is_invisible_to_user"`
	ContextWindowTok struct {
		Dev int `json:"dev"`
	} `json:"context_window_tokens"`
	DisplayConfig struct {
		DisplayName string `json:"display_name"`
	} `json:"display_config"`
}

// traeDeadModels are ids the reference implementation filters out as unusable.
var traeDeadModels = map[string]struct{}{
	"agnes-2.0-flash": {}, "agnes-agent-x": {},
	"deepseek-v4-flash": {}, "deepseek-v4-pro": {},
	"auto": {}, "work": {},
}

func (s *traeSource) liveModels(ctx context.Context) ([]modelRow, error) {
	tok, err := s.auth.Resolve(ctx)
	if err != nil {
		return nil, err
	}
	dev, _ := s.auth.device()
	body := `{"function":"solo_work_lite","config_names":null,"need_prompt":false,"current_config_info":null,"poly_prompt":true,"mode_type":null,"agent_type":null}`
	rawURL := traeAgentHost + "/api/ide/v1/get_detail_param"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, v := range s.auth.headers(tok, dev, "application/json") {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("trae get_detail_param: http %d", resp.StatusCode)
	}
	var doc struct {
		ConfigInfoList []traeConfigEntry `json:"config_info_list"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("trae get_detail_param parse: %w", err)
	}
	var out []modelRow
	for _, c := range doc.ConfigInfoList {
		name := c.ConfigName
		display := c.DisplayConfig.DisplayName
		if name == "" || display == "" || !c.ConfigSwitch || c.InvisibleToUser {
			continue
		}
		if _, dead := traeDeadModels[strings.ToLower(name)]; dead {
			continue
		}
		out = append(out, modelRow{
			ID:            namespaceModel(s.ID(), name),
			RemoteID:      name,
			Source:        s.ID(),
			Name:          display,
			ContextWindow: c.ContextWindowTok.Dev,
			Vendor:        "trae",
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("trae get_detail_param: no usable models")
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// traeModelEntry is one row of the cached model list (fallback catalog).
type traeModelEntry struct {
	Name          string   `json:"name"`
	DisplayName   string   `json:"display_name"`
	Multimodal    bool     `json:"multimodal"`
	IsDefault     bool     `json:"is_default"`
	IsNew         bool     `json:"is_new"`
	IsBeta        bool     `json:"is_beta"`
	PromptMax     flexSize `json:"prompt_max_tokens"`
	ModelType     string   `json:"model_type"`
	ContextWindow struct {
		Max     flexSize `json:"max"`
		Default flexSize `json:"default"`
	} `json:"context_window_size"`
}

// flexSize is a size that may arrive as a number, a numeric string, an array of
// those, or null. The largest value seen wins.
type flexSize struct {
	value int
	set   bool
}

func (s *flexSize) UnmarshalJSON(raw []byte) error {
	text := trimSpace(string(raw))
	if text == "" || text == "null" {
		return nil
	}
	if strings.HasPrefix(text, "[") {
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil
		}
		for _, item := range items {
			var nested flexSize
			if err := nested.UnmarshalJSON(item); err == nil && nested.set && nested.value > s.value {
				s.value, s.set = nested.value, true
			}
		}
		return nil
	}
	number, err := strconv.ParseFloat(strings.Trim(text, `"`), 64)
	if err != nil {
		return nil
	}
	s.value, s.set = int(number), true
	return nil
}

func (s flexSize) Int() int {
	if !s.set {
		return 0
	}
	return s.value
}

func readTraeModelList() (map[string][]traeModelEntry, error) {
	path := traeStateDB()
	if path == "" {
		return nil, fmt.Errorf("state store path is unknown on this platform")
	}
	rows, err := querySQLite(path,
		`select value from ItemTable where key like ?`, "%"+traeModelListKeySuffix)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 || len(rows[0]) == 0 {
		return nil, fmt.Errorf("the model list row is absent")
	}
	var doc map[string][]traeModelEntry
	if err := json.Unmarshal([]byte(rows[0][0]), &doc); err != nil {
		return nil, fmt.Errorf("the model list is not readable: %w", err)
	}
	return doc, nil
}

// cachedModels reports Trae's on-disk model list, grouped by agent family.
func (s *traeSource) cachedModels() ([]modelRow, error) {
	doc, err := readTraeModelList()
	if err != nil {
		return nil, err
	}

	type entry struct {
		model  traeModelEntry
		groups map[string]struct{}
	}
	byName := map[string]*entry{}
	for group, models := range doc {
		for _, model := range models {
			if model.Name == "" {
				continue
			}
			existing, ok := byName[model.Name]
			if !ok {
				existing = &entry{model: model, groups: map[string]struct{}{}}
				byName[model.Name] = existing
			}
			existing.groups[group] = struct{}{}
			if existing.model.DisplayName == "" && model.DisplayName != "" {
				existing.model.DisplayName = model.DisplayName
			}
			if model.ContextWindow.Max.Int() > existing.model.ContextWindow.Max.Int() {
				existing.model.ContextWindow = model.ContextWindow
			}
			existing.model.Multimodal = existing.model.Multimodal || model.Multimodal
		}
	}
	if len(byName) == 0 {
		return nil, fmt.Errorf("Trae 的模型清单为空")
	}

	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]modelRow, 0, len(names))
	for _, name := range names {
		item := byName[name]
		groups := make([]string, 0, len(item.groups))
		for group := range item.groups {
			groups = append(groups, group)
		}
		sort.Strings(groups)

		row := modelRow{
			ID:             namespaceModel(s.ID(), name),
			RemoteID:       name,
			Source:         s.ID(),
			Name:           firstNonEmpty(item.model.DisplayName, name),
			SupportsImages: item.model.Multimodal,
			Vendor:         strings.Join(groups, ","),
		}
		if item.model.ContextWindow.Max.Int() > 0 {
			row.ContextWindow = item.model.ContextWindow.Max.Int()
		} else if item.model.ContextWindow.Default.Int() > 0 {
			row.ContextWindow = item.model.ContextWindow.Default.Int()
		}
		row.MaxTokens = item.model.PromptMax.Int()
		out = append(out, row)
	}
	return out, nil
}

// SendChat forwards one chat turn to the agent host, translating Trae's
// event-stream into plain OpenAI SSE frames.
func (s *traeSource) SendChat(ctx context.Context, remoteModelID string, preparedBody string) (*chatResponse, error) {
	tok, err := s.auth.Resolve(ctx)
	if err != nil {
		if err == errTraeNotSignedIn {
			return refusal("Trae CN 未登录：请在工作台点「登录 Trae」，在浏览器完成授权后即可代理对话。"), nil
		}
		return nil, err
	}
	dev, _ := s.auth.device()

	body, err := buildTraeChatBody(preparedBody, remoteModelID)
	if err != nil {
		return nil, err
	}
	rawURL := traeAgentHost + "/api/agent/v3/llm_utils_chat"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, v := range s.auth.headers(tok, dev, "text/event-stream") {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, fmt.Errorf("trae chat: http %d body=%s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return &chatResponse{
		StatusCode:  resp.StatusCode,
		ContentType: "text/event-stream",
		Body:        newTraeSSETranslator(resp.Body, remoteModelID),
	}, nil
}

// buildTraeChatBody rewrites an OpenAI chat body into llm_utils_chat's shape.
func buildTraeChatBody(preparedBody, model string) (string, error) {
	var req struct {
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
		Stream       bool            `json:"stream"`
		Temperature  *float64        `json:"temperature"`
		TopP         *float64        `json:"top_p"`
		MaxTokens    *int            `json:"max_tokens"`
		ReasonEffort string          `json:"reasoning_effort"`
		Stop         json.RawMessage `json:"stop"`
		Tools        json.RawMessage `json:"tools"`
		ToolChoice   json.RawMessage `json:"tool_choice"`
		Extras       map[string]any  `json:"-"`
	}
	if err := json.Unmarshal([]byte(preparedBody), &req); err != nil {
		return "", fmt.Errorf("the chat request body is not valid JSON: %w", err)
	}

	messages := make([]any, 0, len(req.Messages))
	for _, m := range req.Messages {
		role := m.Role
		if role == "developer" {
			role = "system"
		}
		messages = append(messages, map[string]any{
			"role":    role,
			"content": traeNormalizeContent(m.Content),
		})
	}

	out := map[string]any{
		"messages":    messages,
		"function":    "solo_work_lite",
		"stream":      true,
		"config_name": model,
		"model":       model,
	}
	if req.Temperature != nil {
		out["temperature"] = *req.Temperature
	}
	if req.TopP != nil {
		out["top_p"] = *req.TopP
	}
	if req.MaxTokens != nil && *req.MaxTokens > 0 {
		out["max_tokens"] = *req.MaxTokens
	} else {
		out["max_tokens"] = 1000000
	}
	switch strings.ToLower(strings.TrimSpace(req.ReasonEffort)) {
	case "", "auto", "none", "off":
	default:
		out["reasoning_effort"] = req.ReasonEffort
	}
	if len(req.Stop) > 0 && string(req.Stop) != "null" {
		out["stop"] = json.RawMessage(req.Stop)
	}
	if len(req.Tools) > 0 && string(req.Tools) != "null" {
		out["tools"] = traeNormalizeTools(req.Tools)
		if len(req.ToolChoice) > 0 && string(req.ToolChoice) != "null" {
			if tc := traeNormalizeToolChoice(req.ToolChoice); tc != nil {
				out["tool_choice"] = tc
			}
		}
	}

	payload, err := json.Marshal(out)
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

// traeNormalizeContent turns a string content into the parts array the gateway
// expects, passing an existing array through unchanged.
func traeNormalizeContent(raw json.RawMessage) any {
	if len(raw) == 0 {
		return []any{}
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return []any{map[string]any{"type": "text", "text": s}}
	}
	var parts []any
	if err := json.Unmarshal(raw, &parts); err == nil {
		return parts
	}
	return []any{}
}

// traeNormalizeTools stringifies each tool's parameters object, which the
// gateway's Go struct expects as a JSON string.
func traeNormalizeTools(raw json.RawMessage) any {
	var tools []map[string]any
	if json.Unmarshal(raw, &tools) != nil {
		return json.RawMessage(raw)
	}
	for _, tool := range tools {
		fn, ok := tool["function"].(map[string]any)
		if !ok {
			continue
		}
		if params, ok := fn["parameters"]; ok {
			if b, err := json.Marshal(params); err == nil {
				fn["parameters"] = string(b)
			}
		}
	}
	return tools
}

// traeNormalizeToolChoice collapses the OpenAI tool_choice shapes to what the
// gateway accepts (a bare string, or omitted for none).
func traeNormalizeToolChoice(raw json.RawMessage) any {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if s == "none" {
			return nil
		}
		return s
	}
	var obj struct {
		Type     string `json:"type"`
		Function struct {
			Name string `json:"name"`
		} `json:"function"`
	}
	if json.Unmarshal(raw, &obj) == nil {
		switch obj.Type {
		case "none":
			return nil
		case "function":
			if obj.Function.Name != "" {
				return obj.Function.Name
			}
		case "auto", "required":
			return obj.Type
		}
	}
	return nil
}

// traeSSETranslator converts Trae's event-stream (event:output / token_usage /
// done / error) into plain OpenAI SSE chunks as it streams.
type traeSSETranslator struct {
	pr     *io.PipeReader
	cancel context.CancelFunc
	once   sync.Once
}

func newTraeSSETranslator(upstream io.ReadCloser, model string) *traeSSETranslator {
	ctx, cancel := context.WithCancel(context.Background())
	pr, pw := io.Pipe()
	t := &traeSSETranslator{pr: pr, cancel: cancel}

	go func() {
		defer upstream.Close()
		defer pw.Close()

		id := fmt.Sprintf("chatcmpl-%d", time.Now().UnixNano())
		created := time.Now().Unix()
		writeChunk := func(delta map[string]any, finish any) {
			chunk := map[string]any{
				"id":      id,
				"object":  "chat.completion.chunk",
				"created": created,
				"model":   model,
				"choices": []any{map[string]any{
					"index":         0,
					"delta":         delta,
					"finish_reason": finish,
				}},
			}
			b, _ := json.Marshal(chunk)
			pw.Write([]byte("data: " + string(b) + "\n\n"))
		}

		writeChunk(map[string]any{"role": "assistant"}, nil)

		scanner := bufio.NewScanner(upstream)
		scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
		var event string
		var data strings.Builder
		var usage map[string]any
		flush := func() {
			name := event
			payload := data.String()
			event = ""
			data.Reset()
			if payload == "" {
				return
			}
			switch name {
			case "output":
				var o struct {
					Response         string           `json:"response"`
					ReasoningContent string           `json:"reasoning_content"`
					ToolCalls        []map[string]any `json:"tool_calls"`
				}
				if json.Unmarshal([]byte(payload), &o) != nil {
					return
				}
				delta := map[string]any{}
				if o.Response != "" {
					delta["content"] = o.Response
				}
				if o.ReasoningContent != "" {
					delta["reasoning_content"] = o.ReasoningContent
				}
				if len(o.ToolCalls) > 0 {
					delta["tool_calls"] = o.ToolCalls
				}
				if len(delta) > 0 {
					writeChunk(delta, nil)
				}
			case "token_usage":
				var u map[string]any
				if json.Unmarshal([]byte(payload), &u) == nil {
					usage = u
				}
			case "done":
				var d struct {
					FinishReason string `json:"finish_reason"`
				}
				_ = json.Unmarshal([]byte(payload), &d)
				reason := d.FinishReason
				if reason == "" {
					reason = "stop"
				}
				writeChunk(map[string]any{}, reason)
				if usage != nil {
					writeUsageChunk(pw, id, created, model, usage)
				}
				pw.Write([]byte("data: [DONE]\n\n"))
			case "error":
				pw.Write([]byte("data: " + payload + "\n\n"))
				pw.Write([]byte("data: [DONE]\n\n"))
			}
		}

		for scanner.Scan() {
			if ctx.Err() != nil {
				return
			}
			line := scanner.Text()
			if line == "" {
				flush()
				continue
			}
			if strings.HasPrefix(line, ":") {
				continue
			}
			if strings.HasPrefix(line, "event:") {
				event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
				continue
			}
			if strings.HasPrefix(line, "data:") {
				if data.Len() > 0 {
					data.WriteString("\n")
				}
				data.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
				continue
			}
		}
		// Upstream may end without a blank line; flush any trailing event.
		flush()
		// Always terminate the OpenAI stream even if `done` never arrived.
		if usage != nil {
			writeUsageChunk(pw, id, created, model, usage)
		}
		pw.Write([]byte("data: [DONE]\n\n"))
	}()
	return t
}

func writeUsageChunk(pw *io.PipeWriter, id string, created int64, model string, usage map[string]any) {
	prompt, _ := usage["prompt_tokens"].(float64)
	completion, _ := usage["completion_tokens"].(float64)
	total, ok := usage["total_tokens"].(float64)
	if !ok || total == 0 {
		total = prompt + completion
	}
	chunk := map[string]any{
		"id":      id,
		"object":  "chat.completion.chunk",
		"created": created,
		"model":   model,
		"choices": []any{},
		"usage": map[string]any{
			"prompt_tokens":     int(prompt),
			"completion_tokens": int(completion),
			"total_tokens":      int(total),
		},
	}
	b, _ := json.Marshal(chunk)
	pw.Write([]byte("data: " + string(b) + "\n\n"))
}

func (t *traeSSETranslator) Read(p []byte) (int, error) { return t.pr.Read(p) }

func (t *traeSSETranslator) Close() error {
	t.once.Do(func() {
		t.cancel()
		t.pr.Close()
	})
	return nil
}
