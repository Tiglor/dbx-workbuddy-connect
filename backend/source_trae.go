// Trae CN source.
//
// STATUS: catalog-only. Trae's chat path can NOT be proxied, for the same class
// of reason as Qoder, recorded here so the reconnaissance is not repeated:
//
//   - Trae CN keeps its model catalog on disk in the VSCode-compatible store
//     `%APPDATA%\Trae CN\User\globalStorage\state.vscdb`, under
//     `<uid>_AI.agent.model.model_list_map`. That document is ~107 KB and lists
//     7 agent groups (builder, builder_v3, chat_v3, code_reviewer, ...) with
//     display names, prompt token budgets, context windows and multimodal flags.
//   - It contains DISPLAY NAMES only (`Doubao-Seed-Code`, `deepseek-V3.1`), not
//     the request ids a gateway call needs.
//   - No access token is stored in that store. The `aha` / `ahanet` modules hold
//     only a device id, an access policy blob and feature flags. Trae's own
//     agent database (`ModularData\ai-agent\database.db`) is page-encrypted —
//     it has no SQLite header and its WAL yields no readable rows — so it is not
//     a usable credential or catalog source either.
//
// What this source therefore provides: the model list Trae itself shows, so the
// workbench can display it, plus a refusal that explains the limitation.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

const traeSourceID = "trae"

type traeSource struct{}

func newTraeSource() *traeSource { return &traeSource{} }

func (s *traeSource) ID() string   { return traeSourceID }
func (s *traeSource) Name() string { return "Trae CN" }

// traeStateDB is the VSCode-compatible global storage.
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

func traeAppPath() string {
	if runtime.GOOS != "windows" {
		return ""
	}
	candidates := []string{`D:\Trae CN\Trae CN.exe`}
	if local := os.Getenv("LOCALAPPDATA"); local != "" {
		candidates = append(candidates, filepath.Join(local, "Programs", "Trae CN", "Trae CN.exe"))
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
	path := traeStateDB()
	if path == "" {
		status.State = "unsupported-platform"
		status.Detail = "Trae CN 的凭据/清单位置仅在 Windows 上已知。"
		return status
	}
	if _, err := os.Stat(path); err != nil {
		status.State = "not-installed"
		status.Detail = "本机未找到 Trae CN 的数据目录。"
		return status
	}
	status.Installed = true
	status.CredentialPath = path
	if app := traeAppPath(); app != "" {
		status.AppPath = app
	}
	if _, err := readTraeModelList(); err != nil {
		status.State = "catalog-unavailable"
		status.Detail = "找不到 Trae 的模型清单缓存: " + err.Error()
		return status
	}
	status.State = "no-user-token"
	status.Detail = "Trae CN 的令牌存于系统凭据管理器/进程内存,磁盘上没有;" +
		"因此只能读取模型清单,无法代理对话。"
	return status
}

// traeModelEntry is one row of the cached model list.
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
//
// This matters: `context_window_size.max` is a number on some rows and an array
// on others, and a strict int field makes the entire catalog unreadable when a
// single odd row appears.
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
			// An array we cannot read means "unknown", not a decode failure.
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

// Int returns the value, or 0 when absent.
func (s flexSize) Int() int {
	if !s.set {
		return 0
	}
	return s.value
}

// readTraeModelList loads the cached model list document.
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

// Models reports Trae's cached model list, grouped by agent family.
func (s *traeSource) Models(ctx context.Context) ([]modelRow, error) {
	doc, err := readTraeModelList()
	if err != nil {
		return nil, err
	}

	// The same model appears under several agent families; report it once,
	// recording which families offer it.
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
			// Prefer a row that carries a display name or a larger window.
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

// SendChat always refuses: Trae stores no request id or token this plugin can use.
func (s *traeSource) SendChat(ctx context.Context, remoteModelID string, preparedBody string) (*chatResponse, error) {
	return refusal("Trae CN 目前只能读取模型清单,无法代理对话:它不把用户令牌写入磁盘," +
		"且缓存的清单只有显示名、没有可调用的请求 id。这是该应用凭据设计的限制。"), nil
}
