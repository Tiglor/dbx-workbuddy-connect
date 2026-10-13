// Qoder CN source.
//
// STATUS: catalog-only. Qoder's chat path can NOT be proxied yet, and the
// reason is recorded here so nobody re-does the reconnaissance:
//
//   - Qoder CN does not write a user access token anywhere readable. Its own
//     state database (`%APPDATA%\com.qodercn.app.stable\main.sqlite`) has
//     `account_profiles`, `byok_model_credentials` and `mcp_oauth_credentials`
//     tables — all present but EMPTY. The legacy store
//     (`~/.qoder-cn/shared_client/cache/db/local.db`) has a `supabase_token`
//     table that is also empty.
//   - The only token on disk is `~/.qoder-cn/shared_client/cache/machine_token.json`,
//     a machine token, not a user token. The gateway rejects it.
//   - Inference actually runs through a packed local daemon on 127.0.0.1:64003
//     speaking MCP, not through the HTTP gateway this plugin would need.
//
// What IS readable: the model keys the app has actually used, in
// `chat_message.model_info` (`{"model_key":"auto"}`) and `chat_sessions.model`
// (`qfmodel`, `auto`). This source reports those so the workbench can show what
// Qoder is using, and refuses chat with an actionable message.

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

const qoderSourceID = "qoder"

type qoderSource struct{}

func newQoderSource() *qoderSource { return &qoderSource{} }

func (s *qoderSource) ID() string   { return qoderSourceID }
func (s *qoderSource) Name() string { return "Qoder CN" }

// qoderMessageDB is the app's own state database.
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

// qoderLegacyDB is the shared client's local cache.
func qoderLegacyDB() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".qoder-cn", "shared_client", "cache", "db", "local.db")
}

func (s *qoderSource) Status(ctx context.Context) sourceStatus {
	status := sourceStatus{ID: s.ID(), Name: s.Name()}

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
	if app := qoderAppPath(); app != "" {
		status.AppPath = app
	}

	// A readable user token would flip this to ready; today there is none.
	token, _ := readQoderMachineToken()
	if token == "" {
		status.State = "no-user-token"
		status.Detail = "Qoder CN 不把用户令牌写入磁盘(仅有机器令牌),且推理走本地守护进程;" +
			"因此只能读取模型清单,无法代理对话。"
		return status
	}
	status.State = "machine-token-only"
	status.Detail = "只找到机器令牌(非用户令牌),网关会拒绝;只能读取模型清单。"
	return status
}

func qoderAppPath() string {
	if runtime.GOOS != "windows" {
		return ""
	}
	for _, candidate := range []string{
		`D:\Qoder CN\Qoder CN.exe`,
		`C:\Program Files\Qoder CN\Qoder CN.exe`,
	} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	if local := os.Getenv("LOCALAPPDATA"); local != "" {
		candidate := filepath.Join(local, "Programs", "Qoder CN", "Qoder CN.exe")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

// readQoderMachineToken reads the machine token, which is deliberately NOT
// treated as a usable credential.
func readQoderMachineToken() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	path := filepath.Join(home, ".qoder-cn", "shared_client", "cache", "machine_token.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var doc struct {
		Token string `json:"token"`
	}
	if err := jsonUnmarshal(raw, &doc); err != nil {
		return "", err
	}
	return doc.Token, nil
}

// modelKeyPattern matches the model keys Qoder records in its session rows.
var modelKeyPattern = regexp.MustCompile(`"(?:model_key|model)"\s*:\s*"([^"]{1,64})"`)

// Models reports the model keys Qoder's own history shows it using.
func (s *qoderSource) Models(ctx context.Context) ([]modelRow, error) {
	seen := map[string]struct{}{}

	// Preferred: the dedicated preferences table, when the app has populated it.
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
		// Fall back to what the session history actually used.
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

	// The legacy cache keeps the full model_info JSON per message.
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

// SendChat always refuses: no user token exists on disk to send.
func (s *qoderSource) SendChat(ctx context.Context, remoteModelID string, preparedBody string) (*chatResponse, error) {
	app := qoderAppPath()
	hint := "请先打开 Qoder CN 并保持登录"
	if app != "" {
		hint = "Qoder CN 的真实令牌只存在于运行中的进程内存里,插件无法读取"
	}
	return refusal(fmt.Sprintf(
		"Qoder CN 目前只能读取模型清单,无法代理对话:%s。这是该应用凭据设计的限制,不是配置问题。", hint)), nil
}

// describeQoderBlockers is used by the workbench diagnostics panel.
func describeQoderBlockers() string {
	parts := []string{}
	if _, err := readQoderMachineToken(); err == nil {
		parts = append(parts, "存在机器令牌(非用户令牌)")
	}
	parts = append(parts, "用户令牌不落盘", "推理经本地守护进程 127.0.0.1:64003")
	return strings.Join(parts, "; ")
}
