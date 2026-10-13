// Loopback OpenAI-compatible endpoint.
//
// This is the piece DBX actually consumes: added once under AI settings as an
// "OpenAI Compatible" provider, DBX reads the model roster from GET /v1/models
// and sends chat turns to POST /v1/chat/completions.
//
// The listener binds 127.0.0.1 only and requires a bearer token, because the
// loopback interface is not a trust boundary on a shared machine: any local
// process (or a DNS-rebinding page) can reach 127.0.0.1.

package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// maxRequestBody bounds a forwarded chat body.
	maxRequestBody = 64 << 20

	// streamIdleTimeout is the ceiling for one streaming answer.
	streamIdleTimeout = 5 * time.Minute

	bridgeStateFilename = "bridge.json"
)

// bridgeState is persisted so the endpoint URL and token stay stable across
// sidecar restarts, which keeps the DBX provider configuration valid.
type bridgeState struct {
	Token string `json:"token"`
	Port  int    `json:"port"`
}

type bridgeServer struct {
	server  *http.Server
	sources []modelSource
	token   string
	port    int
	state   string
	// portChanged records that the remembered port was unavailable, so the
	// endpoint the user already configured is now stale.
	portChanged bool
}

// startBridge listens on an ephemeral loopback port, reusing the previously
// saved port and token when they are still free.
func startBridge(sources []modelSource, dataDir string) (*bridgeServer, error) {
	statePath := filepath.Join(dataDir, bridgeStateFilename)
	state := loadBridgeState(statePath)
	if state.Token == "" {
		state.Token = randomToken()
	}

	bridge := &bridgeServer{sources: sources, token: state.Token}

	// Prefer the remembered port so the endpoint survives a sidecar restart and
	// the provider entry configured in DBX keeps working. When that port is
	// gone, take any free one — and say so, because the endpoint the user has
	// already configured will no longer be correct.
	rememberedPort := state.Port
	listener, err := listenLoopback(rememberedPort)
	if err != nil && rememberedPort != 0 {
		listener, err = listenLoopback(0)
		if err == nil {
			bridge.portChanged = true
		}
	}
	if err != nil {
		return nil, err
	}
	bridge.port = listener.Addr().(*net.TCPAddr).Port

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", bridge.handleHealth)
	mux.HandleFunc("/v1/models", bridge.handleModels)
	mux.HandleFunc("/v1/chat/completions", bridge.handleChat)

	bridge.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 15 * time.Second,
	}

	// Persisting is best-effort, but a failure must be visible: if the state
	// cannot be written, the port and token change on every restart and the
	// displayed values cannot be trusted across sessions.
	if err := saveBridgeState(statePath, bridgeState{Token: bridge.token, Port: bridge.port}); err != nil {
		bridge.state = fmt.Sprintf("端点可用,但状态无法写入 %s(%v);重启后端口和令牌会变化。",
			statePath, err)
	}

	go func() {
		if err := bridge.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			bridge.state = err.Error()
		}
	}()
	return bridge, nil
}

// listenLoopback binds 127.0.0.1 on the preferred port (0 = any free port).
func listenLoopback(port int) (net.Listener, error) {
	return net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
}

func randomToken() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		// A predictable token would be worse than refusing to start.
		panic("cannot obtain randomness for the endpoint token: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func loadBridgeState(path string) bridgeState {
	raw, err := os.ReadFile(path)
	if err != nil {
		return bridgeState{}
	}
	var state bridgeState
	if err := json.Unmarshal(raw, &state); err != nil {
		return bridgeState{}
	}
	return state
}

func saveBridgeState(path string, state bridgeState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	// Owner-only: the token authorises access to the user's WorkBuddy account.
	return os.WriteFile(path, raw, 0o600)
}

func (b *bridgeServer) url() string { return fmt.Sprintf("http://127.0.0.1:%d", b.port) }

// info is what the workbench shows the user.
//
// The token and port reported here are the values actually in effect for this
// process. They are the authority: the on-disk state file is only a hint for
// the next start.
func (b *bridgeServer) info() map[string]any {
	out := map[string]any{
		"running":  true,
		"endpoint": b.url() + "/v1",
		"baseUrl":  b.url(),
		"token":    b.token,
		"port":     b.port,
		"models":   b.url() + "/v1/models",
		"chat":     b.url() + "/v1/chat/completions",
	}
	if b.portChanged {
		out["portChanged"] = true
		out["warning"] = "上次使用的端口已被占用,端点端口已改变;DBX 里那条 AI 配置需要更新为新地址。"
	}
	if b.state != "" {
		out["error"] = b.state
	}
	return out
}

func (b *bridgeServer) close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return b.server.Shutdown(ctx)
}

// requireBearer enforces the endpoint token in constant time.
func (b *bridgeServer) requireBearer(w http.ResponseWriter, r *http.Request) bool {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(strings.ToLower(header), "bearer ") {
		writeOpenAIError(w, http.StatusUnauthorized, "unauthorized", "missing or invalid Authorization bearer")
		return false
	}
	presented := strings.TrimSpace(header[len("Bearer "):])
	if subtle.ConstantTimeCompare([]byte(presented), []byte(b.token)) != 1 {
		writeOpenAIError(w, http.StatusUnauthorized, "unauthorized", "missing or invalid Authorization bearer")
		return false
	}
	return true
}

func (b *bridgeServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if !b.requireBearer(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleModels is the discovery call DBX makes to populate its model menu.
//
// It merges every source, so one DBX provider entry exposes all of them. Model
// ids are namespaced (`workbuddy/hy3`, `trae/Doubao-Seed-Code`) so a chat turn
// can be routed back to the app that owns it.
func (b *bridgeServer) handleModels(w http.ResponseWriter, r *http.Request) {
	if !b.requireBearer(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()

	data := make([]map[string]any, 0, 64)
	for _, source := range b.sources {
		rows, err := source.Models(ctx)
		if err != nil {
			// A source that cannot answer is skipped; the rest still serve.
			continue
		}
		for _, row := range rows {
			data = append(data, map[string]any{
				"id":       row.ID,
				"object":   "model",
				"created":  0,
				"owned_by": row.Source,
			})
		}
	}
	if len(data) == 0 {
		writeOpenAIError(w, http.StatusBadGateway, "catalog_unavailable",
			"no model source could be read; check that WorkBuddy is installed and signed in")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": data})
}

// handleChat forwards one chat completion, streaming the upstream SSE through.
func (b *bridgeServer) handleChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	if !b.requireBearer(w, r) {
		return
	}
	if contentType := r.Header.Get("Content-Type"); !strings.Contains(strings.ToLower(contentType), "application/json") {
		writeOpenAIError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return
	}

	raw, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody))
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "bad_request", "could not read the request body")
		return
	}

	// Route on the namespaced model id, which names the owning source.
	var probe struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil || probe.Model == "" {
		writeOpenAIError(w, http.StatusBadRequest, "bad_request", "the request body must be JSON carrying a model id")
		return
	}
	sourceID, remoteModelID, ok := splitModelID(probe.Model)
	if !ok {
		writeOpenAIError(w, http.StatusBadRequest, "unknown_model",
			fmt.Sprintf("model %q is not namespaced by source; expected <source>/<model>", probe.Model))
		return
	}
	source := findSource(b.sources, sourceID)
	if source == nil {
		writeOpenAIError(w, http.StatusNotFound, "unknown_model",
			fmt.Sprintf("no model source named %q is configured", sourceID))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), streamIdleTimeout)
	defer cancel()

	res, err := source.SendChat(ctx, remoteModelID, prepareChatBody(string(raw)))
	if err != nil {
		writeOpenAIError(w, http.StatusBadGateway, "upstream_unreachable", err.Error())
		return
	}
	// A source may refuse before contacting upstream (no usable credential).
	if res.Reason != "" {
		writeOpenAIError(w, http.StatusNotImplemented, "source_not_callable", res.Reason)
		return
	}
	if res.Body == nil {
		writeOpenAIError(w, http.StatusBadGateway, "upstream_error", "the source returned no response body")
		return
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		detail, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		code := "upstream_error"
		status := http.StatusBadGateway
		switch res.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			code, status = "not_signed_in", http.StatusUnauthorized
		case http.StatusTooManyRequests:
			code, status = "rate_limited", http.StatusTooManyRequests
		case http.StatusBadRequest:
			code, status = "bad_request", http.StatusBadRequest
		}
		writeOpenAIError(w, status, code,
			fmt.Sprintf("%s upstream HTTP %d: %s", source.Name(), res.StatusCode, firstLine(detail)))
		return
	}

	if res.ContentType != "" {
		w.Header().Set("Content-Type", res.ContentType)
	} else {
		w.Header().Set("Content-Type", "text/event-stream")
	}
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 16<<10)
	for {
		n, readErr := res.Body.Read(buf)
		if n > 0 {
			if _, writeErr := w.Write(buf[:n]); writeErr != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				// Surface a truncated stream the way OpenAI clients expect.
				_, _ = w.Write([]byte("data: [DONE]\n\n"))
				if flusher != nil {
					flusher.Flush()
				}
			}
			return
		}
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	payload, err := json.Marshal(body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}

func writeOpenAIError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]any{
			"message": message,
			"type":    "invalid_request_error",
			"code":    code,
		},
	})
}
