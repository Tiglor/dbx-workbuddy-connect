package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// newTestBridge starts the loopback endpoint against the sources available on
// this machine. Skipped when WorkBuddy is not signed in.
func newTestBridge(t *testing.T) *bridgeServer {
	t.Helper()
	if os.Getenv("WORKBUDDY_ELECTRON_BIN") == "" {
		t.Skip("WORKBUDDY_ELECTRON_BIN not set; skipping live endpoint test")
	}
	client := newUpstreamClient()
	store := newCredentialStore(client, t.TempDir())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := store.resolve(ctx); err != nil {
		t.Skipf("no usable WorkBuddy credential on this machine: %v", err)
	}
	sources := []modelSource{newWorkBuddySource(client, store)}
	bridge, err := startBridge(sources, t.TempDir())
	if err != nil {
		t.Fatalf("startBridge: %v", err)
	}
	t.Cleanup(func() { _ = bridge.close() })
	return bridge
}

func bridgeGet(t *testing.T, bridge *bridgeServer, path, token string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, bridge.url()+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res, body
}

// TestEndpointRequiresToken proves the loopback listener is not open to any
// local process.
func TestEndpointRequiresToken(t *testing.T) {
	bridge := newTestBridge(t)

	res, _ := bridgeGet(t, bridge, "/v1/models", "")
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /v1/models = %d, want 401", res.StatusCode)
	}
	res, _ = bridgeGet(t, bridge, "/v1/models", "wrong-token")
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong token /v1/models = %d, want 401", res.StatusCode)
	}
	res, body := bridgeGet(t, bridge, "/healthz", bridge.token)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("healthz = %d (%s)", res.StatusCode, body)
	}
}

// TestModelsEndpointShape verifies the discovery document matches what an
// OpenAI-compatible client (DBX included) expects.
func TestModelsEndpointShape(t *testing.T) {
	bridge := newTestBridge(t)

	res, body := bridgeGet(t, bridge, "/v1/models", bridge.token)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("/v1/models = %d: %s", res.StatusCode, body)
	}
	var doc struct {
		Object string `json:"object"`
		Data   []struct {
			ID      string `json:"id"`
			Object  string `json:"object"`
			OwnedBy string `json:"owned_by"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if doc.Object != "list" {
		t.Errorf("object = %q, want list", doc.Object)
	}
	if len(doc.Data) == 0 {
		t.Fatal("no models returned")
	}
	for _, m := range doc.Data {
		if m.ID == "" {
			t.Error("model with empty id")
		}
		if m.Object != "model" {
			t.Errorf("model %s object = %q, want model", m.ID, m.Object)
		}
		// Ids must be namespaced by source so chat can route back to the app.
		if source, _, ok := splitModelID(m.ID); !ok || source == "" {
			t.Errorf("model id %q is not namespaced by source", m.ID)
		}
	}
	t.Logf("discovered %d models, first = %s", len(doc.Data), doc.Data[0].ID)
}

// TestChatStreamForwardsSSE performs one real streaming turn through the
// endpoint, using the smallest possible request.
func TestChatStreamForwardsSSE(t *testing.T) {
	if os.Getenv("WORKBUDDY_LIVE_CHAT") == "" {
		t.Skip("set WORKBUDDY_LIVE_CHAT=1 to spend credit on one live chat turn")
	}
	bridge := newTestBridge(t)

	// The model id is namespaced, exactly as DBX would send it back.
	payload := `{"model":"workbuddy/deepseek-v4.1-flash","messages":[{"role":"user","content":"hi"}],"max_tokens":8}`
	req, err := http.NewRequest(http.MethodPost, bridge.url()+"/v1/chat/completions", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+bridge.token)
	req.Header.Set("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST chat: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("chat = %d: %s", res.StatusCode, body)
	}
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "data:") {
		t.Fatalf("response is not SSE: %s", firstLine(body))
	}
	t.Logf("received %d bytes of SSE", len(body))
}

// TestUnnamespacedModelIsRejected proves routing fails closed.
func TestUnnamespacedModelIsRejected(t *testing.T) {
	bridge := newTestBridge(t)

	payload := `{"model":"deepseek-v4.1-flash","messages":[{"role":"user","content":"hi"}]}`
	req, err := http.NewRequest(http.MethodPost, bridge.url()+"/v1/chat/completions", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+bridge.token)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("unnamespaced model = %d, want 400", res.StatusCode)
	}
}

// TestUnknownSourceIsRejected proves an unknown namespace is refused.
func TestUnknownSourceIsRejected(t *testing.T) {
	bridge := newTestBridge(t)

	payload := `{"model":"nope/some-model","messages":[{"role":"user","content":"hi"}]}`
	req, err := http.NewRequest(http.MethodPost, bridge.url()+"/v1/chat/completions", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+bridge.token)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown source = %d, want 404", res.StatusCode)
	}
}

// TestPrepareChatBodyForcesStream mirrors the upstream's wire requirements.
func TestPrepareChatBodyForcesStream(t *testing.T) {
	out := prepareChatBody(`{"model":"m","messages":[{"role":"developer","content":"x"}],"stream":false,"tool_choice":{"type":"auto"}}`)
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["stream"] != true {
		t.Error("stream was not forced to true")
	}
	if doc["tool_choice"] != "auto" {
		t.Errorf("tool_choice = %v, want the flattened string form", doc["tool_choice"])
	}
	messages, _ := doc["messages"].([]any)
	if len(messages) != 1 {
		t.Fatal("messages lost")
	}
	if role := messages[0].(map[string]any)["role"]; role != "system" {
		t.Errorf("developer role = %v, want rewritten to system", role)
	}
}
