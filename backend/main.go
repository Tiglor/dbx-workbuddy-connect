// WorkBuddy Connect — DBX plugin sidecar.
//
// Brings the models of the locally installed WorkBuddy desktop app into DBX.
//
// How it fits together:
//
//	UI (sandboxed workbench)          this sidecar                WorkBuddy app
//	------------------------          ------------                -------------
//	status            ------------>  read + open credential  --> .info envelope
//	                                     |  (spawns the app once for the key)
//	models / credits  ------------>  WorkBuddy gateways
//	bridge.start      ------------>  loopback OpenAI endpoint  <-- DBX AI provider
//	bridge.info       ------------>  { endpoint, token }
//
// DBX has no plugin API for registering a model provider, so the flow is: this
// sidecar serves an OpenAI-compatible endpoint, and the user adds it once under
// AI settings as an "OpenAI Compatible" provider. DBX then discovers the model
// list from GET /v1/models automatically.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	dbxpluginsdk "github.com/t8y2/dbx/plugins/sdk/go/dbx-plugin-sdk"
)

const pluginID = "io.github.workbuddy.connect"

type plugin struct {
	client  *upstreamClient
	store   *credentialStore
	sources []modelSource
	catalog *catalogCache
	bridge  *bridgeServer

	mutex sync.Mutex
}

// newPlugin wires every model source the plugin knows about.
func newPlugin(dataDir string) *plugin {
	client := newUpstreamClient()
	store := newCredentialStore(client, dataDir)
	return &plugin{
		client: client,
		store:  store,
		// WorkBuddy is the only source with a usable credential today; Qoder and
		// Trae are catalog-only and refuse chat with an explanation.
		sources: []modelSource{
			newWorkBuddySource(client, store),
			newQoderSource(),
			newTraeSource(),
		},
		// Short enough that a sign-in or an app install shows up promptly, long
		// enough to collapse the several reads one workbench load performs.
		catalog: newCatalogCache(20 * time.Second),
	}
}

func (p *plugin) Handle(
	_ dbxpluginsdk.RequestContext,
	method string,
	params json.RawMessage,
	_ *dbxpluginsdk.Emitter,
) (any, *dbxpluginsdk.PluginError) {
	// Diagnostics must go to stderr: stdout carries the JSON-RPC protocol.
	if os.Getenv("DBX_WORKBUDDY_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "[sidecar] method=%s params=%s sources=%d\n", method, string(params), len(p.sources))
	}
	var values map[string]any
	if len(params) > 0 && string(params) != "null" {
		if err := json.Unmarshal(params, &values); err != nil {
			return nil, dbxpluginsdk.NewError(-32602, "Invalid request parameters")
		}
	}
	ctx := context.Background()

	switch method {
	case "connection/test":
		return map[string]any{"success": true, "message": "WorkBuddy Connect is ready."}, nil

	case "status":
		return p.status(ctx), nil

	case "sources":
		return p.sourcesStatus(ctx, values), nil

	case "models":
		return p.models(ctx, values)

	case "credits":
		return p.credits(ctx)

	case "bridge.start":
		return p.bridgeStart(ctx)

	case "bridge.stop":
		return p.bridgeStop()

	case "bridge.info":
		return p.bridgeInfo(), nil

	case "diagnostics":
		return p.diagnostics(ctx), nil

	default:
		return nil, dbxpluginsdk.MethodNotFound(method)
	}
}

// sourcesStatus reports every configured source.
//
// `refresh: true` from the UI bypasses the cache; otherwise this reuses the
// catalog read that the model list is about to make anyway.
func (p *plugin) sourcesStatus(ctx context.Context, values map[string]any) map[string]any {
	force, _ := values["refresh"].(bool)
	statuses, rows, _ := p.catalog.merged(ctx, p.sources, force)
	// The per-source model count comes from the already-read catalog.
	counts := map[string]int{}
	for _, row := range rows {
		counts[row.Source]++
	}
	out := make([]map[string]any, 0, len(statuses))
	for _, status := range statuses {
		out = append(out, map[string]any{
			"id":             status.ID,
			"name":           status.Name,
			"installed":      status.Installed,
			"callable":       status.Callable,
			"state":          status.State,
			"detail":         status.Detail,
			"modelCount":     counts[status.ID],
			"credentialPath": status.CredentialPath,
			"appPath":        status.AppPath,
		})
	}
	return map[string]any{"ok": true, "sources": out}
}

// errorResult renders a failure the UI can show without throwing.
func errorResult(err error) map[string]any {
	return map[string]any{"ok": false, "error": err.Error()}
}

// status reports sign-in state plus whether the endpoint is serving.
func (p *plugin) status(ctx context.Context) map[string]any {
	status := p.store.status(ctx)
	return map[string]any{
		"ok":     true,
		"auth":   status,
		"bridge": p.bridgeInfo(),
	}
}

// models merges the catalogs of every source.
//
// A source that cannot be reached is reported as a warning rather than an
// error, so one app being missing or signed out never empties the whole list.
func (p *plugin) models(ctx context.Context, values map[string]any) (any, *dbxpluginsdk.PluginError) {
	force, _ := values["refresh"].(bool)
	statuses, rows, warnings := p.catalog.merged(ctx, p.sources, force)

	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		item := map[string]any{
			"id":     row.ID,
			"name":   firstNonEmpty(row.Name, row.RemoteID),
			"source": row.Source,
		}
		if row.ContextWindow > 0 {
			item["contextWindow"] = row.ContextWindow
		}
		if row.MaxTokens > 0 {
			item["maxTokens"] = row.MaxTokens
		}
		if row.SupportsImages {
			item["supportsImages"] = true
		}
		if row.SupportsToolCall {
			item["supportsToolCall"] = true
		}
		if row.Vendor != "" {
			item["vendor"] = row.Vendor
		}
		if len(row.Efforts) > 0 {
			item["reasoning"] = map[string]any{
				"supports":         true,
				"supportedEfforts": row.Efforts,
				"defaultEffort":    row.DefaultEffort,
			}
		}
		out = append(out, item)
	}
	return map[string]any{
		"ok":       true,
		"count":    len(out),
		"models":   out,
		"sources":  statuses,
		"warnings": warnings,
	}, nil
}

// credits returns the remaining credit summary.
func (p *plugin) credits(ctx context.Context) (any, *dbxpluginsdk.PluginError) {
	cred, err := p.store.resolve(ctx)
	if err != nil {
		return errorResult(err), nil
	}
	summary, err := p.client.fetchCredits(ctx, cred)
	if err != nil {
		return errorResult(fmt.Errorf("could not read the WorkBuddy credit summary: %w", err)), nil
	}
	// Report only packages that still hold credit: the endpoint returns every
	// package ever issued, including long-expired ones.
	active := make([]map[string]any, 0, len(summary.Accounts))
	for _, entry := range summary.Accounts {
		if entry.Remain <= 0 {
			continue
		}
		row := map[string]any{
			"packageName": entry.PackageName,
			"remain":      entry.Remain,
			"size":        entry.Size,
		}
		if entry.EndTimeMs > 0 {
			row["endTimeMs"] = entry.EndTimeMs
		}
		active = append(active, row)
	}
	return map[string]any{
		"ok":       true,
		"total":    summary.Total,
		"accounts": active,
		"expired":  len(summary.Accounts) - len(active),
	}, nil
}

// diagnostics explains why a machine cannot connect, without printing secrets.
func (p *plugin) diagnostics(ctx context.Context) map[string]any {
	path, format, err := p.store.resolvedDesktopAuthPath()
	electron, electronErr := resolveElectronPath()
	out := map[string]any{
		"ok":               true,
		"desktopAuthPath":  path,
		"authFormat":       format,
		"electronPath":     electron,
		"electronEnvVar":   envElectronBin,
		"electronOverride": os.Getenv(envElectronBin) != "",
	}
	if err != nil {
		out["authError"] = err.Error()
	}
	if electronErr != nil {
		out["electronError"] = electronErr.Error()
		out["hint"] = "Install the WorkBuddy desktop app, or set " + envElectronBin +
			" to its executable path."
	}
	return out
}

// ---- bridge ----------------------------------------------------------------

func (p *plugin) bridgeStart(ctx context.Context) (any, *dbxpluginsdk.PluginError) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if p.bridge != nil {
		return map[string]any{"ok": true, "alreadyRunning": true, "bridge": p.bridge.info()}, nil
	}
	// Starting with no readable catalog at all would produce an endpoint DBX
	// cannot use; report that instead of serving an empty list. This reuses the
	// cached read rather than re-reading every source.
	statuses, rows, _ := p.catalog.merged(ctx, p.sources, false)
	if len(rows) == 0 {
		reasons := make([]string, 0, len(statuses))
		for _, status := range statuses {
			reasons = append(reasons, fmt.Sprintf("%s: %s", status.Name, firstNonEmpty(status.Detail, status.State)))
		}
		return errorResult(fmt.Errorf("没有可用的模型来源:%s", strings.Join(reasons, " / "))), nil
	}
	bridge, err := startBridge(p.sources, p.dataDir())
	if err != nil {
		return errorResult(fmt.Errorf("could not start the local endpoint: %w", err)), nil
	}
	p.bridge = bridge
	return map[string]any{"ok": true, "bridge": bridge.info()}, nil
}

func (p *plugin) bridgeStop() (any, *dbxpluginsdk.PluginError) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if p.bridge == nil {
		return map[string]any{"ok": true, "alreadyStopped": true}, nil
	}
	if err := p.bridge.close(); err != nil {
		return errorResult(err), nil
	}
	p.bridge = nil
	return map[string]any{"ok": true}, nil
}

// bridgeInfo reports the endpoint and its bearer token, or that it is stopped.
func (p *plugin) bridgeInfo() map[string]any {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if p.bridge == nil {
		return map[string]any{"running": false}
	}
	return p.bridge.info()
}

// dataDir is the plugin's own writable directory.
//
// DBX defines DBX_PLUGIN_DATA_DIR for sidecars but (as of 0.6.41) never sets
// it, so the fallback is what normally runs. The fallback is deliberately
// namespaced under a `dbx-plugins` parent: an earlier revision used
// `<UserCacheDir>/<pluginID>` directly, which put the state file in a
// generic-looking top-level directory where unrelated data could collide with
// it — and did, leaving a stale port and token that the running plugin then
// picked up.
func dataDirFromEnv() string {
	if dir := os.Getenv("DBX_PLUGIN_DATA_DIR"); dir != "" {
		return dir
	}
	if cache, err := os.UserCacheDir(); err == nil {
		return filepath.Join(cache, "dbx-plugins", pluginID)
	}
	return filepath.Join(os.TempDir(), "dbx-plugins", pluginID)
}

// dataDir exposes the same resolution on the plugin value.
func (p *plugin) dataDir() string { return dataDirFromEnv() }

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func main() {
	// A hidden self-check mode: run the plugin's own code paths against this
	// machine and print the result. Used to verify a build without DBX, and to
	// inspect upstream documents whose shape is uncertain.
	if len(os.Args) > 1 {
		runSelfCheck(os.Args[1])
		return
	}

	// One construction path for both entry points (RPC server and self-check),
	// so a field can never be wired in one and forgotten in the other.
	metadata := dbxpluginsdk.Metadata{
		ID:      pluginID,
		Version: version,
		// The sidecar answers plugin RPCs only; it declares no connection
		// provider because these apps are model sources, not databases.
		Capabilities: []string{"status"},
	}
	server := dbxpluginsdk.NewServer(metadata, newPlugin(dataDirFromEnv()))
	if err := server.Serve(); err != nil && !errors.Is(err, os.ErrClosed) {
		log.Fatal(err)
	}
}

// version is the plugin version, injected at build time by dbx-plugin package
// when available.
var version = "0.1.0"
