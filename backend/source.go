// Model sources.
//
// The plugin aggregates models from several locally installed AI desktop apps.
// Each app is one implementation of this interface, and the loopback endpoint
// merges them behind a single OpenAI-compatible surface so DBX only needs one
// provider entry.
//
// A source is only *callable* when it can obtain a credential the upstream
// accepts. Sources whose app keeps its token out of reach (an encrypted store,
// the OS credential manager, or process memory only) can still report a
// catalog — but their chat path must fail with a clear reason rather than
// silently sending an unauthenticated request.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// modelRow is one model as advertised to DBX.
type modelRow struct {
	// ID is the identifier DBX sends back on a chat turn. It is namespaced by
	// source so one endpoint can serve several apps without collisions.
	ID string `json:"id"`
	// RemoteID is the id the upstream expects.
	RemoteID string `json:"remoteId"`
	// Source is the owning source id.
	Source string `json:"source"`

	Name             string   `json:"name,omitempty"`
	ContextWindow    int      `json:"contextWindow,omitempty"`
	MaxTokens        int      `json:"maxTokens,omitempty"`
	SupportsImages   bool     `json:"supportsImages,omitempty"`
	SupportsToolCall bool     `json:"supportsToolCall,omitempty"`
	Vendor           string   `json:"vendor,omitempty"`
	Efforts          []string `json:"supportedEfforts,omitempty"`
	DefaultEffort    string   `json:"defaultEffort,omitempty"`
}

// sourceStatus is the per-source state rendered in the workbench.
type sourceStatus struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Installed reports whether the app was found on this machine.
	Installed bool `json:"installed"`
	// Callable reports whether this source can actually serve chat turns.
	Callable bool `json:"callable"`
	// State is a short machine-readable condition.
	State string `json:"state"`
	// Detail explains the state in the user's language.
	Detail string `json:"detail,omitempty"`
	// ModelCount is the number of models this source reports.
	ModelCount int `json:"modelCount"`
	// CredentialPath is where the credential was read from, when readable.
	CredentialPath string `json:"credentialPath,omitempty"`
	// AppPath is the detected application path, when relevant.
	AppPath string `json:"appPath,omitempty"`
}

// modelSource is one locally installed AI app.
type modelSource interface {
	// ID is the stable source key used to namespace model ids.
	ID() string
	// Name is the display name.
	Name() string
	// Status reports availability without contacting the network.
	Status(ctx context.Context) sourceStatus
	// Models returns the catalog, namespaced for DBX.
	Models(ctx context.Context) ([]modelRow, error)
	// SendChat forwards one prepared chat request and returns the raw upstream
	// response. The caller closes the body.
	SendChat(ctx context.Context, remoteModelID string, preparedBody string) (*chatResponse, error)
}

// chatResponse is a thin wrapper so sources can report failures uniformly.
type chatResponse struct {
	StatusCode  int
	ContentType string
	Body        interface {
		Read([]byte) (int, error)
		Close() error
	}
	// Reason is set when the source refuses before contacting upstream.
	Reason string
}

// refusal builds a response that reports why a source cannot serve chat.
func refusal(reason string) *chatResponse {
	return &chatResponse{StatusCode: 0, Reason: reason}
}

// namespaceModel prefixes a remote model id with its source.
func namespaceModel(source, remoteID string) string {
	return source + "/" + remoteID
}

// splitModelID reverses namespaceModel.
func splitModelID(id string) (source string, remoteID string, ok bool) {
	index := strings.Index(id, "/")
	if index <= 0 || index == len(id)-1 {
		return "", "", false
	}
	return id[:index], id[index+1:], true
}

// mergeSources collects status and models from every source, keeping a source
// failure from emptying the whole list.
func mergeSources(ctx context.Context, sources []modelSource) ([]sourceStatus, []modelRow, []string) {
	statuses := make([]sourceStatus, 0, len(sources))
	models := make([]modelRow, 0, 64)
	var warnings []string

	for _, source := range sources {
		status := source.Status(ctx)
		rows, err := source.Models(ctx)
		if err != nil {
			status.Detail = strings.TrimSpace(status.Detail + " " + err.Error())
			warnings = append(warnings, fmt.Sprintf("%s: %v", source.Name(), err))
		} else {
			status.ModelCount = len(rows)
			models = append(models, rows...)
		}
		statuses = append(statuses, status)
	}

	sort.SliceStable(models, func(i, j int) bool {
		if models[i].Source != models[j].Source {
			return models[i].Source < models[j].Source
		}
		return models[i].ID < models[j].ID
	})
	return statuses, models, warnings
}

// findSource resolves a source by id.
func findSource(sources []modelSource, id string) modelSource {
	for _, source := range sources {
		if source.ID() == id {
			return source
		}
	}
	return nil
}

// replaceModel rewrites the model field of an OpenAI chat body.
//
// DBX addresses models by their namespaced id (`<source>/<remote-id>`); each
// source must strip its own namespace before the request goes upstream.
func replaceModel(preparedBody, remoteModelID string) (string, error) {
	var body map[string]any
	if err := json.Unmarshal([]byte(preparedBody), &body); err != nil {
		return "", fmt.Errorf("the chat request body is not valid JSON: %w", err)
	}
	body["model"] = remoteModelID
	out, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// catalogCache memoises a merged catalog read.
//
// Reading every source is not cheap: one opens another application's SQLite
// databases and another parses a ~200 KB JSON document, while the WorkBuddy
// credential store may have to launch the WorkBuddy binary. The workbench asks
// for the source list and the model list on every load, so without this the same
// reads run two or three times per interaction — which is what made the panel
// feel sluggish.
type catalogCache struct {
	mutex    sync.Mutex
	ttl      time.Duration
	readAt   time.Time
	statuses []sourceStatus
	models   []modelRow
	warnings []string
}

func newCatalogCache(ttl time.Duration) *catalogCache {
	return &catalogCache{ttl: ttl}
}

// merged returns a cached catalog while it is fresh, otherwise re-reads.
//
// `force` bypasses the cache for an explicit user refresh. A read that produced
// no models at all is not cached, so a transient failure cannot stick to the
// panel.
func (c *catalogCache) merged(ctx context.Context, sources []modelSource, force bool) ([]sourceStatus, []modelRow, []string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if !force && c.statuses != nil && time.Since(c.readAt) < c.ttl {
		return c.statuses, c.models, c.warnings
	}

	statuses, models, warnings := mergeSources(ctx, sources)
	if len(models) > 0 {
		c.statuses, c.models, c.warnings = statuses, models, warnings
		c.readAt = time.Now()
	}
	return statuses, models, warnings
}

// invalidate drops the cached catalog, e.g. after the endpoint state changes.
func (c *catalogCache) invalidate() {
	c.mutex.Lock()
	c.readAt = time.Time{}
	c.mutex.Unlock()
}
