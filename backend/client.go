// WorkBuddy upstream HTTP client.
//
// Every endpoint, header and body below was captured from the reference
// implementation's live traffic (dsh-workbuddy-connect, CN variant), not
// guessed:
//
//	GET  https://copilot.tencent.com/v3/config
//	     UA: CLI/2.63.2 CodeBuddy/2.63.2          -> the chat model roster
//	GET  https://copilot.tencent.com/console/enterprises/personal/models
//	                                                -> promotional badges (best effort)
//	POST https://www.codebuddy.cn/v2/billing/meter/get-user-resource
//	     X-User-Id, X-Domain                        -> remaining credit
//	POST https://copilot.tencent.com/v2/chat/completions
//	     WorkBuddy client identity headers          -> the model answer (SSE)
//	POST {chatBase}/v2/plugin/auth/token/refresh
//	     X-Refresh-Token, X-Auth-Refresh-Source     -> a new access token

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	gatewayBase = "https://copilot.tencent.com"
	consoleBase = "https://www.codebuddy.cn"

	// The gateway splits /v3/config by client identity: a CLI-shaped UA yields
	// the chat roster this bridge serves.
	cliUserAgent = "CLI/2.63.2 CodeBuddy/2.63.2"

	// Chat requests carry the desktop app's identity.
	appVersion = "5.5.6"
	chatUA     = "WorkBuddy/" + appVersion + " WorkBuddy/" + appVersion

	jsonTimeout  = 20 * time.Second
	maxErrorBody = 64 * 1024
)

// upstreamModel is one row of the product document's `data.models` array.
//
// Field names are the ones the gateway actually sends (observed live):
// maxInputTokens / maxOutputTokens carry the window sizes; there is no
// `contextWindow` on the CN document.
type upstreamModel struct {
	ID                 string      `json:"id"`
	Name               string      `json:"name"`
	MaxInputTokens     int         `json:"maxInputTokens"`
	MaxOutputTokens    int         `json:"maxOutputTokens"`
	SupportsImages     bool        `json:"supportsImages"`
	Disabled           bool        `json:"disabled"`
	DisabledMultimodal bool        `json:"disabledMultimodal"`
	Vendor             string      `json:"vendor"`
	Credits            *flexNumber `json:"credits"`
	SupportsToolCall   bool        `json:"supportsToolCall"`

	// CN rows carry no reasoning descriptor. These are accepted so an
	// international document degrades gracefully instead of being dropped.
	Reasoning *struct {
		Supports         bool     `json:"supports"`
		OnlyReasoning    bool     `json:"onlyReasoning"`
		SupportedEfforts []string `json:"supportedEfforts"`
		DefaultEffort    string   `json:"defaultEffort"`
	} `json:"reasoning"`
	Billing *struct {
		Credits *flexNumber `json:"credits"`
		Badges  []string    `json:"badges"`
	} `json:"billing"`
}

// flexNumber accepts a JSON number or a numeric string.
//
// The gateway is inconsistent here: `data.models[].credits` arrives as a
// string ("0") while other numeric fields are plain numbers, so a strict
// float64 field makes the whole catalog fail to decode.
type flexNumber float64

func (n *flexNumber) UnmarshalJSON(raw []byte) error {
	text := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	if text == "" || text == "null" {
		return nil
	}
	value, err := strconv.ParseFloat(text, 64)
	if err != nil {
		// An unparseable value means "no number", not a decode failure.
		return nil
	}
	*n = flexNumber(value)
	return nil
}

// Float returns the numeric value.
func (n flexNumber) Float() float64 { return float64(n) }

// catalogDocument is the `/v3/config` answer.
type catalogDocument struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		// Agents selects the roster. The agent named "cli" lists exactly the
		// models this client identity may call; the full `models` array is a
		// superset containing image models, a "default" sentinel and retired
		// rows.
		Agents []struct {
			Name   string   `json:"name"`
			Models []string `json:"models"`
		} `json:"agents"`
		Models []upstreamModel `json:"models"`
	} `json:"data"`
}

// envelope is the gateway's standard answer document.
type envelope struct {
	Code int             `json:"code"`
	Msg  string          `json:"msg"`
	Data json.RawMessage `json:"data"`
}

type upstreamClient struct {
	http *http.Client
}

func newUpstreamClient() *upstreamClient {
	return &upstreamClient{
		http: &http.Client{Timeout: 0}, // streaming responses must not be cut off
	}
}

// chatBase is the origin used for chat, refresh and catalog selection.
func chatBase(cred *credential) string {
	if cred != nil && strings.Contains(cred.Domain, "workbuddy.ai") {
		return "https://www.workbuddy.ai"
	}
	return gatewayBase
}

func doJSON(ctx context.Context, client *http.Client, req *http.Request, timeout time.Duration) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req = req.WithContext(ctx)
	res, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxErrorBody))
	if err != nil {
		return nil, res.StatusCode, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return body, res.StatusCode, fmt.Errorf("upstream HTTP %d: %s", res.StatusCode, firstLine(body))
	}
	return body, res.StatusCode, nil
}

func firstLine(body []byte) string {
	text := trimSpace(string(body))
	if idx := strings.IndexByte(text, '\n'); idx >= 0 {
		text = text[:idx]
	}
	if len(text) > 300 {
		text = text[:300]
	}
	return text
}

func readEnvelope(body []byte) (envelope, error) {
	var env envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return env, fmt.Errorf("upstream returned a non-JSON document: %w", err)
	}
	return env, nil
}

// catalogHeaders are the shared identity headers for the product document.
func catalogHeaders(cred *credential) map[string]string {
	return map[string]string{
		"Authorization": "Bearer " + cred.AccessToken,
		"Accept":        "application/json",
		"Origin":        consoleBase,
		"Referer":       consoleBase + "/",
		"User-Agent":    cliUserAgent,
	}
}

// fetchModels reads the live chat-model roster.
//
// Membership is the `cli` agent's model list intersected with the usable rows
// of `data.models`, in the agent's order — the same rule the reference
// implementation applies. Reading `data.models` alone yields a superset that
// includes image models and a "default" sentinel, which must not be offered as
// chat models.
func (c *upstreamClient) fetchModels(ctx context.Context, cred *credential) ([]upstreamModel, error) {
	body, _, err := c.getJSON(ctx, chatBase(cred)+"/v3/config", catalogHeaders(cred))
	if err != nil {
		return nil, err
	}
	var doc catalogDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("the model catalog document could not be decoded: %w", err)
	}
	if doc.Code != 0 {
		return nil, fmt.Errorf("the model catalog request was rejected: %s", doc.Msg)
	}

	cliIDs := cliAgentModels(doc)
	if len(cliIDs) == 0 {
		return nil, errors.New("the WorkBuddy model catalog lists no cli agent models")
	}

	byID := make(map[string]upstreamModel, len(doc.Data.Models))
	for _, row := range doc.Data.Models {
		// A row without a name or window sizes is not a usable chat model.
		if row.ID == "" || row.Disabled {
			continue
		}
		if row.MaxInputTokens <= 0 || row.MaxOutputTokens <= 0 {
			continue
		}
		byID[row.ID] = row
	}

	models := make([]upstreamModel, 0, len(cliIDs))
	for _, id := range cliIDs {
		if row, ok := byID[id]; ok {
			models = append(models, row)
		}
	}
	if len(models) == 0 {
		return nil, errors.New("the WorkBuddy model catalog resolved to an empty list")
	}
	return models, nil
}

// cliAgentModels returns the model ids the "cli" agent exposes.
func cliAgentModels(doc catalogDocument) []string {
	for _, agent := range doc.Data.Agents {
		if agent.Name == "cli" && len(agent.Models) > 0 {
			return agent.Models
		}
	}
	return nil
}

// getJSON performs an authenticated GET and returns the body.
func (c *upstreamClient) getJSON(ctx context.Context, url string, headers map[string]string) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return doJSON(ctx, c.http, req, jsonTimeout)
}

// billingDocument is the personal billing answer.
//
// The document is nested four levels deep and uses PascalCase names:
//
//	envelope.data.Response.Data.Accounts[]
//	  PackageName, CycleCapacitySize, CycleCapacityRemain, CycleCapacityUsed,
//	  CapacityRemain, CapacitySize, CycleEndTime
//
// `total` is not a returned field: it is the sum of each package's remaining
// credit, computed the same way the reference implementation computes it.
type billingDocument struct {
	Response struct {
		Data struct {
			Accounts []billingAccount `json:"Accounts"`
		} `json:"Data"`
	} `json:"Response"`
}

// billingAccount is one credit package.
type billingAccount struct {
	PackageName         string  `json:"PackageName"`
	CycleCapacitySize   float64 `json:"CycleCapacitySize"`
	CycleCapacityRemain float64 `json:"CycleCapacityRemain"`
	CycleCapacityUsed   float64 `json:"CycleCapacityUsed"`
	CapacityRemain      float64 `json:"CapacityRemain"`
	CapacitySize        float64 `json:"CapacitySize"`
	CycleEndTime        string  `json:"CycleEndTime"`
}

// remaining applies the reference implementation's precedence: a package with
// a cycle capacity reports its cycle remainder, otherwise its absolute
// capacity remainder.
func (a billingAccount) remaining() float64 {
	var remain float64
	switch {
	case a.CycleCapacitySize > 0:
		remain = a.CycleCapacityRemain
	case a.CycleCapacityRemain > 0 || a.CycleCapacityUsed > 0:
		remain = a.CycleCapacityRemain
	default:
		remain = a.CapacityRemain
	}
	if remain < 0 {
		return 0
	}
	return remain
}

func (a billingAccount) capacity() float64 {
	if a.CycleCapacitySize > 0 {
		return a.CycleCapacitySize
	}
	return a.CapacitySize
}

// endTimeMs parses the cycle end, which is not an epoch number.
func (a billingAccount) endTimeMs() int64 {
	text := trimSpace(a.CycleEndTime)
	if text == "" {
		return 0
	}
	for _, layout := range []string{
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
		"2006-01-02",
	} {
		if parsed, err := time.Parse(layout, text); err == nil {
			return parsed.UnixMilli()
		}
	}
	return 0
}

// creditSummary is what the plugin reports to the UI.
type creditSummary struct {
	Total    float64       `json:"total"`
	Accounts []creditEntry `json:"accounts"`
}

// creditEntry is one credit package, normalised for display.
type creditEntry struct {
	PackageName string  `json:"packageName"`
	Remain      float64 `json:"remain"`
	Size        float64 `json:"size"`
	EndTimeMs   int64   `json:"endTimeMs,omitempty"`
}

// fetchCredits reads the aggregated remaining credit.
func (c *upstreamClient) fetchCredits(ctx context.Context, cred *credential) (*creditSummary, error) {
	// An enterprise account answers on a different endpoint with a single cycle
	// quota; the personal endpoint would report it as zero.
	if cred.EnterpriseID != "" {
		return c.fetchEnterpriseCredits(ctx, cred)
	}

	payload := map[string]any{
		"PageNumber":               1,
		"PageSize":                 100,
		"ProductCode":              "p_tcaca",
		"Status":                   []int{0, 3},
		"PackageEndTimeRangeBegin": time.Now().Format("2006-01-02 15:04:05"),
		"PackageEndTimeRangeEnd":   time.Now().AddDate(101, 0, 0).Format("2006-01-02 15:04:05"),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, consoleBase+"/v2/billing/meter/get-user-resource", bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cred.AccessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	if cred.UID != "" {
		req.Header.Set("X-User-Id", cred.UID)
	}
	req.Header.Set("X-Domain", defaultString(cred.Domain, "www.workbuddy.cn"))

	body, _, err := doJSON(ctx, c.http, req, jsonTimeout)
	if err != nil {
		return nil, err
	}
	env, err := readEnvelope(body)
	if err != nil {
		return nil, err
	}
	if env.Code != 0 {
		return nil, fmt.Errorf("upstream rejected the billing request: %s", env.Msg)
	}
	var doc billingDocument
	if err := json.Unmarshal(env.Data, &doc); err != nil {
		return nil, err
	}
	return summariseCredits(doc.Response.Data.Accounts), nil
}

// summariseCredits totals the packages and normalises each row.
func summariseCredits(accounts []billingAccount) *creditSummary {
	summary := &creditSummary{Accounts: make([]creditEntry, 0, len(accounts))}
	for _, account := range accounts {
		remain := account.remaining()
		summary.Total += remain
		entry := creditEntry{
			PackageName: firstNonEmptyString(account.PackageName, "(unnamed)"),
			Remain:      remain,
			Size:        account.capacity(),
		}
		entry.EndTimeMs = account.endTimeMs()
		summary.Accounts = append(summary.Accounts, entry)
	}
	return summary
}

// fetchEnterpriseCredits reads the single-cycle quota an enterprise account gets.
func (c *upstreamClient) fetchEnterpriseCredits(ctx context.Context, cred *credential) (*creditSummary, error) {
	req, err := http.NewRequest(http.MethodPost, consoleBase+"/v2/billing/meter/get-enterprise-user-usage", bytes.NewReader([]byte("{}")))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cred.AccessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User-Id", cred.UID)
	if cred.EnterpriseID != "" {
		req.Header.Set("X-Enterprise-Id", cred.EnterpriseID)
	}
	req.Header.Set("X-Domain", defaultString(cred.Domain, "www.workbuddy.cn"))

	body, _, err := doJSON(ctx, c.http, req, jsonTimeout)
	if err != nil {
		return nil, err
	}
	env, err := readEnvelope(body)
	if err != nil {
		return nil, err
	}
	if env.Code != 0 {
		return nil, fmt.Errorf("upstream rejected the enterprise billing request: %s", env.Msg)
	}
	// The two official call sites disagree on spelling; accept both.
	var quota struct {
		LimitNum float64 `json:"limitNum"`
		Limit    float64 `json:"limit_num"`
		Credit   float64 `json:"credit"`
		UsedNum  float64 `json:"used_num"`
	}
	var wrapper struct {
		Response struct {
			Data json.RawMessage `json:"Data"`
		} `json:"Response"`
	}
	payload := env.Data
	if err := json.Unmarshal(env.Data, &wrapper); err == nil && len(wrapper.Response.Data) > 0 {
		payload = wrapper.Response.Data
	}
	if err := json.Unmarshal(payload, &quota); err != nil {
		return nil, fmt.Errorf("the enterprise billing answer could not be read: %w", err)
	}
	limit := quota.LimitNum
	if limit == 0 {
		limit = quota.Limit
	}
	remaining := limit - quota.UsedNum
	if remaining < 0 {
		remaining = 0
	}
	return &creditSummary{
		Total: remaining,
		Accounts: []creditEntry{{
			PackageName: "企业额度",
			Remain:      remaining,
			Size:        limit,
		}},
	}, nil
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// refreshToken exchanges the refresh token for a new access token.
func (c *upstreamClient) refreshToken(ctx context.Context, cred *credential) (*credential, error) {
	if cred.RefreshToken == "" {
		return nil, errors.New("the access token expired and no refresh token is stored; sign in again in the WorkBuddy desktop app")
	}
	req, err := http.NewRequest(http.MethodPost, chatBase(cred)+"/v2/plugin/auth/token/refresh", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Refresh-Token", cred.RefreshToken)
	req.Header.Set("X-Auth-Refresh-Source", "workbuddy")
	if cred.UID != "" {
		req.Header.Set("X-User-Id", cred.UID)
	}
	req.Header.Set("X-Domain", defaultString(cred.Domain, "www.workbuddy.cn"))

	body, _, err := doJSON(ctx, c.http, req, jsonTimeout)
	if err != nil {
		return nil, fmt.Errorf("token refresh failed: %w", err)
	}
	env, err := readEnvelope(body)
	if err != nil {
		return nil, err
	}
	if env.Code != 0 {
		return nil, fmt.Errorf("token refresh was rejected: %s", env.Msg)
	}
	var data struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
		ExpiresIn    int64  `json:"expiresIn"`
		Domain       string `json:"domain"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		return nil, err
	}
	if data.AccessToken == "" {
		return nil, errors.New("token refresh returned no access token; sign in again in the WorkBuddy desktop app")
	}
	out := *cred
	out.AccessToken = data.AccessToken
	if data.RefreshToken != "" {
		out.RefreshToken = data.RefreshToken
	}
	if data.ExpiresIn > 0 {
		out.ExpiresAtMs = time.Now().UnixMilli() + data.ExpiresIn*1000
	}
	if data.Domain != "" {
		out.Domain = data.Domain
	}
	return &out, nil
}

// chatStream forwards a prepared chat body and returns the raw SSE response.
// The caller must close the returned body.
func (c *upstreamClient) chatStream(ctx context.Context, cred *credential, preparedBody string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, chatBase(cred)+"/v2/chat/completions", strings.NewReader(preparedBody))
	if err != nil {
		return nil, err
	}
	headers := map[string]string{
		"Accept":           "application/json, text/plain, */*",
		"Content-Type":     "application/json",
		"Authorization":    "Bearer " + cred.AccessToken,
		"X-Requested-With": "XMLHttpRequest",
		"Origin":           consoleBase,
		"Referer":          consoleBase + "/",
		"User-Agent":       chatUA,
		"X-Domain":         defaultString(cred.Domain, "www.workbuddy.cn"),
		"X-IDE-Type":       "WorkBuddy",
		"X-IDE-Name":       "WorkBuddy",
		"X-IDE-Version":    appVersion,
		"X-Product":        "SaaS",
	}
	if cred.UID != "" {
		headers["X-User-Id"] = cred.UID
	} else {
		headers["X-No-Enterprise-Id"] = "1"
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return c.http.Do(req.WithContext(ctx))
}

// prepareChatBody mirrors the reference implementation's wire quirks: the
// upstream requires streaming and rejects a structured tool_choice.
func prepareChatBody(source string) string {
	var body map[string]any
	if err := json.Unmarshal([]byte(source), &body); err != nil {
		return source
	}
	body["stream"] = true
	if toolChoice, ok := body["tool_choice"].(map[string]any); ok {
		if kind, ok := toolChoice["type"].(string); ok {
			body["tool_choice"] = kind
		}
	}
	// The developer role is not accepted by this gateway.
	if messages, ok := body["messages"].([]any); ok {
		for _, raw := range messages {
			if message, ok := raw.(map[string]any); ok && message["role"] == "developer" {
				message["role"] = "system"
			}
		}
	}
	out, err := json.Marshal(body)
	if err != nil {
		return source
	}
	return string(out)
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
