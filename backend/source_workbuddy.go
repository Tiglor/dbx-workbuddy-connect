// WorkBuddy source: reuses the desktop app's local sign-in.
//
// This is the fully callable source. The app writes a decryptable credential
// envelope next to itself (see atrest.go), so both the catalog and chat work
// without any user action beyond being signed in.

package main

import (
	"context"
	"fmt"
)

const workbuddySourceID = "workbuddy"

type workBuddySource struct {
	client *upstreamClient
	store  *credentialStore
}

func newWorkBuddySource(client *upstreamClient, store *credentialStore) *workBuddySource {
	return &workBuddySource{client: client, store: store}
}

func (s *workBuddySource) ID() string   { return workbuddySourceID }
func (s *workBuddySource) Name() string { return "WorkBuddy" }

// Status reports sign-in state without contacting the network.
func (s *workBuddySource) Status(ctx context.Context) sourceStatus {
	status := sourceStatus{ID: s.ID(), Name: s.Name()}
	path, format, err := s.store.resolvedDesktopAuthPath()
	status.CredentialPath = path
	if app, appErr := resolveElectronPath(); appErr == nil {
		status.AppPath = app
		status.Installed = true
	}
	if err != nil {
		status.State = "error"
		status.Detail = err.Error()
		return status
	}
	if path == "" {
		status.State = "not-signed-in"
		status.Detail = "未找到 WorkBuddy 的登录文件;请先打开并登录 WorkBuddy 桌面 App。"
		return status
	}
	auth := s.store.status(ctx)
	if auth.State != "signed-in" {
		status.State = "not-signed-in"
		status.Detail = auth.Reason
		return status
	}
	status.Installed = true
	status.Callable = true
	status.State = "ready"
	status.Detail = fmt.Sprintf("已登录(凭据格式 %s)", format)
	return status
}

func (s *workBuddySource) Models(ctx context.Context) ([]modelRow, error) {
	cred, err := s.store.resolve(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.client.fetchModels(ctx, cred)
	if err != nil {
		return nil, err
	}
	out := make([]modelRow, 0, len(rows))
	for _, row := range rows {
		item := modelRow{
			ID:               namespaceModel(s.ID(), row.ID),
			RemoteID:         row.ID,
			Source:           s.ID(),
			Name:             firstNonEmpty(row.Name, row.ID),
			ContextWindow:    row.MaxInputTokens,
			MaxTokens:        row.MaxOutputTokens,
			SupportsImages:   row.SupportsImages && !row.DisabledMultimodal,
			SupportsToolCall: row.SupportsToolCall,
			Vendor:           row.Vendor,
		}
		if row.Reasoning != nil && row.Reasoning.Supports {
			item.Efforts = row.Reasoning.SupportedEfforts
			item.DefaultEffort = row.Reasoning.DefaultEffort
		}
		out = append(out, item)
	}
	return out, nil
}

func (s *workBuddySource) SendChat(ctx context.Context, remoteModelID string, preparedBody string) (*chatResponse, error) {
	cred, err := s.store.resolve(ctx)
	if err != nil {
		return nil, err
	}
	body, err := replaceModel(preparedBody, remoteModelID)
	if err != nil {
		return nil, err
	}
	res, err := s.client.chatStream(ctx, cred, body)
	if err != nil {
		return nil, err
	}
	return &chatResponse{
		StatusCode:  res.StatusCode,
		ContentType: res.Header.Get("Content-Type"),
		Body:        res.Body,
	}, nil
}
