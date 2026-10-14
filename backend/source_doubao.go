// Doubao (豆包) source.
//
// STATUS: credential-only. The session cookie is fully recoverable from the
// desktop app's Chromium store without running it (see doubao_cookies.go), so
// this source can report WHICH account is signed in. It cannot proxy chat:
//
//   - Doubao's chat runs through www.doubao.com's web API, which requires
//     ByteDance's risk-control signature (a_bogus / X-Bogus / msToken) generated
//     by obfuscated, version-churning JS. That layer is unsolved.
//   - Firing UNSIGNED requests at that endpoint is not a neutral failure: since
//     2026-07 ByteDance has silently IP-banned clients that send unsigned,
//     high-frequency web requests. Auto-sending from this plugin could get the
//     user's IP banned, so SendChat refuses rather than risk it.
//
// The refusal states exactly what is missing and the documented path forward, so
// the limitation is never a silent failure.

package main

import (
	"context"
	"fmt"
	"strings"
)

const doubaoSourceID = "doubao"

type doubaoSource struct{}

func newDoubaoSource() *doubaoSource { return &doubaoSource{} }

func (s *doubaoSource) ID() string   { return doubaoSourceID }
func (s *doubaoSource) Name() string { return "豆包 Doubao" }

func (s *doubaoSource) Status(ctx context.Context) sourceStatus {
	status := sourceStatus{ID: s.ID(), Name: s.Name()}
	if app := doubaoAppPath(); app != "" {
		status.Installed = true
		status.AppPath = app
	}
	session, path, err := readDoubaoSession()
	if path != "" {
		status.Installed = true
		status.CredentialPath = path
	}
	if err != nil {
		if strings.Contains(err.Error(), "not installed") {
			status.State = "not-installed"
			status.Detail = "本机未找到豆包桌面端。"
		} else {
			status.State = "not-signed-in"
			status.Detail = "无法从豆包的 Chromium cookie 库解出会话（可能未登录）：" + err.Error()
		}
		return status
	}
	// A decrypted sessionid means an account is signed in, but chat still cannot
	// be proxied: the request-signing layer is unsolved (see file header).
	status.State = "signed-in-not-callable"
	account := session.UID
	if account == "" {
		account = session.Cookies["sessionid"]
		if len(account) > 8 {
			account = account[:8] + "…"
		}
	}
	status.Detail = fmt.Sprintf("已读到登录会话（账号 %s），但豆包的对话接口需要 a_bogus/X-Bogus 风控签名，"+
		"该签名由混淆 JS 生成、尚未复现；发送未签名请求还可能触发字节跳动的静默封 IP，因此不代理对话。", account)
	return status
}

// Models returns nothing: the callable model catalog lives behind the same
// signed web API this source cannot reach.
func (s *doubaoSource) Models(ctx context.Context) ([]modelRow, error) {
	if _, _, err := readDoubaoSession(); err != nil {
		return nil, fmt.Errorf("豆包未登录或 cookie 不可解密：%w", err)
	}
	return nil, fmt.Errorf("豆包的模型清单需通过其签名 Web 接口获取，该签名层尚未复现")
}

// SendChat always refuses; see the file header for why sending would be unsafe.
func (s *doubaoSource) SendChat(ctx context.Context, remoteModelID string, preparedBody string) (*chatResponse, error) {
	return refusal("豆包无法代理对话：其 Web 接口需要 a_bogus/X-Bogus 风控签名（混淆 JS 生成，尚未复现），" +
		"且发送未签名请求自 2026-07 起可能触发字节跳动的静默封 IP。凭据层已可读（能看到登录账号），" +
		"但要打通对话需先抓取一次真实签名流量、确认能否用纯 Go 复现签名。"), nil
}
