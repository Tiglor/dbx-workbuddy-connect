# 本机 AI 应用凭据与模型来源侦察结论

本文记录对四个目标应用(WorkBuddy CN、Qoder CN、TraeWork CN、豆包)的调查结果,
说明每个应用**能不能被代理**、以及不能的原因。目的是避免重复调研。

结论以本机实测为准(2026-10-13)。

---

## 总览

| 应用 | 模型清单 | 代理对话 | 凭据来源 | 结论 |
| --- | --- | --- | --- | --- |
| **WorkBuddy CN** | ✅ 18 个(实时) | ✅ **可用** | 加密凭据文件 + App 私有绑定取密钥 | 已完整实现并验证 |
| **Trae CN** | ✅ 25 个(缓存) | ❌ | 无 | 仅清单 |
| **Qoder CN** | ✅ 3 个(历史记录) | ❌ | 仅机器令牌 | 仅清单 |
| **豆包** | ❓ | ❓ | **Chromium cookies,可解密** | 凭据已解开,请求签名层未解决 |

---

## WorkBuddy CN ✅ 可代理

- 版本 5.8.2,`%LOCALAPPDATA%\Programs\WorkBuddy\WorkBuddy.exe`
- 凭据:`%LOCALAPPDATA%\CodeBuddyExtension\Data\Public\auth\workbuddy-desktop.info`
- 5.6+ 起为加密信封:

```
字段形如 {"$wbEncrypted":1,"envelope":"<base64url(JSON)>"}
envelope = {suite, keyId, nonce(12B,标准base64), authTag(16B,标准base64), ciphertext(标准base64)}
protectorKey = SHA256(atRestSecretKey)          # secret 是 32B base64 字符串的 UTF-8
keyId        = hex(SHA256(protectorKey))[:16]
AAD          = "WB-AAD\0" | 0x01 | len32("WBEV1") | len32("sym-v1") | u32(suite) | len32(keyId) | 0x02 0x00 0x00
明文         = AES-256-GCM(key=protectorKey, nonce, ct||tag, aad)
```

- `atRestSecretKey` **无法从任何文件推导**,只能让 WorkBuddy 自身的可执行文件执行
  `process._linkedBinding("electron_browser_workbuddy_storage").loggerGet()` 取得。
  这是本插件需要原生 sidecar 的根本原因。
- 上游网关(逐字捕获):

| 用途 | 端点 | 关键头 |
| --- | --- | --- |
| 模型目录 | `GET https://copilot.tencent.com/v3/config` | `UA: CLI/2.63.2 CodeBuddy/2.63.2` |
| 促销标签 | `GET https://copilot.tencent.com/console/enterprises/personal/models` | 同上 |
| 额度 | `POST https://www.codebuddy.cn/v2/billing/meter/get-user-resource` | `X-User-Id`、`X-Domain` |
| 对话 | `POST https://copilot.tencent.com/v2/chat/completions` | `X-IDE-*`、`X-Product: SaaS`、`UA: WorkBuddy/5.5.6` |
| 刷新令牌 | `POST {chatBase}/v2/plugin/auth/token/refresh` | `X-Refresh-Token`、`X-Auth-Refresh-Source: workbuddy` |

- **模型会员规则**(关键):`data.agents` 中 `name == "cli"` 的 `models` 数组与
  `data.models` 取交集;`data.models` 单独用会多出 15 个(图像模型、`default` 哨兵、
  已退役行)。过滤条件:`maxInputTokens > 0 && maxOutputTokens > 0 && !disabled`。
- **额度文档是四层嵌套 + PascalCase**:
  `data.Response.Data.Accounts[]`,字段 `CycleCapacitySize` / `CycleCapacityRemain` /
  `CycleCapacityUsed` / `CapacityRemain` / `EndTimeMs`;`total` 不是返回字段,而是逐条累加。
- 注意:`data.models[].credits` 是**字符串**而非数字,严格的 float64 字段会让整个目录解析失败。

---

## Trae CN ❌ 仅清单

- `D:\Trae CN`(安装目录只剩 `debug.log`,主程序不在此)
- 模型清单:`%APPDATA%\Trae CN\User\globalStorage\state.vscdb` →
  `<uid>_AI.agent.model.model_list_map`,约 107 KB:

```
7 个 agent 分类: builder / builder_v3 / chat_v3 / code_reviewer /
                code_review_summary / refactor / solo_agent
每行: name, display_name, multimodal, is_default, prompt_max_tokens,
      context_window_size{max,default}, model_type, custom_config ...
```

- **`context_window_size.max` 在部分行是数字、部分行是数组**,严格 int 字段会让整份清单无法解析。
- **清单只有显示名**(`Doubao-Seed-Code`、`deepseek-V3.1`),**没有可调用的请求 id**。
- **无任何 access token**:`aha` / `ahanet` 只存设备 ID(`device_id`)、访问策略
  (`aha_access_policy`)与功能开关;`ModularData\ai-agent\database.db` 是**页级加密**
  (无 `SQLite format 3` 头,WAL 可打印率 0.37、无 `CREATE TABLE`)。

---

## Qoder CN ❌ 仅清单

- `D:\Qoder CN\Qoder CN.exe`(225 MB,Electron,app.asar 141 MB)
- 状态库:`%APPDATA%\com.qodercn.app.stable\main.sqlite` —— 有
  `account_profiles`、`byok_model_credentials`、`mcp_oauth_credentials`、
  `chat_model_preferences`、`byok_model_profiles` 等表,但**全部 0 行**。
- 旧缓存:`~/.qoder-cn/shared_client/cache/db/local.db` 的 `supabase_token` 表**同样为空**。
- 唯一落盘的令牌是 `~/.qoder-cn/shared_client/cache/machine_token.json`
  (`{token, type, updateAt}`)—— **机器令牌,非用户令牌**,网关会拒绝。
- 真实推理走打包混淆的**本地守护进程**(`127.0.0.1:64003`,MCP 协议),不是 HTTP 网关。
- 可读:它实际用过的模型 key(`chat_message.model_info` → `{"model_key":"auto"}`、
  `chat_sessions.model` → `qfmodel` / `auto`)。
- **另注**:DBX 内置了 `Qoder CLI` 供应商,配 `qoderCliPath`。那才是 DBX 用 Qoder 的
  官方路径,不需要本插件。本机未安装 Qoder CLI。

---

## 豆包 ⚠️ 凭据已解开,请求签名层未解决

- `D:\Doubao\Doubao.exe` v2.31.4,**Chromium 内核**
- 用户数据:`%LOCALAPPDATA%\Doubao\User Data`

### 凭据层 —— 已解决,且不需要运行豆包

标准 Chromium on Windows 方案:

```
Local State → os_crypt.encrypted_key = base64, 前缀 b"DPAPI"
  → CryptUnprotectData(CurrentUser) → 32 字节主密钥
Network\Cookies → encrypted_value = "v10" | nonce(12) | ciphertext | tag(16)
  → AES-256-GCM(主密钥, nonce, ct||tag) → 明文
明文前 32 字节为固定头(两个 16 字节常量),真实值从偏移 32 开始
```

实测解出(35 个 cookie 全部为 `v10`):

```
sessionid            = 83a661a631dda4bd26b94af330499caa
sid_guard            = 83a661a631dda4bd26b94af330499caa%7C1791594627%7C2592000%7C...
sid_tt / uid_tt      = 可读
ttwid                = 1%7CCKqyIcZyuFQt6fxZZGrDGQkVQMP_PNBM1BSOesd3rbQ%7C1791773838%7C...
odin_tt / multi_sids / passport_csrf_token = 可读
```

**验证方法**:用错误密钥解密会 `unable to authenticate` 失败(GCM tag 校验通过),
所以解出的明文是真的,不是巧合。

### 未解决层 —— 请求签名与端点

- 豆包走的是 `www.doubao.com` 的 Web 接口,带字节跳动的风控签名参数
  (`msToken`、`a_bogus` / `X-Bogus` 等),这些由混淆 JS 生成。
- 该层**不是凭据问题**,需要另行研究端点与签名算法,且随版本变动风险高。
- 目前**没有**在插件里实现豆包来源。

若要继续推进豆包,建议路径(按代价递增):

1. 抓一次真实对话流量,确认端点、请求体形状与签名参数集合;
2. 判断签名能否用纯 Go 复现;
3. 不可行时,才考虑复用其本地 JS 运行时生成签名。

---

## 对插件的含义

- `workbuddy` 来源:完整实现,18 个模型可对话。
- `qoder` / `trae` 来源:只读清单,对话请求返回 `501` 与明确原因(不是静默失败)。
- `doubao` 来源:未实现;凭据层技术已验证,瓶颈在请求签名层。
- 所有对他人数据库的读取都以**只读 + `query_only`** 打开,不写入、不加锁、不迁移。
