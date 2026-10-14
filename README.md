# WorkBuddy Connect

**把本机多个 AI 桌面 App 的模型聚合到一个 OpenAI 兼容端点,供 DBX 使用。**

装上插件、点一次「启动端点」,然后在 DBX 的 AI 设置里填两个值,模型就会出现在 DBX 的模型下拉里。

---

## 支持的应用与当前状态

| 应用 | 模型清单 | 代理对话 | 状态 |
| --- | --- | --- | --- |
| **WorkBuddy CN** | ✅ | ✅ **可用** | 读桌面凭据,已完整验证 |
| **Qoder CN** | ✅ 登录后实时 | ✅ **可用(需登录)** | 工作台点「登录 Qoder」跑设备授权 |
| **Trae CN** | ✅ 登录后实时 | ✅ **可用(需登录)** | 工作台点「登录 Trae」跑 OAuth |
| **豆包 Doubao** | ❌ | ❌ **有意拒绝** | 能读到登录账号,但签名层未解 |

### 三个来源分别怎么打通

**WorkBuddy CN** —— 读桌面 App 落盘的加密凭据并解密(需运行一次它的可执行文件取 at-rest 密钥),直接代理对话。

**Qoder CN** —— 用户令牌不落盘,所以插件自己跑官方的**设备授权 OAuth**(PKCE-S256 + `deviceToken` poll/refresh)。在工作台点「登录 Qoder」→ 浏览器授权 → 插件轮询拿到令牌。之后实时读取网关模型清单,并用 **COSY 签名**代理对话(网关的嵌套 SSE 信封会翻译成标准 OpenAI SSE)。

**Trae CN** —— 令牌同样不落盘。插件在 `127.0.0.1:<port>/authorize` 起一个**本地回环监听**(授权页硬性要求这个回调形态),点「登录 Trae」→ 浏览器授权后回调把 auth code 送回监听 → 换成 Cloud-IDE-JWT。会生成并持久化一对 **ECDSA 设备密钥**(ExchangeToken 要求非空 `DevicePublicKey`,且服务端按账号绑定/限制设备数,故必须复用同一身份)。对话走 `llm_utils_chat`,事件流翻译成 OpenAI SSE。

**豆包 Doubao** —— 桌面端是 Chromium 内核,会话 cookie 可用标准方式解密(DPAPI 解出主密钥 + AES-256-GCM 解 `v10` cookie),因此**能读到当前登录账号**。但对话接口需要字节跳动的风控签名(`a_bogus`/`X-Bogus`/`msToken`,由混淆 JS 生成、随版本变动),尚未复现;而且自 2026-07 起对未签名高频 Web 请求会**静默封 IP**。所以插件**明确拒绝对话并说明原因**,而不是冒险发一个可能被连累封 IP 的请求。

> 协议常量与算法移植自 MIT 许可的 [`mmqz/cpa-multi-plugins`](https://github.com/mmqz/cpa-multi-plugins)(© 2026 Sliverkiss/mmqz),为独立移植、未逐行复制,署名见 `NOTICE`。

### 验证边界(诚实说明)

四个来源均已通过 `go build` / `go vet`。WorkBuddy 已用真实账号端到端验证;Qoder / Trae 的**实际对话**需要你在浏览器完成一次真实登录后才能端到端验证(本仓库只做到编译与自检层面)。豆包对话为有意未实现。

## 它怎么工作

```
DBX AI 设置                   本插件 sidecar                      本机 App / 网关
────────────                  ──────────────                      ──────────────
                              ┌─ workbuddy:解密桌面凭据 ─────────► WorkBuddy 网关
「OpenAI Compatible」 ────────┤  qoder:设备授权登录 + COSY 签名 ──► Qoder 网关
 端点: 127.0.0.1:xxxxx/v1     │  trae:回环 OAuth + Cloud-IDE-JWT ─► Trae 网关
 API Key: <随机令牌>          │  doubao:解 cookie 读账号(不对话)
                              ├─ 合并为一份模型清单
GET  /v1/models        ◄──────┤  模型 id 带来源前缀,如 workbuddy/hy3
POST /v1/chat/completions ◄───┘  loopback 端点(仅 127.0.0.1,需 Bearer 令牌)
```

模型 id 按来源加前缀(`workbuddy/hy3`、`qoder/<key>`、`trae/<config_name>`),所以**一份 DBX 配置就能看到全部来源**,对话时按前缀路由回对应网关。无法代理的来源(未登录、或豆包)会被标注,选择它对话会返回明确原因而不是静默失败。

## 安装

### 从插件中心安装(签名的正式包)

在本仓库 Release 页面下载 `.dbxp`,或在 DBX 插件中心搜索。签名包由 DBX Store 审核后发布。

### 本地开发安装(未签名)

1. 下载本仓库 Release 里的 `*-windows-x64.dbxp`(或自行构建)。
2. DBX → 插件中心 → 设置 → 第三方与开发者选项 → 打开「允许安装未签名开发包」。
3. 点「安装 `.dbxp`」选择该文件。
4. 回到「已安装」,打开 **WorkBuddy Connect** 工作台。

## 使用

1. 工作台里点 **启动端点**。若 WorkBuddy 未登录,请先打开并登录它。
2. (可选)在「模型来源」里对 **Qoder** / **Trae** 点 **登录**,浏览器完成授权后即可代理它们的对话。豆包无需登录(自动读 cookie),但不对话。
3. 复制界面上的 **端点地址** 和 **API Key**。
4. 打开 DBX → **设置 → AI → 新建配置**:
   - 提供者:**OpenAI Compatible**
   - 端点:粘贴端点地址(形如 `http://127.0.0.1:xxxxx/v1`)
   - API Key:粘贴 API Key
   - API 风格:**completions**
5. 保存。全部来源的模型会一起出现在模型选择器里。

## 环境变量

| 变量 | 用途 |
| --- | --- |
| `WORKBUDDY_ELECTRON_BIN` | 显式指定 WorkBuddy 可执行文件路径。装到非标准位置或自动探测失败时使用。 |
| `TRAE_APP_PATH` | 显式指定 Trae CN 可执行文件路径(如 `D:\Trae CN\Trae CN.exe`)。装到非标准位置时使用。 |
| `DOUBAO_APP_PATH` | 显式指定豆包可执行文件路径(如 `D:\Doubao\Doubao.exe`)。装到非标准位置时使用。 |
| `DBX_WORKBUDDY_DEBUG` | 设为任意值后,把每次 RPC 方法调用打到 stderr,便于排查。 |
| `QODER_REGION` | 设为 `intl` 走 Qoder 国际站(qoder.com / openapi.qoder.sh);默认 `cn`(qoder.cn)。 |

工作台底部的「诊断」区域会显示实际使用的凭据文件与程序路径。

## 安全模型

- **端点只监听 `127.0.0.1`**,并要求 `Authorization: Bearer <随机令牌>`。回环地址本身不是信任边界(同机进程和 DNS rebinding 页面都能访问),所以令牌是必需的。
- **令牌与凭据副本以 0600 权限写入插件自己的数据目录**,不外传。Qoder/Trae 登录后拿到的令牌同样只存本地(`qoder-token.json` / `trae-token.json` / `trae-device.json`)。
- **出站目标仅限各 App 自己的官方域名**:WorkBuddy(腾讯)、Qoder(`qoder.cn` / `qoder.com.cn` / `qoder.sh`)、Trae(`trae.cn` / `trae.com.cn` / `mchost.guru`)。豆包**不产生任何出站请求**(只本地读 cookie)。
- **登录走官方授权页,不是模拟登录**:Qoder 用设备授权,Trae 用 `127.0.0.1` 回环 OAuth 回调;插件不碰你的账号密码,也不做进程注入/内存读取。
- **读取别的应用的数据库一律以只读 + `query_only` 方式打开**,不会写入、加锁或迁移它们的数据。
- **读取 WorkBuddy 加密凭据需要运行一次它自身的可执行文件**(用它的私有 `electron_browser_workbuddy_storage` 绑定取 at-rest 密钥)。这是该凭据设计的唯一解。
- 本插件**不会修改**任何被代理应用的文件,也不会改动 DBX 的配置。

### 凭证归属与共用

**每个来源代理的都是"使用者自己"的凭证,插件里没有任何内置或共享的账号。**

| 来源 | 凭证从哪来 | 归属 |
| --- | --- | --- |
| WorkBuddy | 读**本机**桌面 App 落盘的加密凭据 | 本机登录的账号 |
| Qoder | 使用者在浏览器跑设备授权登录 | 登录者本人账号 |
| Trae | 使用者在浏览器跑回环 OAuth 授权 | 登录者本人账号 |
| 豆包 | 解**本机** Chromium cookie 库 | 本机登录的账号 |

拿到的令牌只存在**本机**插件数据目录(`%LOCALAPPDATA%\dbx-plugins\io.github.workbuddy.connect\`,0600),回环端点也只转发给这台机器已登录的账号。**不存在跨人共享的凭证池。**

- **分发 `.dbxp` 插件包给同事 → 可以。** 包里只有代码,不含你的 token;同事装上后各自登录各自账号,各用各的额度。
- **共享你的个人凭证 → 不要。** 那需要手动把数据目录里的 `*-token.json` 拷给别人,等于泄露 Bearer 令牌、违反各应用服务条款;Trae 还会因服务端按账号绑定/限制设备数而触发风控。
- 建议只在**内网点对点**分发,不要公开大范围传播(这些是对厂商私有网关的逆向代理)。

## 已知限制

- DBX 没有给插件提供「注册模型供应商」的接口,所以**必须手工做一次上面的 AI 配置**。这是宿主能力边界,不是插件缺陷。
- **Qoder / Trae 需要在工作台各登录一次**;令牌会持久化并按需自动刷新(Qoder 用 refresh_token,Trae 用 legacy 刷新路径)。Trae 账号有设备数上限,插件复用同一份持久化设备身份以避免占满。
- **豆包无法代理对话**:签名层(`a_bogus`/`X-Bogus`)未复现,且未签名请求有被静默封 IP 的风险,故有意拒绝(详见上文)。
- WorkBuddy 取密钥必须能启动它的可执行文件;若缺失或被安全策略阻止,可设置 `WORKBUDDY_ELECTRON_BIN`。
- 重启 sidecar 后端口保持不变(状态文件会记住),但若该端口被占用则改用空闲端口,此时 DBX 里那条配置需同步更新。

## 开发

需要 Go 1.22+ 与 Node.js 22+(后者仅用于 `dbx-plugin dev` 开发宿主)。

```bash
# 浏览器开发宿主,不需要启动 DBX
dbx-plugin dev --path . --port 5190

# 打包未签名候选包
dbx-plugin package .

# 自检(不需要 DBX):直接跑插件自身的代码路径
  <sidecar> --status     登录状态与探测到的路径
  <sidecar> --sources    每个来源的状态与模型数
  <sidecar> --models     合并后的清单,按来源分组
  <sidecar> --credits    WorkBuddy 剩余额度
```

SDK 已 vendor 到 `backend/dbx-plugin-sdk/`,`go.mod` 用相对路径引用,克隆即可构建。SQLite 读取使用纯 Go 驱动(`modernc.org/sqlite`),因此不需要 CGO、可从一台机器交叉编译到全部 DBX 目标平台。

### 仓库卫生

构建产物与本机/IDE 配置一律不入库,已在 `.gitignore` 里排除:

- `dist/`(打包出的 `.dbxp` 与 artifact 元数据,均可由源码重新构建)。
- `backend/*.exe`、`backend/dbx-workbuddy-connect`(sidecar 编译产物;打包器从源码现编,仓库里放旧二进制会被误打进包)。
- `.dbx-dev/`(`dbx-plugin dev` 开发宿主的本机缓存)。
- `.idea/`、`.vscode/`、`*.iml`(逐人逐机的 IDE 配置)。
- `.dbx-repository-signing-key.env`(签名密钥,绝不能提交)。

贡献时 `git status` 应只出现源码/文档改动;若冒出上面这些,说明忽略规则被改坏了。

## 免责声明

仅供个人学习研究,仅驱动使用者**自己的**账号在本机调用。请遵守各应用的服务条款。本项目与 WorkBuddy/腾讯、Qoder/阿里云、Trae/字节跳动、豆包/字节跳动均无关联。

本项目的 WorkBuddy 加密实现与上游协议细节参考了 [`dsh-workbuddy-connect`](https://github.com/corrinehu/dsh-workbuddy-connect)(MIT);Qoder 与 Trae 的协议常量与算法移植自 [`mmqz/cpa-multi-plugins`](https://github.com/mmqz/cpa-multi-plugins)(© 2026 Sliverkiss/mmqz,MIT),均为独立移植、未逐行复制。完整署名见 [NOTICE](NOTICE)。

## 许可

Apache-2.0,见 [LICENSE](LICENSE)。
