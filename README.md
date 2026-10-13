# WorkBuddy Connect

**把本机多个 AI 桌面 App 的模型聚合到一个 OpenAI 兼容端点,供 DBX 使用。**

装上插件、点一次「启动端点」,然后在 DBX 的 AI 设置里填两个值,模型就会出现在 DBX 的模型下拉里。

---

## 支持的应用与当前状态

| 应用 | 模型清单 | 代理对话 | 状态 |
| --- | --- | --- | --- |
| **WorkBuddy CN** | ✅ 18 个 | ✅ **可用** | 已完整验证 |
| **Trae CN** | ✅ 25 个 | ❌ 不可用 | 只能读取清单 |
| **Qoder CN** | ✅ 3 个 | ❌ 不可用 | 只能读取清单 |

### 为什么后两个只能读清单

这不是配置问题,是这两个应用的凭据设计决定的。逐一说明,以免重复调研:

**Qoder CN**
- 用户 access token **不落盘**。它自己的状态库 `%APPDATA%\com.qodercn.app.stable\main.sqlite` 里 `account_profiles`、`byok_model_credentials`、`mcp_oauth_credentials` 三张表都存在但**全为空**;旧版缓存 `~/.qoder-cn/shared_client/cache/db/local.db` 的 `supabase_token` 表同样为空。
- 磁盘上只有 `~/.qoder-cn/shared_client/cache/machine_token.json` —— 这是**机器令牌**,不是用户令牌,网关会拒绝。
- 真实推理走打包混淆的**本地守护进程**(`127.0.0.1:64003`,MCP 协议),不是本插件能代理的 HTTP 网关。
- 可读的是它实际用过的模型 key(`chat_message.model_info`、`chat_sessions.model`)。

**Trae CN**
- 模型清单就落在磁盘上:`%APPDATA%\Trae CN\User\globalStorage\state.vscdb` 的
  `<uid>_AI.agent.model.model_list_map`,107 KB,含 7 个 agent 分类(builder、chat_v3、code_reviewer…)与显示名、上下文窗口、多模态标记。
- 但该清单只有**显示名**(`Doubao-Seed-Code`、`deepseek-V3.1`),**没有可调用的请求 id**。
- **没有任何 access token**:`aha` / `ahanet` 模块只存设备 ID、访问策略和功能开关;它自己的 agent 库 `ModularData\ai-agent\database.db` 是**页级加密**的(无 SQLite 头,WAL 也读不出可读行)。

如果你希望这两个也能真正代理,需要的是**运行时从运行中的进程取令牌**这条路线(注入/挂钩),本插件有意不做这件事。

## 它怎么工作

```
DBX AI 设置                   本插件 sidecar                      本机 App
────────────                  ──────────────                      ────────
                              ┌─ workbuddy:读加密凭据并解密 ────► WorkBuddy 网关
「OpenAI Compatible」 ────────┤  qoder:读磁盘缓存的模型 key ────► (仅清单)
 端点: 127.0.0.1:xxxxx/v1     │  trae:读 state.vscdb 的清单 ─────► (仅清单)
 API Key: <随机令牌>          │
                              ├─ 合并为一份模型清单
GET  /v1/models        ◄──────┤  模型 id 带来源前缀,如 workbuddy/hy3
POST /v1/chat/completions ◄───┘  loopback 端点(仅 127.0.0.1,需 Bearer 令牌)
```

模型 id 按来源加前缀(`workbuddy/hy3`、`trae/Doubao-Seed-Code`),所以**一份 DBX 配置就能看到全部来源**,对话时按前缀路由回对应的 App。清单里无法代理的来源会被标注,选择它对话会返回 `501` 和明确原因,而不是静默失败。

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
2. 复制界面上的 **端点地址** 和 **API Key**。
3. 打开 DBX → **设置 → AI → 新建配置**:
   - 提供者:**OpenAI Compatible**
   - 端点:粘贴端点地址(形如 `http://127.0.0.1:xxxxx/v1`)
   - API Key:粘贴 API Key
   - API 风格:**completions**
4. 保存。全部来源的模型会一起出现在模型选择器里。

## 环境变量

| 变量 | 用途 |
| --- | --- |
| `WORKBUDDY_ELECTRON_BIN` | 显式指定 WorkBuddy 可执行文件路径。装到非标准位置或自动探测失败时使用。 |
| `DBX_WORKBUDDY_DEBUG` | 设为任意值后,把每次 RPC 方法调用打到 stderr,便于排查。 |

工作台底部的「诊断」区域会显示实际使用的凭据文件与程序路径。

## 安全模型

- **端点只监听 `127.0.0.1`**,并要求 `Authorization: Bearer <随机令牌>`。回环地址本身不是信任边界(同机进程和 DNS rebinding 页面都能访问),所以令牌是必需的。
- **令牌与凭据副本以 0600 权限写入插件自己的数据目录**,不外传。
- **插件只访问各 App 自己的网关**(腾讯 `copilot.tencent.com` / `codebuddy.cn`),没有其他出站目标。
- **读取别的应用的数据库一律以只读 + `query_only` 方式打开**,不会写入、加锁或迁移它们的数据。
- **读取 WorkBuddy 加密凭据需要运行一次它自身的可执行文件**(用它的私有 `electron_browser_workbuddy_storage` 绑定取 at-rest 密钥)。这是该凭据设计的唯一解,不涉及注入或内存读取。
- 本插件**不会修改**任何被代理应用的文件,也不会改动 DBX 的配置。

## 已知限制

- DBX 没有给插件提供「注册模型供应商」的接口,所以**必须手工做一次第 3 步的配置**。这是宿主能力边界,不是插件缺陷。
- Qoder CN 与 Trae CN **只能读取模型清单,无法代理对话**(原因见上)。
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

## 免责声明

仅供个人学习研究,仅驱动使用者**自己的**账号在本机调用。请遵守各应用的服务条款。本项目与 WorkBuddy/腾讯、Qoder/阿里云、Trae/字节跳动均无关联。

本项目的 WorkBuddy 加密实现与上游协议细节参考了 [`dsh-workbuddy-connect`](https://github.com/corrinehu/dsh-workbuddy-connect)(MIT),在此致谢。

## 许可

Apache-2.0,见 [LICENSE](LICENSE)。
