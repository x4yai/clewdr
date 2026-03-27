# 客户端指纹差异修复方案

## 概述

通过对真实 Claude Code CLI v2.1.84 二进制和 VS Code 扩展 extension.js 的逆向分析，发现 clewdr 与真实客户端存在以下关键差异。本文档列出每个差异的修复方案。

---

## 差异 1：版本号过旧（高优先级）

| | clewdr | 真实 CLI |
|--|--------|---------|
| VERSION | `2.1.76` | `2.1.84` |
| USER_AGENT | `claude-code/2.1.76` | `claude-code/2.1.84` |

### 修复
- 文件：`src/config/constants.rs:21-22`
- `CLAUDE_CODE_VERSION` → `"2.1.84"`
- `CLAUDE_CODE_USER_AGENT` → `"claude-code/2.1.84"`

### 影响
billing header 的 hash 会随版本变化（`SHA256(salt + sampled + VERSION)[0:3]`），更新版本号后 hash 会自动正确。

---

## 差异 2：entrypoint 默认值错误（高优先级）

| | clewdr | 真实 CLI |
|--|--------|---------|
| 默认 entrypoint | `"cli"` | `"unknown"` |

### 发现
真实 CLI 从环境变量 `CLAUDE_CODE_ENTRYPOINT` 读取，如果未设置则默认 `"unknown"`。VS Code 扩展设置为 `"claude-vscode"`。

### 修复
- 文件：`src/middleware/claude/request.rs:131-134`
- 将 fallback 从 `"cli"` 改为 `"unknown"`

### 测试影响
`request.rs:427` 测试用例中硬编码了 `cc_entrypoint=cli`，需要同步更新为 `cc_entrypoint=unknown`。

---

## 差异 3：anthropic-beta 基础值不匹配（高优先级）

| | clewdr | 真实 CLI |
|--|--------|---------|
| CLAUDE_BETA_BASE | `"oauth-2025-04-20"` | `"claude-code-20250219"` |

### 发现
真实 CLI 二进制中 `oauth-2025-04-20` **完全不存在**。核心 beta 标志是 `claude-code-20250219`，配合 `interleaved-thinking-2025-05-14` 等功能标志动态组合。

VS Code 扩展中 `oauth-2025-04-20` 用于 **OAuth 认证流程**（exchange.rs 中的 OauthClient），而不是消息请求。

### 修复
- 文件：`src/claude_code_state/chat.rs:23`
- 将 `CLAUDE_BETA_BASE` 从 `"oauth-2025-04-20"` 改为 `"claude-code-20250219"`
- 新增常量 `CLAUDE_BETA_OAUTH` = `"oauth-2025-04-20"` 仅用于 OAuth 流程
- `exchange.rs:30` 中引用改为 `CLAUDE_BETA_OAUTH`

### 附加 beta 标志
真实 CLI 在消息请求中动态组合多个 beta 标志。最关键的是：
- `interleaved-thinking-2025-05-14`（交错思考）
- `context-1m-2025-08-07`（1M 上下文，clewdr 已有）

clewdr 的 `merge_anthropic_beta_header` 已经支持从客户端请求中合并额外 beta（通过 `extra` 参数），所以只需修正基础值。

---

## 差异 4：OAuth URL 过时（中优先级）

| | clewdr | 真实客户端 |
|--|--------|-----------|
| TOKEN_URL | `api.anthropic.com/v1/oauth/token` | `platform.claude.com/v1/oauth/token` |
| REDIRECT_URI | `console.anthropic.com/oauth/code/callback` | `platform.claude.com/oauth/code/callback` |

### 修复
- 文件：`src/config/constants.rs:19-20`
- `CC_TOKEN_URL` → `"https://platform.claude.com/v1/oauth/token"`
- `CC_REDIRECT_URI` → `"https://platform.claude.com/oauth/code/callback"`

### 风险
旧 URL 可能仍然有效（重定向），但使用新 URL 更符合真实客户端行为。

---

## 差异 5：缺少 interleaved-thinking beta（中优先级）

真实 CLI 在消息请求中始终包含 `interleaved-thinking-2025-05-14`。

### 修复
- 文件：`src/claude_code_state/chat.rs`
- 在 `merge_anthropic_beta_header` 中，将 `interleaved-thinking-2025-05-14` 作为默认 beta 之一

---

## 差异 6：billing header 中的 cch 值（低优先级，已一致）

clewdr 的 `cch=00000` 与真实 CLI 一致，无需修改。

---

## 差异 7：TLS 指纹不匹配（信息记录，暂不修复）

| | clewdr | 真实 CLI |
|--|--------|---------|
| TLS 栈 | wreq + Chromium Emulation | Bun 内置 TLS |

真实 Claude Code CLI 使用 Bun 运行时内置的 TLS，不是 Chrome/Firefox 的 TLS 指纹。clewdr 用 Chromium 模拟的 TLS 指纹反而可能更不容易被屏蔽（CDN 对浏览器更友好），暂不修改。

---

## 差异 8：缺少 X-Stainless-* Headers（信息记录，暂不修复）

VS Code 扩展通过 Anthropic JS SDK 发送 `X-Stainless-Lang`、`X-Stainless-OS` 等 headers。这些是 SDK 特有的遥测 header，CLI 二进制（Bun 运行时）可能不发送。Claude Code 路径模拟的是 CLI 而非 VS Code 扩展，暂不添加。

---

## 修复实施清单

| 编号 | 差异 | 文件 | 优先级 |
|------|------|------|--------|
| 1 | 版本号 2.1.76→2.1.84 | `constants.rs:21-22` | 高 |
| 2 | entrypoint cli→unknown | `request.rs:134` | 高 |
| 3 | beta 基础值 | `chat.rs:23`, `exchange.rs:30` | 高 |
| 4 | OAuth URL | `constants.rs:19-20` | 中 |
| 5 | interleaved-thinking beta | `chat.rs` | 中 |
| 6 | cch 值 | — | 已一致 |
| 7 | TLS 指纹 | — | 暂不修复 |
| 8 | X-Stainless headers | — | 暂不修复 |
