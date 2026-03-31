# X-Stainless 请求头与检测向量分析

> 更新日期：2026-03-31
> 基于 clewdr v2.1.86 与真实 Claude Code CLI v2.1.88 的对比分析

---

## 背景

之前的 `fingerprint_fix_plan.md` 将 X-Stainless 头标记为"暂不修复"，理由是"CLI 二进制可能不发送"。
但经过进一步验证，**真实 Claude Code CLI 确实发送 X-Stainless 头**，因为它内部使用 `@anthropic-ai/sdk` TypeScript SDK，
该 SDK 由 Stainless 代码生成器构建，会自动注入这些头。

## 发送到 Anthropic API 的请求头对比

| Header | clewdr（当前） | 真实 CLI |
|--------|---------------|---------|
| `Authorization` | `Bearer {token}` ✅ | `Bearer {token}` |
| `User-Agent` | `claude-code/2.1.86` ❌ 版本旧 | `claude-code/2.1.88` |
| `anthropic-beta` | 动态合并 ✅ | 动态合并 |
| `anthropic-version` | `2023-06-01` ✅ | `2023-06-01` |
| `x-stainless-lang` | ❌ 缺失 | `js` |
| `x-stainless-package-version` | ❌ 缺失 | SDK 版本号（如 `0.80.0`） |
| `x-stainless-os` | ❌ 缺失 | `MacOS` / `Linux` / `Windows` |
| `x-stainless-arch` | ❌ 缺失 | `arm64` / `x64` |
| `x-stainless-runtime` | ❌ 缺失 | `node`（Bun 报告为 node） |
| `x-stainless-runtime-version` | ❌ 缺失 | Node/Bun 版本号 |
| `x-stainless-retry-count` | ❌ 缺失 | `0`（首次请求） |

## Billing Header 对比

```
# clewdr 当前格式
x-anthropic-billing-header: cc_version=2.1.86.{hash}; cc_entrypoint=unknown; cch=00000;

# 真实 CLI 格式
x-anthropic-billing-header: cc_version=2.1.88.{hash}; cc_workload={value}; cc_entrypoint={env}; cch=00000;
```

差异：
1. 版本号：`2.1.86` → `2.1.88`
2. 缺少 `cc_workload` 字段（来自 AsyncLocalStorage，通常有值）
3. 字段顺序：`cc_workload` 应在 `cc_entrypoint` 之前

## 检测原理

Anthropic 服务端可以通过以下方式检测代理：

1. **X-Stainless 头缺失**：所有通过 Anthropic SDK 发出的请求都带有这些头。如果 `User-Agent` 声称是 `claude-code/*` 但没有 stainless 头，则明显不是真正的 SDK 客户端。
2. **版本号过旧**：Claude Code CLI 频繁更新，旧版本号是异常信号。
3. **cc_workload 缺失**：billing header 中缺少此字段也是一个信号。
4. **TLS 指纹**：wreq 模拟的是浏览器 TLS，而非 Node.js/Bun 的 TLS 栈。

## 修复方案

### 优先级 1：添加 X-Stainless 请求头

**文件**：`src/claude_code_state/chat.rs`（`execute_claude_request` 和 `execute_claude_count_tokens_request`）

在发送到 Anthropic API 的请求中添加：
```rust
.header("x-stainless-lang", "js")
.header("x-stainless-package-version", ANTHROPIC_SDK_VERSION)
.header("x-stainless-os", stainless_os())
.header("x-stainless-arch", stainless_arch())
.header("x-stainless-runtime", "node")
.header("x-stainless-runtime-version", NODE_VERSION)
.header("x-stainless-retry-count", "0")
```

### 优先级 2：更新版本号

**文件**：`src/config/constants.rs`
- `CLAUDE_CODE_VERSION` → `"2.1.88"`
- `CLAUDE_CODE_USER_AGENT` → `"claude-code/2.1.88"`

### 优先级 3：补充 cc_workload 字段

**文件**：`src/middleware/claude/request.rs`（`claude_code_billing_header` 函数）

在 billing header 中添加 `cc_workload` 字段。

### 优先级 4：TLS 指纹（暂不修复）

wreq 不支持模拟 Node.js/Bun 的 TLS 栈。浏览器模拟的 TLS 对 CDN 更友好，风险较低。
