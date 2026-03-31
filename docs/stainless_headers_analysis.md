# X-Stainless 请求头与检测向量分析

> 更新日期：2026-03-31
> 基于真实 Claude Code CLI v2.1.88 请求捕获（详见 `claude_code_cli_real_request_capture.md`）
> 状态：**大部分已修复**

---

## 背景

通过本地 HTTP 捕获服务器截获真实 Claude Code CLI 发出的请求，发现多项 header 和 body 字段差异。
已完成的修复和剩余问题记录如下。

## 已完成的修复（本次提交）

### 1. User-Agent 格式修正 ✅
- 旧值：`claude-code/2.1.88`
- 新值：`claude-cli/2.1.88 (external, cli)`

### 2. X-Stainless 版本号修正 ✅
- `x-stainless-package-version`：`0.80.0` → `0.74.0`
- `x-stainless-runtime-version`：`22.13.1` → `v24.3.0`（加 `v` 前缀）

### 3. 新增缺失 Headers ✅
- `anthropic-dangerous-direct-browser-access: true`
- `x-app: cli`
- `x-stainless-timeout: 600`（消息请求）/ `300`（count_tokens）
- `Accept: application/json`

### 4. 新增 anthropic-beta flags ✅
- `context-management-2025-06-27`
- `prompt-caching-scope-2026-01-05`

### 5. URL 添加 `?beta=true` 查询参数 ✅

### 6. JSON 字段顺序修正 ✅
- 新顺序：`model → messages → system → tools → metadata → max_tokens → thinking → context_management → stream`

## 剩余问题

### P1: 缺失 `X-Claude-Code-Session-Id` Header
- 真实 CLI 发送 UUID 格式的会话 ID
- 需要在 `ClaudeCodeState` 中生成并保持会话级别的 UUID

### P2: cch 动态计算
- 当前硬编码为 `00000`
- 真实 CLI 生成动态值（如 `1e4ec`），计算逻辑未知

### P2: metadata 字段
- 真实 CLI 发送 `metadata.user_id`，包含 device_id、account_uuid、session_id
- 当前未生成此字段

### P3: TLS 指纹
- wreq 模拟浏览器 TLS，而非 Node.js TLS 栈
- 暂不修复，浏览器模拟对 CDN 更友好
