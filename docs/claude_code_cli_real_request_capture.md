# Claude Code CLI 真实请求捕获分析（v2 - 全链路验证）

> 捕获日期：2026-03-31
> CLI 版本：Claude Code CLI 2.1.88（编译时间 2026-03-30T22:00:36Z）
> 捕获方式：透明 HTTP 代理拦截 CLI → model-family → clewdr 全链路
> 对比目标：clewdr 当前实现（commit eb3f8de）
> 验证方式：真实 CLI 发起 `claude -p "Say hello"` 请求

---

## 1. 捕获环境

```
Claude Code CLI 2.1.88
  → capture proxy :9999
    → model-family :3000 (new-api AI 网关)
      → clewdr :8484 (逆向代理)
        → api.anthropic.com
```

CLI 因 model-family 返回 503（model_not_found）重试了 10 次，每次请求完全一致，提供了充分的数据验证。

---

## 2. HTTP Headers 完整对比

### 真实 CLI 发出的 21 个 Headers

```
Accept: application/json
Accept-Encoding: gzip, deflate, br, zstd
Connection: keep-alive
Content-Length: 112628
Content-Type: application/json
Host: 127.0.0.1:9999
User-Agent: claude-cli/2.1.88 (external, cli)
X-Claude-Code-Session-Id: e39d95a3-a7d6-41fa-9925-6b2a9bd71ecc
X-Stainless-Arch: arm64
X-Stainless-Lang: js
X-Stainless-OS: MacOS
X-Stainless-Package-Version: 0.74.0
X-Stainless-Retry-Count: 0
X-Stainless-Runtime: node
X-Stainless-Runtime-Version: v24.3.0
X-Stainless-Timeout: 600
anthropic-beta: claude-code-20250219,interleaved-thinking-2025-05-14,context-management-2025-06-27,prompt-caching-scope-2026-01-05
anthropic-dangerous-direct-browser-access: true
anthropic-version: 2023-06-01
x-api-key: {api_key}
x-app: cli
```

### Header 逐项对比

| Header | 真实 CLI | clewdr 当前 | 状态 |
|--------|---------|------------|------|
| `User-Agent` | `claude-cli/2.1.88 (external, cli)` | `claude-cli/2.1.88 (external, cli)` | ✅ 已修复 |
| `X-Claude-Code-Session-Id` | UUID 格式 | **缺失** | ❌ **缺失** |
| `X-Stainless-Package-Version` | `0.74.0` | `0.74.0` | ✅ 已修复 |
| `X-Stainless-Runtime-Version` | `v24.3.0` | `v24.3.0` | ✅ 已修复 |
| `X-Stainless-Timeout` | `600` | `600` | ✅ 已修复 |
| `x-app` | `cli` | `cli` | ✅ 已修复 |
| `anthropic-dangerous-direct-browser-access` | `true` | `true` | ✅ 已修复 |
| `Accept` | `application/json` | `application/json` | ✅ 已修复 |
| `anthropic-version` | `2023-06-01` | `2023-06-01` | ✅ |
| `x-stainless-lang` | `js` | `js` | ✅ |
| `x-stainless-os` | `MacOS` | 动态检测 | ✅ |
| `x-stainless-arch` | `arm64` | 动态检测 | ✅ |
| `x-stainless-runtime` | `node` | `node` | ✅ |
| `x-stainless-retry-count` | `0` | `0` | ✅ |

### anthropic-beta Header 对比

**真实 CLI 发送的 4 个 beta flags（消息请求）：**
```
claude-code-20250219,interleaved-thinking-2025-05-14,context-management-2025-06-27,prompt-caching-scope-2026-01-05
```

| Beta Flag | 真实 CLI | clewdr 当前 | 状态 |
|-----------|---------|------------|------|
| `claude-code-20250219` | ✅ | ✅ | 正确 |
| `interleaved-thinking-2025-05-14` | ✅ | ✅ | 正确 |
| `context-management-2025-06-27` | ✅ | ✅ | ✅ 已修复 |
| `prompt-caching-scope-2026-01-05` | ✅ | ✅ | ✅ 已修复 |
| `oauth-2025-04-20` | ❌ (API key 模式不含) | 条件添加（cookie 认证时） | ✅ 已修复 |
| `effort-2025-11-24` | ✅ (opus-4-6 请求) | 条件添加（opus-4-6/sonnet-4-6） | ✅ 已修复 |
| `context-1m-2025-08-07` | ❌ (非 1M 模式) | 条件添加 | ✅ 正确 |

**源码确认**：`oauth-2025-04-20` 在 `isClaudeAISubscriber()` (cookie/OAuth 认证) 时包含在消息请求中，API key 模式不包含。`effort-2025-11-24` 在支持 effort 的模型（opus-4-6, sonnet-4-6）请求中始终包含。

---

## 3. URL 路径

| 项目 | 真实 CLI | clewdr 当前 | 状态 |
|------|---------|------------|------|
| 消息端点 | `POST /v1/messages?beta=true` | `POST /v1/messages?beta=true` | ✅ 已修复 |

---

## 4. 请求体（Body）完整结构

### 4.1 顶层字段及顺序

**真实 CLI 的 JSON 字段顺序（9 个字段）：**
```json
{
  "model": "claude-sonnet-4-5-20250514",
  "messages": [...],
  "system": [...],
  "tools": [...],
  "metadata": {...},
  "max_tokens": 32000,
  "thinking": {"budget_tokens": 31999, "type": "enabled"},
  "context_management": {"edits": [{"type": "clear_thinking_20251015", "keep": "all"}]},
  "stream": true
}
```

**clewdr struct 字段声明顺序：**
```
model → messages → system → tools → tool_choice(skip) → metadata → max_tokens → thinking → context_management → stream → temperature(skip) → ...
```

当 `skip_serializing_if = "Option::is_none"` 生效时（optional 字段为 None），序列化后的字段顺序与真实 CLI 一致。✅

### 4.2 真实 CLI 不发送的字段

以下字段真实 CLI **完全不出现在 JSON 中**（即使是 null 也不发送）：
- `temperature`
- `top_k`
- `top_p`
- `stop_sequences`
- `tool_choice`
- `n`
- `container`
- `mcp_servers`
- `output_config`
- `output_format`
- `service_tier`

clewdr 使用 `#[serde(skip_serializing_if = "Option::is_none")]` 正确处理了这些字段。✅

### 4.3 metadata 字段

```json
{
  "user_id": "{\"device_id\":\"6199ed6c2b15511fc681b961f5105bd38f76861df15d3c45b04b8c33ae569979\",\"account_uuid\":\"\",\"session_id\":\"e39d95a3-a7d6-41fa-9925-6b2a9bd71ecc\"}"
}
```

说明：
- `user_id` 的值是一个 **JSON 字符串**（嵌套 JSON），不是对象
- `device_id`：64 字符 SHA-256 hex，设备指纹
- `account_uuid`：API key 模式为空字符串
- `session_id`：与 `X-Claude-Code-Session-Id` header 一致

clewdr 状态：`CreateMessageParams` 有 `metadata: Option<Metadata>` 字段，如果客户端发送了 metadata 会透传。但 clewdr 自身不生成 metadata，当非 CLI 客户端（如 SillyTavern）使用时会缺失。⚠️

### 4.4 context_management 字段

```json
{
  "edits": [
    {
      "type": "clear_thinking_20251015",
      "keep": "all"
    }
  ]
}
```

clewdr 状态：`CreateMessageParams` 有 `context_management: Option<serde_json::Value>` 字段，会透传。但 clewdr 不主动生成此字段。⚠️

### 4.5 Thinking 配置

| 项目 | 真实 CLI | clewdr |
|------|---------|--------|
| `max_tokens` | `32000` | 取决于请求 |
| `thinking.budget_tokens` | `31999`（= max_tokens - 1） | 取决于请求 |
| `thinking.type` | `"enabled"` | `"enabled"` |

### 4.6 Tools

真实 CLI 发送 24 个工具定义。clewdr 不修改 tools，透传客户端请求。✅

---

## 5. System Prompt 结构

真实 CLI 的 system 是一个包含 4 个 text block 的数组：

| 索引 | type | 长度 | cache_control | 内容 |
|------|------|------|---------------|------|
| [0] | text | 80 | null | billing header |
| [1] | text | 62 | null | Agent SDK 声明 |
| [2] | text | 11695 | `{"type":"ephemeral","scope":"global"}` | 主系统提示 |
| [3] | text | 15801 | null | 会话特定指导 |

### Billing Header 详细分析

**真实 CLI：**
```
x-anthropic-billing-header: cc_version=2.1.88.e09; cc_entrypoint=cli; cch=865dc;
```

**clewdr 当前生成：**
```
x-anthropic-billing-header: cc_version=2.1.88.{hash}; cc_entrypoint={env}; cch=00000;
```

| 组件 | 真实 CLI | clewdr | 状态 |
|------|---------|--------|------|
| `cc_version` | `2.1.88.e09` | `2.1.88.{hash[..3]}` | ✅ 动态计算匹配 |
| `cc_entrypoint` | `cli` | 取决于 `CLAUDE_CODE_ENTRYPOINT` 环境变量 | ⚠️ 默认值是 `unknown`，应为 `cli` |
| `cch` | `865dc`（5位 hex，动态值） | `00000`（硬编码） | ❌ **不匹配** |

#### cch 值深度分析

- CLI 二进制中源码为 `cch=00000`（硬编码常量）
- 但运行时输出 `cch=865dc`（5位 hex）
- 多次重试中 cch 值**不变**（同一请求体）
- 不同会话/消息的 cch 值**不同**（上次捕获为 `1e4ec`）
- 推断：存在某个运行时中间件（可能在 Anthropic SDK 的 `prepareOptions` 或 `prepareRequest` hook 中）在发送前计算并替换 cch 值
- cch 可能是对请求体某些内容的 hash（前 5 位 hex），用于内容完整性校验

### Agent SDK 声明（Block [1]）

```
You are a Claude agent, built on Anthropic's Claude Agent SDK.
```

这是 `isNonInteractive=true`（`-p` 模式）时的声明。交互模式下可能不同。

### System Prompt Cache Control

- Block [2] 使用 `{"type":"ephemeral","scope":"global"}` — clewdr 的 `strip_ephemeral_scope_from_system` 会正确去掉 `scope` 字段 ✅
- Block [0], [1], [3] 无 cache_control

---

## 6. User Message 结构

```
[0] role=user, content=[4 blocks]:
    [0] type=text, len=7097, cache=null      （skills 列表等 system-reminder）
    [1] type=text, len=4777, cache=null      （plan mode context）
    [2] type=text, len=306,  cache=null      （日期等 context）
    [3] type=text, len=9,    cache={"type":"ephemeral"}  （用户实际消息 "Say hello"）
```

- 所有 message content 都使用 block 数组格式 `[{"type":"text","text":"..."}]` ✅
- 用户实际消息的 block 带 `{"type":"ephemeral"}` cache_control（无 scope）

---

## 7. 修复清单（按优先级）

### ✅ 已修复（上一轮优化后确认正确）

1. User-Agent 格式 → `claude-cli/2.1.88 (external, cli)` ✅
2. URL query string → `?beta=true` ✅
3. X-Stainless-Package-Version → `0.74.0` ✅
4. X-Stainless-Runtime-Version → `v24.3.0` ✅
5. anthropic-beta 新增 flags → `context-management` + `prompt-caching-scope` ✅
6. 缺失 headers → `x-app`, `anthropic-dangerous-direct-browser-access`, `X-Stainless-Timeout` ✅
7. Accept header → `application/json` ✅

### ✅ 全部已修复

以上 v1-v2 修复项均已完成。

### ⚠️ 已知无法完美复制的项

**`cch` 值（native client attestation）**
- 真实 CLI 的 `cch` 值由 Bun 运行时的 `Attestation.zig` 在 HTTP 发送前替换 `00000` 占位符
- 这是密码学级别的客户端认证，无法在 Rust 中复制
- clewdr 使用基于消息内容的 SHA256 前 5 位 hex 作为伪值，格式匹配但无法通过密码学验证

---

## 8. 原始捕获数据

捕获文件位置：
- `/tmp/claude_captures/cap_20260331_165038_1_request_headers.json` - 完整 headers
- `/tmp/claude_captures/cap_20260331_165038_1_request_body.json` - 完整请求体 (112KB)
- `/tmp/claude_captures/cap_20260331_165038_1_request_analysis.json` - 结构分析

共捕获 10 次重试请求，所有请求内容一致（仅时间戳不同）。

---

## 9. Header 顺序参考

真实 CLI 发送的 header 顺序（按照 HTTP/1.1 发送顺序）：

```
Accept
Content-Type
User-Agent
X-Claude-Code-Session-Id
X-Stainless-Arch
X-Stainless-Lang
X-Stainless-OS
X-Stainless-Package-Version
X-Stainless-Retry-Count
X-Stainless-Runtime
X-Stainless-Runtime-Version
X-Stainless-Timeout
anthropic-beta
anthropic-dangerous-direct-browser-access
anthropic-version
x-api-key
x-app
Connection
Host
Accept-Encoding
Content-Length
```

注：后 4 个是 HTTP 层自动添加的（Connection, Host, Accept-Encoding, Content-Length）。

---

## 10. opus-4-6 vs sonnet-4-5 差异

使用 `claude-opus-4-6` 模型的真实 CLI 请求与 `claude-sonnet-4-5-20250514` 有以下关键差异：

| 字段 | sonnet-4-5 | opus-4-6 |
|------|-----------|----------|
| `max_tokens` | `32000` | `64000` |
| `thinking` | `{"budget_tokens":31999,"type":"enabled"}` | `{"type":"adaptive"}` |
| `output_config` | 无 | `{"effort":"medium"}` |
| body 顶层字段数 | 9 个 | 10 个（多 `output_config`） |

### 字段顺序（opus-4-6）

```
model → messages → system → tools → metadata → max_tokens → thinking → context_management → output_config → stream
```

注意 `output_config` 插在 `context_management` 和 `stream` 之间。clewdr 的 `CreateMessageParams` 需要确保 `output_config` 字段在正确位置。

### Thinking 模式差异

- **sonnet-4-5**: 使用 `{"budget_tokens": 31999, "type": "enabled"}` — 有明确的 token 预算
- **opus-4-6**: 使用 `{"type": "adaptive"}` — 自适应思考，无预算限制

### output_config

```json
{"effort": "medium"}
```

这是 opus-4-6 特有的推理努力程度配置，可选值为 `low`/`medium`/`high`/`max`。

---

## 11. 全链路验证测试流程

### 11.1 环境要求

| 组件 | 端口 | 说明 |
|------|------|------|
| Claude Code CLI | - | `claude` 命令（2.1.88+） |
| model-family | 3000 | AI 网关（new-api），配有指向 clewdr 的 Claude 渠道 |
| clewdr | 8484 | 本项目的逆向代理 |
| capture proxy | 9999 | Python 透明捕获代理（可选：9998 用于第二跳捕获） |

### 11.2 捕获代理脚本

脚本位置：`/tmp/capture_proxy.py`

```bash
# 用法：
# 参数1: 监听端口 (默认 9999)
# 参数2: 上游地址 (默认 127.0.0.1:3000)
python3 /tmp/capture_proxy.py [listen_port] [upstream_host:port]

# 示例：
# CLI → capture → model-family
python3 /tmp/capture_proxy.py 9999 127.0.0.1:3000

# model-family → capture → clewdr
python3 /tmp/capture_proxy.py 9998 127.0.0.1:8484
```

脚本功能：
- 透明转发所有 HTTP 请求到上游
- 完整记录每个请求的 headers、body、response
- 支持 SSE 流式响应转发（chunked encoding）
- 自动分析 JSON body 结构
- 所有捕获文件保存到 `/tmp/claude_captures/`

每个请求生成 3-4 个文件：
- `cap_{timestamp}_{id}_request_headers.json` — HTTP headers
- `cap_{timestamp}_{id}_request_body.json` — 完整请求体
- `cap_{timestamp}_{id}_request_analysis.json` — 结构分析
- `cap_{timestamp}_{id}_response_info.json` — 响应摘要

### 11.3 测试步骤

#### 步骤 1：确认服务启动

```bash
# 确认 model-family 运行中
curl -s http://127.0.0.1:3000/ | head -3

# 确认 clewdr 运行中（用最新编译版本）
cargo build --release
./target/release/clewdr &
curl -s http://127.0.0.1:8484/ | head -3
```

#### 步骤 2：确认 model-family 渠道配置

```bash
# 查看 clewdr 渠道（type=14 是 Claude 类型）
sqlite3 /path/to/model-family/one-api.db \
  "SELECT id, type, name, base_url, models FROM channels WHERE type=14;"

# 预期输出类似：
# 1|14|rp|http://127.0.0.1:8484/code|claude-sonnet-4-6,claude-haiku-4-5-20251001,claude-opus-4-6
```

#### 步骤 3：获取 model-family API token

```bash
sqlite3 /path/to/model-family/one-api.db \
  "SELECT key FROM tokens WHERE status=1 AND deleted_at IS NULL LIMIT 1;"
```

#### 步骤 4：启动捕获代理

```bash
# 清理旧捕获
rm -rf /tmp/claude_captures/*

# 启动代理（后台运行）
python3 /tmp/capture_proxy.py 9999 127.0.0.1:3000 > /tmp/proxy_9999.log 2>&1 &

# 确认代理运行
curl -s http://127.0.0.1:9999/ | head -3
```

#### 步骤 5：发送 CLI 请求

```bash
# 替换 YOUR_TOKEN 为步骤 3 获取的 token
ANTHROPIC_BASE_URL=http://127.0.0.1:9999 \
ANTHROPIC_API_KEY=YOUR_TOKEN \
claude -p "Say hello" --model claude-opus-4-6 --output-format text
```

#### 步骤 6：分析捕获数据

```bash
# 查看捕获文件列表
ls -la /tmp/claude_captures/

# 查看请求 headers
cat /tmp/claude_captures/cap_*_1_request_headers.json | python3 -m json.tool

# 查看请求体结构分析
cat /tmp/claude_captures/cap_*_1_request_analysis.json | python3 -m json.tool

# 查看代理日志
cat /tmp/proxy_9999.log
```

#### 步骤 7：清理

```bash
# 停止代理
kill $(lsof -t -i :9999) 2>/dev/null

# 清理捕获
rm -rf /tmp/claude_captures/*
```

### 11.4 双跳捕获（可选）

如需同时捕获 model-family → clewdr 的请求：

```bash
# 1. 启动第二个代理（9998 → 8484）
python3 /tmp/capture_proxy.py 9998 127.0.0.1:8484 > /tmp/proxy_9998.log 2>&1 &

# 2. 修改 model-family 渠道指向代理
sqlite3 /path/to/model-family/one-api.db \
  "UPDATE channels SET base_url='http://127.0.0.1:9998/code' WHERE id=1;"

# 3. 运行测试（同步骤 5）

# 4. 测试完毕后恢复
sqlite3 /path/to/model-family/one-api.db \
  "UPDATE channels SET base_url='http://127.0.0.1:8484/code' WHERE id=1;"
kill $(lsof -t -i :9998) 2>/dev/null
```

### 11.5 常见问题

| 错误 | 原因 | 解决 |
|------|------|------|
| 503 model_not_found | model-family 渠道未配置该模型 | 检查渠道的 models 字段 |
| 429 No cookie available | clewdr 没有可用 cookie | 在 clewdr 管理面板添加有效 cookie |
| Connection refused :8484 | clewdr 未启动 | `./target/release/clewdr &` |
| Connection refused :3000 | model-family 未启动 | 启动 model-family 服务 |

---

## 12. 修复历史

### v3 修复（2026-03-31，源码分析 + opus-4-6 全链路验证后）

| # | 优先级 | 修复内容 | 文件 |
|---|--------|---------|------|
| 1 | P0 | 新增 `effort-2025-11-24` beta flag（opus-4-6/sonnet-4-6 条件添加） | `chat.rs` |
| 2 | P1 | cookie 认证时恢复 `oauth-2025-04-20` beta flag（源码确认 `isClaudeAISubscriber()` 时包含） | `chat.rs` |

### v2 修复（2026-03-31，全链路验证后）

| # | 优先级 | 修复内容 | 文件 |
|---|--------|---------|------|
| 1 | P0 | 从消息请求 beta header 中移除 `oauth-2025-04-20`（后在 v3 中恢复为条件添加） | `chat.rs` |
| 2 | P0 | 新增 `X-Claude-Code-Session-Id` header（UUID v4） | `mod.rs` + `chat.rs` |
| 3 | P1 | `cch` 从硬编码 `00000` 改为动态 5 位 hex hash | `request.rs` |
| 4 | P1 | `cc_entrypoint` 默认值从 `unknown` 改为 `cli` | `request.rs` |
| 5 | P1 | 非 CLI 客户端自动生成 `metadata` 和 `context_management` | `request.rs` |
| 6 | P2 | billing header 后插入 Agent SDK 声明 system block | `request.rs` |

### v1 修复（2026-03-31，初始分析后）

- User-Agent 格式修正
- URL 添加 `?beta=true`
- X-Stainless 版本对齐
- 新增 beta flags
- 新增缺失 headers
