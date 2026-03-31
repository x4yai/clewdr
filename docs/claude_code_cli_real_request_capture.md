# Claude Code CLI 真实请求捕获分析

> 捕获日期：2026-03-31
> CLI 版本：Claude Code CLI 2.1.88
> 捕获方式：本地 HTTP 请求捕获服务器，通过 `ANTHROPIC_BASE_URL` 重定向 CLI 请求
> 对比目标：clewdr 当前实现（commit fa0ae5b）

---

## 1. HTTP Headers 完整对比

### 真实 CLI 发出的 Headers（共 21 个）

```
Accept: application/json
Accept-Encoding: gzip, deflate, br, zstd
Connection: keep-alive
Content-Length: 112630
Content-Type: application/json
Host: 127.0.0.1:9999
User-Agent: claude-cli/2.1.88 (external, cli)
X-Claude-Code-Session-Id: 1e528e30-51b2-4d76-830b-f8e37aefe1d6
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
| `User-Agent` | `claude-cli/2.1.88 (external, cli)` | `claude-code/2.1.88` | **错误** - 名称和格式完全不同 |
| `X-Claude-Code-Session-Id` | UUID 格式，每会话唯一 | 缺失 | **缺失** |
| `X-Stainless-Package-Version` | `0.74.0` | `0.80.0` | **版本不匹配** |
| `X-Stainless-Runtime-Version` | `v24.3.0`（带 `v` 前缀） | `22.13.1`（无前缀） | **版本不匹配 + 格式不同** |
| `X-Stainless-Timeout` | `600`（消息请求）/ `300`（count_tokens） | 缺失 | **缺失** |
| `x-app` | `cli` | 缺失 | **缺失** |
| `anthropic-dangerous-direct-browser-access` | `true` | 缺失 | **缺失** |
| `Accept` | `application/json` | 未显式设置 | **可能缺失** |
| `x-stainless-lang` | `js` | `js` | 正确 |
| `x-stainless-os` | `MacOS` | 动态检测 | 正确 |
| `x-stainless-arch` | `arm64` | 动态检测 | 正确 |
| `x-stainless-runtime` | `node` | `node` | 正确 |
| `x-stainless-retry-count` | `0` | `0` | 正确 |
| `anthropic-version` | `2023-06-01` | `2023-06-01` | 正确 |
| `Authorization` | 无（API key 模式用 x-api-key） | `Bearer {token}`（OAuth 模式） | 正确（模式不同） |

### anthropic-beta Header 对比

| Beta Flag | 真实 CLI | clewdr 当前 | 状态 |
|-----------|---------|------------|------|
| `claude-code-20250219` | 有 | 有 | 正确 |
| `interleaved-thinking-2025-05-14` | 有 | 有 | 正确 |
| `context-management-2025-06-27` | 有 | 缺失 | **缺失** - 新增 beta |
| `prompt-caching-scope-2026-01-05` | 有 | 缺失 | **缺失** - 新增 beta |
| `oauth-2025-04-20` | 无（API key 模式不需要） | 有 | 多余（OAuth 时需要） |
| `context-1m-2025-08-07` | 无（非 1M 模式） | 条件添加 | 正确（按需） |

---

## 2. URL 路径对比

| 项目 | 真实 CLI | clewdr 当前 |
|------|---------|------------|
| 消息端点 | `/v1/messages?beta=true` | `/v1/messages`（无 query string） |
| 认证方式 | `x-api-key` header | `Bearer` token |

**重要发现**：真实 CLI 在 URL 上附加了 `?beta=true` 查询参数。

---

## 3. 请求体（Body）完整结构

### 3.1 顶层字段及顺序

真实 CLI 的 JSON 字段顺序（已确认）：

```json
{
  "model": "claude-sonnet-4-5-20250514",
  "messages": [...],
  "system": [...],
  "tools": [...],
  "metadata": {...},
  "max_tokens": 32000,
  "thinking": {"budget_tokens": 31999, "type": "enabled"},
  "context_management": {...},
  "stream": true
}
```

**clewdr 当前字段顺序**（由 serde 序列化决定）：

```json
{
  "model": "...",
  "max_tokens": ...,
  "messages": [...],
  "system": ...,
  "stream": ...,
  "temperature": ...,
  "top_k": ...,
  "top_p": ...,
  "thinking": ...,
  "tools": ...,
  "tool_choice": ...,
  "stop_sequences": ...,
  "metadata": ...
}
```

### 3.2 新增字段

#### `context_management`（新字段）

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

**用途**：控制 thinking 内容的清理策略。clewdr 当前完全缺失此字段。

#### `metadata`（新字段）

```json
{
  "user_id": "{\"device_id\":\"6199ed6c...\",\"account_uuid\":\"\",\"session_id\":\"1e528e30-...\"}"
}
```

**说明**：
- `user_id` 的值是一个 **JSON 字符串**（嵌套 JSON），非对象
- `device_id`：设备指纹，SHA-256 格式
- `account_uuid`：账号 UUID（API key 模式为空字符串）
- `session_id`：会话 ID，与 `X-Claude-Code-Session-Id` header 一致

### 3.3 Thinking 配置

| 项目 | 真实 CLI | clewdr 当前 |
|------|---------|------------|
| `max_tokens` | `32000` | 取决于请求 |
| `thinking.budget_tokens` | `31999`（= max_tokens - 1） | `4096`（硬编码默认值） |
| `thinking.type` | `"enabled"` | `"enabled"` |

### 3.4 System Prompt 结构

真实 CLI 的 system 是一个包含 4 个 text block 的数组：

```
[0] type=text, cache_control=null
    内容: "x-anthropic-billing-header: cc_version=2.1.88.e09; cc_entrypoint=cli; cch=1e4ec;"
    （billing header 作为第一个 system block）

[1] type=text, cache_control=null
    内容: "You are a Claude agent, built on Anthropic's Claude Agent SDK."
    （Agent SDK 声明，62 chars）

[2] type=text, cache_control={"type": "ephemeral", "scope": "global"}
    内容: 主要系统提示（工具说明、行为准则等）
    （11695 chars，带 ephemeral+scope:global 缓存控制）

[3] type=text, cache_control=null
    内容: "# Session-specific guidance\n..."
    （会话特定指导，15805 chars）
```

**与 clewdr 的差异**：
- clewdr 的 `strip_ephemeral_scope_from_system` 会去掉 `scope` 字段，这是正确行为
- clewdr 在 system 前面 prepend billing header 和 custom_system，结构基本匹配

### 3.5 Message Content 结构

```
[0] role=user, 4 blocks:
    [0] text, len=7097, cache_control=null      （skills 列表等 system-reminder）
    [1] text, len=4775, cache_control=null      （更多 context）
    [2] text, len=306,  cache_control=null      （git status 等）
    [3] text, len=9,    cache_control={"type": "ephemeral"}  （用户实际消息 "Say hello"）
```

**确认**：所有 message content 都使用 block 数组格式 `[{"type":"text","text":"..."}]`，从不使用裸字符串。

### 3.6 缺失的字段（真实 CLI 未发送）

以下字段真实 CLI **不发送**（即使为 null/undefined 也不出现在 JSON 中）：
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

---

## 4. Billing Header 详细分析

### HTTP Header vs System Block

**关键发现**：`x-anthropic-billing-header` **不是作为 HTTP header 发送的**，而是嵌入在 system prompt 的第一个 text block 中。

clewdr 当前的实现（在 `prepend_system_blocks` 中将 billing header 作为 system block prepend）与真实 CLI 行为一致。

### 格式对比

```
# 真实 CLI（捕获值）
x-anthropic-billing-header: cc_version=2.1.88.e09; cc_entrypoint=cli; cch=1e4ec;

# clewdr 生成格式
x-anthropic-billing-header: cc_version=2.1.88.{3-char-hash}; cc_entrypoint={env}; cch=60593;
```

差异：
- `cch` 值不同：真实 CLI 为 `1e4ec`（5位16进制），clewdr 硬编码为 `60593`（5位10进制）
- 说明 `cch` 不是固定值，可能是动态计算的

### cch 值分析

观察到两次捕获中 `cch` 值不同（`89a2a` 在旧文档中，`1e4ec` 在本次捕获中），说明：
- `cch` 是动态值，不是固定常量
- 可能基于某种 hash 或计算逻辑
- clewdr 的硬编码 `60593` 不正确

---

## 5. 修复优先级清单

### P0 - 高检测风险

1. **User-Agent 格式错误**
   - 当前：`claude-code/2.1.88`
   - 应为：`claude-cli/2.1.88 (external, cli)`
   - 文件：`src/config/constants.rs` → `CLAUDE_CODE_USER_AGENT`

2. **缺失 anthropic-beta flags**
   - 缺少：`context-management-2025-06-27`
   - 缺少：`prompt-caching-scope-2026-01-05`
   - 文件：`src/claude_code_state/chat.rs` → beta 常量

3. **URL 缺少 `?beta=true`**
   - 当前：`POST /v1/messages`
   - 应为：`POST /v1/messages?beta=true`
   - 文件：`src/claude_code_state/chat.rs` → `execute_claude_request`

4. **X-Stainless 版本不匹配**
   - `X-Stainless-Package-Version`：`0.80.0` → `0.74.0`
   - `X-Stainless-Runtime-Version`：`22.13.1` → `v24.3.0`（需要加 `v` 前缀）
   - 文件：`src/config/constants.rs`

### P1 - 中等检测风险

5. **缺失 Headers**
   - `X-Claude-Code-Session-Id`：需要生成 UUID 并在会话中保持不变
   - `x-app: cli`
   - `anthropic-dangerous-direct-browser-access: true`
   - `X-Stainless-Timeout: 600`
   - 文件：`src/claude_code_state/chat.rs` → request builder

6. **缺失 body 字段 `context_management`**
   - 需要添加到 `CreateMessageParams` 类型定义中
   - 文件：`src/types/claude.rs`

7. **缺失 body 字段 `metadata`**
   - 需要添加到 `CreateMessageParams` 类型定义中
   - 生成合理的 `device_id` 和 `session_id`
   - 文件：`src/types/claude.rs`

### P2 - 低检测风险

8. **cch 值硬编码**
   - 当前硬编码为 `00000`，真实 CLI 生成动态值（如 `1e4ec`）
   - 需要逆向 `cch` 的计算逻辑
   - 文件：`src/middleware/claude/request.rs`

9. **JSON 字段顺序**
   - 真实 CLI 的顶层字段顺序：model → messages → system → tools → metadata → max_tokens → thinking → context_management → stream
   - 可以通过 `#[serde(rename_all)]` 或自定义序列化调整
   - 当前 serde 默认按 struct 字段声明顺序

10. **Thinking budget 默认值**
    - 真实 CLI 用 `max_tokens - 1`（如 `31999`）
    - clewdr 默认 `4096`

---

## 6. 原始捕获数据

捕获文件位置：
- `/tmp/capture_req_1.json` - 完整请求体 (112KB)
- `/tmp/capture_headers_1.txt` - 完整 headers

可通过 `python3 -m json.tool /tmp/capture_req_1.json | head -100` 查看。
