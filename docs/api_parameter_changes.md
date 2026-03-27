# API 参数不兼容变更分析

## 概述

通过逆向分析 Claude Code CLI v2.1.84 和 VS Code 扩展，发现以下 API 参数变更与 clewdr 现有实现存在不兼容。

---

## 变更 1：thinking.type=enabled 已弃用（信息，clewdr 已支持 adaptive）

真实客户端警告：
> `'thinking.type=enabled' is deprecated. Use 'thinking.type=adaptive' instead`

- Opus 4.6 / Sonnet 4.6 必须使用 `thinking: {type: "adaptive"}`
- `budget_tokens` 在 4.6 模型上已弃用

**clewdr 现状**：`Thinking` 枚举已包含 `Adaptive` 变体（`claude.rs:160`），无需修改。透传即可。

---

## 变更 2：缺少 compaction_delta（高优先级）

真实客户端支持 `content_block_delta` 中的 `compaction_delta` 类型：
```json
{"type": "content_block_delta", "index": 0, "delta": {"type": "compaction_delta", "content": "..."}}
```

**clewdr 现状**：`ContentBlockDelta` 枚举（`claude.rs:946-955`）缺少此变体。

**影响**：
- Claude Code 路径（`claude_code_state/chat.rs:476`）：`from_str` 失败 → `else` 分支跳过 → 事件丢失但不崩溃
- Claude Web 路径（`response.rs:102`）：同上，静默跳过
- OAI 转换（`claude2oai.rs:79`）：同上

虽然不会崩溃（因为 `let Ok(...) else` 模式），但 compaction 内容会被丢弃。

### 修复
`ContentBlockDelta` 增加 `CompactionDelta` 变体。

---

## 变更 3：MessageDeltaContent 缺少新字段（低优先级）

真实客户端在 `message_delta` 事件中包含：
- `container` — 容器信息
- `context_management` — 上下文管理状态

**clewdr 现状**：`MessageDeltaContent`（`claude.rs:957-961`）只有 `stop_reason` 和 `stop_sequence`。

**影响**：由于 serde 默认忽略未知字段（struct 不是 `#[serde(deny_unknown_fields)]`），反序列化不会失败。但这些字段不会被保留在转发中。

对于 Claude Code 路径，响应是直接透传的（`forward_stream_with_usage`），不经过 MessageDeltaContent 反序列化后重新序列化，所以实际不受影响。

### 修复
不需要立即修复。如果未来需要读取这些字段，可以添加为 `Option<Value>`。

---

## 修复清单

| 优先级 | 变更 | 修复 | 文件 |
|--------|------|------|------|
| 高 | compaction_delta 缺失 | 增加枚举变体 | `src/types/claude.rs:946` |
| 信息 | thinking adaptive | 已支持，无需修改 | — |
| 低 | MessageDeltaContent 新字段 | 暂不修复 | — |
