# 版本升级影响分析（2.1.76 → 2.1.84）

## 概述

本次版本更新涉及版本号、OAuth URL、anthropic-beta 基础值等多项变更。以下分析每个变更对现有功能的潜在影响。

---

## 1. Prompt Cache 命中（影响：低）

### 分析
- billing header（含版本号）作为 system prompt 的第一个 text block 注入
- `system_prompt_hash` 仅计算**带 `cache_control` 的 blocks**（`request.rs:383-398`）
- billing header 是纯文本 block，**不带 cache_control**
- 因此版本号变化**不影响** system_prompt_hash

### 结论
moka 缓存亲和性（同一 system prompt hash → 同一 cookie）不受版本更新影响。

### Anthropic 服务端 prompt caching
billing header 内容变化会导致 Anthropic 服务端的 prompt cache 失效（system prompt 内容变了），但这是一次性代价，后续请求会重新建立缓存。

---

## 2. OAuth Token Refresh（影响：中，已有回退机制）

### 分析
- Token URL 从 `api.anthropic.com` 改为 `platform.claude.com`
- 已持久化的 token（toml 文件中的 `refresh_token`）是从旧 URL 签发的
- `refresh_token()` 方法（`exchange.rs:215`）使用新 URL 刷新旧 token

### 风险场景
1. 用户升级 clewdr 后，toml 中有旧 token
2. Token 过期 → 触发 `refresh_token()`
3. 旧 refresh_token 打向 `platform.claude.com/v1/oauth/token`
4. 如果 Anthropic 统一了 token 存储 → 成功
5. 如果没有统一 → `invalid_grant` 错误

### 回退机制
`exchange.rs:255-293` 已有完善的回退：
```
invalid_grant → 清除旧 token → 重新 get_organization() → exchange_code() → exchange_token()
```
**最坏情况**：第一次 refresh 失败，自动重新授权，用户无感知。

### 结论
**无需修改代码**。回退机制已覆盖此场景。

---

## 3. Cookie 序列化兼容性（影响：低）

### 分析
- `CookieStatus` 所有新字段都有 `#[serde(default)]`
- 旧 toml 文件缺少新字段 → 默认值填充，不会报错
- 新 toml 文件被旧版本读取 → TOML 忽略未知字段，不会报错

### 结论
**双向兼容，无需修改**。

---

## 4. anthropic-beta 变更（影响：低）

### 分析
- 消息请求：`oauth-2025-04-20` → `claude-code-20250219`
- OAuth 流程：保持 `oauth-2025-04-20`
- 新增 `interleaved-thinking-2025-05-14`

### 风险
- 如果 Anthropic API 基于 beta header 做功能门控，新 beta 值可能解锁新功能或改变行为
- `claude-code-20250219` 是 Claude Code 专用标识，可能触发 Claude Code 专属的限速/配额逻辑

### 结论
**这是正确的行为**——clewdr 模拟 Claude Code 客户端，应该使用 Claude Code 的 beta 标识。

---

## 5. Billing Header Hash 变化（影响：信息性）

### 旧版本
```
cc_version=2.1.76.<hash>; cc_entrypoint=cli; cch=00000;
```

### 新版本
```
cc_version=2.1.84.<hash>; cc_entrypoint=unknown; cch=00000;
```

变化点：
- 版本号：`2.1.76` → `2.1.84`
- Hash 前缀：因版本号参与 SHA256 计算，hash 完全不同
- Entrypoint：`cli` → `unknown`

### 影响
billing header 嵌入 system prompt 中，Anthropic 服务端可能用它来：
1. 识别客户端版本
2. 计费统计
3. 功能门控

使用正确的版本号和 entrypoint 是**期望的行为**。

---

## 总结

| 变更 | 影响 | 是否需要修复 |
|------|------|------------|
| 版本号 2.1.76→2.1.84 | prompt cache 一次性失效 | 否（预期行为） |
| OAuth URL 变更 | 旧 token refresh 可能失败 | 否（已有 invalid_grant 回退） |
| Cookie 序列化 | 双向兼容 | 否 |
| anthropic-beta 变更 | 正确的 Claude Code 标识 | 否（预期行为） |
| billing header 变化 | 版本号/entrypoint 更新 | 否（预期行为） |
| system_prompt_hash | 不受 billing header 影响 | 否 |

**结论：本次版本升级不需要额外的兼容性修复。所有潜在风险都已被现有回退机制覆盖。**
