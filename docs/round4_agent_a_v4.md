# Round 4 - Agent A: V4 精确实施方案

## P0 Bug 修复：transform_response 在 self 而非 state 上调用

### 问题精确描述
文件：`src/claude_web_state/chat.rs` 第 49-50 行

`state = self.to_owned()` 后，`bootstrap()`、`send_chat()` 在 `state` 上执行，但 `transform_response()` 在 `self` 上执行。

**影响**：
- `self.cookie` = None → usage 持久化跳过
- `self.last_params` = None → token 计数失效
- `self.usage.input_tokens` = 0 → 基数错误

**Claude Code 路径不受影响**（所有操作都在 state 上执行）。

### 修复方案

#### 方案 A：简单替换（推荐）

```diff
// chat.rs 第 50 行
-    .and_then(async |r| self.transform_response(r).await)
+    .and_then(async |r| state.transform_response(r).await)
```

但需验证借用：`state` 在 `web_res` 闭包中已被 `&mut` 捕获。`and_then` 链的第二个闭包可能无法再借用 `state`。

#### 方案 B：拆解 and_then 链（更安全）

```rust
// 先 await web_res，再调用 state.transform_response
let web_res = async { state.bootstrap().await.and(state.send_chat(p).await) }
    .instrument(info_span!("claude_web", "cookie" = cookie.cookie.ellipse()))
    .await;

match web_res {
    Ok(r) => match state.transform_response(r).await {
        Ok(b) => { /* clean_chat + return */ }
        Err(e) => { /* clean_chat + error handling */ }
    },
    Err(e) => { /* clean_chat + error handling */ }
}
```

---

## Bootstrap 缓存方案

### 设计
- `CookieStatus` 新增 `bootstrap_cache: Option<BootstrapCache>` 字段
- `BootstrapCache` 包含 `org_uuid`, `capabilities`, `cached_at`
- TTL：5 分钟
- Cookie 切换时自然清缓存（不同 CookieStatus 实例）

### 代码位置
- `src/config/cookie.rs`：新增 BootstrapCache 结构体
- `src/claude_web_state/bootstrap.rs:27`：方法开头加缓存检查

### 风险
- 缓存期间账户状态变化不会被感知（5 分钟 TTL 可接受）
- `check_flags` 检查会被跳过

---

## 并发池水位保护方案

### 设计
- `CookieActorState` 新增 `in_flight: HashMap<String, usize>`
- `dispatch` 中选择并发数最低的 cookie
- `collect` 中递减并发计数
- 配置项 `max_cookie_concurrency`（默认 2）

### 代码位置
- `src/services/cookie_actor.rs:185-208`
- `src/config/clewdr_config.rs`：新增配置项

---

## V4 优先级最终排序

| 优先级 | 项目 | 改动量 | 风险 |
|--------|------|--------|------|
| **P0** | transform_response self→state bug | 1-20 行 | 无 |
| P1 | Bootstrap 缓存 | ~15 行 | 低（TTL 可配） |
| P1 | 并发池水位保护 | ~30 行 | 低 |
| P2 | Proxy 池 + Cookie-Proxy 亲和性 | ~40 行 | 中 |
| P3 | Per-cookie Emulation 绑定 | ~8 行 | 低 |
| P3 | SUPER_CLIENT Emulation | 5 行 | 无 |
