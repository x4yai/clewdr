# Round 3 - Agent A: V3 方案（回应 Agent B 撤回退避 + 新发现）

## 关键发现：try_chat 中 state/self 不同步是真实 Bug

### Bug 描述
`chat.rs` 第 43-51 行：`state = self.to_owned()` clone 后，`bootstrap()`、`send_chat()` 在 `state` 上执行，但 `transform_response()` 在 `self` 上执行。

**影响**：
- `self.cookie` 始终为 None → usage 统计永远不会被持久化
- `self.last_params` 始终为 None → 精确 token 计数永远被跳过
- `self.endpoint`、`self.proxy`、`self.client` 可能过时

### 修复方案
将 `self.transform_response(r)` 改为 `state.transform_response(r)`，并解决借用问题。

---

## 对"指数退避撤回"的判断

**Agent B 部分正确，但结论过于绝对。**

- 正确的部分：每次重试确实是换 cookie，per-request 退避无意义
- 遗漏的场景：小 cookie 池 + 全局频率限制（per-IP）→ 密集轮换可能导致整个池在极短时间内全部进入 exhausted

**V3 结论**：不做 per-request 指数退避。改为在 `CookieActor::dispatch` 中加"池级冷却保护"——低优先级 TODO。

---

## Cookie-Proxy 亲和性方案

### 数据结构
```rust
// cookie.rs - CookieStatus 新增
#[serde(default)]
pub assigned_proxy: Option<String>,
```

### 分配逻辑
```rust
// cookie_actor.rs - dispatch 中
// 首次使用时 round-robin 分配代理并记录到 cookie
// 后续使用时复用已绑定的代理
```

### 前置条件
需先实现 proxy 池（`proxy_pool: Vec<String>`），当前单 proxy 架构下无需实现。

---

## V3 优先级排序

| 优先级 | 项目 | 改动量 | 说明 |
|--------|------|--------|------|
| **P0** | `try_chat` state/self 不同步 bug | ~20 行 | usage 统计和 token 计数完全失效 |
| P1 | Per-cookie Emulation 绑定 | ~8 行 | 避免同一 cookie 多次请求 JA3 不一致 |
| P1 | Bootstrap 缓存 | ~12 行 | 减少 API 调用次数，降低特征暴露 |
| P2 | 代理池（极简版） | ~25 行 | `proxy_pool: Vec<String>` |
| P2 | Cookie-Proxy 亲和性 | ~30 行 | 依赖代理池实现 |
| P3 | SUPER_CLIENT Emulation | 5 行 | 防御性修复 |
| P3 | Emulation 多样化 | ~10 行 | 收益不确定 |
| P3 | 池级冷却保护 | ~15 行 | 防止小池瞬时耗尽 |
