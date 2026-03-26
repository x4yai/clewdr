# Round 2 - Agent B: V2 方案评审 + 自我修正

## 对自己之前建议的重新验证

### 1. Emulation 多样化 → 可行，但降级为低优先级
- wreq-util 的 Emulation 有 75+ 变体，技术可行
- 需要修改 3 处（`claude_web_state/mod.rs:131`, `claude_code_state/mod.rs:74,132`），不是"一行代码"
- **新观点**：Claude 检测可能基于 cookie 级别（session 认证），TLS 指纹多样化不带来实质反检测效果
- 建议只在 Chromium 系内选（Chrome134-137, Edge134），不要跨到 Firefox/Safari

### 2. 代理池 → 可行，但有隐藏复杂度
- figment 和 TOML 都支持 `Vec<String>` 类型
- `wreq_proxy` 是 `#[serde(skip)]`，`validate()` 需改为解析所有代理存为 `Vec<Proxy>`
- **新发现**：需要 cookie-proxy 亲和性（同一 cookie 绑定同一代理），否则同一 cookie 从不同 IP 登录触发异常
- 建议在 `CookieStatus` 增加 `assigned_proxy_index: Option<usize>`

### 3. 指数退避 → **撤回此建议**
- 重新审视 `try_chat` 后发现：重试只在 `InvalidCookie` 时触发
- `return_cookie` 把当前 cookie 移到 exhausted，下次 `request_cookie` 拿不同 cookie
- 重试是"换 cookie 再试"，不是"同一 cookie 重试"——退避等待完全没意义
- **之前的建议是错误的**，没有仔细看重试语义就给了通用建议

## 新发现的真实问题

### 问题 1：`try_chat` 中 state vs self 状态不同步
```rust
let mut state = self.to_owned();  // clone
// state 上执行 bootstrap、send_chat
// 但 transform_response 在 self 上执行
```
`state` 拿到新 cookie/org_uuid/conv_uuid，但 `self` 没有更新。如果 `transform_response` 依赖这些字段可能有 bug。

### 问题 2：cookie-proxy 亲和性设计
代理池必须考虑同一 cookie 绑定同一代理，否则同一 cookie 从不同 IP 登录触发检测。

### 问题 3：SUPER_CLIENT 无 Emulation
`LazyLock::new(Client::new)` 无浏览器指纹，是防御性编程隐患。

## 对 V2 方案的评审意见

| Agent A V2 项目 | Agent B 评价 |
|------|------|
| Emulation 多样化 | 认可方向，降级为低优先级 |
| 代理池 | 认可，但必须加 cookie-proxy 亲和性 |
| 指数退避 | **反对**——重试是换 cookie，退避无意义 |
| Per-cookie Emulation 绑定 | 认可，这是 Agent A 的有价值新发现 |
| Bootstrap 缓存 | 认可，减少请求模式指纹 |
| SUPER_CLIENT Emulation | 认可，防御性修复 |
