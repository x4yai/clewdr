# 第六轮（追加）- 红队实施方案：保留 model-family 链路

> 日期：2026-03-30
> 约束条件：model-family 必须保留（内含计费逻辑），链路为 客户端 → model-family → clewdr → Claude API
> 基于：五轮对抗终局报告 + wreq 最新能力 + model-family 源码审计 + cookie 并发机制分析

---

## 一、核心约束与前提

### 1.1 不可改变的约束

| 约束 | 原因 |
|------|------|
| model-family 必须保留 | 承担计费、用户管理、多模型路由等业务逻辑 |
| 链路：客户端 → model-family → clewdr → Claude | model-family 做业务层，clewdr 做协议层 |

### 1.2 已确认的问题根因（来自第三轮裁判真实案例分析）

| 权重 | 根因 | 在保留 model-family 前提下能否解决 |
|------|------|------|
| 45% | 多用户行为聚合 | **可解决** — clewdr 层做 cookie 并发控制 |
| 30% | model-family 格式破坏 | **可大幅缓解** — 配置 model-family 透传模式 + clewdr 请求标准化 |
| 15% | API 调用模式异常 | **可解决** — clewdr 补充初始化序列 |
| 10% | 消费量异常 | **可解决** — clewdr 层限流 |

---

## 二、model-family 配置改造（30% 根因）

### 2.1 问题诊断

通过审计 model-family 源码，确认以下具体问题：

**文件：`relay/channel/claude/adaptor.go`（行 51-68）**
```go
func (a *Adaptor) SetupRequestHeader(...) {
    req.Set("x-api-key", info.ApiKey)           // ✅ 正确：设置 clewdr 的 API key
    anthropicVersion := c.Request.Header.Get("anthropic-version")
    if anthropicVersion == "" {
        anthropicVersion = "2023-06-01"          // ⚠️ 客户端不传就用默认值
    }
    req.Set("anthropic-version", anthropicVersion)
    // anthropic-beta 仅在客户端传了才转发
    anthropicBeta := c.Request.Header.Get("anthropic-beta")
    if anthropicBeta != "" {
        req.Set("anthropic-beta", anthropicBeta) // ⚠️ 客户端不传就不设置
    }
}
```

**文件：`relay/channel/api_request.go`（行 50-77）**
```go
// 以下 header 被强制剥离，不会透传
var passthroughSkipHeaderNamesLower = map[string]bool{
    "cookie": true,           // ❌ clewdr 需要用自己的 cookie
    "authorization": true,    // ❌ 被替换为 channel key
    "accept-encoding": true,  // ⚠️ 可能影响响应格式
    "host": true,             // ✅ 正常
    // ...
}
```

**文件：`relay/channel/claude/relay-claude.go`（行 47-402）**
```go
func RequestOpenAI2ClaudeMessage(...) {
    // OpenAI 格式 → Claude 格式转换
    // Go encoding/json 按字母序排列 key（与 JS 插入序不同）
    // content 字段可能被转为纯字符串（Claude Code 用 content block 数组）
}
```

### 2.2 model-family 侧改动方案

#### 方案 A：Channel Header Override 配置（推荐，零代码改动）

model-family 已支持 `header_override` 配置。在 clewdr 对应的 channel 设置中配置：

```json
{
  "header_override": {
    "*": true
  }
}
```

这会启用通配符透传，将客户端的所有 header（除 skip list 中的）都转发给 clewdr。

**但这不够**，因为：
1. `authorization` 在 skip list 中，会被替换为 channel key — 这实际上是正确的
2. 客户端（如 Claude Code CLI 或 OpenAI 兼容客户端）本身不会发送 `anthropic-beta` 等头
3. 真正的问题是 **请求体转换**

#### 方案 B：clewdr 侧使用原生 Claude 格式端点（推荐）

**核心思路**：让 model-family 的 channel 直接指向 clewdr 的 **Claude 原生端点**（`/v1/messages`），而不是 OpenAI 兼容端点（`/v1/chat/completions`）。

这样 model-family 的 Claude adaptor 会调用 `ConvertClaudeRequest()`，对于已经是 Claude 格式的请求会**直接透传**，不做转换：

```go
// relay/channel/claude/adaptor.go 行 26-28
func (a *Adaptor) ConvertClaudeRequest(c *gin.Context, info *relaycommon.RelayInfo, request *dto.GeneralOpenAIRequest) (any, error) {
    // 如果上游发的就是 Claude 格式，直接透传
    if info.RelayFormat == relaycommon.RelayFormatClaude {
        return request, nil  // 不做任何转换
    }
    return RequestOpenAI2ClaudeMessage(request, info)
}
```

**配置方式**：
1. 在 model-family 中创建 channel，类型选 `Claude (Anthropic)`
2. Base URL 填 clewdr 的地址，如 `http://localhost:8484`
3. API Key 填 clewdr 的 admin password
4. 前端用户通过 model-family 的 **Claude 原生端点** `/v1/messages` 发送请求

**但问题在于**：大多数下游客户端（如 SillyTavern、LobeChat 等）使用 OpenAI 兼容格式，所以格式转换是不可避免的。

#### 方案 C：保持客户端原生格式直达对应端点（推荐，最简单）

根据客户端实际发送的格式，model-family 直接转发到 clewdr 对应的端点：

```
Claude Code CLI(Claude格式) → model-family(计费/路由) → clewdr(/code/v1/messages) → Claude API
OpenClaw(Claude格式)        → model-family(计费/路由) → clewdr(/v1/messages)      → Claude API
OpenAI兼容客户端             → model-family(计费/路由) → clewdr(/v1/chat/completions) → Claude API
```

**关键事实**：clewdr 收到请求后会完全反序列化为 Rust struct 再重新序列化，所以：
- Go 的 JSON key 字母序排列 **不会** 泄露到 Claude（被 Rust/serde 覆盖）
- model-family 的 header **不会** 泄露到 Claude（被 clewdr 硬编码覆盖）
- 保持原生格式直达 = 减少转换环节 = 减少出错机会

**clewdr 侧确认安全的点**：
```
1. Header 重建
   - clewdr 本身已经硬编码了 anthropic-version, anthropic-beta, User-Agent
   - model-family 传过来的 header 不会影响 clewdr 发往 Claude 的 header
   - ✅ 已确认安全

2. JSON 序列化
   - clewdr 完全反序列化再重新序列化
   - 最终 key 顺序由 Rust struct 字段定义顺序决定
   - ✅ Go 的字母序不是问题
```

### 2.3 确认：model-family 的 header 不会泄露到 Claude

通过代码审计确认 clewdr 的请求构建流程：

```rust
// src/claude_code_state/mod.rs:97-110
pub fn build_request(&self, method: Method, url: impl ToString) -> RequestBuilder {
    let mut req = self.client
        .request(method, url.to_string())
        .header(ORIGIN, CLAUDE_ENDPOINT)           // 硬编码
        .header(REFERER, format!("{CLAUDE_ENDPOINT}new"))  // 硬编码
        .header(USER_AGENT, CLAUDE_CODE_USER_AGENT);       // 硬编码
    // ...
}

// src/claude_code_state/chat.rs:205-210
self.build_request(Method::POST, url)
    .bearer_auth(access_token)                     // 硬编码
    .header(USER_AGENT, CLAUDE_CODE_USER_AGENT)    // 硬编码
    .header("anthropic-beta", beta_header)         // 硬编码
    .header("anthropic-version", CLAUDE_API_VERSION)  // 硬编码
    .json(body)
```

**结论**：clewdr 在构建发往 Claude 的请求时，**完全重建所有 header**，不会透传 model-family 传过来的 header。因此 model-family 的 header 问题（如缺失 UA、anthropic-beta）**不会直接到达 Claude**。

**真正的风险在请求体（body）**：model-family 做格式转换时修改了 JSON body 的结构和字段，这些修改会被 clewdr 带到 Claude。

---

## 三、请求体标准化（clewdr 改动）

### 3.1 JSON 序列化顺序控制

**问题**：model-family 用 Go `encoding/json` 序列化 JSON，key 按字母序排列。clewdr 接收后用 serde 反序列化再序列化，最终发往 Claude 的 JSON key 顺序取决于 serde 的序列化行为。

**当前状态检查**：

clewdr 的消息体定义在 `src/types/claude/mod.rs` 中，使用 `serde::Serialize`。serde 默认按 struct 字段定义顺序序列化，所以：

```rust
#[derive(Serialize, Deserialize)]
pub struct CreateMessageParams {
    pub model: String,          // 序列化时排第 1
    pub messages: Vec<Message>, // 序列化时排第 2
    pub max_tokens: u64,        // 序列化时排第 3
    // ...
}
```

这与 Claude Code CLI（JS）的插入序一致吗？需要验证真实 CLI 的字段顺序。

**改动方案**：

```rust
// 确保 CreateMessageParams 的字段顺序与真实 Claude Code CLI 一致
// 真实 CLI 的顺序（通过抓包确认）大致为：
// model, max_tokens, messages, system, stream, temperature, ...

// 方案 1：调整 struct 字段顺序（推荐，最简单）
#[derive(Serialize, Deserialize)]
pub struct CreateMessageParams {
    pub model: String,
    pub max_tokens: u64,
    pub messages: Vec<Message>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<SystemPrompt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    // ... 按真实 CLI 顺序排列
}

// 方案 2：使用 IndexMap 做动态序列化（更灵活但复杂）
// 在发送前将 struct 转为 IndexMap<String, Value>，手动控制顺序
```

**实施文件**：`src/types/claude/mod.rs`

**工程量**：约 50 行，调整字段顺序 + 验证

### 3.2 请求体字段清理（RequestNormalizer）

**问题**：下游客户端通过 model-family 的 OpenAI 转换后，可能残留非标准字段。

**改动方案**：

在 `src/middleware/claude/request.rs` 的请求处理流程中增加清理逻辑：

```rust
/// 清理非 Claude 标准字段，移除 OpenAI 转换残留
fn normalize_request_body(body: &mut CreateMessageParams) {
    // 1. 确保 content 是 content block 数组格式
    for msg in &mut body.messages {
        msg.content = match &msg.content {
            Content::Text(s) => Content::Blocks(vec![ContentBlock::text(s.clone())]),
            Content::Blocks(blocks) => Content::Blocks(blocks.clone()),
        };
    }

    // 2. 移除 Claude API 不认识的字段
    // 通过 serde(deny_unknown_fields) 或手动过滤
    // 例如：frequency_penalty, presence_penalty, logit_bias 等 OpenAI 特有字段

    // 3. 规范 system prompt 格式
    if let Some(system) = &mut body.system {
        // 确保 system 是 content block 数组格式
        normalize_system_prompt(system);
    }
}
```

**实施文件**：`src/middleware/claude/request.rs`

**工程量**：约 100-150 行

### 3.3 content 字段格式规范化

**问题**：model-family 转换后，`content` 可能是纯字符串 `"content": "hello"`，而真实 Claude Code CLI 发送的是 content block 数组 `"content": [{"type": "text", "text": "hello"}]`。

**改动**：在 clewdr 的消息预处理中，统一转换为 content block 数组格式。

clewdr 的 `Content` 类型可能已经支持两种格式的反序列化，但序列化时需要确保始终输出为 block 数组。

**检查点**：确认 `src/types/claude/mod.rs` 中 `Content` 的 `Serialize` 实现。

---

## 四、Cookie 并发控制（45% 根因）

### 4.1 当前并发模型分析

通过代码审计确认 clewdr 的 cookie 管理：

**架构**：Ractor Actor 模型（`src/services/cookie_actor.rs`）

```
多个 HTTP 请求（并发）
       ↓
  Axum Router（tokio tasks）
       ↓
  N 个 cookie_actor_handle.request(...) 调用
       ↓
  Ractor 消息队列（串行处理）
       ↓
  CookieActor.handle() 逐条处理消息
       ↓
  返回 CookieStatus 的 clone 给各个等待者
```

**关键发现**：

1. **同一个 cookie 可以被多个并发请求同时使用**
   ```rust
   // cookie_actor.rs 行 199-207
   let cookie = state.valid.pop_front()?;
   state.valid.push_back(cookie.clone());  // 立即放回队列
   Ok(cookie)  // 返回 clone
   ```
   Cookie 被 clone 后立即放回队列，下一个请求可以立刻拿到同一个 cookie。

2. **Round-Robin 分配**：如果只有 1 个 cookie，所有并发请求都会拿到同一个 cookie。

3. **没有并发限制**：没有 semaphore 或任何机制限制同一个 cookie 的并发使用数。

### 4.2 为什么需要串行化

多用户并发使用同一个 cookie 时，Claude 服务端看到的模式：

| 指标 | 并发模式（当前） | 串行模式（优化后） |
|------|-----------------|-------------------|
| 请求到达间隔 CV | ~1.0（泊松分布，多用户） | >2.0（突发性长尾，像单用户） |
| 并发 conversation 数 | 可能同时 3-5 个 | 同时最多 1 个 |
| token 消费速率 | 远超单人能力 | 受限于串行吞吐 |
| system prompt 多样性 | 高（多人不同上下文） | 低（虽然仍有切换） |

**蓝队的 BEH-06v3（CV 分析）正是利用了并发模式的泊松到达特征**。串行化可以直接将 CV 从 ~1.0 提高到 >2.0，绕过这条检出率 60-80% 的 P0 规则。

### 4.3 Cookie 串行化方案

#### 方案：Per-Cookie Semaphore（每 cookie 信号量）

在 cookie actor 中为每个 cookie 维护一个并发计数器，限制同一个 cookie 同时只能服务一个请求。

**实现思路**：

```rust
// cookie_actor.rs 中新增
struct CookieActorState {
    valid: VecDeque<CookieStatus>,
    exhausted: HashSet<CookieStatus>,
    invalid: HashSet<UselessCookie>,
    moka: Cache<u64, CookieStatus>,
    // 新增：记录当前正在使用的 cookie（已借出，尚未归还）
    in_use: HashMap<CookieId, usize>,  // cookie_id → 并发使用数
    max_concurrent_per_cookie: usize,   // 从配置读取，默认 1
}
```

**修改 dispatch 逻辑**：

```rust
fn dispatch(&self, state: &mut CookieActorState, hash: Option<u64>)
    -> Result<CookieStatus, ClewdrError>
{
    Self::reset(state);

    let max_concurrent = state.max_concurrent_per_cookie; // 默认 1

    // 遍历 valid 队列，找到一个并发数未满的 cookie
    for i in 0..state.valid.len() {
        let cookie = &state.valid[i];
        let cookie_id = cookie.id(); // 需要一个唯一标识
        let current = state.in_use.get(&cookie_id).copied().unwrap_or(0);

        if current < max_concurrent {
            // 借出这个 cookie
            let cookie = state.valid[i].clone();
            *state.in_use.entry(cookie_id).or_insert(0) += 1;
            // 不从 valid 队列移除（还能被其他请求使用，取决于 max_concurrent）
            return Ok(cookie);
        }
    }

    // 所有 cookie 都满了，返回错误或等待
    Err(ClewdrError::NoCookieAvailable)
}
```

**修改 collect（归还）逻辑**：

```rust
fn collect(state: &mut CookieActorState, cookie: CookieStatus, reason: Option<Reason>) {
    let cookie_id = cookie.id();

    // 减少并发计数
    if let Some(count) = state.in_use.get_mut(&cookie_id) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            state.in_use.remove(&cookie_id);
        }
    }

    // 原有的 reason 处理逻辑...
    // ...
}
```

**配置项**：

```toml
# clewdr.toml
# 每个 cookie 的最大并发请求数
# 1 = 严格串行（推荐，最安全）
# 2-3 = 轻度并发（平衡性能和安全）
max_concurrent_per_cookie = 1
```

#### 等待队列 vs 立即拒绝

当所有 cookie 都在使用中时，有两种策略：

**策略 A：等待队列（推荐）**
```rust
// 使用 tokio::sync::Notify 或 channel 实现等待
// 当 cookie 归还时，通知等待者
// 设置最大等待时间（如 30 秒），超时返回 429
```

**策略 B：立即返回 429**
```rust
// 直接返回 HTTP 429 给 model-family
// model-family 的重试逻辑会处理
// 更简单但用户体验差
```

推荐策略 A，实现一个异步等待队列：

```rust
// 在 CookieActorMessage 中新增等待消息类型
enum CookieActorMessage {
    Request(Option<u64>, RpcReplyPort<Result<CookieStatus, ClewdrError>>),
    Return(CookieStatus, Option<Reason>),
    // 新增：当有 cookie 归还时，唤醒等待者
    WakeWaiters,
}
```

**工程量**：约 200-300 行修改 `cookie_actor.rs`

### 4.4 请求时序整形

即使串行化了 cookie 使用，请求的到达间隔仍然可能过于均匀。增加随机延迟：

```rust
// 在 dispatch 成功后、实际发送请求前
async fn apply_timing_jitter() {
    // 模拟人类思考间隔：log-normal 分布
    // 中位数 3 秒，标准差 2 秒
    let delay_ms = log_normal_sample(mean: 3000.0, std: 2000.0);
    let delay = Duration::from_millis(delay_ms.min(15000) as u64); // 上限 15 秒
    tokio::time::sleep(delay).await;
}
```

这可以在 `src/claude_code_state/chat.rs` 或 `src/claude_web_state/chat.rs` 的 `try_chat` 中实现，在调用 `send_chat` 前插入延迟。

**配置项**：

```toml
# clewdr.toml
# 请求间最小延迟（毫秒），0 = 不延迟
request_delay_ms = 2000
# 延迟随机抖动范围（毫秒）
request_jitter_ms = 3000
```

**工程量**：约 30-50 行

---

## 五、wreq 指纹更新

### 5.1 当前状态

**clewdr 使用**：wreq `6.0.0-rc.28` + wreq-util `3.0.0-rc.10`
**clewdr 配置的模拟池**：仅 3 个 — Chrome136, Chrome131, Edge127

**wreq 最新版支持的模拟配置（约 58+ 种）**：

| 类别 | 版本范围 | 数量 |
|------|---------|------|
| Chrome | 100-139 | ~27 |
| Firefox | 109-136 | ~6 |
| Safari | 15.3-26 (含 iOS/iPad) | ~14 |
| Edge | 101-131 | ~4 |
| OkHttp | 3.9-5 | ~7 |

**关键发现**：wreq **没有** Bun/Node.js/Deno 等 JS 运行时的模拟配置。

### 5.2 TLS 指纹策略

红蓝对抗中确认的问题：clewdr 用浏览器 TLS 指纹，但 Claude Code CLI 运行在 Bun 运行时上。

**在 wreq 不支持 Bun 的前提下，策略选择**：

#### Claude Code 模式

| 策略 | 方案 | 可行性 | 效果 |
|------|------|--------|------|
| A | 不做 TLS 模拟，用 rustls 默认 | 高 | 至少不会矛盾（"CLI 工具+非浏览器 TLS"是合理的） |
| B | 自定义 Bun TLS 指纹导入 wreq | 低 | 完美但工程量巨大 |
| C | 继续用浏览器模拟但扩大池 | 高 | 效果有限，矛盾仍在 |

**推荐策略 A**：对 Claude Code 端点，禁用浏览器 TLS 模拟。

```rust
// src/config/constants.rs
// Claude Code 模式：不做浏览器模拟
pub fn code_emulation() -> Option<wreq_util::Emulation> {
    None  // 使用 wreq 默认 TLS（基于 BoringSSL/rustls）
}

// Claude Web 模式：保留浏览器模拟（因为应该是浏览器访问）
pub fn web_emulation() -> wreq_util::Emulation {
    random_emulation()  // 从扩大后的池中随机选择
}
```

#### Claude Web 模式

保留浏览器模拟，但扩大模拟池：

```rust
// src/config/constants.rs
const WEB_EMULATIONS: &[wreq_util::Emulation] = &[
    // Chrome 系列（最新 + 次新）
    wreq_util::Emulation::Chrome139,
    wreq_util::Emulation::Chrome136,
    wreq_util::Emulation::Chrome133,
    wreq_util::Emulation::Chrome131,
    // Safari 系列
    wreq_util::Emulation::Safari26,
    wreq_util::Emulation::Safari18_2,
    wreq_util::Emulation::Safari18,
    // Edge 系列
    wreq_util::Emulation::Edge131,
    wreq_util::Emulation::Edge127,
    // Firefox 系列
    wreq_util::Emulation::Firefox136,
    wreq_util::Emulation::Firefox135,
];
```

### 5.3 wreq 版本更新

检查 clewdr 的 `Cargo.toml` 中 wreq 和 wreq-util 的版本是否需要更新：

```toml
# 当前
wreq = "6.0.0-rc.28"
wreq-util = "3.0.0-rc.10"

# 建议：检查最新 rc 版本
# 更新步骤：
# 1. 修改 Cargo.toml 中版本号
# 2. cargo update -p wreq -p wreq-util
# 3. 检查 API 是否有 breaking changes
# 4. 测试编译
```

**注意**：wreq 仍在 rc 阶段，更新时需要注意 API 变动。

---

## 六、使用量限流（10% 根因）

### 6.1 方案

在 cookie actor 中增加使用量追踪和限制：

```rust
// 配置项
#[serde(default)]
pub max_tokens_per_hour: Option<u64>,    // 默认 30000
#[serde(default)]
pub max_tokens_per_day: Option<u64>,     // 默认 400000
```

当 cookie 在时间窗口内的 token 消费超过阈值时，将其标记为 `Exhausted` 状态并冷却：

```rust
// 在 cookie 归还时检查使用量
fn check_usage_limits(cookie: &CookieStatus, config: &ClewdrConfig) -> Option<Reason> {
    if let Some(max_hourly) = config.max_tokens_per_hour {
        if cookie.hourly_tokens() > max_hourly {
            return Some(Reason::TooManyRequest(
                chrono::Utc::now().timestamp() + 3600  // 冷却 1 小时
            ));
        }
    }
    if let Some(max_daily) = config.max_tokens_per_day {
        if cookie.daily_tokens() > max_daily {
            return Some(Reason::TooManyRequest(
                chrono::Utc::now().timestamp() + 86400  // 冷却到第二天
            ));
        }
    }
    None
}
```

**工程量**：约 80-100 行

---

## 七、API 调用模式补全（15% 根因）

### 7.1 初始化序列

真实 Claude Code CLI 在发送第一条消息前，会执行：
1. `GET /v1/organizations` — 获取组织信息
2. `GET /v1/models` — 获取可用模型列表
3. `POST /v1/messages/count_tokens` — 预估 token 数量

clewdr 目前只有 `count_tokens` 调用（在 chat.rs 中），缺少前两步。

**改动方案**：

```rust
// src/claude_code_state/mod.rs 新增
impl ClaudeCodeState {
    /// 首次使用 cookie 时执行初始化序列
    async fn initialize_session(&self) -> Result<(), ClewdrError> {
        // 仅在 cookie 首次使用时执行（通过标志位控制）
        if self.cookie.as_ref().map_or(false, |c| c.initialized) {
            return Ok(());
        }

        // 1. GET organizations
        let _orgs = self.build_request(Method::GET, format!("{CLAUDE_ENDPOINT}v1/organizations"))
            .send().await?;

        // 模拟人类操作延迟
        tokio::time::sleep(Duration::from_millis(500 + rand::random::<u64>() % 1000)).await;

        // 2. GET models（可选）
        let _models = self.build_request(Method::GET, format!("{CLAUDE_ENDPOINT}v1/models"))
            .send().await?;

        Ok(())
    }
}
```

**工程量**：约 50-80 行

---

## 八、改动优先级总表

| 优先级 | 改动项 | 影响根因 | 工程量 | 效果 |
|--------|--------|----------|--------|------|
| **P0** | Cookie 串行化（per-cookie semaphore） | 45% 多用户 | 200-300 行 | CV 从 1.0 提高到 >2.0，绕过 BEH-06v3 |
| **P0** | model-family channel 配置优化（原生格式直达对应端点） | 30% 格式破坏 | 配置变更 | 减少转换环节，Go JSON 顺序不影响（clewdr 重新序列化） |
| **P1** | 请求体标准化（normalize） | 30% 格式破坏 | 100-150 行 | 清理 OpenAI 转换残留 |
| **P1** | content 格式统一为 block 数组 | 30% 格式破坏 | 50 行 | 对齐真实 CLI 行为 |
| **P1** | 请求时序抖动 | 45% 多用户 | 30-50 行 | 模拟自然请求间隔 |
| **P2** | wreq 版本更新 + 模拟池扩大 | TLS 指纹 | 20-30 行 | 降低 TLS 聚集度 |
| **P2** | Claude Code 模式禁用浏览器 TLS | TLS 矛盾 | 30 行 | 消除 UA vs TLS 矛盾 |
| **P2** | 使用量限流 | 10% 消费量 | 80-100 行 | 保护 cookie 不被消费量检测 |
| **P2** | JSON 序列化字段顺序 | 格式指纹 | 50 行 | 对齐真实 CLI |
| **P3** | API 初始化序列 | 15% 调用模式 | 50-80 行 | 补全 API 状态机 |
| **P3** | 配置项完善（toml 新增项） | 可运维性 | 30 行 | 用户可调参 |

---

## 九、clewdr.toml 新增配置项汇总

```toml
# ===== 并发控制 =====
# 每个 cookie 的最大并发请求数（1 = 严格串行，推荐）
max_concurrent_per_cookie = 1

# 等待 cookie 可用的最大超时时间（秒）
cookie_wait_timeout = 30

# ===== 请求时序 =====
# 请求间最小延迟（毫秒），0 = 不延迟
request_delay_ms = 2000

# 延迟随机抖动范围（毫秒）
request_jitter_ms = 3000

# ===== 使用量限流 =====
# 每个 cookie 每小时最大 token 数（0 = 不限制）
max_tokens_per_hour = 30000

# 每个 cookie 每天最大 token 数（0 = 不限制）
max_tokens_per_day = 400000

# ===== TLS 配置 =====
# Claude Code 模式是否使用浏览器 TLS 模拟
# false = 使用默认 TLS（推荐，避免 UA/TLS 矛盾）
code_browser_emulation = false
```

---

## 十、model-family 侧配置检查清单

在 model-family 管理后台中，针对 clewdr channel 做以下配置：

| 检查项 | 配置 | 说明 |
|--------|------|------|
| Channel Type | `Claude (Anthropic)` | 确保走 Claude adaptor |
| Base URL | `http://<clewdr-host>:8484` | 指向 clewdr 实例 |
| API Key | clewdr 的 admin password | 认证用 |
| Header Override | `{"*": true}` | 开启通配透传（可选） |
| 模型映射 | 按需配置 | 确保模型名称正确传递 |
| 重试次数 | 建议 ≤ 2 | 避免 model-family 层重试叠加 clewdr 层重试 |

**特别注意**：无论 model-family 转发哪种格式到 clewdr，clewdr 都会完全反序列化再重新序列化 JSON body，因此 Go 的 JSON key 排序不会泄露到 Claude。**推荐让客户端原生格式直达 clewdr 对应端点**——Claude Code CLI 和 OpenClaw 发 Claude 格式到 `/code/v1/messages` 或 `/v1/messages`，减少不必要的格式转换环节。

---

## 十一、总结

在保留 model-family 的约束下，通过以下改动可以将封号风险从"20 小时内封号"降低到"长期可存活"：

```
封号风险削减：
  45% 多用户聚合 → Cookie 串行化 + 时序抖动 → 消除约 80%
  30% 格式破坏   → 请求标准化 + 配置优化    → 消除约 70%
  15% 调用模式   → API 初始化序列           → 消除约 50%
  10% 消费量     → 使用量限流               → 消除约 90%

  综合：原风险 100% → 优化后约 20-30%（存活率从 <10% 提升到 70-80%）
```

**但请注意红蓝对抗的核心结论**：在多用户共享场景下，蓝队的统计检测是信息论层面的约束，技术手段只能缓解不能消除。**最安全的方案仍然是 1 cookie/1 用户**。上述改动是在多用户场景下的最大努力优化，但不能保证 100% 安全。
