# ClewdR 检测向量深度分析与优化方案

> 更新日期：2026-03-30
> 基于 clewdr 当前版本（模拟 Claude Code v2.1.86）的全面审计

---

## 目录

1. [概述](#概述)
2. [检测向量分类](#检测向量分类)
3. [第一类：网络层指纹（高风险）](#第一类网络层指纹高风险)
4. [第二类：请求特征指纹（高风险）](#第二类请求特征指纹高风险)
5. [第三类：行为模式（中风险）](#第三类行为模式中风险)
6. [第四类：静态指纹（中风险）](#第四类静态指纹中风险)
7. [第五类：请求修正与兼容处理（低风险）](#第五类请求修正与兼容处理低风险)
8. [优化方案总览](#优化方案总览)
9. [实施优先级](#实施优先级)

---

## 概述

本文档基于对 clewdr 源码的完整审计，系统性记录了所有可能被 Anthropic 服务端检测到的异常信号。每个检测向量包含：

- **问题描述**：异常行为的具体表现
- **代码位置**：涉及的源文件和行号
- **检测原理**：服务端如何利用该信号识别代理
- **风险等级**：高 / 中 / 低
- **优化方案**：具体的代码修改建议

---

## 检测向量分类

| 类别 | 风险 | 数量 | 说明 |
|------|------|------|------|
| 网络层指纹 | 高 | 3 | TLS、安全头、连接特征 |
| 请求特征指纹 | 高 | 5 | Header、billing、system prompt |
| 行为模式 | 中 | 6 | 对话生命周期、探测、重试 |
| 静态指纹 | 中 | 5 | 硬编码常量、共享 ID |
| 请求修正 | 低 | 4 | 自动修正、消息清理 |

---

## 第一类：网络层指纹（高风险）

### DV-01：TLS 指纹与客户端身份矛盾

**问题描述**

clewdr 使用 `wreq` 库模拟浏览器 TLS 指纹（Chrome136、Chrome131、Edge127），但声称的客户端身份是 `claude-code/2.1.86`（CLI 工具）。

真正的 Claude Code CLI 运行在 **Bun 运行时** 上，使用的是 BoringSSL/LibTLS，其 JA3/JA4 指纹与浏览器完全不同。服务端看到的矛盾是：

> User-Agent: claude-code/2.1.86（CLI 工具）
> TLS 指纹: Chrome 136（浏览器）

**代码位置**

```
src/config/constants.rs:145-165    # 浏览器模拟配置
```

```rust
const EMULATIONS: &[wreq_util::Emulation] = &[
    wreq_util::Emulation::Chrome136,
    wreq_util::Emulation::Chrome131,
    wreq_util::Emulation::Edge127,
];

pub fn random_emulation() -> wreq_util::Emulation {
    let mut h = DefaultHasher::new();
    std::thread::current().id().hash(&mut h);
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .hash(&mut h);
    EMULATIONS[h.finish() as usize % EMULATIONS.len()]
}
```

**检测原理**

Anthropic 服务端（或前置 CDN 如 Cloudflare）可以提取每个连接的 JA3/JA4 TLS 指纹，并与 User-Agent 声明的客户端进行交叉验证：

- Chrome 浏览器的 JA3 哈希 ≠ Bun 运行时的 JA3 哈希
- 如果 UA 说是 CLI 但 TLS 像浏览器，立即标记为可疑
- 仅 3 个浏览器版本也使得指纹池过小

**优化方案**

方案 A：模拟 Bun 运行时的 TLS 指纹（推荐）
```
- 研究 Bun v1.x 使用的 TLS 库（基于 BoringSSL）
- 提取 Bun 的 JA3/JA4 指纹
- 在 wreq 中添加 Bun 运行时的模拟配置
- 或使用 rustls 原生（不做浏览器模拟），其指纹更接近非浏览器客户端
```

方案 B：不做 TLS 模拟
```
- 移除 wreq 的浏览器模拟
- 使用 rustls 默认配置
- 非浏览器 TLS 指纹虽然与 Bun 不完全一致，但至少不会产生
  "声称是 CLI 但 TLS 像浏览器"的矛盾
```

方案 C：让 TLS 指纹与 UA 一致（仅 Claude Web 模式）
```
- Claude Web 模式：保留浏览器 TLS 模拟（因为应该是浏览器访问）
- Claude Code 模式：切换到非浏览器 TLS
- 根据 provider 类型选择不同的 TLS 配置
```

---

### DV-02：缺少浏览器安全头（Claude Web 模式）

**问题描述**

真实浏览器在发送请求时会自动附带一系列安全头，clewdr 全部缺失：

| 缺失的 Header | 真实浏览器的值 |
|---------------|---------------|
| `Sec-Fetch-Site` | `same-site` / `cross-site` |
| `Sec-Fetch-Mode` | `cors` / `navigate` |
| `Sec-Fetch-Dest` | `empty` / `document` |
| `Sec-Ch-Ua` | `"Chromium";v="136", ...` |
| `Sec-Ch-Ua-Mobile` | `?0` |
| `Sec-Ch-Ua-Platform` | `"macOS"` |
| `Accept-Language` | `en-US,en;q=0.9,zh-CN;q=0.8` |
| `DNT` | `1` |

**代码位置**

```
src/claude_web_state/mod.rs:95-111    # Web 模式请求构建
src/claude_code_state/mod.rs:97-110   # Code 模式请求构建
```

这两处 `build_request` 方法都只设置了 `Origin`、`Referer`、`User-Agent`，没有任何 Sec-* 头。

**检测原理**

- 浏览器自动添加的 Sec-* 头无法通过 JavaScript 伪造（fetch spec 要求）
- 服务端可以检测到：有 Cookie 的请求（应该是浏览器）却没有 Sec-* 头
- Cloudflare Bot Management 会将缺失 Sec-* 头的请求标记为可疑

**优化方案**

```rust
// Claude Web 模式的 build_request 中添加：
fn build_request(&self, method: Method, url: impl ToString) -> RequestBuilder {
    let mut req = self.client
        .request(method, url.to_string())
        .header(ORIGIN, CLAUDE_WEB_ENDPOINT)
        .header(REFERER, /* ... */)
        .header(USER_AGENT, /* browser UA */)
        // 添加浏览器安全头
        .header("Sec-Fetch-Site", "same-origin")
        .header("Sec-Fetch-Mode", "cors")
        .header("Sec-Fetch-Dest", "empty")
        .header("Sec-Ch-Ua", r#""Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99""#)
        .header("Sec-Ch-Ua-Mobile", "?0")
        .header("Sec-Ch-Ua-Platform", r#""macOS""#)
        .header("Accept-Language", "en-US,en;q=0.9");
    // ...
}
```

注意：
- Sec-Ch-Ua 的版本号应与 TLS 模拟的浏览器版本一致
- Claude Code 模式不需要这些头（CLI 不是浏览器）
- 需要根据模拟的浏览器动态生成对应版本的 Sec-Ch-Ua

---

### DV-03：浏览器模拟池过小

**问题描述**

仅有 3 个浏览器配置（Chrome136、Chrome131、Edge127），全部是 Chromium 系。

**检测原理**

Anthropic 可以统计所有连接的 TLS 指纹分布。如果大量请求集中在这 3 个精确版本上（没有任何 Safari、Firefox、其他 Chrome 小版本），这本身就是异常。

**优化方案**

```rust
// 扩展浏览器模拟池
const EMULATIONS: &[wreq_util::Emulation] = &[
    // 添加更多 Chrome 版本
    wreq_util::Emulation::Chrome136,
    wreq_util::Emulation::Chrome135,
    wreq_util::Emulation::Chrome134,
    wreq_util::Emulation::Chrome131,
    // 添加 Safari（如果 wreq 支持）
    wreq_util::Emulation::Safari18,
    // 添加 Edge
    wreq_util::Emulation::Edge127,
    wreq_util::Emulation::Edge131,
];
```

但如果采用 DV-01 方案 A/B（Claude Code 模式不做浏览器模拟），则此问题仅影响 Claude Web 模式。

---

## 第二类：请求特征指纹（高风险）

### DV-04：Billing Header 作为 System Prompt 注入

**问题描述**

`x-anthropic-billing-header` 本应是 HTTP 头，但 clewdr 将其作为 **system prompt 文本块** 注入到消息体中：

```
x-anthropic-billing-header: cc_version=2.1.86.xxx; cc_entrypoint=unknown; cch=d1347;
```

这段文本被 Claude 模型看到了，也被 Anthropic 后端看到了。

**代码位置**

```
src/middleware/claude/request.rs:366-377
```

```rust
let mut system_prefixes = vec![ContentBlock::text(claude_code_billing_header(
    &body.messages,
))];
if let Some(custom_system) = CLEWDR_CONFIG
    .load()
    .custom_system
    .clone()
    .filter(|s| !s.trim().is_empty())
{
    system_prefixes.push(ContentBlock::text(custom_system));
}
prepend_system_blocks(&mut body, system_prefixes);
```

**检测原理**

- Anthropic 后端可以扫描 system prompt 中是否出现 `x-anthropic-billing-header:` 格式的文本
- 正常的 Claude Code CLI 是将 billing header 作为 **HTTP 头** 发送的，不会出现在消息内容中
- 这是一个非常明显的代理特征

**优化方案**

将 billing header 从 system prompt 移到 HTTP 请求头中：

```rust
// 在 claude_code_state/chat.rs 的 execute_claude_request 中
// 将 billing header 作为 HTTP 头发送，而不是注入 system prompt

let billing = claude_code_billing_header(&body.messages);

self.client
    .post(endpoint)
    .bearer_auth(access_token)
    .header(USER_AGENT, CLAUDE_CODE_USER_AGENT)
    .header("anthropic-beta", beta_header)
    .header("anthropic-version", CLAUDE_API_VERSION)
    .header("x-anthropic-billing-header", billing)  // 作为 HTTP 头
    .json(body)
    .send()
```

同时移除 `request.rs:366-377` 中的 system prompt 注入逻辑。

---

### DV-05：cc_entrypoint 默认值异常

**问题描述**

```rust
// src/middleware/claude/request.rs:131-134
let entrypoint = env::var(CLAUDE_CODE_ENTRYPOINT_ENV)
    .ok()
    .filter(|value| !value.trim().is_empty())
    .unwrap_or_else(|| "unknown".to_string());
```

大多数 clewdr 部署不会设置 `CLAUDE_CODE_ENTRYPOINT` 环境变量，导致所有请求的 `cc_entrypoint=unknown`。

**检测原理**

真实客户端的 entrypoint 值分布：
| 客户端 | entrypoint |
|--------|-----------|
| CLI | `cli` |
| VS Code | `claude-vscode` |
| JetBrains | `claude-jetbrains` |

大量 `cc_entrypoint=unknown` 的请求是异常的。

**优化方案**

方案 A：默认使用 `cli`（最常见的真实值）
```rust
.unwrap_or_else(|| "cli".to_string());
```

方案 B：随机选择合理的 entrypoint
```rust
const ENTRYPOINTS: &[&str] = &["cli", "claude-vscode", "claude-jetbrains"];
// 每个 session 固定一个 entrypoint（不能每个请求换）
```

方案 C：在配置文件中提供设置项
```toml
# clewdr.toml
cc_entrypoint = "cli"  # 或 "claude-vscode"
```

推荐方案 A，最简单且覆盖最大用户群。

---

### DV-06：cch 值硬编码

**问题描述**

```rust
// src/middleware/claude/request.rs:137
format!(
    "x-anthropic-billing-header: cc_version={CLAUDE_CODE_VERSION}.{}; cc_entrypoint={entrypoint}; cch=d1347;",
    &version_hash[..3]
)
```

`cch=d1347` 在所有请求中固定不变。

**检测原理**

- 所有 clewdr 实例共享同一个 `cch` 值
- 如果真实客户端的 `cch` 是动态生成的或因版本不同而不同，固定值就是指纹
- Anthropic 可以统计 `cch` 值的分布，发现 `d1347` 异常集中

**优化方案**

需要逆向分析真实 Claude Code CLI 中 `cch` 的生成逻辑：

```
1. 抓包真实 CLI 多次请求，观察 cch 值是否变化
2. 如果变化：提取生成算法，在 clewdr 中复现
3. 如果固定：确认真实值是否也是 d1347
   - 如果是，无需修改
   - 如果不是，更新为正确的固定值
```

---

### DV-07：Billing Salt 硬编码

**问题描述**

```rust
// src/config/constants.rs:23
pub const CLAUDE_CODE_BILLING_SALT: &str = "59cf53e54c78";
```

billing header 中的版本哈希由 `SHA256(salt + sampled_chars + version)` 生成。

**检测原理**

如果 Anthropic 服务端也独立计算这个哈希：
- Salt 正确 → 哈希匹配 → 通过
- Salt 错误 → 哈希不匹配 → 立即标记为伪造

如果 salt 随版本更新而变化，硬编码的旧 salt 在版本号更新后会导致哈希不匹配。

**优化方案**

```
1. 每次更新版本号时，从真实 CLI 二进制中提取新的 salt
2. 验证方法：
   a. 安装对应版本的 Claude Code CLI
   b. 在 CLI 二进制或 extension.js 中搜索 salt 字符串
   c. 对比是否与当前硬编码值一致
3. 考虑建立自动化脚本，在新版本发布时自动提取 salt
```

---

### DV-08：Billing Header 的 sample 逻辑可能不一致

**问题描述**

```rust
// src/middleware/claude/request.rs:113-118
fn sample_js_code_unit(text: &str, idx: usize) -> String {
    text.encode_utf16()
        .nth(idx)
        .map(|unit| String::from_utf16_lossy(&[unit]))
        .unwrap_or_else(|| "0".to_string())
}
```

从第一条用户消息的 UTF-16 编码中取索引 [4, 7, 20] 的 code unit。

**检测原理**

- 如果真实 CLI 的采样逻辑不同（不同索引、不同消息源、不同编码方式），则哈希一定不匹配
- Rust 的 `encode_utf16()` 与 JavaScript 的 `charCodeAt()` 在处理代理对（surrogate pairs）时可能有细微差异

**优化方案**

```
1. 对比验证：用相同输入在 JS 和 Rust 中分别执行采样，确认结果一致
2. 特别注意 emoji 和中文等非 BMP 字符的处理
3. 验证 "第一条用户消息" 的定义是否与真实 CLI 一致
   - clewdr: first_user_message_text() 的实现
   - 真实 CLI: 可能是最后一条用户消息或全部消息的拼接
```

---

## 第三类：行为模式（中风险）

### DV-09：对话快速创建/删除（Claude Web）

**问题描述**

```rust
// src/claude_web_state/chat.rs:111-133（创建）
let new_uuid = uuid::Uuid::new_v4().to_string();
// 命名格式：ClewdR-{UTC时间戳}
body["name"] = json!(format!("ClewdR-{}", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S")));

// src/claude_web_state/chat.rs:60-78（删除）
// 请求完成后立即删除对话（除非 preserve_chats = true）
```

每次请求的生命周期：`创建对话 → 发送消息 → 接收回复 → 删除对话`

**检测原理**

- 正常用户很少在几秒内创建并删除对话
- 对话命名格式 `ClewdR-*` 直接暴露了代理身份
- 大量短生命周期对话的统计模式与正常用户完全不同

**优化方案**

方案 A：修改命名格式
```rust
// 移除 "ClewdR" 前缀，使用更自然的名称
// 选项1：让 Claude 自动生成名称（不设置 name 字段）
// 选项2：使用随机的自然语言短语
body["name"] = json!(null);  // 让服务端自动生成
```

方案 B：对话复用
```rust
// 不要每次都创建新对话，在一定时间窗口内复用已有对话
// 维护一个对话池，按时间/消息数轮换
struct ConversationPool {
    active: HashMap<String, ConversationInfo>,
    max_messages_per_conv: usize,  // 例如 10
    max_age: Duration,             // 例如 30 分钟
}
```

方案 C：延迟删除
```rust
// 不要立即删除，而是在一段时间后异步清理
// 或者完全不删除（依赖用户手动清理或设置自动过期）
```

推荐组合：方案 A + 方案 C（移除 ClewdR 前缀 + 延迟/不删除）。

---

### DV-10：1M 上下文自动探测

**问题描述**

```rust
// src/claude_code_state/chat.rs:133-187
let attempts: Vec<bool> = if channel.is_some() {
    match cookie_support {
        Some(false) => vec![false],
        _ => vec![true, false],  // 先尝试 1M，失败后回退
    }
} else if requested_1m {
    vec![true, false]
} else {
    vec![false]
};
```

对 Sonnet 4.x 和 Opus 4.6 模型自动先尝试 1M 上下文请求，失败后回退到标准请求。

**检测原理**

- 模式：`请求(含1M beta) → 失败 → 立即重试(不含1M beta)`
- 这种快速失败-重试模式是代理的典型行为
- 正常 CLI 知道自己是否有 1M 权限，不需要这种探测

**优化方案**

方案 A：持久化 1M 支持状态
```rust
// 首次探测后将结果持久化到配置文件
// 后续请求直接使用缓存的结果，不再探测
// 定期（如每小时）重新探测一次
```

方案 B：让用户显式配置
```toml
# clewdr.toml
enable_1m_context = true  # 或 false
```

方案 C：增加探测间隔
```rust
// 探测失败后，在较长时间内（如 1 小时）不再重试
// 避免短时间内的 try-fail-retry 模式
```

---

### DV-11：Usage 端点频繁调用

**问题描述**

```rust
// src/claude_code_state/chat.rs:246-287
const CLAUDE_USAGE_URL: &str = "https://api.anthropic.com/api/oauth/usage";
```

clewdr 在每次请求后调用 `/api/oauth/usage` 来追踪 cookie 的使用量和重置边界。

**检测原理**

- 正常 CLI 用户极少调用 usage 端点
- 代理为了管理 cookie 池会频繁查询
- 高频 usage 查询与低频对话请求的比例异常

**优化方案**

```rust
// 降低 usage 查询频率
// 当前：每次对话后都查询
// 优化：每 N 次对话或每 M 分钟查询一次

const USAGE_CHECK_INTERVAL: Duration = Duration::from_secs(30 * 60); // 30 分钟
const USAGE_CHECK_EVERY_N_REQUESTS: u32 = 10;

// 或者完全移除 usage 查询，改用本地估算
// 根据已知的速率限制窗口（5h session / 7d weekly）本地计算
```

---

### DV-12：测试消息拦截

**问题描述**

```rust
// src/middleware/claude/request.rs:62-71, 298-304
static TEST_MESSAGE_CLAUDE: LazyLock<Message> =
    LazyLock::new(|| Message::new_blocks(Role::User, vec![ContentBlock::text("Hi")]));

if !body.stream.unwrap_or_default()
    && (body.messages == vec![TEST_MESSAGE_CLAUDE.to_owned()]
        || body.messages == vec![TEST_MESSAGE_OAI.to_owned()])
{
    return Err(ClewdrError::TestMessage);
}
```

当检测到仅包含 "Hi" 的非流式请求时，返回合成响应而不转发到 Anthropic。

**检测原理**

- Anthropic 可以发送探测请求来验证端点是否被代理
- 如果特定的简单消息总是不到达服务端，而其他消息正常到达，可以推断存在代理
- 拦截逻辑过于简单，只匹配单条 "Hi" 消息

**优化方案**

方案 A：移除测试消息拦截
```rust
// 最简单 - 让所有消息正常转发
// 缺点：消耗 token
```

方案 B：如果需要保留，使其不可探测
```rust
// 不要基于消息内容拦截，而是基于本地标记
// 例如：只有通过特定 API key 或特定 header 的请求才走测试路径
// 不要将此逻辑放在消息处理的主路径上
```

---

### DV-13：重试模式可预测

**问题描述**

```rust
// src/claude_code_state/chat.rs:51-126
for i in 0..CLEWDR_CONFIG.load().max_retries + 1 {
    // max_retries 默认 5
    // 速率限制冷却 30 分钟
    if Self::is_token_rate_limited(&e) {
        let cooldown = chrono::Utc::now().timestamp() + 1800; // 30 min 硬编码
    }
}
```

**检测原理**

- 固定的重试次数 + 固定的冷却时间 = 可预测的模式
- 正常 CLI 的重试策略可能使用指数退避（exponential backoff）
- 速率限制后精确 30 分钟恢复，不像人类行为

**优化方案**

```rust
// 1. 添加随机抖动（jitter）
let base_cooldown = 1800; // 30 min
let jitter = rand::random::<u64>() % 300; // 0-5 min 随机
let cooldown = base_cooldown + jitter as i64;

// 2. 使用指数退避
let delay = Duration::from_secs(2u64.pow(retry_count).min(300)); // max 5 min
let jittered = delay + Duration::from_millis(rand::random::<u64>() % 1000);
tokio::time::sleep(jittered).await;
```

---

### DV-14：缺少遥测/心跳流量

**问题描述**

真实的 Claude Code CLI 除了聊天请求外，还会发送：

- 遥测数据（telemetry events）
- 编辑器状态心跳
- 文件上下文信息
- 会话元数据

clewdr 只转发聊天请求，没有任何"伴随流量"。

**检测原理**

服务端看到的模式：
- 正常用户：`心跳, 遥测, 聊天请求, 心跳, 遥测, ...`
- clewdr 用户：`聊天请求, 聊天请求, 聊天请求, ...`

一个只发聊天请求、没有任何其他活动的"幽灵客户端"非常可疑。

**优化方案**

此项优化复杂度较高，需要：

```
1. 逆向分析真实 CLI 的遥测端点和数据格式
2. 模拟周期性的心跳请求
3. 生成合理的遥测数据（不需要真实内容，只需格式正确）

// 伪代码
async fn start_heartbeat_loop(client: &Client, token: &str) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        interval.tick().await;
        // 发送心跳到遥测端点
        client.post(TELEMETRY_ENDPOINT)
            .bearer_auth(token)
            .json(&heartbeat_payload())
            .send()
            .await
            .ok();
    }
}
```

注意：如果不确定遥测格式，错误的遥测反而会成为更大的检测信号。此项建议暂缓，优先处理其他更确定的问题。

---

## 第四类：静态指纹（中风险）

### DV-15：OAuth Client ID 共享

**问题描述**

```rust
// src/config/constants.rs:18
pub const CC_CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
```

所有使用默认配置的 clewdr 实例共享同一个 OAuth Client ID。

**检测原理**

- Anthropic 可以监控每个 client_id 下的活跃 token 数量
- 如果一个 client_id 关联了异常多的 token 和 IP 地址，明显是共享使用
- client_id 本身可能就在 Anthropic 的监控列表中

**优化方案**

方案 A：使用真实 CLI 的 client_id
```
1. 从自己安装的 Claude Code CLI 中提取 client_id
2. 每个用户使用自己 CLI 安装中的 client_id
3. 在文档中指导用户如何提取
```

方案 B：配置文件设置（已支持但未推广）
```toml
# clewdr.toml - 已有此配置项
claude_code_client_id = "your-own-client-id"
```

方案 C：首次启动时自动提取
```rust
// 启动时检测本机是否安装了 Claude Code CLI
// 如果有，自动读取其 client_id
fn detect_local_client_id() -> Option<String> {
    let cli_path = dirs::data_dir()?.join("claude/versions");
    // 读取 CLI 配置文件中的 client_id
    // ...
}
```

---

### DV-16：Beta Header 组合固定

**问题描述**

```rust
// src/claude_code_state/chat.rs:24-28
pub(super) const CLAUDE_BETA_BASE: &str = "claude-code-20250219";
pub(super) const CLAUDE_BETA_OAUTH: &str = "oauth-2025-04-20";
const CLAUDE_BETA_INTERLEAVED_THINKING: &str = "interleaved-thinking-2025-05-14";
const CLAUDE_BETA_CONTEXT_1M_TOKEN: &str = "context-1m-2025-08-07";
```

每次请求的 beta header 是固定组合：
```
claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14[,context-1m-2025-08-07]
```

**检测原理**

- 真实 CLI 的 beta 标记会随版本更新变化
- 版本 2.1.86 的 beta 组合如果与 2.1.90 不同，而 clewdr 没跟进更新，就会出现版本-beta 不匹配
- 所有 clewdr 用户发送完全相同的 beta 组合

**优化方案**

```
1. 每次更新版本号时，同步更新 beta 标记
2. 建立 beta 标记与版本号的对应关系文档
3. 考虑从真实 CLI 动态提取 beta 配置
```

---

### DV-17：API Version 过旧

**问题描述**

```rust
// src/claude_code_state/chat.rs:30
pub(super) const CLAUDE_API_VERSION: &str = "2023-06-01";
```

API 版本号 `2023-06-01` 距今已近 3 年。

**检测原理**

- 声称是 v2.1.86 的客户端使用 2023 年的 API 版本，时间跨度异常
- 真实 CLI 可能已更新到更新的 API 版本
- 但需要确认：真实 CLI 2.1.86 是否确实还在用 `2023-06-01`

**优化方案**

```
1. 从真实 CLI 2.1.86 中提取实际使用的 API 版本
2. 如果真实 CLI 确实还在用 2023-06-01，则无需修改
3. 如果已更新，同步更新
```

---

### DV-18：User-Agent 版本冻结

**问题描述**

```rust
// src/config/constants.rs:21-22
pub const CLAUDE_CODE_VERSION: &str = "2.1.86";
pub const CLAUDE_CODE_USER_AGENT: &str = "claude-code/2.1.86";
```

所有 clewdr 实例在所有时间段都发送相同的 UA 版本。

**检测原理**

- Claude Code CLI 有自动更新机制，真实用户的版本会逐渐分散
- 如果大量请求在新版本发布后很久仍然使用旧版本，是异常
- 服务端统计 UA 版本分布时，某个旧版本的异常高占比会被注意

**优化方案**

方案 A：自动追踪最新版本（推荐）
```rust
// 启动时或定期检查 Claude Code CLI 的最新版本
// 方式1：检查本地安装的 CLI 版本
// 方式2：从 npm/GitHub 获取最新版本号

async fn fetch_latest_version() -> Option<String> {
    // npm registry 查询
    let resp = client.get("https://registry.npmjs.org/@anthropic-ai/claude-code/latest")
        .send().await.ok()?;
    let json: Value = resp.json().await.ok()?;
    json["version"].as_str().map(String::from)
}
```

方案 B：在配置文件中暴露版本设置
```toml
# clewdr.toml
claude_code_version = "2.1.86"  # 用户手动更新
```

---

### DV-19：Referer 固定格式

**问题描述**

```rust
// src/claude_code_state/mod.rs:104
.header(REFERER, format!("{CLAUDE_ENDPOINT}new"))
// 结果: Referer: https://api.anthropic.com/new
```

所有 Claude Code 模式的请求都使用固定的 Referer。

**检测原理**

- 真实 CLI 可能不发送 Referer，或使用不同的格式
- 固定的 Referer 是指纹

**优化方案**

```
1. 确认真实 CLI 是否发送 Referer 头
2. 如果不发送：移除 Referer
3. 如果发送：对齐格式
```

---

## 第五类：请求修正与兼容处理（低风险）

### DV-20：自动移除 top_p

**问题描述**

```rust
// src/middleware/claude/request.rs:350-352
if body.temperature.is_some() {
    body.top_p = None;
}
```

当 temperature 和 top_p 同时存在时，自动移除 top_p。

**检测原理**

- 正常客户端不会发送后又移除参数
- 但由于是在代理层修改后才发送，服务端看到的请求本身是合法的
- 风险较低，仅在服务端同时收到了原始请求（通过其他渠道）时才有意义

**优化方案**

保持现状，或者在文档中告知用户不要同时设置这两个参数。

---

### DV-21：Ephemeral Cache Scope 剥离

**问题描述**

```rust
// src/middleware/claude/request.rs:167-193
fn strip_ephemeral_scope_from_system(system: &mut Value) {
    // 移除 cache_control 中的 scope 字段
}
```

**检测原理**

- 客户端发送的请求不应该包含然后被移除的字段
- 但同样，服务端看到的是修改后的请求，风险低

**优化方案**

保持现状。

---

### DV-22：消息清理/消毒

**问题描述**

```rust
// src/middleware/claude/request.rs:215-253
if CLEWDR_CONFIG.load().sanitize_messages {
    body.messages = sanitize_messages(body.messages);
}
```

可选功能：去除消息中的前后空白、移除空的 assistant 消息。

**检测原理**

- 如果启用，可能改变消息的 hash 特征
- 默认关闭，风险很低

**优化方案**

保持现状。

---

### DV-23：Custom System Prompt 注入

**问题描述**

```rust
// src/middleware/claude/request.rs:370-376
if let Some(custom_system) = CLEWDR_CONFIG
    .load()
    .custom_system
    .clone()
    .filter(|s| !s.trim().is_empty())
{
    system_prefixes.push(ContentBlock::text(custom_system));
}
```

用户可配置自定义 system prompt 前缀。

**检测原理**

- Anthropic 可以分析 system prompt 中是否包含异常模式
- 如果大量请求的 system prompt 以相同的自定义前缀开头，可被关联
- 风险取决于用户配置的内容

**优化方案**

保持现状，但建议用户：
- 不要在 custom_system 中包含可识别的模式（如项目名称、代理标识）
- 保持 custom_system 的独特性，避免多个用户使用相同内容

---

## 优化方案总览

| 编号 | 问题 | 优化方案 | 复杂度 | 预期效果 |
|------|------|----------|--------|----------|
| DV-01 | TLS 指纹矛盾 | 按 provider 类型选择 TLS 配置 | 高 | 消除最大检测面 |
| DV-02 | 缺少安全头 | Claude Web 模式添加 Sec-* 头 | 低 | 降低浏览器模式检测率 |
| DV-03 | 模拟池过小 | 扩展浏览器配置 | 低 | 降低指纹聚集度 |
| DV-04 | Billing Header 注入 system prompt | 改为 HTTP 头发送 | 中 | 消除最明显异常 |
| DV-05 | entrypoint=unknown | 默认改为 `cli` | 低 | 对齐真实行为 |
| DV-06 | cch 硬编码 | 逆向验证并对齐 | 中 | 确保一致性 |
| DV-07 | Salt 硬编码 | 版本更新时同步 salt | 中 | 确保哈希正确 |
| DV-08 | Sample 逻辑差异 | 跨语言验证 | 中 | 确保哈希正确 |
| DV-09 | 对话快速创建/删除 | 移除 ClewdR 前缀 + 延迟删除 | 低 | 降低行为异常度 |
| DV-10 | 1M 自动探测 | 持久化结果 + 增加间隔 | 低 | 减少异常请求模式 |
| DV-11 | Usage 频繁查询 | 降低查询频率 | 低 | 减少异常流量 |
| DV-12 | 测试消息拦截 | 移除或改造 | 低 | 消除探测漏洞 |
| DV-13 | 重试模式固定 | 指数退避 + 随机抖动 | 低 | 模拟自然行为 |
| DV-14 | 缺少遥测 | 模拟心跳（风险高，暂缓） | 高 | 降低幽灵客户端特征 |
| DV-15 | Client ID 共享 | 用户自行提取 | 低 | 分散指纹 |
| DV-16 | Beta 组合固定 | 版本更新时同步 | 低 | 保持一致性 |
| DV-17 | API Version 过旧 | 验证并对齐 | 低 | 保持一致性 |
| DV-18 | UA 版本冻结 | 自动追踪最新版本 | 中 | 减少版本异常 |
| DV-19 | Referer 固定 | 验证并对齐 | 低 | 消除指纹 |
| DV-20~23 | 请求修正 | 保持现状 | — | 低风险，不急 |

---

## 实施优先级

### P0 - 立即修复（最大检测面）

1. **DV-04**：Billing Header 从 system prompt 移到 HTTP 头
2. **DV-01**：Claude Code 模式不做浏览器 TLS 模拟
3. **DV-09**：移除对话名称中的 "ClewdR" 标识

### P1 - 短期修复（1-2 天）

4. **DV-05**：entrypoint 默认值改为 `cli`
5. **DV-15**：推广 client_id 自定义配置
6. **DV-02**：Claude Web 模式添加浏览器安全头
7. **DV-13**：重试策略添加随机抖动

### P2 - 中期优化（需要逆向分析）

8. **DV-06/07/08**：验证 cch、salt、sample 逻辑与真实 CLI 的一致性
9. **DV-10/11**：降低 1M 探测和 usage 查询频率
10. **DV-18**：自动追踪 CLI 最新版本
11. **DV-16/17**：同步 beta 标记和 API 版本

### P3 - 长期改进（高复杂度）

12. **DV-14**：遥测/心跳模拟（需谨慎，错误的遥测可能更危险）
13. **DV-03**：扩展浏览器模拟池

---

## 附录：检测向量风险矩阵

```
        高确定性（服务端确认可检测）
        │
        │  DV-04(billing注入)   DV-01(TLS矛盾)
        │  DV-09(ClewdR命名)
        │
        │      DV-05(unknown)   DV-15(共享ID)
        │      DV-14(缺遥测)
        │
        │          DV-06(cch)   DV-07(salt)
        │          DV-10(1M探测)
        │
        │              DV-13(重试)  DV-12(拦截)
        │              DV-16(beta)  DV-18(UA冻结)
        │
        └──────────────────────────────── 高影响（直接导致封号）
```

左上角的检测向量是最应该优先修复的。
