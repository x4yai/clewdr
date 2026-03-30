# 第一轮 - 红队反代方案

> 日期：2026-03-30
> 目标服务商：model-family（类 Anthropic Claude 订阅服务）
> 参考实现：clewdr 当前版本（模拟 Claude Code v2.1.86）
> 目标：设计一套尽可能难以检测的反向代理方案

---

## 目录

1. [总体架构](#总体架构)
2. [维度一：TLS 指纹伪装](#维度一tls-指纹伪装)
3. [维度二：请求头完美模拟](#维度二请求头完美模拟)
4. [维度三：行为模式模拟](#维度三行为模式模拟)
5. [维度四：认证流程模拟](#维度四认证流程模拟)
6. [维度五：反检测策略](#维度五反检测策略)
7. [自评](#自评)

---

## 总体架构

```
                                ┌─────────────────────┐
                                │   model-family API  │
                                │   (检测系统 + CDN)   │
                                └──────────▲──────────┘
                                           │
                                    TLS (Bun/BoringSSL 指纹)
                                           │
                              ┌────────────┴────────────┐
                              │    Phantom Proxy Core    │
                              │  ┌────────────────────┐  │
                              │  │  Session Manager   │  │
                              │  │  (会话生命周期管理) │  │
                              │  ├────────────────────┤  │
                              │  │  Fingerprint Engine │  │
                              │  │  (指纹一致性引擎)  │  │
                              │  ├────────────────────┤  │
                              │  │  Traffic Simulator  │  │
                              │  │  (伴随流量生成器)   │  │
                              │  ├────────────────────┤  │
                              │  │  Auth Coordinator   │  │
                              │  │  (认证流程编排)     │  │
                              │  └────────────────────┘  │
                              └────────────▲────────────┘
                                           │
                                   标准 HTTPS
                                           │
                              ┌────────────┴────────────┐
                              │     下游客户端           │
                              │  (SillyTavern 等)       │
                              └─────────────────────────┘
```

核心设计原则：**每个 cookie/token 对应一个完整的"虚拟用户"身份（Virtual Persona），包含一致的指纹、行为模式和会话历史。**

---

## 维度一：TLS 指纹伪装

### 1.1 问题分析

clewdr 当前最大的矛盾：User-Agent 声称是 `claude-code/2.1.86`（CLI 工具，运行在 Bun 上），但 TLS 指纹是 Chrome/Edge 浏览器。model-family 的 CDN 层（如 Cloudflare）可以提取 JA3/JA4 指纹并交叉验证。

**矛盾一览：**
```
声称身份:  claude-code/2.1.86  →  应该是 Bun 运行时
TLS 指纹:  Chrome136/131/Edge127  →  明显是浏览器
结论:     身份矛盾，标记可疑
```

### 1.2 技术方案：Bun 运行时 TLS 指纹精确复现

**策略：不再模拟浏览器，而是精确复现 Bun 运行时的 TLS 握手特征。**

#### 步骤一：提取真实 Bun TLS 指纹

```bash
# 1. 安装目标版本的 Bun
curl -fsSL https://bun.sh/install | bash

# 2. 启动 TLS 指纹捕获代理
# 使用 ja3proxy 或 mitmproxy 的 JA3 插件
mitmproxy --mode socks5 --script ja3_extractor.py

# 3. 通过 Bun 发起 HTTPS 请求，捕获其 ClientHello
bun -e "fetch('https://ja3er.com/json').then(r => r.json()).then(console.log)"

# 4. 记录 Bun 的 JA3/JA4 指纹
# 预期输出示例：
# JA3:  771,4865-4866-4867-49195-49196-...,0-23-65281-...,29-23-24,0
# JA4:  t13d1517h2_8daaf6152771_e5627efa2ab1
```

#### 步骤二：在 TLS 库中复现指纹

```rust
// 方案 A：使用 rustls 配置模拟 Bun/BoringSSL
// Bun 底层使用 BoringSSL，其 ClientHello 特征与 Chrome 不同

use rustls::{ClientConfig, CipherSuite, ProtocolVersion, SignatureScheme};

fn build_bun_tls_config() -> ClientConfig {
    let mut config = ClientConfig::builder()
        .with_protocol_versions(&[
            &rustls::version::TLS13,
            &rustls::version::TLS12,
        ])
        .unwrap()
        .with_no_client_auth();

    // Bun/BoringSSL 的 cipher suite 顺序（需从抓包确认）
    // 关键：顺序和组合必须与真实 Bun 完全一致
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    // BoringSSL 的 supported_groups 顺序
    // X25519 优先，然后 P-256, P-384
    // 这与 Chrome 的浏览器 TLS 略有不同

    // BoringSSL 特有的扩展：
    // - 不发送 SNI padding（与浏览器不同）
    // - compress_certificate 扩展（brotli）
    // - application_settings (ALPS) 扩展

    config
}

// 方案 B：直接链接 BoringSSL（更精确）
// 通过 boring-sys crate 使用 BoringSSL 作为 TLS 后端
// 优点：指纹天然一致
// 缺点：增加编译复杂度

// 方案 C：使用 wreq 的自定义 TLS 配置（如果支持）
fn build_wreq_client_for_code() -> wreq::Client {
    wreq::Client::builder()
        // 不使用任何浏览器模拟
        // 使用原生 TLS 配置，模拟 Bun 的握手参数
        .tls_info(true)
        // 精确设置 cipher suite 和扩展顺序
        .build()
        .unwrap()
}
```

#### 步骤三：双模 TLS 引擎

```rust
/// 根据代理模式选择不同的 TLS 配置
enum ProxyMode {
    /// Claude Code 模式 - 使用 Bun/BoringSSL TLS 指纹
    ClaudeCode,
    /// Claude Web 模式 - 使用真实浏览器 TLS 指纹
    ClaudeWeb,
}

fn create_client(mode: ProxyMode) -> wreq::Client {
    match mode {
        ProxyMode::ClaudeCode => {
            // 不做浏览器模拟，使用 Bun-like TLS
            wreq::Client::builder()
                // 可能需要 fork wreq 添加 BoringSSL 后端支持
                .build()
                .unwrap()
        }
        ProxyMode::ClaudeWeb => {
            // Web 模式保留浏览器 TLS 模拟
            // 但需要扩展模拟池
            let emulation = random_emulation();
            wreq::Client::builder()
                .emulation(emulation)
                .build()
                .unwrap()
        }
    }
}
```

### 1.3 预期规避的检测

- **JA3/JA4 指纹与 UA 交叉验证**：消除 "CLI 身份 + 浏览器 TLS" 矛盾
- **CDN 层 Bot Detection**：Bun 指纹不在浏览器 bot 检测规则中
- **TLS 指纹聚类分析**：不再集中在 3 个浏览器版本上

### 1.4 局限性

- **Bun 版本追踪**：Bun 更新频率高，TLS 指纹可能随版本变化，需持续跟踪
- **BoringSSL 精确复现困难**：cipher suite 顺序、扩展字段等细节多，Rust 生态缺乏完整的 BoringSSL 绑定
- **不同操作系统差异**：macOS/Linux/Windows 上 Bun 的 TLS 行为可能有差异
- **HTTP/2 指纹**：除 TLS 外，HTTP/2 的 SETTINGS 帧、窗口大小等也可作为指纹，本方案未覆盖

---

## 维度二：请求头完美模拟

### 2.1 问题分析

clewdr 的请求头存在多个与真实客户端不一致的特征：
1. Billing header 被注入为 system prompt 文本而非 HTTP 头
2. cc_entrypoint 默认为 "unknown"
3. cch 值硬编码
4. 缺少浏览器安全头（Web 模式）
5. Referer 格式固定

### 2.2 技术方案：Header 精确对齐引擎

#### 2.2.1 Billing Header 修正

**核心修复：将 billing header 从 system prompt 移到 HTTP 头。**

```rust
// 修改前（当前 clewdr）：billing header 被注入为 system prompt
// prepend_system_blocks(&mut body, vec![
//     ContentBlock::text(claude_code_billing_header(&body.messages))
// ]);

// 修改后：billing header 作为 HTTP 请求头发送
fn execute_claude_request(
    &mut self,
    access_token: &str,
    body: &CreateMessageParams,
    use_context_1m: bool,
) -> Result<wreq::Response, ClewdrError> {
    let beta_header = Self::merge_anthropic_beta_header(
        self.anthropic_beta_header.as_deref(),
        use_context_1m,
    );

    // 计算 billing header 值（不含 "x-anthropic-billing-header: " 前缀）
    let billing_value = compute_billing_value(&body.messages);

    self.client
        .post(endpoint)
        .bearer_auth(access_token)
        .header(USER_AGENT, CLAUDE_CODE_USER_AGENT)
        .header("anthropic-beta", beta_header)
        .header("anthropic-version", CLAUDE_API_VERSION)
        .header("x-anthropic-billing-header", billing_value) // 作为 HTTP 头
        .json(body) // body 中不再包含 billing 文本
        .send()
        .await
}

fn compute_billing_value(messages: &[Message]) -> String {
    let sampled = [4, 7, 20]
        .into_iter()
        .map(|idx| sample_js_code_unit(first_user_message_text(messages), idx))
        .collect::<String>();
    let version_hash = format!(
        "{:x}",
        Sha256::digest(format!(
            "{CLAUDE_CODE_BILLING_SALT}{sampled}{CLAUDE_CODE_VERSION}"
        ))
    );
    let entrypoint = resolve_entrypoint();

    format!(
        "cc_version={CLAUDE_CODE_VERSION}.{}; cc_entrypoint={entrypoint}; cch=88e20;",
        &version_hash[..3]
    )
}
```

#### 2.2.2 Entrypoint 智能选择

```rust
/// 每个 Virtual Persona 在创建时分配一个 entrypoint，
/// 整个会话生命周期内保持不变
struct VirtualPersona {
    cookie: CookieStatus,
    entrypoint: String,
    os_platform: String,
    // ...
}

/// entrypoint 分布模拟真实用户群体
fn assign_entrypoint(persona_seed: u64) -> String {
    // 基于真实用户群的估计分布：
    // - VS Code: ~55%（最流行的编辑器）
    // - CLI: ~25%
    // - JetBrains: ~15%
    // - Neovim/其他: ~5%
    let roll = persona_seed % 100;
    match roll {
        0..=54 => "claude-vscode".to_string(),
        55..=79 => "cli".to_string(),
        80..=94 => "claude-jetbrains".to_string(),
        _ => "cli".to_string(), // 保守降级
    }
}
```

#### 2.2.3 Claude Web 模式 - 完整浏览器头模拟

```rust
/// 为 Claude Web 模式构建与 TLS 模拟一致的浏览器头
fn build_browser_headers(emulation: &Emulation) -> HeaderMap {
    let mut headers = HeaderMap::new();

    // 根据 TLS 模拟的浏览器版本动态生成 Sec-Ch-Ua
    let (brand, version) = match emulation {
        Emulation::Chrome136 => ("Google Chrome", "136"),
        Emulation::Chrome131 => ("Google Chrome", "131"),
        Emulation::Edge127 => ("Microsoft Edge", "127"),
        // ...
    };

    headers.insert(
        "Sec-Ch-Ua",
        format!(
            r#""{brand}";v="{version}", "Chromium";v="{version}", "Not.A/Brand";v="99""#
        ).parse().unwrap(),
    );
    headers.insert("Sec-Ch-Ua-Mobile", "?0".parse().unwrap());
    headers.insert("Sec-Ch-Ua-Platform", r#""macOS""#.parse().unwrap());
    headers.insert("Sec-Fetch-Site", "same-origin".parse().unwrap());
    headers.insert("Sec-Fetch-Mode", "cors".parse().unwrap());
    headers.insert("Sec-Fetch-Dest", "empty".parse().unwrap());
    headers.insert("Accept-Language", "en-US,en;q=0.9".parse().unwrap());

    headers
}
```

#### 2.2.4 请求头顺序一致性

```rust
/// HTTP/1.1 头顺序是指纹的一部分
/// 真实 Bun 的头顺序需要通过抓包确认
///
/// 典型的 Bun fetch() 头顺序：
/// 1. host (自动)
/// 2. connection (自动)
/// 3. content-length (自动)
/// 4. 用户设置的头（按设置顺序）
///
/// 确保 wreq 不会对头进行字母排序
fn build_ordered_request(client: &wreq::Client, url: &str) -> wreq::RequestBuilder {
    // 按照真实 Claude Code CLI 的头设置顺序
    client.post(url)
        .header("content-type", "application/json")         // 1
        .header("authorization", "Bearer ...")               // 2
        .header("user-agent", "claude-code/2.1.86")          // 3
        .header("anthropic-version", "2023-06-01")           // 4
        .header("anthropic-beta", "claude-code-20250219,...") // 5
        .header("x-anthropic-billing-header", "...")          // 6
        .header("accept", "application/json")                // 7
}
```

### 2.3 预期规避的检测

- **System prompt 内容扫描**：不再将 billing 信息泄露到 prompt 中
- **Entrypoint 异常分布检测**：合理的 entrypoint 分布
- **浏览器头完整性检查**（Web 模式）：Sec-* 头齐全
- **头顺序指纹**：与真实客户端一致

### 2.4 局限性

- **头顺序验证困难**：HTTP/2 中头是二进制编码的 HPACK，顺序语义不同
- **cch 生成逻辑未知**：需要逆向真实 CLI 的 cch 计算方式，目前只能硬编码
- **Billing salt 依赖版本**：每次 CLI 版本更新需要手动提取新 salt
- **请求头的实际验证力度未知**：model-family 是否真的检查所有这些头

---

## 维度三：行为模式模拟

### 3.1 问题分析

当前 clewdr 的行为模式与真实用户差异巨大：
1. 对话快速创建/删除（秒级生命周期）
2. 纯聊天请求流量（无伴随流量）
3. 机械化的请求间隔
4. 1M 上下文自动探测的 try-fail-retry 模式
5. 频繁的 usage 端点查询

### 3.2 技术方案：行为仿真引擎

#### 3.2.1 会话生命周期管理

```rust
/// 会话管理器：模拟真实用户的对话生命周期
struct SessionManager {
    /// 活跃会话池（按 cookie 分组）
    sessions: HashMap<CookieId, SessionState>,
}

struct SessionState {
    /// 当前活跃对话 UUID
    active_conversation: Option<String>,
    /// 对话中已发送的消息数
    message_count: u32,
    /// 对话创建时间
    created_at: Instant,
    /// 配置
    config: SessionConfig,
}

struct SessionConfig {
    /// 每个对话的最大消息数（正态分布，均值 8，标准差 3）
    max_messages_per_conv: u32,
    /// 对话最大存活时间（30-120 分钟）
    max_conv_lifetime: Duration,
    /// 对话删除延迟（0-24 小时，或不删除）
    delete_delay: Option<Duration>,
}

impl SessionManager {
    /// 决定是否复用现有对话或创建新对话
    fn get_or_create_conversation(&mut self, cookie_id: &CookieId) -> ConversationAction {
        if let Some(session) = self.sessions.get(cookie_id) {
            if session.message_count < session.config.max_messages_per_conv
                && session.created_at.elapsed() < session.config.max_conv_lifetime
            {
                // 复用现有对话
                return ConversationAction::Reuse(session.active_conversation.clone().unwrap());
            }
        }
        // 创建新对话
        ConversationAction::Create
    }

    /// 异步延迟删除旧对话
    fn schedule_deletion(&self, conv_uuid: String, delay: Duration) {
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            // 删除对话
            // ...
        });
    }
}

enum ConversationAction {
    Reuse(String),
    Create,
}
```

#### 3.2.2 对话命名自然化

```rust
/// 生成看起来自然的对话名称
fn generate_natural_conversation_name() -> Option<String> {
    // 方案 1：不设置名称，让服务端自动生成（最安全）
    None

    // 方案 2：如果必须设置名称，使用自然格式
    // let templates = [
    //     "Quick question about {}",
    //     "Help with {}",
    //     "Debug {} issue",
    //     "Code review",
    //     "Refactoring task",
    // ];
    // Some(templates[rand() % templates.len()].to_string())
}
```

#### 3.2.3 伴随流量生成器

```
┌──────────────────────────────────────────────────┐
│                Traffic Simulator                  │
│                                                   │
│  ┌─────────┐  ┌─────────┐  ┌──────────────────┐ │
│  │Heartbeat│  │Telemetry│  │ Context Activity  │ │
│  │ 30-60s  │  │ 2-5min  │  │  与聊天请求交织   │ │
│  └────┬────┘  └────┬────┘  └────────┬─────────┘ │
│       │            │                │             │
│       └────────────┼────────────────┘             │
│                    ▼                              │
│            Scheduled Queue                        │
│            (随机化时间抖动)                        │
└──────────────────────────────────────────────────┘
```

```rust
/// 伴随流量生成器
/// 注意：此功能风险较高，错误的遥测格式反而会成为检测信号
/// 建议在完整逆向遥测协议后再启用
struct TrafficSimulator {
    client: wreq::Client,
    access_token: String,
    running: Arc<AtomicBool>,
}

impl TrafficSimulator {
    /// 启动伴随流量（在获取 token 后立即启动）
    async fn start(&self) {
        let client = self.client.clone();
        let token = self.access_token.clone();
        let running = self.running.clone();

        tokio::spawn(async move {
            let mut heartbeat_interval = tokio::time::interval(
                Duration::from_secs(30 + rand::random::<u64>() % 30) // 30-60s
            );

            while running.load(Ordering::Relaxed) {
                heartbeat_interval.tick().await;

                // 发送最小化的心跳
                // 格式需要从真实 CLI 逆向获取
                let _ = client.post("https://api.anthropic.com/v1/telemetry")
                    .bearer_auth(&token)
                    .header("user-agent", CLAUDE_CODE_USER_AGENT)
                    .json(&serde_json::json!({
                        "type": "heartbeat",
                        "timestamp": chrono::Utc::now().to_rfc3339(),
                        "session_id": uuid::Uuid::new_v4().to_string(),
                    }))
                    .send()
                    .await;
            }
        });
    }
}
```

#### 3.2.4 请求时序仿真

```rust
/// 请求间隔模拟：避免机械化的固定间隔
struct TimingSimulator;

impl TimingSimulator {
    /// 在发送请求前添加人类化的延迟
    /// 模拟用户阅读响应、思考、打字的时间
    fn human_delay(response_length: usize) -> Duration {
        // 基础阅读时间：假设 250 词/分钟
        let words = response_length / 5;
        let reading_secs = (words as f64 / 250.0 * 60.0).min(30.0);

        // 思考时间：2-8 秒
        let thinking_secs = 2.0 + rand::random::<f64>() * 6.0;

        // 打字时间：根据输入长度（但反代不知道下一条消息长度，所以用固定范围）
        let typing_secs = 3.0 + rand::random::<f64>() * 15.0;

        Duration::from_secs_f64(reading_secs + thinking_secs + typing_secs)
    }

    /// 添加亚秒级抖动，避免整数秒对齐
    fn add_jitter(base: Duration) -> Duration {
        base + Duration::from_millis(rand::random::<u64>() % 500)
    }
}
```

**重要注意：** 时序模拟需要在"代理对下游的响应"和"代理对上游的请求"之间添加延迟。但这会增加用户感知的延迟。可以通过"请求入队后延迟发送"而非"阻塞下游"来缓解，但实现复杂度更高。

#### 3.2.5 1M 上下文探测优化

```rust
/// 优化 1M 探测：首次探测后持久化结果，长期不再重复探测
struct Context1mCache {
    /// 每个 cookie 的 1M 支持状态
    support_map: HashMap<CookieId, Context1mState>,
}

struct Context1mState {
    sonnet_supported: Option<bool>,
    opus_supported: Option<bool>,
    /// 上次探测时间
    last_probed: Instant,
    /// 最小重新探测间隔：24 小时
    reprobe_interval: Duration,
}

impl Context1mState {
    fn should_probe(&self, channel: Claude1mChannel) -> bool {
        let current = match channel {
            Claude1mChannel::Sonnet => self.sonnet_supported,
            Claude1mChannel::Opus => self.opus_supported,
        };
        // 从未探测过 -> 探测
        if current.is_none() {
            return true;
        }
        // 已知不支持 -> 长时间后重新探测
        if current == Some(false) && self.last_probed.elapsed() > self.reprobe_interval {
            return true;
        }
        false
    }
}
```

### 3.3 预期规避的检测

- **对话生命周期异常检测**：对话不再秒级创建/删除
- **纯聊天流量检测**：有伴随的心跳/遥测流量
- **机械化请求间隔检测**：请求间隔符合人类行为分布
- **Try-fail-retry 模式检测**：1M 探测不再频繁

### 3.4 局限性

- **伴随流量高风险**：如果遥测格式不正确，反而成为更强的检测信号。建议在完整逆向遥测协议前不启用此功能
- **延迟增加**：请求时序仿真会增加端到端延迟
- **对话复用的上下文累积**：多轮对话复用同一个 conversation 会导致上下文窗口膨胀
- **真实 CLI 的请求模式未知**：我们对真实 CLI 的精确请求时序分布缺乏数据

---

## 维度四：认证流程模拟

### 4.1 问题分析

clewdr 的 OAuth 流程存在以下问题：
1. 所有实例共享同一个 `client_id`
2. Token 刷新失败后立即重新走完整 OAuth 流程
3. 频繁的 usage 端点查询

### 4.2 技术方案：认证行为自然化

#### 4.2.1 Client ID 隔离

```rust
/// 每个部署实例应使用独立的 client_id
/// 优先级：用户配置 > 本地 CLI 提取 > 默认值（不推荐）
fn resolve_client_id() -> String {
    // 1. 用户在配置文件中显式设置
    if let Some(id) = config.claude_code_client_id.clone() {
        return id;
    }

    // 2. 尝试从本地安装的 Claude Code CLI 提取
    if let Some(id) = extract_local_client_id() {
        return id;
    }

    // 3. 降级到默认值（应在日志中警告）
    tracing::warn!(
        "Using default shared client_id. \
         This increases detection risk. \
         Set claude_code_client_id in config."
    );
    CC_CLIENT_ID.to_string()
}

/// 从本地 Claude Code 安装中提取 client_id
fn extract_local_client_id() -> Option<String> {
    // VS Code 扩展路径
    let vscode_ext = dirs::home_dir()?
        .join(".vscode/extensions");

    // 查找 claude-dev 或 claude-code 扩展
    for entry in std::fs::read_dir(vscode_ext).ok()? {
        let path = entry.ok()?.path();
        if path.file_name()?.to_str()?.contains("claude") {
            let package_json = path.join("package.json");
            if let Ok(content) = std::fs::read_to_string(&package_json) {
                if let Ok(json) = serde_json::from_str::<Value>(&content) {
                    if let Some(id) = json["contributes"]["configuration"]
                        ["properties"]["claude.oauthClientId"]["default"]
                        .as_str()
                    {
                        return Some(id.to_string());
                    }
                }
            }
        }
    }
    None
}
```

#### 4.2.2 Token 生命周期管理

```rust
/// 优化 token 管理：减少异常的认证行为
struct TokenManager {
    /// 提前刷新 token（在过期前 5 分钟）
    refresh_buffer: Duration,
}

impl TokenManager {
    /// 主动刷新而非等到过期
    fn should_refresh(&self, token: &TokenInfo) -> bool {
        if let Some(expires_at) = token.expires_at {
            let buffer = chrono::Utc::now().timestamp() + self.refresh_buffer.as_secs() as i64;
            return buffer >= expires_at;
        }
        false
    }

    /// 刷新失败时的渐进退避
    async fn refresh_with_backoff(&mut self, max_attempts: u32) -> Result<(), ClewdrError> {
        for attempt in 0..max_attempts {
            match self.try_refresh().await {
                Ok(_) => return Ok(()),
                Err(e) => {
                    if attempt + 1 < max_attempts {
                        // 指数退避 + 随机抖动
                        let delay = Duration::from_secs(
                            2u64.pow(attempt) + rand::random::<u64>() % 5
                        );
                        tokio::time::sleep(delay).await;
                    }
                    if Self::is_invalid_grant(&e) {
                        // 不要立即重新 OAuth，等待一段时间
                        let wait = Duration::from_secs(30 + rand::random::<u64>() % 60);
                        tokio::time::sleep(wait).await;
                        return self.full_reauth().await;
                    }
                }
            }
        }
        Err(ClewdrError::TooManyRetries)
    }
}
```

#### 4.2.3 Usage 查询频率控制

```rust
/// 降低 usage 端点的查询频率
struct UsageTracker {
    /// 上次查询时间
    last_query: Option<Instant>,
    /// 最小查询间隔
    min_interval: Duration, // 默认 30 分钟
    /// 本地估算的 token 使用量
    local_estimate: UsageEstimate,
    /// 累计请求数（每 N 次查询一次）
    request_count: u32,
    query_every_n: u32, // 默认 10
}

impl UsageTracker {
    fn should_query(&self) -> bool {
        // 满足以下任一条件才查询：
        // 1. 从未查询过
        if self.last_query.is_none() {
            return true;
        }
        // 2. 距上次查询已超过最小间隔 且 累计了足够多的请求
        let interval_ok = self.last_query
            .map(|t| t.elapsed() >= self.min_interval)
            .unwrap_or(true);
        let count_ok = self.request_count >= self.query_every_n;

        interval_ok && count_ok
    }
}
```

### 4.3 预期规避的检测

- **Client ID 聚集检测**：每个实例使用独立 ID
- **异常认证模式检测**：token 提前刷新，避免过期后的突发认证流量
- **Usage 查询频率异常**：大幅降低查询频率

### 4.4 局限性

- **Client ID 提取依赖本地环境**：服务器部署环境通常没有 Claude Code CLI
- **提前刷新可能浪费 token 生命周期**：如果 token 在某个窗口不需要使用，提前刷新是多余的
- **本地 usage 估算不精确**：可能导致超限

---

## 维度五：反检测策略

### 5.1 对抗已知检测手段

#### 5.1.1 对抗 System Prompt 扫描

```rust
/// 确保不向 system prompt 中注入任何可识别的模式
fn sanitize_system_prompt(body: &mut CreateMessageParams) {
    // 1. 不注入 billing header 文本（已在 2.2.1 中修复）

    // 2. 如果用户设置了 custom_system，警告不要包含可识别模式
    if let Some(ref custom) = config.custom_system {
        let suspicious_patterns = [
            "clewdr", "reverse proxy", "反代", "proxy",
            "jailbreak", "bypass", "override",
        ];
        for pattern in &suspicious_patterns {
            if custom.to_lowercase().contains(pattern) {
                tracing::warn!(
                    "Custom system prompt contains suspicious pattern '{}'. \
                     This may trigger content-based detection.",
                    pattern
                );
            }
        }
    }

    // 3. 不要在 system prompt 开头添加固定格式的文本块
    //    如果必须添加，使用多种表述方式随机化
}
```

#### 5.1.2 对抗探测请求（Canary Detection）

```rust
/// 移除基于消息内容的测试拦截
/// 当前的 "Hi" 消息拦截是可探测的：
/// - 发送 "Hi" → 未到达服务端 → 检测到代理
/// - 发送 "Hello" → 到达服务端 → 确认存在选择性转发
///
/// 策略：不拦截任何消息，全部透传
/// 如果需要测试功能，通过下游 API 的特殊头控制
fn should_intercept(body: &CreateMessageParams, headers: &HeaderMap) -> bool {
    // 只有在请求包含特殊的本地测试头时才拦截
    // 这个头永远不会被外部请求包含
    headers.contains_key("x-clewdr-test-mode")
}
```

#### 5.1.3 对抗 IP 关联分析

```
策略：IP 多样化

方案 A：住宅代理轮换
┌─────────────┐      ┌──────────────────┐      ┌──────────────┐
│ Phantom Core │ ───> │ 住宅代理服务      │ ───> │ model-family │
│              │      │ (每个 cookie 固定  │      │              │
│              │      │  一个出口 IP)      │      │              │
└─────────────┘      └──────────────────┘      └──────────────┘

方案 B：每个 cookie 绑定独立的出口 IP
- 使用云服务商的多 IP 实例
- 或通过 SOCKS5 代理池
- 关键：同一个 cookie 的所有请求必须从同一个 IP 发出

实现：
struct CookieIpBinding {
    bindings: HashMap<CookieId, IpAddr>,
    proxy_pool: Vec<ProxyConfig>,
}

impl CookieIpBinding {
    fn get_proxy(&mut self, cookie_id: &CookieId) -> &ProxyConfig {
        self.bindings.entry(cookie_id.clone()).or_insert_with(|| {
            // 首次使用时分配一个固定的代理
            let idx = self.next_proxy_index();
            self.proxy_pool[idx].clone()
        })
    }
}
```

#### 5.1.4 对抗流量模式分析

```rust
/// 请求速率控制：确保每个 cookie 的请求频率在合理范围内
struct RateLimiter {
    /// 每小时最大请求数（模拟活跃用户：10-30 请求/小时）
    max_requests_per_hour: u32,
    /// 请求间隔的最小值（防止突发）
    min_interval: Duration,
    /// 活跃时段模拟（不在凌晨发送大量请求）
    active_hours: (u8, u8), // (start_hour, end_hour) UTC
}

impl RateLimiter {
    fn should_allow(&self, cookie_id: &CookieId) -> Result<(), Duration> {
        let now = chrono::Utc::now();
        let hour = now.hour() as u8;

        // 在非活跃时段降低请求频率
        if hour < self.active_hours.0 || hour > self.active_hours.1 {
            // 凌晨只允许偶尔的请求
            if self.recent_count(cookie_id) > 2 {
                let wait = Duration::from_secs(
                    (self.active_hours.0 as u64 - hour as u64) * 3600
                );
                return Err(wait);
            }
        }

        // 检查短期速率
        if let Some(last) = self.last_request(cookie_id) {
            if last.elapsed() < self.min_interval {
                return Err(self.min_interval - last.elapsed());
            }
        }

        Ok(())
    }
}
```

#### 5.1.5 版本自动追踪

```rust
/// 定期检查 Claude Code CLI 的最新版本，自动更新指纹
struct VersionTracker {
    current_version: String,
    check_interval: Duration, // 每 6 小时检查一次
}

impl VersionTracker {
    async fn check_for_update(&mut self) -> Option<VersionUpdate> {
        // 从 npm registry 获取最新版本
        let resp = reqwest::get(
            "https://registry.npmjs.org/@anthropic-ai/claude-code/latest"
        ).await.ok()?;
        let json: Value = resp.json().await.ok()?;
        let latest = json["version"].as_str()?;

        if latest != self.current_version {
            // 注意：自动更新版本号后，还需要更新：
            // - billing salt
            // - beta headers
            // - cch 值
            // 这些无法自动提取，需要人工逆向
            tracing::warn!(
                "New Claude Code version available: {} (current: {}). \
                 Manual update of salt/beta/cch may be required.",
                latest, self.current_version
            );
            return Some(VersionUpdate {
                new_version: latest.to_string(),
                // 只能自动更新版本号和 UA
                auto_applicable: true,
                // salt/beta 需要手动逆向
                needs_manual_review: true,
            });
        }
        None
    }
}

struct VersionUpdate {
    new_version: String,
    auto_applicable: bool,
    needs_manual_review: bool,
}
```

### 5.2 预期规避的检测

- **System prompt 内容分析**：无可识别模式
- **Canary/蜜罐请求**：全部透传，无选择性拦截
- **IP 聚集分析**：每个 cookie 独立 IP
- **流量时序分析**：符合人类活跃时段分布
- **版本滞后检测**：及时跟进版本更新

### 5.3 局限性

- **IP 隔离成本高**：住宅代理服务每月费用可观
- **版本更新的滞后窗口**：CLI 发布新版到逆向完成之间有时间窗口
- **不可见的服务端检测**：model-family 可能有我们不知道的检测维度（设备指纹、行为机器学习模型等）

---

## 自评

### 预期检测绕过率

| 检测维度 | 当前 clewdr 绕过率 | 本方案预期绕过率 | 置信度 |
|----------|-------------------|-----------------|--------|
| TLS 指纹检测 | 10% | 75% | 中 |
| 请求头异常检测 | 20% | 85% | 高 |
| 行为模式检测 | 15% | 60% | 低 |
| 认证异常检测 | 40% | 80% | 中 |
| 内容/prompt 检测 | 30% | 90% | 高 |
| IP 关联检测 | 50% | 85% | 中 |
| **综合绕过率** | **~25%** | **~75%** | — |

### 薄弱环节（诚实评估）

1. **TLS 指纹（中等薄弱）**：Bun 的 BoringSSL 指纹复现在 Rust 生态中缺乏现成工具。rustls 和 BoringSSL 的 ClientHello 存在底层差异（扩展顺序、GREASE 值等），精确匹配需要大量工程投入。HTTP/2 指纹（SETTINGS 帧参数、WINDOW_UPDATE 行为）同样是检测面，本方案未充分覆盖。

2. **遥测/伴随流量（高度薄弱）**：本方案的伴随流量模拟高度依赖对真实 CLI 遥测协议的逆向。错误的遥测格式不如不发送。在完成协议逆向之前，建议不启用此功能。这意味着"幽灵客户端"特征仍然存在。

3. **机器学习检测模型（无法评估）**：model-family 可能训练了行为检测 ML 模型，基于数百个微观特征（请求时序的统计分布、token 使用模式、会话内的对话模式等）。对于这类检测，我们无法评估绕过率，因为不知道特征空间。

4. **版本更新窗口（固有弱点）**：CLI 版本更新后到我们完成逆向（salt、beta、cch）之间存在时间窗口。在此窗口内，版本号与 billing hash 不匹配是确定性的检测信号。

5. **Cookie 共享的本质矛盾**：反代的根本特征是多个下游用户共享少量上游 cookie/token。无论如何伪装请求级别的特征，model-family 都可能通过以下方式检测共享：
   - 同一 token 的对话主题极度分散
   - 同一 token 在短时间内切换多种编程语言/知识领域
   - 同一 token 的活跃时段覆盖多个时区

6. **成本-收益困境**：完整实施本方案（特别是 IP 隔离、遥测模拟、TLS 精确复现）的工程和运营成本可能超过直接购买订阅的成本。这是反代方案的根本经济学问题。

### 建议实施顺序

```
第一阶段（1-3 天，高收益/低成本）：
  ├── 修复 billing header 注入方式（DV-04）
  ├── 修复 entrypoint 默认值（DV-05）
  ├── 移除 ClewdR 对话命名（DV-09）
  ├── 移除测试消息拦截（DV-12）
  └── 降低 usage 查询频率（DV-11）

第二阶段（1-2 周，中等收益/中等成本）：
  ├── Claude Code 模式 TLS 切换（不做浏览器模拟）
  ├── Claude Web 模式添加 Sec-* 头
  ├── 会话生命周期管理（对话复用 + 延迟删除）
  ├── 请求重试添加随机抖动
  └── 1M 探测结果持久化

第三阶段（2-4 周，中等收益/高成本）：
  ├── Bun TLS 指纹精确复现
  ├── 逆向 cch/salt 生成逻辑
  ├── IP 隔离架构
  └── 版本自动追踪

第四阶段（长期，不确定收益/极高成本）：
  ├── 遥测协议逆向与模拟
  ├── HTTP/2 指纹对齐
  └── 对抗 ML 行为模型（如果存在）
```
