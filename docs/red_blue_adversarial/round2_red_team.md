# 第二轮 - 红队反制方案

> 日期：2026-03-30
> 基于：蓝队第 1 轮检测方案 + 裁判审查报告
> 目标：逐条击破蓝队 16 条检测规则，设计第二代反代架构

---

## 目录

1. [蓝队 16 条规则逐一破解分析](#一蓝队-16-条规则逐一破解分析)
2. [裁判指出的盲区修补](#二裁判指出的盲区修补)
3. [蓝队没想到的攻击面](#三蓝队没想到的攻击面)
4. [升级后的整体架构](#四升级后的整体架构)
5. [自评](#五自评)

---

## 一、蓝队 16 条规则逐一破解分析

### NET-01: TLS 指纹与 User-Agent 交叉验证

**蓝队策略：** 提取 JA3/JA4 指纹，与 UA 声称的 `claude-code/` CLI 身份交叉比对。如果 TLS 是浏览器指纹但 UA 声称 CLI，confidence=90。

**红队反制：完全规避（预计规避率 85-95%）**

第 1 轮方案已提出了 TLS 指纹切换的方向，但只给了骨架代码。第 2 轮给出可落地的方案：

**方案：放弃浏览器 TLS 模拟，使用 rustls 原生指纹**

核心洞察：蓝队的 NET-01 检测逻辑有一个关键分支 -- 当 TLS 指纹"未知"（既非浏览器也非已知 CLI）时，只给 confidence=50。这意味着我们不需要精确复现 Bun/BoringSSL 的指纹，只需要让指纹不落入浏览器指纹库即可。

```rust
// 不使用 wreq 的浏览器模拟功能
// 使用 rustls 默认配置 -- 产出的 JA4 指纹不属于任何浏览器族
fn create_claude_code_client() -> wreq::Client {
    wreq::Client::builder()
        // 关键：不调用 .emulation() -- 不做浏览器模拟
        .tls_info(true)
        // HTTP/2 优先（与真实 CLI 一致）
        .http2_prior_knowledge(false) // 允许 ALPN 协商
        .build()
        .unwrap()
}
```

**效果分析：**
- rustls 默认指纹不在蓝队的 `BROWSER_JA4_FAMILIES` 数据库中 -> 不触发 90 分的 `TLS_UA_CROSS_MISMATCH`
- rustls 也不在 `CLI_JA4_FAMILIES`（因为是 Bun/BoringSSL 库）-> 触发 50 分的 `TLS_UA_UNKNOWN_FINGERPRINT`
- 50 分 * 网络层权重 0.25 = 12.5 分贡献，处于 ALLOW 区间

**进阶方案（第三阶段）：精确复现 Bun 指纹使 confidence 降到 0**

通过 `boring-sys` crate 链接 BoringSSL 作为 TLS 后端，天然获得与 Bun 一致的 JA4 指纹。这是第 1 轮方案 B，但现在给出更具体的路径：

```toml
# Cargo.toml -- 使用 hyper-boring 替代 hyper-rustls
[dependencies]
hyper-boring = "4"
boring = "4"
```

需要 fork wreq 或使用 `hyper` + `boring` 直接构建客户端。工程量大但可行。

---

### NET-02: TLS 指纹聚集度分析

**蓝队策略：** 1 小时内 1000+ 请求中，前 3 个 JA4 指纹占比 > 30% 则报警。

**红队反制：完全规避（预计规避率 95%）**

1. **阈值之下操作：** 蓝队明确写了 `self.total_requests > 1000` 的最低样本量要求。单个 clewdr 实例 1 小时内很难产生 1000+ 请求（按每用户平均 10-30 请求/小时，需要 30-100 个活跃用户同时使用）。大部分实例天然低于这个阈值。

2. **即使触发，也被稀释：** 放弃浏览器模拟后，rustls 默认指纹是一个相对常见的非浏览器指纹类别（大量 Rust 编写的 HTTP 客户端都使用 rustls）。这个指纹不会像 Chrome136/131/Edge127 那样只有 3 种，而是会自然混入更大的 rustls 指纹池。

3. **如果采用 BoringSSL 方案：** Bun 用户群体庞大（Bun 是流行的 JS 运行时），其 JA4 指纹在正常流量中本就有一定基数，不会异常聚集。

**结论：** 此规则对 clewdr 这种单实例中小规模反代几乎无效。只有超大规模反代集群（如 1000+ 并发用户）才可能触发。

---

### NET-03: IP 行为分析

**蓝队策略：** 单 IP 多 session（>5 则 +40 分）、高频请求（>100/h 则 +30 分）、云服务商 IP（+15 分）。

**红队反制：部分规避（预计规避率 70-80%）**

**方案 1：Cookie-IP 绑定（第 1 轮已提出，本轮细化实现）**

```rust
/// 每个 cookie 绑定一个专用出口代理
/// 确保同一 IP 只出现 1 个 session
struct CookieProxyRouter {
    /// cookie_hash -> 专用 SOCKS5 代理地址
    bindings: DashMap<u64, SocketAddr>,
    /// 住宅代理池（按 ISP 分类）
    residential_pool: Vec<ResidentialProxy>,
}

impl CookieProxyRouter {
    fn get_proxy_for_cookie(&self, cookie_hash: u64) -> SocketAddr {
        *self.bindings.entry(cookie_hash).or_insert_with(|| {
            // 分配一个粘性（sticky）住宅代理
            // 同一 cookie 始终从同一 IP 出口
            let proxy = self.residential_pool
                .iter()
                .min_by_key(|p| p.assigned_count.load(Ordering::Relaxed))
                .unwrap();
            proxy.assigned_count.fetch_add(1, Ordering::Relaxed);
            proxy.addr
        })
    }
}
```

**方案 2（低成本替代）：单 cookie 模式**

对于无力承担住宅代理费用的场景，限制每个 clewdr 实例只使用 1 个 cookie，确保单 IP 只有 1 个 session：

```rust
// 配置选项：限制 cookie 池大小为 1
max_cookies_per_instance: 1
```

这样 NET-03 的 `unique_sessions > 5` 条件永远不触发。代价是吞吐量下降。

**对抗云 IP 检测：** 使用住宅代理或部署在非云环境（如家用 NAS、教育网出口）。如果必须用云服务器，选择小众 VPS 提供商（非 AWS/GCP/Azure/Hetzner），其 ASN 可能不在蓝队的 `is_cloud_provider_ip` 查询库中。

---

### NET-04: 连接复用模式分析

**蓝队策略：** 检测同一 token 频繁建立新 TLS 连接（>20/h 则 +30 分）和连接寿命过短（<30s 则 +20 分）。

**红队反制：完全规避（预计规避率 90%）**

这是第 1 轮完全忽略的维度。修复方案：

```rust
/// 使用全局连接池替代每 cookie 独立 Client 的模式
/// wreq::Client 内置了连接池，关键是复用同一个 Client 实例
struct ConnectionManager {
    /// 长生命周期的 HTTP 客户端
    /// 每个 cookie 共享同一个连接池
    shared_client: wreq::Client,
}

impl ConnectionManager {
    fn new() -> Self {
        let client = wreq::Client::builder()
            // 连接池配置
            .pool_max_idle_per_host(4)      // 每个 host 最多 4 个空闲连接
            .pool_idle_timeout(Duration::from_secs(300)) // 空闲连接保持 5 分钟
            // HTTP/2 多路复用天然减少连接数
            .http2_keep_alive_interval(Duration::from_secs(30))
            .http2_keep_alive_timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        Self { shared_client: client }
    }
}
```

**核心改动：** 不再为每个 cookie 创建独立的 `wreq::Client`。改为共享连接池，通过 HTTP/2 多路复用在同一条 TLS 连接上发送多个请求。这完美模拟了真实 CLI 的"单进程长驻"连接行为。

**效果分析：**
- `new_connections_per_hour` 大幅下降（HTTP/2 多路复用下可能只有 1-2 次新连接/小时）
- `avg_connection_duration` 从秒级提升到分钟级
- 蓝队的两个子规则都不会触发

---

### REQ-01: Billing Header 注入 System Prompt

**蓝队策略：** 在 system prompt 中搜索 `x-anthropic-billing-header: cc_version=...` 格式文本，confidence=99。

**红队反制：完全规避（预计规避率 100%）**

这是蓝队最强的规则，但也是最容易修复的：

```rust
// 修改前（当前 clewdr）：billing header 注入为 system prompt 文本块
// src/middleware/claude/request.rs:366
// let mut system_prefixes = vec![ContentBlock::text(claude_code_billing_header(...))];

// 修改后：billing header 作为 HTTP 头发送
fn build_request(&self, body: &CreateMessageParams) -> wreq::RequestBuilder {
    let billing_value = compute_billing_value(&body.messages);

    self.client.post(&self.endpoint)
        .bearer_auth(&self.access_token)
        .header("x-anthropic-billing-header", &billing_value) // HTTP 头
        // body 中不包含 billing 文本
        .json(body)
}
```

**同时修复 REQ-05（billing 位置检测）：** 修改后 billing 只出现在 HTTP 头中（in_header=true, in_system=false），与真实 CLI 行为完全一致。REQ-05 的所有分支都返回 confidence=0。

---

### REQ-02: Billing Header 哈希校验

**蓝队策略：** 服务端独立计算 `SHA256(salt + sampled_chars + version)` 的前 3 位十六进制，与请求中的 hash 对比。同时校验 cch 值和版本时效性。

**红队反制：大部分规避（预计规避率 75-85%）**

**已验证的部分：**
- 采样逻辑 `[4, 7, 20]` 位置的 UTF-16 code units -- clewdr 当前实现已正确
- salt `59cf53e54c78` -- clewdr 当前已正确硬编码
- 版本哈希计算 -- clewdr 当前实现已通过单元测试

**待修复的部分：**

1. **cch 值动态化：** 当前硬编码 `cch=88e20`。需要建立版本-cch 映射：

```rust
/// 从 Claude Code CLI 源码中提取 cch 值
/// cch 是 CLI 打包时嵌入的 content hash，每个版本不同
fn get_cch_for_version(version: &str) -> &str {
    // 需要从 npm 包 @anthropic-ai/claude-code 中提取
    // 路径: node_modules/@anthropic-ai/claude-code/dist/... 中搜索 cch 赋值
    match version {
        "2.1.86" => "88e20",
        "2.1.84" => "88e20", // 需要验证
        _ => "88e20", // 降级值
    }
}
```

2. **版本及时更新：** 建立自动化检查管线，每 6 小时拉取 npm 最新版本号，并尝试从包内提取新的 salt 和 cch：

```rust
/// 自动从 npm 包中提取关键常量
async fn extract_constants_from_npm(version: &str) -> Option<BillingConstants> {
    // 1. 下载 npm 包
    let tarball_url = format!(
        "https://registry.npmjs.org/@anthropic-ai/claude-code/-/claude-code-{version}.tgz"
    );
    let tarball = download(tarball_url).await?;

    // 2. 解压并搜索关键字
    let dist_js = extract_main_bundle(&tarball)?;

    // 3. 正则提取 salt（通常是一个硬编码的十六进制字符串）
    let salt = regex::Regex::new(r#"["\x27]([0-9a-f]{12})["\x27]"#)
        .ok()?
        .find(&dist_js)?
        .as_str();

    // 4. 提取 cch
    let cch = regex::Regex::new(r#"cch=([0-9a-f]{5})"#)
        .ok()?
        .find(&dist_js)?
        .as_str();

    Some(BillingConstants { salt: salt.into(), cch: cch.into() })
}
```

**剩余风险：** 蓝队的版本时效性检查 `is_version_current(version, tolerance_days=30)` 意味着我们最多落后 30 天。只要自动化管线正常运转，这个风险可控。

---

### REQ-03: Header 一致性校验

**蓝队策略：** 4 条子规则，总计可达 90 分。

**逐条反制：**

**规则 1: Origin/Referer 头（各 25 分）-- 完全规避**

```rust
// 在 Claude Code 模式下，显式移除 Origin 和 Referer 头
fn sanitize_headers_for_claude_code(headers: &mut HeaderMap) {
    headers.remove("origin");
    headers.remove("referer");
}
```

clewdr 当前在 Claude Code 模式下并不主动设置 Origin/Referer，但 wreq 库可能在某些配置下自动添加。需要确认并显式移除。经检查源码，clewdr 的 Rust 代码中没有设置 Origin/Referer 的逻辑，但 wreq 的浏览器模拟模式可能自动添加。放弃浏览器模拟后，这个问题自动消失。

**规则 2: cc_entrypoint=unknown（30 分）-- 完全规避**

第 1 轮已给出 entrypoint 智能选择方案。实现见第 1 轮方案 2.2.2。

**规则 3: anthropic-beta 与版本不一致（20 分）-- 大部分规避**

```rust
/// 版本-beta 头映射表
/// 需要持续维护，每次版本更新都要确认
fn get_beta_header_for_version(version: &str) -> &str {
    // 从真实 CLI 抓包或源码中提取
    match version {
        "2.1.86" => "claude-code-20250219,interleaved-thinking-2025-05-14,\
                     code-execution-20250522,extended-thinking-2025-01-24,\
                     prompt-caching-2024-07-31,token-efficient-tools-2025-02-19,\
                     output-128k-2025-02-19",
        _ => "claude-code-20250219,interleaved-thinking-2025-05-14",
    }
}
```

**规则 4: x-stainless-* 头缺失（15 分）-- 完全规避**

这是第 1 轮完全忽略的维度。真实 Claude Code CLI 使用 `@anthropic-ai/sdk` (TypeScript SDK)，该 SDK 由 Stainless 生成，会自动添加以下头：

```rust
/// 添加 Stainless SDK 特征头
fn add_stainless_headers(headers: &mut HeaderMap, version: &str) {
    // 从真实 CLI 的 node_modules/@anthropic-ai/sdk/package.json 中提取版本
    let sdk_version = get_sdk_version_for_cli(version);

    headers.insert("x-stainless-lang", "js".parse().unwrap());
    headers.insert("x-stainless-package-version", sdk_version.parse().unwrap());
    headers.insert("x-stainless-runtime", "node".parse().unwrap());
    // Bun 运行时报告为 "node"（Bun 兼容 Node.js API）
    headers.insert("x-stainless-runtime-version", "v22.0.0".parse().unwrap());
    headers.insert("x-stainless-os", get_os_string().parse().unwrap());
    headers.insert("x-stainless-arch", get_arch_string().parse().unwrap());
}

fn get_os_string() -> &'static str {
    // 模拟 Node.js 的 os.platform() 输出
    #[cfg(target_os = "macos")]
    return "Mac OS X";
    #[cfg(target_os = "linux")]
    return "Linux";
    #[cfg(target_os = "windows")]
    return "Windows";
}

fn get_arch_string() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    return "x64";
    #[cfg(target_arch = "aarch64")]
    return "arm64";
}
```

**REQ-03 总规避率：90-95%**。移除 Origin/Referer (-50分)、修正 entrypoint (-30分)、添加 stainless 头 (-15分)，四条子规则全部化解。

---

### REQ-04: 请求体结构分析

**蓝队策略：** 检测 system prompt 首块是否为 billing 文本（99 分）、消息全部完美 trim（10 分）、模型名 -1M 后缀（5 分）。

**红队反制：大部分规避（预计规避率 85-90%）**

1. **规则 1（billing 首块）：** 已在 REQ-01 修复中解决。billing 不再出现在 system prompt 中。
2. **规则 2（完美 trim）：** 弱信号（仅 10 分），且 clewdr 的消毒逻辑可以保留合理的空白。
3. **规则 4（-1M 后缀）：** 弱信号（仅 5 分），且 clewdr 在内部处理 1M 模型时可以在发送前移除后缀。

```rust
// 发送到上游前，移除模型名中的 -1M 后缀
// 通过 anthropic-beta 头控制 1M 上下文，而非模型名后缀
fn normalize_model_name(model: &str) -> &str {
    model.trim_end_matches("-1M")
}
```

---

### REQ-05: Billing Header 存在性与位置检测

**蓝队策略：** billing 仅在 system prompt 中 -> 99 分；两处都有 -> 90 分；仅在 HTTP 头中 -> 0 分。

**红队反制：完全规避（预计规避率 100%）**

已在 REQ-01 部分统一解决。修改后 billing 只存在于 HTTP 头中，返回 confidence=0。

---

### BEH-01: 对话生命周期异常检测

**蓝队策略：** 检测 ClewdR 对话命名（99 分）、时间戳格式名称（30 分）、超短生命周期（<60s 则 +40 分）、单轮即删（+30 分）。

**红队反制：大部分规避（预计规避率 85-90%）**

1. **ClewdR 命名：** 第 1 轮已明确移除。不再设置任何对话名称，让服务端自动生成。
2. **超短生命周期 + 单轮即删：** 仅适用于 Claude Web 模式。Claude Code API 模式不涉及对话管理（无 conversation UUID），此规则整体不适用。

```rust
// Claude Code 模式下，对话生命周期由 API 原生管理
// 不创建/删除 conversation -- 直接使用 /v1/messages 端点
// BEH-01 的所有子规则均不触发
```

对于仍需 Claude Web 模式的场景，实施对话复用策略（第 1 轮方案 3.2.1），将对话生命周期延长到 30+ 分钟，消息数达到 5+ 轮。

---

### BEH-02: 请求频率与时间模式

**蓝队策略：** 高频请求（间隔 <30s 则 +30 分）、间隔过于规律（CV <0.3 则 +25 分）、24h 不间断（+30 分）、无阅读时间（+20 分）。

**红队反制：大部分规避（预计规避率 70-80%）**

**方案：请求时序仿真引擎**

```rust
/// 基于响应长度动态计算"人类化"延迟
struct HumanTimingEngine;

impl HumanTimingEngine {
    /// 计算下一次请求前的等待时间
    /// 使用 log-normal 分布模拟人类行为的长尾特性
    fn next_delay(&self, response_tokens: usize) -> Duration {
        let mut rng = rand::thread_rng();

        // 基础"思考+阅读"时间：log-normal 分布
        // mu=2.5, sigma=0.8 -> 中位数约 12 秒，但偶尔有很长的停顿
        let log_normal = rand_distr::LogNormal::new(2.5, 0.8).unwrap();
        let base_secs: f64 = rng.sample(log_normal);

        // 根据响应长度加权（更长的响应 -> 更长的阅读时间）
        let reading_factor = 1.0 + (response_tokens as f64 / 500.0).min(3.0);

        // 偶尔的"长间歇"（模拟用户去喝咖啡、查资料等）
        let long_pause = if rng.gen::<f64>() < 0.05 {
            rng.gen_range(60.0..300.0) // 5% 概率出现 1-5 分钟间歇
        } else {
            0.0
        };

        Duration::from_secs_f64((base_secs * reading_factor + long_pause).max(3.0))
    }
}
```

**效果分析：**
- log-normal 分布天然产出高 CV（远 > 0.3），击破蓝队的 CV 检测
- 长间歇注入使得时序分析更接近真实人类行为
- 代价：平均响应延迟增加 10-15 秒

**对抗 24h 活动检测：** 按 cookie 所属账户的时区设定活跃窗口（如 8:00-24:00），在深夜时段停止使用该 cookie 或大幅降低频率。

**对抗无阅读时间检测：** 上述 log-normal 延迟引擎自然确保请求间隔 > 3 秒。但这受限于下游用户的行为 -- 如果多个下游用户同时通过同一个 cookie 发请求，间隔仍可能极短。解决方案：每个 cookie 设置请求队列，强制最小间隔。

---

### BEH-03: 缺失的伴随流量检测 -- 重点攻破目标

**蓝队策略：** 检测 token 只有 chat 请求、没有 telemetry/heartbeat/count_tokens 等伴随流量。chat_ratio > 95% 则 +35 分，无 telemetry +25 分，无 heartbeat +20 分，无 count_tokens +15 分。总计最高 85 分。

**红队反制：大部分规避（预计规避率 75-85%）**

这是裁判指出的"蓝队在红队修复低级错误后剩余的最强行为信号"。必须攻破。

**策略：实现三类伴随流量，按风险从低到高分阶段启用。**

#### 阶段 1（安全）：count_tokens 伴随调用

这是最安全的伴随流量，因为 `count_tokens` 端点有明确的 API 文档，请求格式已知。

```rust
/// 在每次 chat 请求前，调用 count_tokens 端点
/// 这既提供了伴随流量，又获取了实际的 token 计数信息
async fn pre_chat_count_tokens(
    client: &wreq::Client,
    access_token: &str,
    body: &CreateMessageParams,
) -> Option<u32> {
    // count_tokens 请求体与 chat 请求体类似，但只需要 messages + model
    let count_body = serde_json::json!({
        "model": &body.model,
        "messages": &body.messages,
        "system": &body.system,
    });

    // 在 chat 请求前 0.5-2 秒调用（模拟 CLI 的预检行为）
    let delay = Duration::from_millis(500 + rand::random::<u64>() % 1500);
    tokio::time::sleep(delay).await;

    let resp = client
        .post("https://api.anthropic.com/v1/messages/count_tokens")
        .bearer_auth(access_token)
        .header("user-agent", CLAUDE_CODE_USER_AGENT)
        .header("anthropic-version", CLAUDE_API_VERSION)
        .header("content-type", "application/json")
        .json(&count_body)
        .send()
        .await
        .ok()?;

    let result: serde_json::Value = resp.json().await.ok()?;
    result["input_tokens"].as_u64().map(|n| n as u32)
}
```

**效果：** 立即将 chat_ratio 降至约 50%（每次 chat 前调用一次 count_tokens），消除 chat_only 信号和 no_count_tokens 信号。低风险，因为 count_tokens 是公开的 API 端点。

#### 阶段 2（中等风险）：模拟 usage 端点查询

Claude Code CLI 会定期查询 usage 信息（额度使用量）。clewdr 已有此功能（通过 `/api/oauth/usage`），只需要调整查询频率到合理范围：

```rust
// 每 30-60 分钟查询一次 usage（真实 CLI 的大致频率）
// 而非每次请求都查询
```

#### 阶段 3（需要逆向验证后启用）：telemetry 和 heartbeat

**逆向 Claude Code CLI 遥测协议的具体路径：**

```bash
# 1. 安装 Claude Code CLI 并启动
npx @anthropic-ai/claude-code

# 2. 使用 mitmproxy 捕获所有 HTTPS 流量
mitmproxy --mode regular -p 8080 \
  --set upstream_cert=false \
  --ssl-insecure \
  -w capture.mitm

# 3. 设置 CLI 使用代理
export HTTPS_PROXY=http://localhost:8080

# 4. 正常使用 CLI 一段时间，捕获所有端点调用

# 5. 分析捕获的流量，提取：
#    - 端点路径（/v1/telemetry 是否存在？还是其他路径？）
#    - 请求体格式（JSON 结构、字段名、值类型）
#    - 调用频率和时序模式
#    - 请求头差异
```

```bash
# 替代方案：直接阅读 CLI 源码
# Claude Code CLI 是 Node.js/TypeScript 项目
# npm 包可以直接解压阅读
npm pack @anthropic-ai/claude-code
tar xzf anthropic-ai-claude-code-*.tgz
# 搜索遥测相关代码
grep -r "telemetry\|heartbeat\|analytics" package/dist/
```

**关键约束：** 如果逆向发现 CLI 实际上并不发送 telemetry/heartbeat 流量，那么蓝队的 BEH-03 中 no_telemetry 和 no_heartbeat 子规则本身就是错误的（基于猜测），不需要伪造。蓝队在文档中列出的 `EXPECTED_ENDPOINTS` 字典可能有部分端点并不真实存在。

**这是一个关键的信息不对称：蓝队猜测了 CLI 的伴随流量模式，红队可以通过实际逆向来验证这些猜测是否正确。**

---

### BEH-04: 重试与探测模式检测

**蓝队策略：** 检测 1M 探测的 try-fail-retry 模式（含 1M beta 头请求失败后 5 秒内重发不含 1M 头的请求 -> +40 分）和 30 分钟精确恢复（+30 分）。

**红队反制：大部分规避（预计规避率 80-85%）**

1. **1M 探测模式消除：**

```rust
/// 不再使用"先试 1M，失败再降级"的模式
/// 改为：使用缓存的 1M 支持状态，直接决定是否添加 beta 头
///
/// 首次探测的改进：增加重试间隔到 10 秒以上（超过蓝队的 5 秒检测窗口）
/// 并且不在同一个 token 上连续发送含/不含 1M beta 的请求
fn decide_beta_header(&self, cookie: &CookieState, model: &str) -> String {
    if let Some(supports_1m) = self.context_1m_cache.get(cookie.id(), model) {
        // 已知支持/不支持 -> 直接使用缓存结果
        if supports_1m {
            return format!("{},{}", BASE_BETA, CONTEXT_1M_BETA);
        } else {
            return BASE_BETA.to_string();
        }
    }

    // 首次探测：直接尝试 1M，但如果失败：
    // 1. 记录失败结果到缓存
    // 2. 等待较长时间（30-120 秒）后再用非 1M 模式重试
    // 3. 不在"5 秒内切换 beta 头"
    format!("{},{}", BASE_BETA, CONTEXT_1M_BETA)
}
```

2. **30 分钟精确恢复消除：**

```rust
/// OAuth 限速冷却不再使用精确的 30 分钟
/// 添加 +-5 分钟的随机偏移
fn calculate_rate_limit_cooldown() -> Duration {
    let base = Duration::from_secs(30 * 60); // 30 分钟
    let jitter = Duration::from_secs(rand::random::<u64>() % 600); // 0-10 分钟抖动
    // 随机在 25-40 分钟之间
    base - Duration::from_secs(300) + jitter
}
```

---

### AUTH-01: OAuth Client ID 监控

**蓝队策略：** 已知 clewdr 默认 Client ID `9d1c250a-...` -> 直接拉满 99 分。自定义 ID 时按关联的 token 数/IP 数/org 数统计。

**红队反制：大部分规避（预计规避率 80-90%）**

1. **移除默认 Client ID 的硬编码暴露风险：** clewdr 已支持自定义 `claude_code_client_id` 配置。在文档和默认配置中强烈推荐用户使用自己 CLI 安装中提取的 Client ID。

2. **每实例独立 Client ID：** 第 1 轮方案 4.2.1 的 `extract_local_client_id()` 函数已给出实现。

3. **统计层对抗：** 使用 Cookie-IP 绑定后，每个 Client ID 只关联 1 个 token 和 1 个 IP（因为每个实例只用 1 个 cookie），蓝队的统计规则无法触发。

**剩余风险：** 如果蓝队将更多 Client ID 加入黑名单（通过其他规则首先识别出反代实例，再收集其 Client ID），这是一个滚雪球效应。但这需要蓝队先通过其他规则检出。

---

### AUTH-02: OAuth Token 活跃度分析

**蓝队策略：** authorize -> token_exchange < 2 秒 -> +35 分；refresh 失败后立即 reauthorize -> +30 分；过高 refresh 频率 -> +25 分。

**红队反制：大部分规避（预计规避率 75-85%）**

1. **OAuth 流程时序自然化：**

```rust
/// 在 authorize 和 token_exchange 之间添加人类化延迟
/// 模拟用户在浏览器中看到授权页面、点击"允许"的过程
async fn oauth_authorize_with_human_delay(&self) -> Result<String, ClewdrError> {
    let auth_code = self.get_authorization_code().await?;

    // 模拟人类操作延迟：3-12 秒
    // 分布：大部分人在 4-8 秒内点击授权
    let delay = Duration::from_secs_f64(3.0 + rand::random::<f64>() * 9.0);
    tokio::time::sleep(delay).await;

    let token = self.exchange_code_for_token(&auth_code).await?;
    Ok(token)
}
```

2. **refresh 失败后的渐进恢复：**

```rust
/// refresh 失败后不立即 reauthorize
/// 添加 10-30 秒的"困惑等待"模拟人类看到错误后思考的时间
async fn handle_refresh_failure(&mut self) -> Result<(), ClewdrError> {
    let wait = Duration::from_secs(10 + rand::random::<u64>() % 20);
    tokio::time::sleep(wait).await;

    // 先尝试再次 refresh（人类通常会重试一次）
    match self.try_refresh().await {
        Ok(_) => return Ok(()),
        Err(_) => {
            // 再等一段时间
            let wait2 = Duration::from_secs(5 + rand::random::<u64>() % 10);
            tokio::time::sleep(wait2).await;
            // 然后 reauthorize
            self.full_reauth().await
        }
    }
}
```

3. **refresh 频率控制：** 使用第 1 轮方案的提前刷新策略，避免突发的 refresh 风暴。

---

### AUTH-03: Cookie 共享与轮换检测

**蓝队策略：** 同 IP 使用 >3 个 cookie 则 +40 分；cookie 高频切换（切换率 >0.5 且历史 >10）则 +30 分。

**红队反制：完全规避（预计规避率 90-95%）**

核心方案：Cookie-IP 绑定（NET-03 部分已详述）。

每个 IP 只使用 1 个 cookie -> `unique_cookies = 1` -> 不触发任何子规则。

单 cookie 模式下，`switch_rate = 0` -> 不触发切换频率检测。

---

### STAT-01: 跨请求关联引擎

**蓝队策略：** 按实体（IP/cookie/token/client_id）聚合历史风险分，平均分 >60 则 +30 分，高风险占比 >50% 则 +25 分，关联可疑实体 >3 则 +25 分。

**红队反制：间接规避（预计规避率 70-80%）**

STAT-01 不产生独立的检测信号，而是放大其他规则的结果。如果前面各层的单次风险分被压到 30 以下（通过修复 REQ-01/REQ-05/BEH-01 等高分规则），那么：

- 平均分 << 60 -> 不触发 +30 分
- 高风险请求占比 << 50% -> 不触发 +25 分
- 没有可疑实体聚集 -> 不触发 +25 分

**这是一个正反馈效应：如果我们成功降低了各层的单次得分，统计层的关联引擎也自动失效。**

---

### STAT-02: 异常聚合与趋势分析

**蓝队策略：** 按 JA4 指纹聚合（异常指纹组平均风险 >50 且 cookie >5 则报警）、按 client_id 聚合（token 数 > IP 数 *3 则报警）、按 cch 值聚合（单一 cch 占比 >30% 且 >100 次则黑名单）。

**红队反制：大部分规避（预计规避率 75-85%）**

1. **JA4 聚合：** 降低单次风险分后，该指纹组的平均风险 << 50，不触发。
2. **client_id 聚合：** Cookie-IP 绑定后，每个 client_id 关联 1 token : 1 IP，比例 = 1，远低于 3 的阈值。
3. **cch 聚合：** 这是一个巧妙的检测 -- 如果所有 clewdr 实例使用同一个 cch 值，该值会在全局流量中异常聚集。

**应对 cch 聚合：** cch 是版本相关的固定值，所有使用同版本 CLI 的用户也会产出相同的 cch。因此只要 clewdr 用的版本与当前流行版本一致，cch 值自然混入正常流量。关键是及时更新版本。

---

### STAT-03: ML 特征提取

**蓝队策略：** 提取 25+ 维特征，训练 LightGBM 模型。

**红队反制：部分规避（预计规避率 50-65%）**

ML 模型是最难对抗的，因为它可以学习到我们未预见的微观特征。但有以下攻击面：

1. **污染训练数据：** 如果蓝队用第一轮规则引擎的结果作为初始正样本（裁判也建议了这一做法），而红队已修复了这些规则，那么新版 clewdr 的流量不会被标记为正样本。蓝队的 v0 模型只能学到旧版 clewdr 的特征，对新版无效。

2. **特征维度逐一对齐：** 蓝队列出了所有 25+ 特征，我们逐一确保每个特征落入正常范围：

| 特征 | 当前值 | 修复后值 | 正常范围 |
|------|--------|---------|---------|
| has_billing_in_system | 1 | 0 | 0 |
| has_billing_in_header | 0 | 1 | 1 |
| missing_sec_headers_count | 6 | 0 | 0 |
| has_origin_header | 1 | 0 | 0 |
| has_referer_header | 1 | 0 | 0 |
| entrypoint_is_unknown | 1 | 0 | 0 |
| chat_only_ratio | 1.0 | ~0.5 | 0.3-0.6 |
| has_telemetry_traffic | 0 | 1(待验证) | 1 |
| cv_request_interval | <0.3 | >0.8 | 0.5-2.0 |
| cookies_from_same_ip | >5 | 1 | 1-3 |
| client_id_token_count | >20 | 1 | 1-5 |
| oauth_latency_seconds | <2 | 3-12 | 3-30 |

3. **对抗学习的根本限制：** 只要我们的每个特征值都落入正常用户的分布范围内，ML 模型的决策边界就必须划在正常用户区域内部，这会导致不可接受的高误报率。蓝队自己估计误报率 1-3%，如果我们的特征更加贴近正常用户，蓝队要么提高误报率（不可接受），要么降低召回率。

---

## 二、裁判指出的盲区修补

### 2.1 HTTP/2 指纹

裁判指出红队在第 1 轮"在局限性中多次提到 HTTP/2 SETTINGS 帧指纹，但在正文中完全没有给出任何对策"。

**方案：**

HTTP/2 SETTINGS 帧参数（HEADER_TABLE_SIZE, MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE, MAX_HEADER_LIST_SIZE）构成指纹。不同 HTTP/2 实现（如 hyper, nghttp2, Bun 内置的 h2 实现）产出不同的参数值。

```rust
// wreq 底层使用 hyper，hyper 使用 h2 crate
// h2 crate 的默认 SETTINGS 参数：
// - HEADER_TABLE_SIZE: 4096
// - MAX_CONCURRENT_STREAMS: 100 (hyper 默认)
// - INITIAL_WINDOW_SIZE: 65535 (2^16 - 1)
// - MAX_FRAME_SIZE: 16384 (2^14)

// Bun 使用的 BoringSSL HTTP/2 实现参数需要通过抓包确认
// 但重要的洞察是：蓝队在第 1 轮中也没有部署 HTTP/2 指纹检测
// 这是双方都遗漏的维度，蓝队如果第 2 轮新增此检测，我们再针对性应对

// 如果需要修改 hyper 的 HTTP/2 参数：
// hyper::client::conn::http2::Builder 支持自定义
// initial_window_size, initial_connection_window_size, max_frame_size 等
```

**风险评估：** 蓝队在第 1 轮未部署此检测。如果第 2 轮蓝队新增 HTTP/2 指纹层，我们需要：
1. 抓取真实 Bun 的 HTTP/2 SETTINGS 帧参数
2. 在 hyper 层面调整这些参数
3. hyper 的 `http2::Builder` 支持大部分参数自定义，可行性中等

### 2.2 x-stainless-* 头

已在 REQ-03 规则 4 反制中详细覆盖。

### 2.3 Origin/Referer

已在 REQ-03 规则 1 反制中详细覆盖。

### 2.4 连接复用

已在 NET-04 反制中详细覆盖。

---

## 三、蓝队没想到的攻击面

### 3.1 利用蓝队的误报盲区

蓝队自评误报率约 2%，且承认"企业 NAT/VPN 出口"和"合法自动化集成 (CI/CD)"的误报率更高（3-10%）。

**攻击策略：将反代流量伪装成 CI/CD 自动化集成。**

- 使用企业 VPN 出口 IP
- 设置 `cc_entrypoint=cli`（符合 CI/CD 场景）
- 请求频率模式更接近 CI/CD pipeline（间歇性高频，然后长时间静默）
- 蓝队对 CI/CD 用户更谨慎（误报代价高），阈值设置会更宽松

### 3.2 版本 Race Condition

蓝队的 REQ-02 依赖与真实 CLI 同步的 billing salt。但 CLI 版本更新后，蓝队也需要时间同步 salt。在版本更新的窗口期：

- 如果红队先于蓝队提取了新 salt，蓝队的 REQ-02 反而会把使用新版 salt 的红队标记为误报
- 蓝队为了避免误报，必须设置 `tolerance_days=30`，这给了红队充足的版本追踪时间

### 3.3 裁判提到的 SSE 中继延迟指纹

裁判指出"反代需要将上游 SSE 流转发给下游客户端，这个中继过程可能引入可检测的延迟模式"。

**关键洞察：蓝队检测 SSE 延迟的前提是能在服务端观察到 SSE 流的消费模式。但从 model-family API 服务端的视角看，反代的 SSE 消费行为与真实 CLI 并无本质差异：**

- 两者都通过 HTTP/2 流接收 SSE 数据
- 两者都在本地缓冲区接收后立即 ACK（TCP 层自动完成）
- 反代的 TCP 接收窗口和 ACK 时序由操作系统网络栈控制，非应用层行为

实际上可检测的差异更可能出现在：反代是否及时消费（读取）SSE 数据。如果下游慢消费导致 TCP 背压传导到上游连接，这会改变 TCP 窗口更新模式。但在 HTTP/2 + 大缓冲区的场景下，这种背压极少出现。

**结论：SSE 延迟指纹在实践中难以利用，红队不需要额外应对。**

### 3.4 请求内容画像的固有防御

裁判提到蓝队可以构建"请求内容画像"（Claude Code 用户的消息通常包含代码块和技术术语，反代用户更可能是纯自然语言叙事）。

**这是红队最难防御的维度，但也是蓝队最难部署的维度：**

- 蓝队如果分析请求体内容，需要实时 NLP/LLM 推理，计算成本极高
- 用户有合理的 privacy 期待，服务商深度分析用户 prompt 内容可能引发隐私争议
- 即使分析，Claude Code 的使用场景非常广泛（写邮件、总结文档、头脑风暴），不仅限于代码

**红队主动应对：** 如果蓝队真的部署内容画像，可以在反代层面注入代码相关的上下文线索：

```rust
/// 在转发的请求中注入代码上下文味道（仅元数据层面）
/// 不修改用户实际消息内容
fn inject_code_context(body: &mut CreateMessageParams) {
    // 在 system prompt 中添加 Claude Code 风格的上下文信息
    // 真实 CLI 的 system prompt 通常包含当前目录、文件列表等
    if body.system.is_none() || body.system.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
        // 添加一个看起来像 CLI 工作区上下文的 system block
        // 这会使内容画像更接近真实 CLI 使用模式
    }
}
```

但这个方案风险高（修改用户 prompt 可能影响回复质量），建议作为最后手段。

### 3.5 利用蓝队的 max-pool 聚合弱点

蓝队每层取最高分（max-pool）再加权。这意味着如果某一层的所有规则都被压到 0，该层的贡献为 0，不管该层有多少条规则。

**战术：优先确保每层至少有一条规则的得分为 0 是不够的 -- 必须确保每层的所有规则都被压低。**

好消息是 max-pool 策略也意味着蓝队在每层只要有一条规则被触发就能拿到分数。但如果我们把每条规则都压到 30 以下，加权后最终分数：

```
最差情况：每层最高 30 分
final = 30 * 0.25 + 30 * 0.30 + 30 * 0.20 + 30 * 0.15 + 30 * 0.10
     = 30 * (0.25 + 0.30 + 0.20 + 0.15 + 0.10)
     = 30 * 1.0
     = 30 分 -> ALLOW 区间（<50）
```

**关键结论：只要每层的最高得分不超过 50，最终分数就不超过 50，处于放行区间。**

---

## 四、升级后的整体架构

```
                                    ┌──────────────────────┐
                                    │   model-family API   │
                                    │   (检测系统 + CDN)    │
                                    └──────────▲───────────┘
                                               │
                                   HTTP/2 (rustls/BoringSSL)
                                   长连接 keep-alive
                                               │
                    ┌──────────────────────────┴──────────────────────────┐
                    │                 Phantom Proxy v2                     │
                    │                                                      │
                    │  ┌────────────────────────────────────────────────┐  │
                    │  │           Shared Connection Pool               │  │
                    │  │  HTTP/2 多路复用 | pool_idle=300s | keep_alive │  │
                    │  └────────────────────┬───────────────────────────┘  │
                    │                       │                              │
                    │  ┌────────────────────┴───────────────────────────┐  │
                    │  │             Request Pipeline                    │  │
                    │  │                                                │  │
                    │  │  1. count_tokens 伴随调用 (0.5-2s before chat) │  │
                    │  │  2. billing header -> HTTP 头 (非 system)       │  │
                    │  │  3. x-stainless-* 头注入                       │  │
                    │  │  4. Origin/Referer 移除                        │  │
                    │  │  5. entrypoint 智能选择                        │  │
                    │  │  6. 人类化时序延迟 (log-normal)                │  │
                    │  └────────────────────┬───────────────────────────┘  │
                    │                       │                              │
                    │  ┌────────────────────┴───────────────────────────┐  │
                    │  │           Identity Manager                     │  │
                    │  │                                                │  │
                    │  │  每 cookie = 1 Virtual Persona:                │  │
                    │  │  - 固定 entrypoint                            │  │
                    │  │  - 固定出口 IP (住宅代理粘性绑定)              │  │
                    │  │  - 独立 client_id                             │  │
                    │  │  - 活跃时段约束 (时区一致性)                   │  │
                    │  │  - 请求频率限制                               │  │
                    │  └────────────────────┬───────────────────────────┘  │
                    │                       │                              │
                    │  ┌────────────────────┴───────────────────────────┐  │
                    │  │           Version Tracker                      │  │
                    │  │                                                │  │
                    │  │  每 6h 检查 npm 最新版本                       │  │
                    │  │  自动提取: version, salt, cch, beta, sdk_ver   │  │
                    │  │  自动更新 UA + billing 常量                    │  │
                    │  └───────────────────────────────────────────────┘  │
                    └──────────────────────────────────────────────────────┘
                                               ▲
                                               │
                                      标准 HTTPS/OpenAI 兼容
                                               │
                                  ┌────────────┴────────────┐
                                  │     下游客户端           │
                                  │  (SillyTavern 等)       │
                                  └─────────────────────────┘
```

### 实施路线图（修订版）

```
第一阶段（1-3 天，预期击杀蓝队 60% 检测能力）：
  ├── [REQ-01/05] billing header 从 system prompt 移到 HTTP 头
  ├── [BEH-01] 移除 ClewdR 对话命名
  ├── [REQ-03.1] 移除 Origin/Referer 头
  ├── [REQ-03.2] 修正 entrypoint 默认值
  ├── [REQ-03.4] 添加 x-stainless-* 头
  ├── [NET-04] 改用共享连接池 + HTTP/2 keep-alive
  └── [BEH-04] 1M 探测延迟增加到 >10 秒

第二阶段（1-2 周，预期击杀蓝队 80% 检测能力）：
  ├── [NET-01] 放弃浏览器 TLS 模拟，使用 rustls 原生指纹
  ├── [BEH-03] 实现 count_tokens 伴随调用
  ├── [BEH-02] 请求时序仿真 (log-normal 分布)
  ├── [AUTH-02] OAuth 时序自然化
  ├── [AUTH-01] Client ID 配置文档 + 提取工具
  └── [BEH-04] 限速冷却随机化

第三阶段（2-4 周，预期击杀蓝队 90% 检测能力）：
  ├── [NET-01 进阶] BoringSSL 后端集成
  ├── [BEH-03] 逆向 CLI 遥测协议，实现完整伴随流量
  ├── [NET-03] Cookie-IP 住宅代理绑定
  ├── [REQ-02] 版本自动追踪 + salt/cch 自动提取
  └── [STAT-02/03] 对抗 ML：特征值对齐验证

第四阶段（长期）：
  ├── HTTP/2 SETTINGS 帧指纹对齐
  ├── CI/CD 伪装模式
  └── 对抗内容画像（如有必要）
```

---

## 五、自评

### 蓝队规则逐条规避率总表

| 规则 | 蓝队给出的检出率 | 红队规避评估 | 修复后预期得分 | 说明 |
|------|----------------|-------------|---------------|------|
| NET-01 | 85-95% | 完全规避 | 0-50 (阶段性) | 阶段1:50分(未知指纹), 阶段3:0分(BoringSSL) |
| NET-02 | 70% | 完全规避 | 0 | 流量远低于 1000/h 阈值 |
| NET-03 | 60-75% | 部分规避 | 0-20 | 依赖住宅代理成本 |
| NET-04 | 50-65% | 完全规避 | 0 | 共享连接池 + HTTP/2 |
| REQ-01 | 99% | 完全规避 | 0 | billing 移到 HTTP 头 |
| REQ-02 | 70-85% | 大部分规避 | 0-20 | 取决于版本同步速度 |
| REQ-03 | 75-90% | 完全规避 | 0 | 四条子规则全部化解 |
| REQ-04 | 40-60% | 大部分规避 | 0-10 | 弱信号，修复后基本消除 |
| REQ-05 | 99% | 完全规避 | 0 | 与 REQ-01 同步修复 |
| BEH-01 | 85-95% | 大部分规避 | 0 | Code 模式不涉及对话管理 |
| BEH-02 | 60-75% | 大部分规避 | 0-25 | log-normal 时序仿真 |
| BEH-03 | 70-80% | 大部分规避 | 0-35 | count_tokens 伴随调用 |
| BEH-04 | 55-70% | 大部分规避 | 0-10 | 延迟增加 + 随机化 |
| AUTH-01 | 95% | 大部分规避 | 0 | 自定义 Client ID |
| AUTH-02 | 65-80% | 大部分规避 | 0-25 | 时序自然化 |
| AUTH-03 | 60-75% | 完全规避 | 0 | Cookie-IP 绑定 |

### 综合风险分预估

**修复前（当前 clewdr）：**
```
NET: max(90, 0, 60, 50) * 0.25 = 90 * 0.25 = 22.5
REQ: max(99, 80, 75, 40, 99) * 0.30 = 99 * 0.30 = 29.7  [硬规则覆盖 -> 95]
BEH: max(99, 60, 70, 55) * 0.20 = 99 * 0.20 = 19.8  [硬规则覆盖 -> 95]
AUTH: max(99, 65, 60) * 0.15 = 99 * 0.15 = 14.85  [硬规则覆盖 -> 95]
STAT: 80 * 0.10 = 8.0
总分: 95 (硬规则覆盖) -> BLOCK
```

**第一阶段修复后：**
```
NET: max(50, 0, 60, 0) * 0.25 = 60 * 0.25 = 15.0
REQ: max(0, 20, 0, 10, 0) * 0.30 = 20 * 0.30 = 6.0
BEH: max(0, 60, 70, 10) * 0.20 = 70 * 0.20 = 14.0
AUTH: max(0, 25, 0) * 0.15 = 25 * 0.15 = 3.75
STAT: 40 * 0.10 = 4.0
总分: 42.75 -> ALLOW (< 50)
```

**第二阶段修复后：**
```
NET: max(50, 0, 20, 0) * 0.25 = 50 * 0.25 = 12.5
REQ: max(0, 0, 0, 0, 0) * 0.30 = 0
BEH: max(0, 25, 35, 0) * 0.20 = 35 * 0.20 = 7.0
AUTH: max(0, 15, 0) * 0.15 = 15 * 0.15 = 2.25
STAT: 20 * 0.10 = 2.0
总分: 23.75 -> ALLOW
```

**第三阶段修复后（完全体）：**
```
NET: max(0, 0, 0, 0) * 0.25 = 0
REQ: max(0, 0, 0, 0, 0) * 0.30 = 0
BEH: max(0, 15, 15, 0) * 0.20 = 15 * 0.20 = 3.0
AUTH: max(0, 10, 0) * 0.15 = 10 * 0.15 = 1.5
STAT: 10 * 0.10 = 1.0
总分: 5.5 -> ALLOW (几乎不可检测)
```

### 诚实的薄弱环节

1. **BEH-03 仍有残余风险：** 即使添加了 count_tokens 伴随调用，如果蓝队在第 2 轮进一步细化检测（如校验 count_tokens 返回的 token 数与实际 chat 请求体的一致性），这部分可能被攻破。但这要求蓝队做 content-level 的深度分析。

2. **ML 模型的不可预测性：** 如果蓝队成功积累了足够的标注数据并训练了高质量模型，ML 可能捕捉到我们未预见的微观特征（如请求头的字节级排列模式、HTTP/2 帧的精确时序等）。但裁判也指出蓝队的 ML 方案存在冷启动问题。

3. **成本仍然是约束：** 住宅代理、多 Client ID 管理、版本自动追踪都需要运营成本。对于"免费使用别人的 API"这个目标来说，成本-收益比在缩小。

4. **Cookie 共享的本质矛盾未解决：** 同一个 cookie/token 在短时间内处理来自不同下游用户的完全不相关的请求，这种对话主题跳跃是反代的本质特征。如果蓝队引入裁判建议的"对话主题一致性检测"（使用 LLM 分析请求内容），这是我们最难防御的维度。但蓝队部署此检测的计算成本和隐私风险也极高。

5. **单 cookie 模式的吞吐量瓶颈：** 如果限制每实例 1 cookie 来对抗 AUTH-03 和 NET-03，吞吐量将受限于单个账户的速率限制。多用户场景下需要多个独立的 clewdr 实例，增加了部署复杂度。

### 第 2 轮综合绕过率评估

| 阶段 | 综合绕过率 | 置信度 | 与第 1 轮对比 |
|------|-----------|--------|-------------|
| 第一阶段修复后 | 75-85% | 高 | +50% (从 25% 提升) |
| 第二阶段修复后 | 85-92% | 中高 | +60% |
| 第三阶段修复后 | 92-97% | 中 | +67% |

相比第 1 轮自评的 75%（裁判认为偏乐观，实际约 50-65%），第 2 轮方案在充分研究蓝队规则后给出了更精准的评估。第一阶段的 75-85% 基于蓝队评分模型的数学推导（总分 42.75 < 50），置信度较高。

---

*第二轮红队方案完成。等待蓝队第二轮检测方案。*
