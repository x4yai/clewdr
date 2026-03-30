# 第一轮 - 蓝队检测方案

> 编制方：model-family 安全团队
> 日期：2026-03-30
> 版本：v1.0
> 目标：设计第一代反向代理检测系统，覆盖 clewdr 及同类工具

---

## 总体架构

检测系统采用**多层置信度评分模型**，每条规则独立产出 0-100 的置信度分数，最终通过加权聚合得到综合风险分，超过阈值则触发处置动作。

```
┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│  网络层检测  │   │  请求层检测  │   │  行为层检测  │   │  认证层检测  │   │  统计层检测  │
│  权重: 0.25  │   │  权重: 0.30  │   │  权重: 0.20  │   │  权重: 0.15  │   │  权重: 0.10  │
└──────┬──────┘   └──────┬──────┘   └──────┬──────┘   └──────┬──────┘   └──────┬──────┘
       │                 │                 │                 │                 │
       └────────────┬────┴────────┬────────┴────────┬────────┘                 │
                    │             │                 │                          │
                    ▼             ▼                 ▼                          │
              ┌──────────────────────────────────────────┐                     │
              │        加权聚合引擎 (Scoring Engine)      │◄────────────────────┘
              │  final_score = Σ(layer_score × weight)   │
              └────────────────┬─────────────────────────┘
                               │
                    ┌──────────┴──────────┐
                    │   处置决策引擎       │
                    │  <50: 放行           │
                    │  50-70: 监控+限速    │
                    │  70-85: 二次验证     │
                    │  >85: 阻断+标记      │
                    └─────────────────────┘
```

---

## 一、网络层检测

### 1.1 TLS 指纹与 User-Agent 交叉验证 (NET-01)

**检测原理**

clewdr 使用 `wreq` 库的浏览器模拟（Chrome136/Chrome131/Edge127），但 User-Agent 声称是 `claude-code/2.1.86`（Bun 运行时 CLI 工具）。真实 Claude Code CLI 运行在 Bun 上，使用 BoringSSL，其 JA3/JA4 指纹与 Chromium 浏览器完全不同。

**检测规则**

```python
# NET-01: TLS-UA 交叉验证
def detect_tls_ua_mismatch(connection):
    ja4_fingerprint = connection.tls_info.ja4_hash
    user_agent = connection.headers.get("User-Agent", "")

    # 构建已知指纹数据库
    BROWSER_JA4_FAMILIES = load_ja4_browser_database()  # Chrome, Edge, Safari, Firefox
    CLI_JA4_FAMILIES = load_ja4_cli_database()           # Bun, Node.js, Python, curl

    ua_claims_cli = "claude-code/" in user_agent
    tls_is_browser = any(
        ja4_fingerprint in family for family in BROWSER_JA4_FAMILIES.values()
    )
    tls_is_cli = any(
        ja4_fingerprint in family for family in CLI_JA4_FAMILIES.values()
    )

    if ua_claims_cli and tls_is_browser:
        # UA 声称 CLI，但 TLS 指纹是浏览器 -> 高度可疑
        return Score(confidence=90, reason="TLS_UA_CROSS_MISMATCH",
                     detail=f"UA={user_agent}, JA4={ja4_fingerprint}")

    if ua_claims_cli and not tls_is_cli:
        # UA 声称 CLI，但 TLS 指纹未知 -> 中度可疑
        return Score(confidence=50, reason="TLS_UA_UNKNOWN_FINGERPRINT")

    return Score(confidence=0)
```

**预期效果**
- 检出率：85-95%（针对使用浏览器 TLS 模拟的 clewdr）
- 误报率：<1%（真实 CLI 的 TLS 不可能是浏览器指纹）
- 盲区：如果攻击者切换到非浏览器 TLS（如 rustls 默认配置），指纹不再是浏览器，此规则降级

### 1.2 TLS 指纹聚集度分析 (NET-02)

**检测原理**

clewdr 仅有 3 个浏览器模拟配置（Chrome136/131、Edge127），所有实例在全球范围内只会产出这 3 种 JA4 指纹。正常用户的 TLS 指纹分布应当呈长尾分布（数百种不同的浏览器小版本）。

**检测规则**

```python
# NET-02: JA4 指纹聚集度
class TLSFingerprintAggregator:
    def __init__(self):
        self.fingerprint_counts = Counter()  # 滑动窗口 1 小时
        self.total_requests = 0

    def analyze(self, ja4_hash):
        self.fingerprint_counts[ja4_hash] += 1
        self.total_requests += 1

        # 单一指纹占比过高
        max_ratio = max(self.fingerprint_counts.values()) / self.total_requests
        unique_count = len(self.fingerprint_counts)

        # 如果前3个指纹占了超过30%的流量，且样本足够
        top3_ratio = sum(sorted(self.fingerprint_counts.values(), reverse=True)[:3]) / self.total_requests

        if self.total_requests > 1000 and top3_ratio > 0.30:
            # 找出这些异常集中的指纹
            suspicious_fps = [
                fp for fp, count in self.fingerprint_counts.items()
                if count / self.total_requests > 0.08
            ]
            return Alert(
                level="medium",
                fingerprints=suspicious_fps,
                detail=f"Top-3 concentration: {top3_ratio:.1%}, unique: {unique_count}"
            )
        return None
```

**预期效果**
- 检出率：70%（作为辅助信号，非独立判断）
- 误报率：5%（某些企业出口可能也有指纹聚集）
- 需要足够的流量样本才有效，适合作为统计层信号

### 1.3 IP 行为分析 (NET-03)

**检测原理**

反向代理通常部署在 VPS/云服务器上，单个 IP 会关联大量不同的 session cookie。正常用户单 IP 通常只有 1-3 个活跃 session。

**检测规则**

```python
# NET-03: IP-Session 关联分析
class IPBehaviorAnalyzer:
    def __init__(self):
        # IP -> set of (session_cookie_hash, org_uuid) in sliding 1h window
        self.ip_sessions = defaultdict(set)
        # IP -> request timestamps for rate analysis
        self.ip_timestamps = defaultdict(list)

    def analyze(self, request):
        ip = request.remote_addr
        session_id = hash(request.cookie + request.org_uuid)
        now = time.time()

        self.ip_sessions[ip].add(session_id)
        self.ip_timestamps[ip].append(now)

        # 清理过期数据（保留 1 小时窗口）
        self.ip_timestamps[ip] = [
            t for t in self.ip_timestamps[ip] if now - t < 3600
        ]

        unique_sessions = len(self.ip_sessions[ip])
        request_count = len(self.ip_timestamps[ip])

        score = 0
        reasons = []

        # 单 IP 多 session（cookie 池特征）
        if unique_sessions > 5:
            score += 40
            reasons.append(f"ip_multi_session: {unique_sessions} sessions")
        elif unique_sessions > 3:
            score += 20
            reasons.append(f"ip_moderate_sessions: {unique_sessions}")

        # 单 IP 高频请求
        if request_count > 100:  # 1 小时内超过 100 次
            score += 30
            reasons.append(f"ip_high_rate: {request_count}/h")

        # 检查 IP 是否为已知云服务商
        if is_cloud_provider_ip(ip):  # ASN 查询: AWS, GCP, Azure, Hetzner...
            score += 15
            reasons.append("cloud_provider_ip")

        return Score(confidence=min(score, 95), reasons=reasons)
```

**预期效果**
- 检出率：60-75%（取决于代理部署方式）
- 误报率：3-8%（企业 NAT、VPN 出口可能触发）
- 局限：使用住宅代理的攻击者可以绕过

### 1.4 连接复用模式分析 (NET-04)

**检测原理**

clewdr 为每个 cookie 创建新的 `wreq::Client`（HTTP 客户端），导致频繁的 TLS 握手。而真实 Claude Code CLI 是单进程长驻应用，会维持持久连接。

```python
# NET-04: 连接生命周期分析
class ConnectionLifecycleAnalyzer:
    def analyze(self, token_id, connection_info):
        # 同一 token 频繁建立新 TLS 连接
        new_connections_per_hour = count_new_tls_handshakes(token_id, window="1h")
        avg_connection_duration = mean_connection_lifetime(token_id, window="1h")

        score = 0
        if new_connections_per_hour > 20:
            score += 30  # 频繁新建连接
        if avg_connection_duration < timedelta(seconds=30):
            score += 20  # 连接寿命过短

        # 真实 CLI 通常维持 keep-alive 连接数分钟
        if new_connections_per_hour > 50 and avg_connection_duration < timedelta(seconds=10):
            score += 30  # 极端模式

        return Score(confidence=min(score, 80))
```

**预期效果**
- 检出率：50-65%
- 误报率：5%（不稳定网络也可能频繁重连）

---

## 二、请求层检测

### 2.1 Billing Header 注入检测 (REQ-01)

**检测原理**

clewdr 将 `x-anthropic-billing-header` 作为 system prompt 的文本块注入消息体中，而非作为 HTTP 头发送。这是最显著的检测信号之一。

**检测规则**

```python
# REQ-01: Billing Header 注入 system prompt
def detect_billing_in_system_prompt(request_body):
    system = request_body.get("system", [])

    if isinstance(system, str):
        system_text = system
    elif isinstance(system, list):
        system_text = " ".join(
            item.get("text", "") if isinstance(item, dict) else str(item)
            for item in system
        )
    else:
        return Score(confidence=0)

    # 检查 system prompt 中是否包含 billing header 格式文本
    BILLING_PATTERN = re.compile(
        r"x-anthropic-billing-header:\s*cc_version=[\d.]+\.\w+;\s*cc_entrypoint=\w+;\s*cch=\w+;"
    )
    match = BILLING_PATTERN.search(system_text)

    if match:
        return Score(
            confidence=99,
            reason="BILLING_HEADER_IN_SYSTEM_PROMPT",
            detail=f"Found billing header text in system prompt: {match.group()}"
        )

    # 退化检测：检查 system prompt 是否包含已知的 billing 关键字模式
    PARTIAL_PATTERNS = [
        r"cc_version=\d+\.\d+\.\d+",
        r"cc_entrypoint=",
        r"cch=[0-9a-f]{5}",
    ]
    partial_hits = sum(
        1 for p in PARTIAL_PATTERNS if re.search(p, system_text)
    )
    if partial_hits >= 2:
        return Score(confidence=85, reason="PARTIAL_BILLING_IN_SYSTEM")

    return Score(confidence=0)
```

**预期效果**
- 检出率：99%（只要 billing header 在 system prompt 中就必然命中）
- 误报率：<0.01%（正常用户的 system prompt 不会有这种格式）
- 这是当前 clewdr 最大的检测面，几乎零误报

### 2.2 Billing Header 哈希校验 (REQ-02)

**检测原理**

即使攻击者将 billing header 移到 HTTP 头中，我们仍可校验其哈希是否由正确的 salt 和采样逻辑生成。billing header 格式为：
`cc_version=VERSION.HASH; cc_entrypoint=ENTRY; cch=VALUE;`

其中 HASH 由 `SHA256(salt + sampled_chars + version)` 的前 3 位十六进制组成。

```python
# REQ-02: Billing Header 哈希验证
CURRENT_BILLING_SALT = "59cf53e54c78"  # 与真实 CLI 同步的 salt

def verify_billing_header(request):
    billing = (
        request.headers.get("x-anthropic-billing-header") or
        extract_billing_from_system(request.body)  # 兼容注入方式
    )
    if not billing:
        return Score(confidence=0)

    parsed = parse_billing_header(billing)
    if not parsed:
        return Score(confidence=70, reason="MALFORMED_BILLING_HEADER")

    version = parsed["cc_version_base"]      # e.g., "2.1.86"
    claimed_hash = parsed["cc_version_hash"]  # e.g., "38b"
    entrypoint = parsed["cc_entrypoint"]
    cch = parsed["cch"]

    # 从请求体中提取第一条 user 消息
    first_user_text = get_first_user_message_text(request.body)

    # 服务端独立计算哈希
    # 采样位置 [4, 7, 20] 的 UTF-16 code units
    sampled = sample_js_code_units(first_user_text, [4, 7, 20])
    expected_hash = sha256(f"{CURRENT_BILLING_SALT}{sampled}{version}").hex()[:3]

    if claimed_hash != expected_hash:
        return Score(
            confidence=80,
            reason="BILLING_HASH_MISMATCH",
            detail=f"claimed={claimed_hash}, expected={expected_hash}"
        )

    # cch 值验证
    KNOWN_CCH_VALUES = get_valid_cch_for_version(version)
    if cch not in KNOWN_CCH_VALUES:
        return Score(confidence=60, reason="UNKNOWN_CCH_VALUE", detail=f"cch={cch}")

    # 版本号时效性检查
    if not is_version_current(version, tolerance_days=30):
        return Score(confidence=40, reason="STALE_VERSION", detail=f"version={version}")

    return Score(confidence=0)

def sample_js_code_units(text, indices):
    """模拟 JavaScript charCodeAt 行为，提取 UTF-16 code units"""
    utf16_units = text.encode("utf-16-le")
    result = ""
    for idx in indices:
        byte_offset = idx * 2
        if byte_offset + 1 < len(utf16_units):
            code_unit = int.from_bytes(utf16_units[byte_offset:byte_offset+2], "little")
            result += chr(code_unit)
        else:
            result += "0"
    return result
```

**预期效果**
- 检出率：70-85%（取决于攻击者是否正确实现了哈希逻辑）
- 误报率：2-5%（真实 CLI 版本升级时 salt 可能变化，需要同步）

### 2.3 Header 一致性校验 (REQ-03)

**检测原理**

clewdr 的请求头存在多处与真实 CLI 不一致的细节：
1. 在 Claude Code 模式下发送 `Origin` 和 `Referer`（真实 CLI 不发这些头）
2. 缺少 Claude Code 特有的遥测头
3. `anthropic-beta` 组合可能落后于真实 CLI 版本

```python
# REQ-03: Header 一致性校验
def detect_header_anomalies(request):
    headers = request.headers
    ua = headers.get("User-Agent", "")
    score = 0
    reasons = []

    if "claude-code/" in ua:
        # Claude Code CLI 模式的 header 校验

        # 规则 1: CLI 不应有 Origin/Referer 头指向 api.anthropic.com
        if headers.get("Origin") == "https://api.anthropic.com/":
            score += 25
            reasons.append("cli_has_origin_header")
        if "Referer" in headers and "api.anthropic.com" in headers["Referer"]:
            score += 25
            reasons.append("cli_has_referer_header")

        # 规则 2: 检查 cc_entrypoint 值
        billing = headers.get("x-anthropic-billing-header", "")
        if "cc_entrypoint=unknown" in billing:
            score += 30
            reasons.append("unknown_entrypoint")

        # 规则 3: anthropic-beta 组合与版本号一致性
        beta = headers.get("anthropic-beta", "")
        version = extract_version_from_ua(ua)
        expected_betas = get_expected_betas_for_version(version)
        if expected_betas and set(beta.split(",")) != expected_betas:
            score += 20
            reasons.append("beta_version_mismatch")

        # 规则 4: 缺少真实 CLI 的特征头
        # 真实 CLI 可能包含 x-stainless-* 头或其他 SDK 头
        expected_cli_headers = ["x-stainless-lang", "x-stainless-package-version"]
        missing = [h for h in expected_cli_headers if h not in headers]
        if missing:
            score += 15
            reasons.append(f"missing_cli_headers: {missing}")

    elif is_browser_ua(ua):
        # 浏览器模式（Claude Web）的 header 校验

        # 规则 5: 浏览器应有 Sec-* 头
        SEC_HEADERS = ["Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest",
                       "Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform"]
        missing_sec = [h for h in SEC_HEADERS if h not in headers]
        if len(missing_sec) > 3:
            score += 40
            reasons.append(f"missing_browser_sec_headers: {len(missing_sec)}/6")
        elif len(missing_sec) > 0:
            score += 15
            reasons.append(f"partial_missing_sec_headers: {len(missing_sec)}/6")

        # 规则 6: Sec-Ch-Ua 应与 TLS 指纹的浏览器版本一致
        sec_ch_ua = headers.get("Sec-Ch-Ua", "")
        if sec_ch_ua:
            claimed_browser_version = parse_sec_ch_ua_version(sec_ch_ua)
            tls_browser_version = infer_browser_from_ja4(request.tls_info.ja4_hash)
            if claimed_browser_version != tls_browser_version:
                score += 30
                reasons.append("sec_ch_ua_tls_mismatch")

    return Score(confidence=min(score, 95), reasons=reasons)
```

**预期效果**
- 检出率：75-90%
- 误报率：3-5%（部分正常用户可能使用自定义 HTTP 客户端）

### 2.4 请求体结构分析 (REQ-04)

**检测原理**

clewdr 的请求预处理会对消息体做多种修改（消毒、参数移除、system prompt 注入），留下与正常请求不同的结构特征。

```python
# REQ-04: 请求体结构异常
def detect_body_anomalies(request_body):
    score = 0
    reasons = []

    system = request_body.get("system", [])
    messages = request_body.get("messages", [])

    # 规则 1: system prompt 第一个块是 billing header 文本
    if isinstance(system, list) and len(system) > 0:
        first_block = system[0]
        if isinstance(first_block, dict) and first_block.get("type") == "text":
            text = first_block.get("text", "")
            if text.startswith("x-anthropic-billing-header:"):
                return Score(confidence=99, reason="BILLING_AS_FIRST_SYSTEM_BLOCK")

    # 规则 2: 消息中存在前后空白被异常去除的模式
    # （正常用户的消息通常带有自然的空白）
    all_text_blocks = extract_all_text_content(messages)
    trimmed_ratio = sum(1 for t in all_text_blocks if t == t.strip()) / max(len(all_text_blocks), 1)
    if len(all_text_blocks) > 5 and trimmed_ratio == 1.0:
        score += 10  # 弱信号
        reasons.append("all_messages_perfectly_trimmed")

    # 规则 3: temperature 有值但 top_p 为 None（可能被代理移除）
    if request_body.get("temperature") is not None and request_body.get("top_p") is None:
        # 这本身是合法的，只做弱记录
        pass

    # 规则 4: 模型名称含异常后缀（-1M, -thinking）
    model = request_body.get("model", "")
    if model.endswith("-1M"):
        score += 5  # 仅弱信号，真实用户也可能用
        reasons.append("model_1m_suffix")

    return Score(confidence=min(score, 60), reasons=reasons)
```

**预期效果**
- 检出率：40-60%（大部分信号较弱，需要与其他层配合）
- 误报率：5-10%

### 2.5 Billing Header 存在性与位置检测 (REQ-05)

**检测原理**

真实的 Claude Code CLI 将 `x-anthropic-billing-header` 作为 HTTP 头发送。如果它同时出现在 HTTP 头和 system prompt 中，或者只出现在 system prompt 中，则是代理的明确信号。

```python
# REQ-05: Billing Header 位置检测
def detect_billing_location(request):
    in_header = "x-anthropic-billing-header" in request.headers
    in_system = has_billing_in_system_prompt(request.body)

    if in_system and not in_header:
        # 仅在 system prompt 中 -> 代理（当前 clewdr 行为）
        return Score(confidence=99, reason="BILLING_ONLY_IN_SYSTEM_PROMPT")

    if in_system and in_header:
        # 两处都有 -> 异常
        return Score(confidence=90, reason="BILLING_IN_BOTH_LOCATIONS")

    if not in_header and not in_system:
        # 完全缺失 -> 可能是旧版或非 Claude Code 客户端
        ua = request.headers.get("User-Agent", "")
        if "claude-code/" in ua:
            return Score(confidence=50, reason="BILLING_MISSING_FOR_CLI")

    return Score(confidence=0)
```

**预期效果**
- 检出率：99%（当前 clewdr 版本必然命中）
- 误报率：<0.01%

---

## 三、行为层检测

### 3.1 对话生命周期异常检测 (BEH-01)

**检测原理**

clewdr 的 Claude Web 模式在每次请求时：创建对话 -> 发送消息 -> 接收回复 -> 删除对话。整个过程在几秒内完成。对话名称格式为 `ClewdR-YYYY-MM-DD HH:MM:SS`。

```python
# BEH-01: 对话生命周期分析
class ConversationLifecycleDetector:
    def __init__(self):
        # conv_uuid -> {created_at, message_count, deleted_at}
        self.conversations = {}

    def on_conversation_create(self, conv_uuid, name, user_id):
        self.conversations[conv_uuid] = {
            "created_at": time.time(),
            "name": name,
            "user_id": user_id,
            "message_count": 0,
            "deleted_at": None,
        }
        score = 0
        reasons = []

        # 检测对话名称
        if name and name.startswith("ClewdR-"):
            return Score(confidence=99, reason="CLEWDR_CONVERSATION_NAME",
                         detail=f"name={name}")

        # 检测对话名称是否符合 UTC 时间戳格式
        TIMESTAMP_PATTERN = re.compile(r"^\w+-\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")
        if name and TIMESTAMP_PATTERN.match(name):
            score += 30
            reasons.append("timestamp_conversation_name")

        return Score(confidence=score, reasons=reasons)

    def on_conversation_delete(self, conv_uuid, user_id):
        conv = self.conversations.get(conv_uuid)
        if not conv:
            return Score(confidence=0)

        lifetime = time.time() - conv["created_at"]
        conv["deleted_at"] = time.time()

        score = 0
        reasons = []

        # 对话存活时间极短（< 60 秒）
        if lifetime < 60:
            score += 40
            reasons.append(f"ultra_short_conversation: {lifetime:.1f}s")
        elif lifetime < 300:
            score += 20
            reasons.append(f"short_conversation: {lifetime:.1f}s")

        # 对话仅有 1 轮消息就被删除
        if conv["message_count"] <= 1:
            score += 30
            reasons.append(f"single_turn_deleted: {conv['message_count']} msgs")

        # 统计用户的短命对话频率
        user_convs = [
            c for c in self.conversations.values()
            if c["user_id"] == user_id and c["deleted_at"]
        ]
        short_ratio = sum(1 for c in user_convs if (c["deleted_at"] - c["created_at"]) < 120) / max(len(user_convs), 1)
        if len(user_convs) > 5 and short_ratio > 0.8:
            score += 30
            reasons.append(f"high_short_conv_ratio: {short_ratio:.0%}")

        return Score(confidence=min(score, 95), reasons=reasons)
```

**预期效果**
- 检出率：85-95%（对 Claude Web 模式的 clewdr 极为有效）
- 误报率：2%（极少数正常用户会快速创建删除对话）
- 局限：不适用于 Claude Code API 模式（无对话管理）

### 3.2 请求频率与时间模式 (BEH-02)

**检测原理**

代理的请求模式具有机器特征：固定间隔、高频突发、缺少人类操作的自然间歇。

```python
# BEH-02: 请求时间模式分析
class RequestTimingAnalyzer:
    def __init__(self):
        self.user_request_times = defaultdict(list)  # user_id -> [timestamp]

    def analyze(self, user_id, timestamp):
        times = self.user_request_times[user_id]
        times.append(timestamp)

        # 保留最近 2 小时
        cutoff = timestamp - 7200
        times[:] = [t for t in times if t > cutoff]

        if len(times) < 10:
            return Score(confidence=0)

        score = 0
        reasons = []

        # 计算请求间隔的统计特征
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
        mean_interval = statistics.mean(intervals)
        std_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0

        # 规则 1: 高频请求（平均间隔 < 30 秒）
        if mean_interval < 30:
            score += 30
            reasons.append(f"high_frequency: mean_interval={mean_interval:.1f}s")

        # 规则 2: 间隔过于规律（变异系数 < 0.3 表示机器行为）
        cv = std_interval / mean_interval if mean_interval > 0 else 0
        if cv < 0.3 and len(intervals) > 20:
            score += 25
            reasons.append(f"regular_timing: cv={cv:.2f}")

        # 规则 3: 24 小时不间断活动（正常用户有睡眠周期）
        hour_distribution = Counter(
            datetime.fromtimestamp(t).hour for t in times
        )
        active_hours = len(hour_distribution)
        if active_hours > 20 and len(times) > 50:
            score += 30
            reasons.append(f"24h_activity: {active_hours} hours active")

        # 规则 4: 无"阅读时间"——请求后几乎立即发下一个请求
        # 正常用户阅读回复需要时间
        instant_followups = sum(1 for i in intervals if i < 5)
        if instant_followups / len(intervals) > 0.5:
            score += 20
            reasons.append("no_reading_time")

        return Score(confidence=min(score, 90), reasons=reasons)
```

**预期效果**
- 检出率：60-75%
- 误报率：5-10%（CI/CD 管道中的合法自动化可能触发）

### 3.3 缺失的伴随流量检测 (BEH-03)

**检测原理**

真实的 Claude Code CLI 除了聊天 API 调用外，还会产生遥测、心跳、文件上下文同步等"伴随流量"。clewdr 只产生纯粹的 API 调用。

```python
# BEH-03: 伴随流量缺失检测
class CompanionTrafficDetector:
    # 已知的 Claude Code CLI 会调用的端点
    EXPECTED_ENDPOINTS = {
        "chat": "/v1/messages",
        "count_tokens": "/v1/messages/count_tokens",
        "telemetry": "/v1/telemetry",
        "usage": "/api/oauth/usage",
        "heartbeat": "/api/heartbeat",
    }

    def __init__(self):
        # token -> set of endpoint categories
        self.token_endpoints = defaultdict(lambda: defaultdict(int))

    def record(self, token_id, endpoint):
        category = self.categorize_endpoint(endpoint)
        self.token_endpoints[token_id][category] += 1

    def analyze(self, token_id):
        endpoints = self.token_endpoints[token_id]
        total_requests = sum(endpoints.values())

        if total_requests < 5:
            return Score(confidence=0)

        score = 0
        reasons = []

        # 只有聊天请求，没有任何其他活动
        chat_ratio = endpoints.get("chat", 0) / total_requests
        has_telemetry = endpoints.get("telemetry", 0) > 0
        has_heartbeat = endpoints.get("heartbeat", 0) > 0

        if chat_ratio > 0.95 and total_requests > 10:
            score += 35
            reasons.append(f"chat_only: {chat_ratio:.0%}")

        if not has_telemetry and total_requests > 20:
            score += 25
            reasons.append("no_telemetry")

        if not has_heartbeat and total_requests > 20:
            score += 20
            reasons.append("no_heartbeat")

        # Chat 与 count_tokens 的比例异常
        # 真实 CLI 通常每次聊天前都调用 count_tokens
        chat_count = endpoints.get("chat", 0)
        tokens_count = endpoints.get("count_tokens", 0)
        if chat_count > 5 and tokens_count == 0:
            score += 15
            reasons.append("no_count_tokens_calls")

        return Score(confidence=min(score, 85), reasons=reasons)
```

**预期效果**
- 检出率：70-80%
- 误报率：5%（部分正规自动化集成可能只调用聊天 API）

### 3.4 重试与探测模式检测 (BEH-04)

**检测原理**

clewdr 有两个特征性的重试模式：
1. 1M 上下文探测：先发含 `context-1m-*` beta 头的请求，失败后立即重发不含该头的请求
2. 固定 30 分钟 OAuth 限速冷却

```python
# BEH-04: 重试/探测模式检测
class RetryPatternDetector:
    def __init__(self):
        self.recent_requests = defaultdict(list)  # token -> [(timestamp, beta_header, status)]

    def record(self, token_id, timestamp, beta_header, response_status):
        self.recent_requests[token_id].append({
            "ts": timestamp,
            "beta": beta_header,
            "status": response_status,
        })

    def analyze(self, token_id):
        requests = self.recent_requests[token_id]
        if len(requests) < 2:
            return Score(confidence=0)

        score = 0
        reasons = []

        # 规则 1: 1M 探测模式
        # 特征：请求A(含1M beta, 400/403/429) -> 请求B(不含1M beta, 200)，间隔 < 5秒
        for i in range(len(requests) - 1):
            a, b = requests[i], requests[i + 1]
            a_has_1m = "context-1m" in a["beta"]
            b_has_1m = "context-1m" in b["beta"]
            a_failed = a["status"] in (400, 403, 429)
            interval = b["ts"] - a["ts"]

            if a_has_1m and not b_has_1m and a_failed and interval < 5:
                score += 40
                reasons.append(f"1m_probe_pattern: interval={interval:.1f}s")
                break

        # 规则 2: OAuth 冷却后精确恢复
        # 特征：429 -> 精确 30 分钟后恢复活动
        rate_limited = [r for r in requests if r["status"] == 429]
        for rl in rate_limited:
            recovery = [
                r for r in requests
                if r["ts"] > rl["ts"] and r["status"] == 200
            ]
            if recovery:
                gap = recovery[0]["ts"] - rl["ts"]
                if 1750 < gap < 1850:  # 约 30 分钟 +/- 50 秒
                    score += 30
                    reasons.append(f"precise_30min_recovery: gap={gap:.0f}s")

        return Score(confidence=min(score, 85), reasons=reasons)
```

**预期效果**
- 检出率：55-70%（仅对有探测行为的会话有效）
- 误报率：2%

---

## 四、认证层检测

### 4.1 OAuth Client ID 监控 (AUTH-01)

**检测原理**

clewdr 硬编码了 OAuth Client ID `9d1c250a-e61b-44d9-88ed-5944d1962f5e`。所有默认配置的 clewdr 实例共享同一个 Client ID。

```python
# AUTH-01: Client ID 异常监控
class ClientIDMonitor:
    def __init__(self):
        self.client_id_stats = defaultdict(lambda: {
            "tokens": set(),
            "ips": set(),
            "orgs": set(),
            "request_count": 0,
            "first_seen": None,
            "last_seen": None,
        })

    def record(self, client_id, token_id, ip, org_id):
        stats = self.client_id_stats[client_id]
        stats["tokens"].add(token_id)
        stats["ips"].add(ip)
        stats["orgs"].add(org_id)
        stats["request_count"] += 1
        now = time.time()
        if not stats["first_seen"]:
            stats["first_seen"] = now
        stats["last_seen"] = now

    def analyze(self, client_id):
        stats = self.client_id_stats[client_id]
        score = 0
        reasons = []

        # 规则 1: 单个 client_id 关联过多唯一 token
        unique_tokens = len(stats["tokens"])
        if unique_tokens > 50:
            score += 40
            reasons.append(f"excessive_tokens: {unique_tokens}")
        elif unique_tokens > 20:
            score += 20
            reasons.append(f"many_tokens: {unique_tokens}")

        # 规则 2: 单个 client_id 来自过多不同 IP
        unique_ips = len(stats["ips"])
        if unique_ips > 100:
            score += 35
            reasons.append(f"excessive_ips: {unique_ips}")
        elif unique_ips > 30:
            score += 15
            reasons.append(f"many_ips: {unique_ips}")

        # 规则 3: 单个 client_id 跨越过多组织
        unique_orgs = len(stats["orgs"])
        if unique_orgs > 10:
            score += 30
            reasons.append(f"cross_org: {unique_orgs} orgs")

        # 规则 4: 已知的 clewdr 默认 client_id
        KNOWN_PROXY_CLIENT_IDS = {
            "9d1c250a-e61b-44d9-88ed-5944d1962f5e",  # clewdr default
        }
        if client_id in KNOWN_PROXY_CLIENT_IDS:
            score = 99
            reasons = ["KNOWN_PROXY_CLIENT_ID"]

        return Score(confidence=min(score, 99), reasons=reasons)
```

**预期效果**
- 检出率：95%（使用默认 Client ID 的实例直接命中黑名单）
- 误报率：<0.1%（误加入黑名单可修正）
- 盲区：如果攻击者使用自定义 Client ID（clewdr 已支持此配置），此规则退化为统计分析

### 4.2 OAuth Token 活跃度分析 (AUTH-02)

**检测原理**

clewdr 的 OAuth 流程具有特征性行为：
1. 使用 cookie 直接调用 authorize 端点获取 code（无浏览器交互）
2. 频繁刷新 token
3. 刷新失败后立即执行完整的重新授权流程

```python
# AUTH-02: OAuth Token 活跃度
class TokenActivityAnalyzer:
    def __init__(self):
        self.token_events = defaultdict(list)  # token -> [{event_type, timestamp}]

    def record_event(self, token_id, event_type, timestamp):
        """event_type: 'authorize', 'token_exchange', 'refresh', 'refresh_fail', 'reauthorize'"""
        self.token_events[token_id].append({
            "type": event_type,
            "ts": timestamp,
        })

    def analyze(self, token_id):
        events = self.token_events[token_id]
        if len(events) < 3:
            return Score(confidence=0)

        score = 0
        reasons = []

        # 规则 1: 授权流程无人类交互
        # authorize -> token_exchange 间隔 < 2 秒 (正常浏览器 OAuth 至少几秒)
        auth_events = [e for e in events if e["type"] == "authorize"]
        exchange_events = [e for e in events if e["type"] == "token_exchange"]
        for auth in auth_events:
            matching_exchange = [
                ex for ex in exchange_events
                if 0 < ex["ts"] - auth["ts"] < 2
            ]
            if matching_exchange:
                gap = matching_exchange[0]["ts"] - auth["ts"]
                score += 35
                reasons.append(f"instant_oauth: authorize->exchange in {gap:.2f}s")
                break

        # 规则 2: refresh 失败后立即 reauthorize（clewdr 特征行为）
        for i in range(len(events) - 1):
            if events[i]["type"] == "refresh_fail" and events[i+1]["type"] == "reauthorize":
                gap = events[i+1]["ts"] - events[i]["ts"]
                if gap < 5:
                    score += 30
                    reasons.append(f"instant_reauth_after_refresh_fail: {gap:.1f}s")
                    break

        # 规则 3: 频繁的 token refresh
        refresh_count = sum(1 for e in events if e["type"] == "refresh")
        window = events[-1]["ts"] - events[0]["ts"]
        if window > 0:
            refreshes_per_hour = refresh_count / (window / 3600)
            if refreshes_per_hour > 10:
                score += 25
                reasons.append(f"excessive_refresh: {refreshes_per_hour:.1f}/h")

        return Score(confidence=min(score, 90), reasons=reasons)
```

**预期效果**
- 检出率：65-80%
- 误报率：3%

### 4.3 Cookie 共享与轮换检测 (AUTH-03)

**检测原理**

clewdr 维护一个 cookie 池（CookieActorHandle），多个请求轮换使用不同 cookie。通过 `system_prompt_hash` 实现缓存亲和性。

```python
# AUTH-03: Cookie 轮换模式
class CookieRotationDetector:
    def __init__(self):
        # ip -> list of (cookie_hash, timestamp)
        self.ip_cookies = defaultdict(list)

    def analyze(self, ip, cookie_hash, timestamp):
        history = self.ip_cookies[ip]
        history.append((cookie_hash, timestamp))

        # 保留 1 小时窗口
        history[:] = [(c, t) for c, t in history if timestamp - t < 3600]

        unique_cookies = len(set(c for c, _ in history))

        score = 0
        reasons = []

        # 规则 1: 同 IP 短时间内使用多个不同 cookie
        if unique_cookies > 3:
            score += 40
            reasons.append(f"cookie_rotation: {unique_cookies} cookies from same IP")

        # 规则 2: cookie 之间的切换频率
        switches = sum(
            1 for i in range(len(history) - 1)
            if history[i][0] != history[i + 1][0]
        )
        switch_rate = switches / max(len(history) - 1, 1)
        if switch_rate > 0.5 and len(history) > 10:
            score += 30
            reasons.append(f"frequent_cookie_switching: rate={switch_rate:.2f}")

        # 规则 3: 同一 cookie 从多个不同 IP 使用
        # (需要跨 IP 聚合 -- 由统计层完成)

        return Score(confidence=min(score, 85), reasons=reasons)
```

**预期效果**
- 检出率：60-75%
- 误报率：5%（企业多出口可能触发）

---

## 五、统计层检测

### 5.1 跨请求关联引擎 (STAT-01)

**检测原理**

单个请求的异常可能不足以下结论，但跨请求的关联分析可以大幅提高置信度。

```python
# STAT-01: 跨请求关联
class CrossRequestCorrelator:
    def __init__(self):
        self.entity_scores = defaultdict(lambda: {
            "scores": [],
            "ip_set": set(),
            "cookie_set": set(),
            "token_set": set(),
            "request_count": 0,
        })

    def add_score(self, entity_id, entity_type, score, request_meta):
        """
        entity_id: IP, cookie hash, token, or client_id
        entity_type: 'ip', 'cookie', 'token', 'client_id'
        """
        data = self.entity_scores[(entity_id, entity_type)]
        data["scores"].append(score)
        data["ip_set"].add(request_meta.ip)
        data["cookie_set"].add(request_meta.cookie_hash)
        data["token_set"].add(request_meta.token_id)
        data["request_count"] += 1

    def correlate(self, entity_id, entity_type):
        data = self.entity_scores[(entity_id, entity_type)]
        if data["request_count"] < 5:
            return None

        scores = data["scores"]
        avg_score = statistics.mean(scores)
        max_score = max(scores)

        # 滑动窗口平均分超阈值的频率
        high_score_ratio = sum(1 for s in scores if s > 50) / len(scores)

        # 关联强度
        correlation_score = 0

        if avg_score > 60:
            correlation_score += 30
        elif avg_score > 40:
            correlation_score += 15

        if high_score_ratio > 0.5:
            correlation_score += 25

        if max_score > 85:
            correlation_score += 20

        # 扩散分析：同一实体关联了多少其他可疑实体
        related_entities = set()
        for ip in data["ip_set"]:
            ip_data = self.entity_scores.get((ip, "ip"))
            if ip_data and statistics.mean(ip_data["scores"]) > 50:
                related_entities.add(ip)
        for cookie in data["cookie_set"]:
            cookie_data = self.entity_scores.get((cookie, "cookie"))
            if cookie_data and statistics.mean(cookie_data["scores"]) > 50:
                related_entities.add(cookie)

        if len(related_entities) > 3:
            correlation_score += 25

        return CorrelationResult(
            entity_id=entity_id,
            entity_type=entity_type,
            correlation_score=min(correlation_score, 95),
            avg_score=avg_score,
            request_count=data["request_count"],
            related_suspicious=len(related_entities),
        )
```

### 5.2 异常聚合与趋势分析 (STAT-02)

```python
# STAT-02: 全局异常聚合
class AnomalyAggregator:
    """
    每小时运行一次，分析全局流量中的代理集群特征。
    """
    def aggregate(self, all_requests_last_hour):
        results = {}

        # 维度 1: 按 JA4 指纹聚合
        ja4_groups = defaultdict(list)
        for req in all_requests_last_hour:
            ja4_groups[req.ja4_hash].append(req)

        for ja4, requests in ja4_groups.items():
            if len(requests) < 10:
                continue
            # 计算该指纹组的平均风险分
            avg_risk = statistics.mean(r.risk_score for r in requests)
            unique_ips = len(set(r.ip for r in requests))
            unique_cookies = len(set(r.cookie_hash for r in requests))

            if avg_risk > 50 and unique_cookies > 5:
                results[f"ja4:{ja4}"] = {
                    "type": "tls_cluster",
                    "avg_risk": avg_risk,
                    "requests": len(requests),
                    "unique_ips": unique_ips,
                    "unique_cookies": unique_cookies,
                    "action": "escalate" if avg_risk > 70 else "monitor",
                }

        # 维度 2: 按 client_id 聚合
        client_groups = defaultdict(list)
        for req in all_requests_last_hour:
            if req.client_id:
                client_groups[req.client_id].append(req)

        for cid, requests in client_groups.items():
            unique_tokens = len(set(r.token_id for r in requests))
            unique_ips = len(set(r.ip for r in requests))

            # 异常比例：token 数远大于 IP 数（cookie 池特征）
            if unique_tokens > 10 and unique_tokens > unique_ips * 3:
                results[f"client_id:{cid}"] = {
                    "type": "token_pool",
                    "unique_tokens": unique_tokens,
                    "unique_ips": unique_ips,
                    "ratio": unique_tokens / max(unique_ips, 1),
                    "action": "investigate",
                }

        # 维度 3: 按 billing header 的 cch 值聚合
        cch_groups = defaultdict(int)
        for req in all_requests_last_hour:
            cch = extract_cch(req)
            if cch:
                cch_groups[cch] += 1

        total_with_cch = sum(cch_groups.values())
        for cch, count in cch_groups.items():
            ratio = count / max(total_with_cch, 1)
            # 如果单个 cch 值占比异常高
            if ratio > 0.3 and count > 100:
                results[f"cch:{cch}"] = {
                    "type": "shared_cch",
                    "count": count,
                    "ratio": ratio,
                    "action": "blacklist_cch",
                }

        return results
```

### 5.3 机器学习特征提取 (STAT-03)

```python
# STAT-03: ML 特征向量提取（供离线训练和在线推理使用）
def extract_ml_features(request, session_history):
    """
    为每个请求提取特征向量，供 gradient boosting 模型使用。
    """
    features = {}

    # --- 网络层特征 ---
    features["ja4_hash_encoded"] = hash_encode(request.ja4_hash)  # embedding
    features["is_cloud_ip"] = int(is_cloud_provider_ip(request.ip))
    features["ip_asn_encoded"] = hash_encode(request.ip_asn)
    features["tls_ua_match"] = int(tls_matches_ua(request))

    # --- 请求层特征 ---
    features["has_billing_in_system"] = int(has_billing_in_system_prompt(request.body))
    features["has_billing_in_header"] = int("x-anthropic-billing-header" in request.headers)
    features["missing_sec_headers_count"] = count_missing_sec_headers(request.headers)
    features["has_origin_header"] = int("Origin" in request.headers)
    features["has_referer_header"] = int("Referer" in request.headers)
    features["ua_version_age_days"] = ua_version_age(request.headers.get("User-Agent", ""))
    features["system_prompt_block_count"] = count_system_blocks(request.body)
    features["entrypoint_is_unknown"] = int("cc_entrypoint=unknown" in str(request.headers))
    features["model_has_1m_suffix"] = int(request.body.get("model", "").endswith("-1M"))

    # --- 行为层特征 (会话级) ---
    features["session_request_count"] = len(session_history)
    features["mean_request_interval"] = mean_interval(session_history)
    features["cv_request_interval"] = cv_interval(session_history)  # 变异系数
    features["active_hours_24h"] = count_active_hours(session_history)
    features["chat_only_ratio"] = chat_endpoint_ratio(session_history)
    features["has_telemetry_traffic"] = int(any_telemetry(session_history))

    # --- 认证层特征 ---
    features["client_id_token_count"] = client_id_unique_tokens(request.client_id)
    features["client_id_ip_count"] = client_id_unique_ips(request.client_id)
    features["token_refresh_rate_per_hour"] = token_refresh_rate(request.token_id)
    features["oauth_latency_seconds"] = oauth_flow_latency(request.token_id)
    features["cookies_from_same_ip"] = cookies_from_ip(request.ip)

    # --- 对话层特征 (仅 Claude Web) ---
    features["conv_lifetime_seconds"] = conv_lifetime(request)
    features["conv_name_is_timestamp"] = int(is_timestamp_name(request))
    features["conv_single_turn_ratio"] = single_turn_ratio(session_history)

    return features

# 模型训练伪代码
def train_detector_model():
    # 使用标注数据训练 LightGBM
    import lightgbm as lgb

    X_train, y_train = load_labeled_data()  # y: 0=正常, 1=代理
    model = lgb.LGBMClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        class_weight="balanced",  # 处理不平衡数据
    )
    model.fit(X_train, y_train)
    return model
```

**预期效果**
- 检出率：80-90%（在充足标注数据下）
- 误报率：1-3%（通过阈值调节）
- 需要至少数周的标注数据积累

---

## 综合评分模型

### 最终风险分计算

```python
class ProxyDetectionEngine:
    LAYER_WEIGHTS = {
        "network": 0.25,
        "request": 0.30,
        "behavior": 0.20,
        "auth": 0.15,
        "stats": 0.10,
    }

    # 每层取该层内所有规则的最高分（max-pool），再加权聚合
    def calculate_final_score(self, request, session):
        layer_scores = {}

        # 网络层
        net_scores = [
            self.net01_tls_ua_mismatch(request),
            self.net02_tls_clustering(request),
            self.net03_ip_behavior(request),
            self.net04_connection_lifecycle(request),
        ]
        layer_scores["network"] = max(s.confidence for s in net_scores)

        # 请求层
        req_scores = [
            self.req01_billing_in_system(request),
            self.req02_billing_hash(request),
            self.req03_header_consistency(request),
            self.req04_body_anomalies(request),
            self.req05_billing_location(request),
        ]
        layer_scores["request"] = max(s.confidence for s in req_scores)

        # 行为层
        beh_scores = [
            self.beh01_conv_lifecycle(request, session),
            self.beh02_request_timing(request, session),
            self.beh03_companion_traffic(request, session),
            self.beh04_retry_patterns(request, session),
        ]
        layer_scores["behavior"] = max(s.confidence for s in beh_scores)

        # 认证层
        auth_scores = [
            self.auth01_client_id(request),
            self.auth02_token_activity(request, session),
            self.auth03_cookie_rotation(request, session),
        ]
        layer_scores["auth"] = max(s.confidence for s in auth_scores)

        # 统计层
        stat_score = self.ml_model_predict(request, session)
        layer_scores["stats"] = stat_score

        # 加权聚合
        final_score = sum(
            layer_scores[layer] * weight
            for layer, weight in self.LAYER_WEIGHTS.items()
        )

        # 硬规则覆盖：某些信号置信度极高，直接拉满
        HARD_RULES = [
            ("REQ-01", req_scores),   # billing 注入 system prompt
            ("REQ-05", req_scores),   # billing 位置异常
            ("AUTH-01", auth_scores), # 已知代理 Client ID
            ("BEH-01", beh_scores),   # ClewdR 对话名称
        ]
        for rule_name, scores in HARD_RULES:
            for s in scores:
                if s.confidence >= 95:
                    final_score = max(final_score, 95)

        return FinalVerdict(
            score=final_score,
            layer_scores=layer_scores,
            all_signals=[s for group in [net_scores, req_scores, beh_scores, auth_scores] for s in group],
        )

    def decide_action(self, verdict):
        score = verdict.score
        if score < 50:
            return Action.ALLOW
        elif score < 70:
            return Action.MONITOR_AND_RATE_LIMIT
        elif score < 85:
            return Action.CHALLENGE  # 要求二次验证
        else:
            return Action.BLOCK_AND_FLAG
```

### 处置动作详情

| 分数区间 | 动作 | 具体措施 |
|----------|------|----------|
| 0-49 | ALLOW | 正常放行，记录基础指标 |
| 50-69 | MONITOR_AND_RATE_LIMIT | 降低速率限制（如 50% 的正常额度），持续监控，收集更多信号 |
| 70-84 | CHALLENGE | 触发验证挑战（如要求重新 OAuth 授权、CAPTCHA），暂停服务直到通过 |
| 85-100 | BLOCK_AND_FLAG | 立即阻断请求，标记关联的 token/cookie/IP，通知安全团队人工审核 |

---

## 自评

### 预期整体检出率

| 场景 | 预期检出率 |
|------|-----------|
| 默认配置的 clewdr (当前版本) | **95-99%** |
| 修复了 billing 注入的 clewdr | **75-85%** |
| 修复了 billing + 自定义 Client ID 的 clewdr | **60-75%** |
| 全面优化的 clewdr (TLS/billing/ClientID/遥测全部修复) | **30-50%** |

### 预期误报率

| 用户群体 | 预期误报率 |
|----------|-----------|
| 普通个人用户 (浏览器/CLI) | **< 1%** |
| 企业用户 (NAT/VPN 出口) | **3-5%** |
| 合法自动化集成 (CI/CD) | **5-10%** |
| 整体加权误报率 | **~2%** |

### 最大盲区

1. **全面模拟的高级攻击者**：如果攻击者修复了 TLS 指纹（使用 Bun 运行时或模拟其指纹）、将 billing header 移到 HTTP 头中正确发送、使用自提取的 Client ID、添加遥测心跳模拟，则网络层和请求层检测大幅失效，只剩行为层和统计层提供弱信号。预计检出率降至 30-50%。

2. **低频单 cookie 使用**：如果攻击者只使用一个 cookie、低频请求（模拟人类节奏），则 IP 分析、cookie 轮换检测、频率分析全部失效。这类流量几乎无法与正常用户区分。

3. **住宅代理网络**：如果攻击者通过住宅代理池发出请求，每个请求来自不同的住宅 IP，则 IP 行为分析和云服务商检测全部失效。

4. **伴随流量模拟的代价**：如果攻击者成功模拟了遥测和心跳流量（格式正确、频率合理），BEH-03 检测完全失效。但这需要逆向分析真实 CLI 的遥测协议，门槛较高。

5. **ML 模型冷启动**：统计层的 ML 模型需要标注数据训练，在部署初期无法发挥作用。前期完全依赖规则引擎。

### 维护成本

- 每次 Claude Code CLI 版本更新需要同步更新：已知 Client ID、beta 头组合、billing salt、cch 值、UA 版本
- TLS 指纹数据库需要定期更新（新浏览器版本发布时）
- ML 模型需要定期用新标注数据重训练（建议每月一次）
- 误报反馈需要人工审核并纳入训练集

---

*文档结束*
