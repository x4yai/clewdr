# 第二轮 - 蓝队加固方案

> 编制方：model-family 安全团队
> 日期：2026-03-30
> 版本：v2.0
> 前提假设：红队已完成第一阶段修复（billing header 移至 HTTP 头、ClewdR 命名移除、entrypoint 合理化、测试拦截移除）

---

## 一、对红队第 1 轮方案的逐项分析

### 1.1 红队已修复项与我方失效规则

| 红队修复项 | 我方失效规则 | 影响评估 |
|------------|-------------|---------|
| Billing header 从 system prompt 移至 HTTP 头 | REQ-01 (confidence=99), REQ-05 (confidence=99) | **致命** -- 两条最强硬规则完全失效 |
| 移除 ClewdR 对话命名 | BEH-01 的名称子规则 | **严重** -- 该规则的核心检测逻辑失效 |
| Entrypoint 智能选择 | REQ-03 规则 2 (cc_entrypoint=unknown) | **完全规避** |
| 移除测试消息拦截 | 简单 Canary 探测失效 | 需要升级为更隐蔽的主动探测 |
| Cookie-IP 绑定 | AUTH-03 同 IP 多 cookie 子规则 | **部分规避** |
| Usage 查询频率控制 | BEH-02 部分触发条件 | **部分规避** |

### 1.2 红队仍然无法完美解决的弱点

经过对红队方案的深入分析，以下弱点即使在红队执行完全部四个阶段后仍然存在：

**弱点一：TLS/HTTP/2 指纹的工程难度**

红队承认 Bun/BoringSSL 的 TLS 指纹精确复现在 Rust 生态中"缺乏现成工具"。三个备选方案（rustls 模拟、BoringSSL 绑定、wreq 自定义）均为骨架代码，无 PoC 验证。HTTP/2 SETTINGS 帧指纹在红队方案中完全空白。这意味着在第二轮中，TLS+HTTP/2 联合指纹仍然是我方的有效检测面。

**弱点二：伴随流量模拟的致命困境**

红队自评此项为"高度薄弱"，并建议"在完整逆向遥测协议前不启用"。这造成一个两难：不发送遥测流量 -> 被 BEH-03 检测为"幽灵客户端"；发送错误格式的遥测 -> 成为更强的检测信号。我方在本轮将大幅强化这一维度。

**弱点三：Cookie 共享的本质矛盾**

红队在自评中坦诚："多个下游用户共享少量上游 cookie/token"这一根本特征无法在请求级别伪装掉。具体表现为：
- 同一 token 的对话主题在短时间内极度分散
- 同一 token 覆盖多个时区的活跃模式
- 同一 token 在短时间内切换编程语言/知识领域

**弱点四：x-stainless-* SDK 头的遗漏**

红队方案完全未提及 `x-stainless-lang`、`x-stainless-package-version`、`x-stainless-runtime` 等 Anthropic SDK 自动附加的特征头。这是一个红队在第一轮完全忽略的细节。

**弱点五：SSE 中继延迟特征**

红队方案只关注了 HTTP 请求/响应层面，未涉及 SSE (Server-Sent Events) 流的中继特征。反代需要接收上游 SSE 流再转发给下游，这个中继过程会引入可检测的延迟模式和缓冲特征。

**弱点六：请求内容画像失配**

红队的下游用户主要来自 SillyTavern 等角色扮演场景，其请求内容（大段角色设定、纯自然语言叙事、多角色对话）与 Claude Code 的代码辅助场景（代码块、文件路径、技术术语、工具调用）截然不同。红队方案中没有对请求内容进行任何伪装。

---

## 二、第二代检测规则（新增 + 加固）

### 2.1 HTTP/2 指纹检测 (NET-05) [新增]

**检测原理**

HTTP/2 连接建立时客户端发送的 SETTINGS 帧包含多个参数（HEADER_TABLE_SIZE、MAX_CONCURRENT_STREAMS、INITIAL_WINDOW_SIZE、MAX_HEADER_LIST_SIZE 等），不同运行时的默认值截然不同。Bun (BoringSSL) 的 HTTP/2 参数与 wreq (hyper) 的参数有显著差异。此外，HTTP/2 的 WINDOW_UPDATE 帧策略和 PRIORITY 帧模式也是指纹的一部分。

```python
# NET-05: HTTP/2 指纹检测
class HTTP2FingerprintDetector:
    # 已知的 Bun/BoringSSL HTTP/2 SETTINGS 参数（需从真实 CLI 抓包确认）
    BUN_H2_PROFILE = {
        "HEADER_TABLE_SIZE": 65536,
        "MAX_CONCURRENT_STREAMS": 1000,
        "INITIAL_WINDOW_SIZE": 6291456,
        "MAX_HEADER_LIST_SIZE": 262144,
        # SETTINGS 帧中参数的发送顺序也是指纹的一部分
        "settings_order": [
            "HEADER_TABLE_SIZE",
            "MAX_CONCURRENT_STREAMS",
            "INITIAL_WINDOW_SIZE",
            "MAX_HEADER_LIST_SIZE",
        ],
    }

    # hyper (wreq 底层) 的默认 HTTP/2 参数
    HYPER_H2_PROFILE = {
        "HEADER_TABLE_SIZE": 4096,       # hyper 默认值
        "MAX_CONCURRENT_STREAMS": 200,    # hyper 默认值
        "INITIAL_WINDOW_SIZE": 1048576,   # hyper 默认 1MB
        "MAX_HEADER_LIST_SIZE": 16384,
    }

    def analyze(self, connection):
        if connection.protocol != "h2":
            return Score(confidence=0)

        client_settings = connection.h2_client_settings
        ua = connection.headers.get("User-Agent", "")

        if "claude-code/" not in ua:
            return Score(confidence=0)

        score = 0
        reasons = []

        # 规则 1: SETTINGS 参数与 Bun 不匹配
        for param, expected_value in self.BUN_H2_PROFILE.items():
            if param == "settings_order":
                continue
            actual = client_settings.get(param)
            if actual is not None and actual != expected_value:
                score += 15
                reasons.append(f"h2_{param}_mismatch: expected={expected_value}, actual={actual}")

        # 规则 2: SETTINGS 参数匹配 hyper 默认值（wreq 后端暴露）
        hyper_match_count = sum(
            1 for param, val in self.HYPER_H2_PROFILE.items()
            if client_settings.get(param) == val
        )
        if hyper_match_count >= 3:
            score += 40
            reasons.append(f"h2_matches_hyper_defaults: {hyper_match_count}/4 params")

        # 规则 3: SETTINGS 参数发送顺序
        actual_order = connection.h2_settings_order
        expected_order = self.BUN_H2_PROFILE["settings_order"]
        if actual_order and actual_order != expected_order:
            score += 20
            reasons.append("h2_settings_order_mismatch")

        # 规则 4: WINDOW_UPDATE 策略
        # Bun 使用 connection-level window update, hyper 有不同的流控策略
        window_update_pattern = connection.h2_window_update_behavior
        if window_update_pattern == "hyper_default":
            score += 15
            reasons.append("h2_window_update_matches_hyper")

        return Score(confidence=min(score, 90), reasons=reasons)
```

**预期效果**
- 检出率：75-90%（HTTP/2 参数是红队完全未覆盖的盲区）
- 误报率：<2%（不同运行时的 HTTP/2 参数高度确定）
- 关键优势：红队即使修复了 TLS 指纹，HTTP/2 指纹仍独立提供检测信号

### 2.2 SSE 流式传输中继检测 (NET-06) [新增]

**检测原理**

反代需要将上游 SSE 流转发给下游客户端，这个中继过程会引入可检测的特征：
1. **延迟叠加**：每个 SSE event 到达客户端的时间 = 服务端生成时间 + 网络延迟 + 代理处理延迟。中继会引入额外的固定延迟分量。
2. **缓冲阶梯**：代理可能按固定缓冲区大小批量转发 SSE events，导致"阶梯式"数据到达（多个 events 同时到达，然后暂停，再同时到达）。
3. **字节边界异常**：真实的直连 SSE 流，event 边界与 TCP segment 边界的关系是随机的；但代理的 re-serialize 可能导致每个 event 都精确对齐 segment 边界。

```python
# NET-06: SSE 中继检测
class SSERelayDetector:
    def analyze_sse_stream(self, stream_events):
        """
        分析单个 SSE 流的 event 到达时序。
        stream_events: [(event_data, server_timestamp, client_receive_timestamp)]
        """
        if len(stream_events) < 10:
            return Score(confidence=0)

        score = 0
        reasons = []

        # 计算每个 event 的到达间隔
        inter_arrival_times = [
            stream_events[i+1][2] - stream_events[i][2]
            for i in range(len(stream_events) - 1)
        ]

        # 规则 1: 阶梯式到达检测
        # 如果多个 events 的到达间隔 < 1ms（批量到达），随后有较长间隔
        burst_count = sum(1 for t in inter_arrival_times if t < 0.001)
        burst_ratio = burst_count / len(inter_arrival_times)
        if burst_ratio > 0.3:
            score += 30
            reasons.append(f"sse_burst_pattern: {burst_ratio:.0%} events in bursts")

        # 规则 2: 固定延迟分量检测
        # 计算 server_timestamp 与 client_receive_timestamp 的差值
        latencies = [e[2] - e[1] for e in stream_events if e[1] > 0]
        if len(latencies) > 5:
            min_latency = min(latencies)
            max_latency = max(latencies)
            latency_std = statistics.stdev(latencies)
            # 直连的延迟波动主要来自网络抖动
            # 中继的延迟波动还包含代理处理时间的变化
            # 如果最小延迟显著高于预期（>50ms），可能有额外跳点
            if min_latency > 0.05 and latency_std < 0.01:
                score += 25
                reasons.append(f"sse_extra_hop_detected: min_latency={min_latency*1000:.1f}ms")

        # 规则 3: Event 大小的规律性
        # 代理 re-serialize 可能改变 event 的字节分布
        event_sizes = [len(e[0]) for e in stream_events]
        if len(event_sizes) > 10:
            # 检查是否有固定的缓冲区对齐模式
            size_mod_counts = Counter(s % 4096 for s in event_sizes if s > 100)
            if len(size_mod_counts) <= 3:
                score += 15
                reasons.append("sse_buffer_alignment_detected")

        return Score(confidence=min(score, 80), reasons=reasons)
```

**预期效果**
- 检出率：50-70%（取决于代理的缓冲实现）
- 误报率：3-5%（CDN/边缘节点也可能引入类似模式）
- 局限：需要服务端在 SSE event 中嵌入精确的生成时间戳以校准延迟

### 2.3 请求内容画像检测 (BEH-05) [新增]

**检测原理**

Claude Code 是代码辅助工具，其请求内容具有高度特征性的"代码味"。反代透传的 SillyTavern 等下游请求则是纯自然语言叙事/角色扮演内容。通过轻量级内容分类器，可以检测声称是 Claude Code 但内容不像代码辅助的请求。

```python
# BEH-05: 请求内容画像
class ContentProfileDetector:
    # Claude Code 典型内容特征
    CODE_INDICATORS = [
        r'```\w*\n',                    # 代码块
        r'[/\\][\w.]+\.\w{1,5}',        # 文件路径
        r'function\s+\w+',              # 函数定义
        r'class\s+\w+',                 # 类定义
        r'import\s+\w+',               # 导入语句
        r'def\s+\w+\s*\(',             # Python 函数
        r'(?:npm|pip|cargo|go)\s+\w+', # 包管理器命令
        r'(?:git|docker)\s+\w+',       # 开发工具命令
        r'\b(?:error|exception|stack\s*trace|traceback)\b', # 错误诊断
        r'\b(?:TODO|FIXME|BUG|HACK)\b', # 代码注释标记
    ]

    # 非 Claude Code 内容特征（角色扮演/创意写作）
    RP_INDICATORS = [
        r'\*[^*]+\*',                    # 角色扮演动作描述 *like this*
        r'{{(char|user)\}\}',           # SillyTavern 模板变量
        r'\b(?:OOC|IC|NSFW)\b',        # 角色扮演元标记
        r'(?:personality|scenario|greeting|example_dialogue):', # 角色卡字段
        r'<(?:system|char|user)_?(?:prompt|persona|description)>', # 角色扮演 XML 标签
    ]

    # tool_use 相关特征（Claude Code 高频使用工具）
    TOOL_USE_INDICATORS = [
        r'"type"\s*:\s*"tool_use"',
        r'"type"\s*:\s*"tool_result"',
        r'"name"\s*:\s*"(?:Read|Write|Edit|Bash|Glob|Grep)"', # Claude Code 内置工具
    ]

    def analyze(self, request):
        ua = request.headers.get("User-Agent", "")
        if "claude-code/" not in ua:
            return Score(confidence=0)

        # 提取所有文本内容
        all_text = extract_all_message_text(request.body)
        system_text = extract_system_text(request.body)
        combined = all_text + " " + system_text

        if len(combined) < 100:
            return Score(confidence=0)

        score = 0
        reasons = []

        # 计算代码味指标
        code_hits = sum(
            1 for pattern in self.CODE_INDICATORS
            if re.search(pattern, combined, re.IGNORECASE)
        )
        code_ratio = code_hits / len(self.CODE_INDICATORS)

        # 计算角色扮演指标
        rp_hits = sum(
            1 for pattern in self.RP_INDICATORS
            if re.search(pattern, combined)
        )

        # 计算工具使用指标
        tool_hits = sum(
            1 for pattern in self.TOOL_USE_INDICATORS
            if re.search(pattern, combined)
        )
        messages = request.body.get("messages", [])
        has_tool_use = any(
            isinstance(m.get("content"), list) and
            any(b.get("type") in ("tool_use", "tool_result") for b in m["content"] if isinstance(b, dict))
            for m in messages
        )

        # 规则 1: 声称 Claude Code 但完全没有代码味
        if code_ratio < 0.1 and len(combined) > 500:
            score += 20
            reasons.append(f"no_code_flavor: code_ratio={code_ratio:.0%}")

        # 规则 2: 包含角色扮演特征
        if rp_hits >= 2:
            score += 35
            reasons.append(f"rp_content_detected: {rp_hits} indicators")

        # 规则 3: 多轮对话无任何 tool_use/tool_result
        # Claude Code 的核心交互模式是调用工具
        if len(messages) > 6 and not has_tool_use and tool_hits == 0:
            score += 25
            reasons.append(f"no_tool_usage_in_{len(messages)}_messages")

        # 规则 4: System prompt 超长且非代码上下文
        # Claude Code 的 system prompt 通常由工具自动生成，包含项目结构信息
        if len(system_text) > 5000 and code_ratio < 0.15:
            score += 20
            reasons.append("long_non_code_system_prompt")

        # 规则 5: 消息中缺少 Claude Code 的典型交互模式
        # 真实 Claude Code 的 assistant 回复通常包含工具调用
        assistant_msgs = [m for m in messages if m.get("role") == "assistant"]
        if len(assistant_msgs) > 3:
            assistant_with_tools = sum(
                1 for m in assistant_msgs
                if isinstance(m.get("content"), list) and
                any(b.get("type") == "tool_use" for b in m["content"] if isinstance(b, dict))
            )
            tool_ratio = assistant_with_tools / len(assistant_msgs)
            if tool_ratio < 0.2:
                score += 15
                reasons.append(f"low_assistant_tool_ratio: {tool_ratio:.0%}")

        return Score(confidence=min(score, 90), reasons=reasons)
```

**预期效果**
- 检出率：70-85%（对 SillyTavern 等角色扮演下游极为有效）
- 误报率：3-5%（部分用户确实用 Claude Code 做非代码任务）
- 关键优势：这是红队几乎无法对抗的维度。要绕过此检测，红队需要对下游请求内容进行实时改写/注入代码特征，这会破坏下游用户的实际使用体验

### 2.4 Stainless SDK 特征头检测 (REQ-06) [新增]

**检测原理**

真实 Claude Code CLI 使用 `@anthropic-ai/sdk`（基于 Stainless 生成的 SDK），该 SDK 在每个请求中自动附加一组特征头。这些头的存在性、值的格式和相互一致性构成了强检测信号。

```python
# REQ-06: Stainless SDK 特征头检测
class StainlessSDKDetector:
    # 真实 SDK 附加的头（需从实际抓包确认完整列表）
    EXPECTED_STAINLESS_HEADERS = {
        "x-stainless-lang": "js",                    # SDK 语言
        "x-stainless-package-version": None,          # 版本号，动态
        "x-stainless-os": None,                       # 操作系统
        "x-stainless-arch": None,                     # CPU 架构
        "x-stainless-runtime": "bun",                 # 运行时
        "x-stainless-runtime-version": None,          # 运行时版本
        "x-stainless-retry-count": None,              # 重试次数（可选）
    }

    def analyze(self, request):
        ua = request.headers.get("User-Agent", "")
        if "claude-code/" not in ua:
            return Score(confidence=0)

        headers = request.headers
        score = 0
        reasons = []

        # 规则 1: 缺少 Stainless 头
        missing_required = []
        for header_name, expected_value in self.EXPECTED_STAINLESS_HEADERS.items():
            if header_name not in headers:
                missing_required.append(header_name)
            elif expected_value is not None and headers[header_name] != expected_value:
                score += 10
                reasons.append(f"stainless_value_mismatch: {header_name}")

        if len(missing_required) >= 4:
            score += 40
            reasons.append(f"missing_stainless_headers: {missing_required}")
        elif len(missing_required) >= 2:
            score += 20
            reasons.append(f"partial_missing_stainless: {missing_required}")

        # 规则 2: runtime 与 UA 的一致性
        runtime = headers.get("x-stainless-runtime", "")
        if runtime and runtime != "bun":
            score += 25
            reasons.append(f"stainless_runtime_not_bun: {runtime}")

        # 规则 3: OS/arch 与其他信号的一致性
        stainless_os = headers.get("x-stainless-os", "")
        if stainless_os:
            # 与 IP 地理位置的弱关联（某些地区偏好特定 OS）
            # 主要检查 OS 值是否合法
            valid_os = {"Linux", "Darwin", "Windows_NT"}
            if stainless_os not in valid_os:
                score += 15
                reasons.append(f"invalid_stainless_os: {stainless_os}")

        # 规则 4: package-version 与 UA 中版本号的一致性
        pkg_version = headers.get("x-stainless-package-version", "")
        ua_version = extract_version_from_ua(ua)
        if pkg_version and ua_version:
            # SDK 版本号应与 CLI 版本号不同但在合理范围内
            # 真实 CLI 使用特定版本的 SDK
            if not is_compatible_sdk_version(pkg_version, ua_version):
                score += 15
                reasons.append(f"sdk_cli_version_mismatch: sdk={pkg_version}, cli={ua_version}")

        return Score(confidence=min(score, 85), reasons=reasons)
```

**预期效果**
- 检出率：80-90%（红队第一轮完全遗漏此维度）
- 误报率：<1%（真实 SDK 总是附加这些头）
- 防守优势：红队即使在第二轮补上这些头，也需要持续追踪 SDK 版本号、运行时版本等动态值的匹配关系

### 2.5 伴随流量深度语义验证 (BEH-03v2) [加固]

**检测原理**

第一轮的 BEH-03 仅检测"有没有"伴随流量。第二轮升级为语义级验证：不仅要求伴随流量存在，还要求其内容与主请求流之间具有逻辑一致性。

```python
# BEH-03v2: 伴随流量深度语义验证
class CompanionTrafficSemanticValidator:
    def analyze(self, token_id, request_history):
        """
        request_history: 该 token 最近所有请求的有序列表
        """
        score = 0
        reasons = []

        # --- 基础存在性检测（继承自 BEH-03）---
        endpoint_counts = Counter(r["endpoint_category"] for r in request_history)
        total = len(request_history)
        if total < 5:
            return Score(confidence=0)

        chat_count = endpoint_counts.get("chat", 0)
        count_tokens_count = endpoint_counts.get("count_tokens", 0)
        telemetry_count = endpoint_counts.get("telemetry", 0)

        # --- 新增：语义一致性验证 ---

        # 规则 1: count_tokens 与 chat 的时序配对
        # 真实 CLI 在每次 chat 请求前 0.5-2 秒调用 count_tokens
        # 且 count_tokens 的请求体应与随后的 chat 请求体一致
        chat_requests = [r for r in request_history if r["endpoint_category"] == "chat"]
        ct_requests = [r for r in request_history if r["endpoint_category"] == "count_tokens"]

        if chat_count > 5 and count_tokens_count == 0:
            score += 30
            reasons.append("no_count_tokens_before_chat")
        elif chat_count > 5 and count_tokens_count > 0:
            # 检查时序配对
            paired = 0
            for chat_req in chat_requests:
                # 寻找 0.5-5 秒前的 count_tokens 请求
                preceding_ct = [
                    ct for ct in ct_requests
                    if 0.5 < chat_req["timestamp"] - ct["timestamp"] < 5.0
                ]
                if preceding_ct:
                    # 验证请求体一致性（messages 应相同或为子集）
                    ct_body_hash = preceding_ct[-1].get("body_hash")
                    chat_body_hash = chat_req.get("body_hash")
                    if ct_body_hash and chat_body_hash:
                        if ct_body_hash == chat_body_hash:
                            paired += 1
                        else:
                            # count_tokens 的 body 与 chat 不一致 -> 伪造的伴随流量
                            score += 20
                            reasons.append("count_tokens_body_mismatch")
                            break

            pair_ratio = paired / max(chat_count, 1)
            if pair_ratio < 0.3 and chat_count > 10:
                score += 20
                reasons.append(f"low_ct_chat_pairing: {pair_ratio:.0%}")

        # 规则 2: telemetry 的 session_id 一致性
        # 真实 CLI 的 telemetry 心跳包含 session_id，
        # 该 ID 应与 chat 请求中的 conversation 上下文相关联
        if telemetry_count > 0:
            telemetry_sessions = set(
                r.get("telemetry_session_id") for r in request_history
                if r["endpoint_category"] == "telemetry" and r.get("telemetry_session_id")
            )
            # 如果所有 telemetry 使用同一个随机 session_id，但在 1 小时内
            # 有多个不同的 chat conversation，则 session_id 与实际会话不匹配
            chat_conversations = set(
                r.get("conversation_id") for r in request_history
                if r["endpoint_category"] == "chat" and r.get("conversation_id")
            )
            if len(telemetry_sessions) == 1 and len(chat_conversations) > 3:
                score += 15
                reasons.append("telemetry_session_id_static_across_conversations")

        # 规则 3: heartbeat 频率与活跃度的相关性
        # 真实 CLI 的心跳在用户活跃时更频繁，idle 时减少
        # 代理的固定间隔心跳与活跃度无关
        if telemetry_count > 5:
            heartbeat_intervals = []
            telemetry_requests = sorted(
                [r for r in request_history if r["endpoint_category"] == "telemetry"],
                key=lambda r: r["timestamp"]
            )
            for i in range(len(telemetry_requests) - 1):
                interval = telemetry_requests[i+1]["timestamp"] - telemetry_requests[i]["timestamp"]
                heartbeat_intervals.append(interval)

            if len(heartbeat_intervals) > 5:
                cv = statistics.stdev(heartbeat_intervals) / statistics.mean(heartbeat_intervals)
                if cv < 0.15:
                    score += 20
                    reasons.append(f"heartbeat_too_regular: cv={cv:.2f}")

        return Score(confidence=min(score, 85), reasons=reasons)
```

**预期效果**
- 检出率：75-85%
- 误报率：3%
- 关键加固：即使红队在第二轮添加了伴随流量，语义层校验大幅提高了伪造难度

### 2.6 会话主题一致性分析 (BEH-06) [新增]

**检测原理**

反代共享 cookie 导致同一 token 在短时间内被不同下游用户使用，产生主题极度分散的对话模式。真实的单一用户通常在一个时间段内围绕有限的几个主题工作。

```python
# BEH-06: 会话主题一致性
class SessionTopicCoherenceDetector:
    def analyze(self, token_id, conversations_1h):
        """
        conversations_1h: 该 token 在 1 小时内的所有对话
        每个对话包含 messages 列表
        """
        if len(conversations_1h) < 3:
            return Score(confidence=0)

        score = 0
        reasons = []

        # 提取每个对话的主题向量（使用轻量级方法）
        topics = []
        for conv in conversations_1h:
            user_messages = " ".join(
                extract_text(m) for m in conv["messages"] if m["role"] == "user"
            )
            topic_features = self.extract_topic_features(user_messages)
            topics.append(topic_features)

        # 规则 1: 编程语言急剧切换
        # 同一用户在 1 小时内不太可能在 5+ 种不同语言间切换
        languages_per_conv = [t["detected_languages"] for t in topics]
        all_languages = set()
        for langs in languages_per_conv:
            all_languages.update(langs)
        if len(all_languages) > 5 and len(conversations_1h) > 3:
            score += 25
            reasons.append(f"language_diversity: {len(all_languages)} languages in 1h")

        # 规则 2: 主题领域跳跃
        # 使用关键词聚类检测主题是否在完全不相关的领域间跳转
        domain_sets = [t["domain_keywords"] for t in topics]
        cross_conv_overlap = []
        for i in range(len(domain_sets)):
            for j in range(i+1, len(domain_sets)):
                if domain_sets[i] and domain_sets[j]:
                    overlap = len(domain_sets[i] & domain_sets[j]) / max(
                        len(domain_sets[i] | domain_sets[j]), 1
                    )
                    cross_conv_overlap.append(overlap)

        if cross_conv_overlap:
            avg_overlap = statistics.mean(cross_conv_overlap)
            if avg_overlap < 0.05 and len(conversations_1h) > 5:
                score += 30
                reasons.append(f"topic_incoherence: avg_overlap={avg_overlap:.2%}")

        # 规则 3: 对话风格不一致
        # 不同下游用户的写作风格（消息长度、标点使用、大小写习惯）差异显著
        style_vectors = [t["style_vector"] for t in topics]
        if len(style_vectors) > 3:
            style_variance = self.compute_style_variance(style_vectors)
            if style_variance > 2.0:  # 标准化后的方差阈值
                score += 20
                reasons.append(f"style_inconsistency: variance={style_variance:.1f}")

        return Score(confidence=min(score, 85), reasons=reasons)

    def extract_topic_features(self, text):
        """轻量级主题特征提取（不依赖 LLM）"""
        # 编程语言检测
        language_patterns = {
            "python": r'\b(?:def |import |print\(|lambda )',
            "javascript": r'\b(?:const |let |function |=>\s*\{)',
            "rust": r'\b(?:fn |let mut |impl |pub fn)',
            "java": r'\b(?:public class |System\.out|@Override)',
            "go": r'\b(?:func |package |fmt\.)',
            "cpp": r'\b(?:#include|std::|nullptr)',
        }
        detected_languages = set(
            lang for lang, pat in language_patterns.items()
            if re.search(pat, text)
        )

        # 领域关键词提取
        words = set(re.findall(r'\b[a-z]{3,15}\b', text.lower()))
        domain_keywords = words & self.DOMAIN_VOCABULARY  # 预定义的领域词汇表

        # 风格向量
        sentences = text.split('.')
        avg_sentence_len = statistics.mean(len(s.split()) for s in sentences if s.strip()) if sentences else 0
        uppercase_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
        punctuation_ratio = sum(1 for c in text if c in '.,;:!?') / max(len(text), 1)

        return {
            "detected_languages": detected_languages,
            "domain_keywords": domain_keywords,
            "style_vector": [avg_sentence_len, uppercase_ratio, punctuation_ratio],
        }
```

**预期效果**
- 检出率：60-75%（对多用户共享场景有效）
- 误报率：5-8%（团队共享账户可能触发）
- 局限：单用户使用反代时不触发

### 2.7 Billing Header 增强校验 (REQ-02v2) [加固]

**检测原理**

红队已将 billing header 移至 HTTP 头，但仍有多个可校验维度。

```python
# REQ-02v2: Billing Header 增强校验
def enhanced_billing_verification(request):
    billing = request.headers.get("x-anthropic-billing-header", "")
    if not billing:
        ua = request.headers.get("User-Agent", "")
        if "claude-code/" in ua:
            return Score(confidence=40, reason="billing_header_missing_for_cli")
        return Score(confidence=0)

    parsed = parse_billing_header(billing)
    if not parsed:
        return Score(confidence=70, reason="malformed_billing_header")

    score = 0
    reasons = []

    # 规则 1: 版本号与 billing hash 的严格校验（继承自 REQ-02）
    # 构建完整的版本-salt-cch 映射表
    VERSION_SALT_MAP = {
        "2.1.84": {"salt": "59cf53e54c78", "valid_cch": {"88e20"}},
        "2.1.86": {"salt": "59cf53e54c78", "valid_cch": {"88e20"}},
        # 每次 CLI 更新同步更新此表
    }

    version = parsed["cc_version_base"]
    claimed_hash = parsed["cc_version_hash"]
    cch = parsed["cch"]

    version_info = VERSION_SALT_MAP.get(version)
    if version_info:
        # 独立计算 hash 并校验
        first_user_text = get_first_user_message_text(request.body)
        sampled = sample_js_code_units(first_user_text, [4, 7, 20])
        expected_hash = sha256(
            f"{version_info['salt']}{sampled}{version}"
        ).hex()[:3]

        if claimed_hash != expected_hash:
            score += 50
            reasons.append(f"billing_hash_mismatch: claimed={claimed_hash}, expected={expected_hash}")

        if cch not in version_info["valid_cch"]:
            score += 30
            reasons.append(f"invalid_cch: {cch}")
    else:
        # 未知版本号
        score += 20
        reasons.append(f"unknown_cli_version: {version}")

    # 规则 2: 版本号与 anthropic-beta 头的功能集一致性
    beta = request.headers.get("anthropic-beta", "")
    expected_betas = get_expected_betas_for_version(version)
    if expected_betas:
        beta_set = set(b.strip() for b in beta.split(","))
        # 检查是否包含该版本不应支持的 beta 功能
        unexpected = beta_set - expected_betas
        missing = expected_betas - beta_set
        if unexpected:
            score += 15
            reasons.append(f"unexpected_beta_features: {unexpected}")
        if missing:
            score += 10
            reasons.append(f"missing_beta_features: {missing}")

    # 规则 3: billing header 不应出现在非 messages 端点
    endpoint = request.path
    non_billing_endpoints = ["/v1/messages/count_tokens", "/api/oauth/"]
    if any(endpoint.startswith(ep) for ep in non_billing_endpoints):
        if billing:
            score += 20
            reasons.append(f"billing_on_wrong_endpoint: {endpoint}")

    return Score(confidence=min(score, 90), reasons=reasons)
```

### 2.8 连接复用模式增强 (NET-04v2) [加固]

```python
# NET-04v2: 连接生命周期增强分析
class ConnectionLifecycleAnalyzerV2:
    def analyze(self, token_id, connection_info):
        score = 0
        reasons = []

        # 继承基础规则
        new_connections_per_hour = count_new_tls_handshakes(token_id, window="1h")
        avg_connection_duration = mean_connection_lifetime(token_id, window="1h")

        if new_connections_per_hour > 20:
            score += 25

        # 新增规则 1: 连接复用率
        # 真实 CLI 在一个 keep-alive 连接上发送多个请求
        # clewdr 每个 cookie 创建新 Client，复用率极低
        reuse_ratio = requests_per_connection(token_id, window="1h")
        if reuse_ratio < 2.0 and new_connections_per_hour > 5:
            score += 25
            reasons.append(f"low_connection_reuse: {reuse_ratio:.1f} req/conn")

        # 新增规则 2: TLS 握手时间的稳定性
        # 代理到 API 的 TLS 握手时间应相对稳定
        # 但如果使用了代理池，不同出口节点的 RTT 差异导致握手时间波动大
        handshake_times = get_tls_handshake_durations(token_id, window="1h")
        if len(handshake_times) > 5:
            hs_cv = statistics.stdev(handshake_times) / statistics.mean(handshake_times)
            if hs_cv > 0.8:
                score += 15
                reasons.append(f"handshake_time_variance: cv={hs_cv:.2f}")

        # 新增规则 3: 连接建立时刻与请求的关联
        # 真实 CLI 启动时建立连接，之后长期复用
        # 代理在每个下游请求到达时才建立新连接
        conn_request_gap = avg_gap_between_connection_and_first_request(token_id)
        if conn_request_gap is not None and conn_request_gap < 0.1:
            # 连接建立后 <100ms 就发请求 -> 按需建连特征
            score += 15
            reasons.append(f"on_demand_connection: gap={conn_request_gap*1000:.0f}ms")

        return Score(confidence=min(score, 85), reasons=reasons)
```

---

## 三、主动防御策略

### 3.1 服务端工具调用探针 (PROBE-01)

**原理**

真实 Claude Code CLI 具备执行 tool_use 指令并回传 tool_result 的能力。反代只是透传 API 请求，其下游客户端（如 SillyTavern）无法处理 Claude Code 特有的工具调用。我们可以在特定条件下让模型输出一个轻量级的"能力探测"工具调用，观察客户端是否能正确处理。

```python
# PROBE-01: 工具调用能力探针
class ToolUseProbe:
    """
    在风险分处于灰色地带（50-70 分）的会话中，注入一个轻量级工具调用探针。
    策略：利用模型的 system prompt（服务端可追加不可见指令）引导模型
    在回复中包含一个无害的工具调用，观察后续请求是否包含对应的 tool_result。
    """

    # 探针工具定义
    PROBE_TOOL = {
        "name": "get_workspace_info",
        "description": "Get basic info about the current workspace",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        }
    }

    def should_probe(self, session_risk_score):
        # 只对灰色地带的会话探测
        return 50 <= session_risk_score <= 70

    def inject_probe(self, request_body):
        """
        服务端修改：在请求的 tools 列表中追加探针工具。
        如果模型在回复中调用了此工具，观察后续请求中是否有对应的 tool_result。
        """
        tools = request_body.get("tools", [])
        # 检查是否已包含类似工具（避免重复）
        if not any(t.get("name") == self.PROBE_TOOL["name"] for t in tools):
            tools.append(self.PROBE_TOOL)
            request_body["tools"] = tools
        return request_body

    def verify_response(self, token_id, response_tool_uses, next_request_within_timeout):
        """
        检查客户端是否在超时内发回了 tool_result。
        """
        probe_calls = [
            tu for tu in response_tool_uses
            if tu.get("name") == "get_workspace_info"
        ]

        if not probe_calls:
            return None  # 模型未调用探针工具，无法判断

        probe_id = probe_calls[0].get("id")

        # 等待客户端的下一个请求（超时 30 秒）
        if next_request_within_timeout:
            messages = next_request_within_timeout.body.get("messages", [])
            # 检查是否包含对应 probe_id 的 tool_result
            has_result = any(
                isinstance(m.get("content"), list) and
                any(
                    b.get("type") == "tool_result" and
                    b.get("tool_use_id") == probe_id
                    for b in m["content"] if isinstance(b, dict)
                )
                for m in messages
            )
            if not has_result:
                return Score(confidence=75, reason="PROBE_TOOL_RESULT_MISSING",
                             detail=f"probe_id={probe_id}")
            else:
                # 检查 tool_result 的内容是否合理
                # 真实 CLI 会返回工作区信息，反代可能返回空或错误
                result_content = extract_tool_result(messages, probe_id)
                if result_content and is_valid_workspace_info(result_content):
                    return Score(confidence=0)  # 通过探测
                else:
                    return Score(confidence=50, reason="PROBE_RESULT_SUSPICIOUS",
                                 detail=f"content={result_content[:100]}")
        else:
            # 超时无响应
            return Score(confidence=60, reason="PROBE_NO_FOLLOWUP",
                         detail="No request within 30s after tool_use probe")
```

**预期效果**
- 检出率：85-95%（对无法处理 tool_use 的下游客户端近乎必杀）
- 误报率：<1%（真实 CLI 总是处理 tool_use）
- 风险：可能被红队识别为探针并特殊处理。但这需要红队实现完整的工具执行模拟。

### 3.2 响应水印与追踪 (PROBE-02)

**原理**

在 SSE 响应流中注入不可见的追踪标记，用于关联多个看似独立的会话。

```python
# PROBE-02: 响应流水印
class ResponseWatermark:
    """
    在 SSE 响应的 text delta 中注入不可见字符（如零宽空格 U+200B、
    零宽非连接符 U+200C 等）编码的 tracking ID。

    如果反代将响应原样透传给下游，下游用户可能在回复中引用
    带有水印的文本，我们可以在后续请求中检测到这些水印。
    """

    ZERO_WIDTH_CHARS = ['\u200b', '\u200c', '\u200d', '\ufeff']

    def encode_watermark(self, tracking_id: str) -> str:
        """将 tracking ID 编码为零宽字符序列"""
        bits = bin(int(tracking_id[:8], 16))[2:].zfill(32)
        return ''.join(
            self.ZERO_WIDTH_CHARS[int(bits[i:i+2], 2)]
            for i in range(0, len(bits), 2)
        )

    def inject_watermark(self, sse_text: str, tracking_id: str) -> str:
        """在文本的自然断句处注入水印"""
        watermark = self.encode_watermark(tracking_id)
        # 在第一个句号或换行后注入
        for sep in ['. ', '.\n', '\n\n']:
            idx = sse_text.find(sep)
            if idx > 0:
                return sse_text[:idx+len(sep)] + watermark + sse_text[idx+len(sep):]
        return sse_text  # 无合适位置则不注入

    def detect_watermark(self, text: str) -> Optional[str]:
        """从文本中检测并解码水印"""
        zw_sequence = [c for c in text if c in self.ZERO_WIDTH_CHARS]
        if len(zw_sequence) >= 16:
            # 尝试解码
            bits = ''.join(
                format(self.ZERO_WIDTH_CHARS.index(c), '02b')
                for c in zw_sequence[:16]
            )
            tracking_id = hex(int(bits, 2))[2:].zfill(8)
            return tracking_id
        return None

    def check_request_for_watermarks(self, request_body):
        """检查请求体中是否包含我们注入的水印"""
        all_text = extract_all_message_text(request_body)
        found_id = self.detect_watermark(all_text)
        if found_id:
            # 检查这个 tracking_id 是否属于不同的 token/session
            original_session = lookup_tracking_id(found_id)
            current_token = request_body.get("_token_id")
            if original_session and original_session["token_id"] != current_token:
                return Score(
                    confidence=90,
                    reason="CROSS_SESSION_WATERMARK",
                    detail=f"tracking_id={found_id} from session={original_session['token_id']}"
                )
        return Score(confidence=0)
```

**预期效果**
- 检出率：20-30%（仅当下游用户在后续消息中引用了带水印的回复时触发）
- 误报率：<0.1%
- 作用：虽然检出率低，但可用于跨会话关联，发现共享代理集群

### 3.3 蜜罐账户 (PROBE-03)

**原理**

创建看似被泄露的高价值 cookie/token，投放到反代社区常用的分享渠道，用于：
1. 直接识别使用蜜罐凭证的反代请求
2. 收集反代的行为特征用于训练 ML 模型
3. 追踪反代社区的传播链路

```python
# PROBE-03: 蜜罐账户
class HoneypotAccountSystem:
    def __init__(self):
        # 蜜罐凭证集合
        self.honeypot_tokens = set()
        self.honeypot_cookies = set()

    def create_honeypot(self):
        """创建一个看似真实的蜜罐账户"""
        account = {
            "cookie": generate_realistic_cookie(),
            "org_id": generate_org_id(),
            "subscription_tier": "max_5",  # 高价值订阅
            "features": ["claude-3-5-sonnet", "claude-3-5-opus", "extended-thinking"],
        }
        self.honeypot_cookies.add(account["cookie"])
        return account

    def deploy_honeypots(self):
        """
        部署策略：
        1. 在已知反代论坛/Discord 的分享频道投放
        2. 在公开 GitHub 仓库中"不小心"提交包含 cookie 的配置文件
        3. 在 Pastebin 等平台投放
        """
        pass

    def on_honeypot_request(self, request, honeypot_id):
        """
        蜜罐被触发时：
        1. 正常响应（不要暴露蜜罐身份）
        2. 记录完整的请求特征用于 ML 训练
        3. 追踪请求来源的 IP/TLS 指纹
        """
        # 收集该反代的所有特征
        features = extract_complete_fingerprint(request)

        # 记录用于 ML 模型训练
        save_confirmed_proxy_sample(features, source="honeypot")

        # 构建该反代的指纹签名，用于发现其他非蜜罐流量
        proxy_signature = build_proxy_signature(features)
        register_known_proxy_signature(proxy_signature)

        # 正常响应，但降低优先级/限制能力
        return HoneypotAction.RESPOND_NORMALLY_AND_MONITOR
```

---

## 四、多账户关联图分析 (GRAPH-01) [新增维度]

**原理**

第一轮的检测在单实体维度（IP、cookie、token、client_id）独立分析。第二轮引入全局实体关联图，通过图分析发现分布式反代集群。

```python
# GRAPH-01: 实体关联图分析
class EntityGraphAnalyzer:
    """
    构建 IP <-> Cookie <-> Token <-> ClientID <-> Organization 的关联图。
    通过社区发现算法找到异常紧密的实体集群。
    """

    def __init__(self):
        self.graph = nx.Graph()

    def add_observation(self, request):
        """为每个请求添加图中的边"""
        ip = request.remote_addr
        cookie = hash(request.cookie)
        token = request.token_id
        client_id = request.client_id
        org = request.org_id

        # 添加节点和边
        self.graph.add_edge(f"ip:{ip}", f"cookie:{cookie}", weight=1)
        self.graph.add_edge(f"cookie:{cookie}", f"token:{token}", weight=1)
        self.graph.add_edge(f"token:{token}", f"client:{client_id}", weight=1)
        self.graph.add_edge(f"token:{token}", f"org:{org}", weight=1)

        # 如果同一 IP 使用了不同 cookie，加强 IP 到 cookie 的边权重
        existing = self.graph[f"ip:{ip}"]
        for neighbor in existing:
            if neighbor.startswith("cookie:") and neighbor != f"cookie:{cookie}":
                # 同 IP 多 cookie -> 加强关联
                if self.graph.has_edge(f"ip:{ip}", neighbor):
                    self.graph[f"ip:{ip}"][neighbor]["weight"] += 2

    def detect_clusters(self):
        """使用社区发现算法检测异常集群"""
        # Louvain 社区发现
        communities = nx.community.louvain_communities(self.graph)

        suspicious_clusters = []
        for community in communities:
            cookies = [n for n in community if n.startswith("cookie:")]
            ips = [n for n in community if n.startswith("ip:")]
            tokens = [n for n in community if n.startswith("token:")]
            clients = [n for n in community if n.startswith("client:")]

            # 异常指标：
            # 1. 集群中 cookie 数量过多（代理 cookie 池）
            # 2. cookie-to-IP 比例异常（多 cookie 少 IP）
            # 3. 集群内所有实体共享少量 client_id
            if len(cookies) > 5 and len(clients) <= 2:
                suspicious_clusters.append({
                    "cookies": cookies,
                    "ips": ips,
                    "tokens": tokens,
                    "clients": clients,
                    "risk": "high" if len(cookies) > 10 else "medium",
                    "reason": f"cookie_pool_cluster: {len(cookies)} cookies, "
                              f"{len(ips)} IPs, {len(clients)} client_ids",
                })

        return suspicious_clusters

    def geographic_consistency_check(self, cluster):
        """检查集群内 IP 的地理分布与账户注册地是否一致"""
        ip_geos = [geoip_lookup(ip.split(":")[1]) for ip in cluster["ips"]]
        token_regions = [
            get_account_registration_region(t.split(":")[1])
            for t in cluster["tokens"]
        ]

        # 计算地理分散度
        unique_countries = set(g["country"] for g in ip_geos if g)
        unique_regions = set(r for r in token_regions if r)

        # 如果 IP 分布在 3+ 个国家，但所有账户注册在同一地区
        if len(unique_countries) > 3 and len(unique_regions) == 1:
            return Score(confidence=60, reason="geo_dispersion_mismatch",
                         detail=f"IPs in {unique_countries}, accounts in {unique_regions}")

        # 如果 IP 国家与账户注册国完全不一致
        ip_countries = set(g["country"] for g in ip_geos if g)
        account_countries = set(r for r in token_regions if r)
        if ip_countries and account_countries and not ip_countries & account_countries:
            return Score(confidence=50, reason="geo_mismatch",
                         detail=f"IPs: {ip_countries}, accounts: {account_countries}")

        return Score(confidence=0)
```

---

## 五、调整后的综合评分模型

### 5.1 权重重分配

第一轮的权重过度依赖请求层（0.30）。在红队修复了 billing 注入后，请求层的确定性信号大幅下降。第二轮重新平衡权重：

```python
class ProxyDetectionEngineV2:
    LAYER_WEIGHTS = {
        "network": 0.25,      # 保持（新增 HTTP/2 指纹 + SSE 检测）
        "request": 0.20,      # 下降（REQ-01/05 失效，但新增 REQ-06 Stainless 头）
        "behavior": 0.25,     # 上升（核心阵地：内容画像 + 主题一致性 + 伴随流量语义）
        "auth": 0.10,         # 下降（Client ID 可被替换）
        "content": 0.10,      # 新增（请求内容画像独立成层）
        "graph": 0.10,        # 新增（实体关联图分析）
    }

    # 新增硬规则
    HARD_RULES_V2 = [
        "PROBE-01",  # 工具调用探针未通过
        "PROBE-02",  # 跨会话水印发现
        "PROBE-03",  # 蜜罐账户触发
        "BEH-05",    # 角色扮演内容检测（confidence >= 80）
        "NET-05",    # HTTP/2 指纹匹配 hyper 默认值（confidence >= 80）
    ]
```

### 5.2 灰度处置策略

```python
def decide_action_v2(self, verdict, session_history):
    score = verdict.score

    if score < 40:
        return Action.ALLOW

    elif score < 55:
        # 灰色地带：启动主动探测
        return Action.MONITOR_AND_PROBE  # 触发 PROBE-01

    elif score < 70:
        # 中等风险：限速 + 持续监控 + 收集更多信号
        return Action.RATE_LIMIT_50PCT

    elif score < 85:
        # 高风险：严格限速 + 要求二次验证
        return Action.RATE_LIMIT_10PCT_AND_CHALLENGE

    else:
        # 极高风险：阻断
        return Action.BLOCK_AND_FLAG
```

---

## 六、防御红队第 2 轮可能的改进

### 6.1 预判红队可能的第 2 轮动作及预备对策

| 红队可能的改进 | 我方预备对策 |
|---------------|-------------|
| 添加 x-stainless-* 头 | REQ-06 不仅检查存在性，还校验版本号动态一致性。红队需要持续追踪 SDK 版本与 CLI 版本的映射关系 |
| 实现 count_tokens 伴随调用 | BEH-03v2 校验 count_tokens 的请求体是否与后续 chat 的请求体一致（body hash 比对） |
| HTTP/2 参数自定义 | NET-05 检查多个参数的组合一致性。wreq/hyper 底层可能不支持自定义全部 HTTP/2 参数 |
| 更精确的 TLS 指纹 | TLS + HTTP/2 + 连接行为的三维交叉验证，单独修复 TLS 仍会被 HTTP/2 层捕获 |
| 请求内容注入代码特征 | BEH-05 检查多轮对话中 tool_use/tool_result 的完整交互链，注入代码片段无法伪造工具执行流 |
| 住宅代理 IP 隔离 | GRAPH-01 通过实体关联图在多维度交叉关联，即使每个 cookie 使用独立 IP 也会被 client_id 或行为模式关联 |
| OAuth 时序自然化 | AUTH-02 加入 OAuth code 的二次使用检测（正常 code 只使用一次，代理可能重放 code） |

### 6.2 不可模拟的检测维度

以下维度是红队在架构上无法完美模拟的（不是工程难度问题，而是根本性矛盾）：

1. **tool_use 端到端执行**：真实 CLI 接收到 tool_use 后会在本地文件系统执行操作（读文件、写文件、运行命令），并将真实的执行结果回传。反代的下游客户端（SillyTavern）无法执行这些操作。即使红队实现了虚假的 tool_result 生成，result 的内容（如文件内容、命令输出）无法与对话上下文保持逻辑一致性。

2. **请求内容的领域一致性**：Claude Code 的使用场景是代码辅助，请求内容天然包含代码、文件路径、技术术语。反代的下游用户发送的角色扮演/创意写作内容与此截然不同。红队要绕过此检测，必须对下游请求进行实时内容改写，这会根本性地破坏下游用户的使用体验。

3. **多用户共享的统计特征**：同一 token 被多个不相关用户使用时，主题分散度、写作风格方差、时区覆盖范围等统计特征与单用户使用有根本性差异。红队只能通过减少共享（一个 cookie 只给一个用户）来缓解，但这会大幅增加运营成本，削弱反代的经济优势。

---

## 七、自评

### 7.1 预期检出率（第二代系统）

| 场景 | 第一代检出率 | 第二代检出率 | 变化原因 |
|------|------------|------------|---------|
| 默认 clewdr (当前版本) | 95-99% | 95-99% | 低级错误仍然存在，第一代规则即可杀死 |
| 红队第一阶段修复后 | 55-70% | 80-90% | HTTP/2 指纹 + Stainless 头 + 内容画像补齐了被击杀的规则 |
| 红队全面优化后 | 30-50% | 55-70% | 伴随流量语义验证 + 主题一致性 + 工具探针提供深层检测 |
| 单用户低频使用反代 | 10-20% | 25-40% | 内容画像和工具探针仍然有效，但统计类检测全部失效 |

### 7.2 新增检测维度的评估

| 检测规则 | 预期检出率 | 预期误报率 | 红队绕过难度 |
|----------|-----------|-----------|------------|
| NET-05 HTTP/2 指纹 | 75-90% | <2% | 高（需修改 HTTP/2 库底层参数） |
| NET-06 SSE 中继检测 | 50-70% | 3-5% | 中（可通过逐 event 流式转发缓解） |
| BEH-05 内容画像 | 70-85% | 3-5% | 极高（无法在不破坏用户体验的前提下伪装） |
| BEH-06 主题一致性 | 60-75% | 5-8% | 高（需要限制每 cookie 只服务一个用户） |
| REQ-06 Stainless SDK 头 | 80-90% | <1% | 中（可模拟，但需持续追踪版本） |
| BEH-03v2 伴随流量语义 | 75-85% | 3% | 极高（需要完整模拟 count_tokens 请求体一致性） |
| PROBE-01 工具探针 | 85-95% | <1% | 极高（需实现完整的工具执行模拟） |
| GRAPH-01 关联图 | 50-65% | 3% | 高（需要每个 cookie 完全隔离所有标识） |

### 7.3 诚实评估仍存在的盲区

1. **低频单用户单 cookie 的代码场景用户**：如果一个攻击者只用一个 cookie、低频请求、且其下游用户恰好也在做代码相关的工作，则几乎所有检测维度都会失效。这种场景下检出率可能低于 20%。

2. **SSE 中继检测的实际部署难度**：精确的 SSE event 时序测量需要在服务端记录每个 event 的生成时间戳，这对基础设施有要求。且 CDN 节点也会引入缓冲，可能产生类似中继的特征。

3. **内容画像的误报风险**：部分 Claude Code 用户确实用它来做非代码任务（如写文档、回复邮件）。BEH-05 可能对这些用户产生误报。需要设置较高的阈值和多轮观察。

4. **工具探针的可感知性**：如果反代社区发现并传播了"model-family 会注入探针工具调用"的信息，红队可以实现特殊处理（检测到探针工具名称时生成假的 tool_result）。因此探针工具的名称和格式需要定期轮换。

5. **零宽字符水印的脆弱性**：如果反代实现了文本净化（移除零宽字符），PROBE-02 完全失效。但这本身可以成为检测信号（正常客户端不会主动移除零宽字符）。

6. **图分析的冷启动**：GRAPH-01 需要积累足够的观测数据才能发现有意义的集群。在部署初期效果有限。

### 7.4 维护成本评估

| 项目 | 频率 | 工作量 |
|------|------|--------|
| CLI 版本更新同步（salt/cch/beta/stainless 版本） | 每 1-2 周 | 2-4 小时 |
| TLS/HTTP/2 指纹数据库更新 | 每月 | 4-8 小时 |
| 探针工具名称和格式轮换 | 每月 | 1-2 小时 |
| ML 模型重训练 | 每月 | 8-16 小时 |
| 蜜罐账户投放和监控 | 持续 | 4 小时/周 |
| 误报反馈审核 | 持续 | 8 小时/周 |

---

*第二轮蓝队方案结束。等待红队第二轮方案及裁判审查。*
