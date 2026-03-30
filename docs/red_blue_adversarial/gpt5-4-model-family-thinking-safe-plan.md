# GPT-5.4 Model-Family Thinking-Safe Plan

> 日期：2026-03-30
> 前提：`model-family` 不能去除
> 目标：在保留 `model-family` 的前提下，降低 Claude Code / Claude thinking 请求被中转层破坏的风险

---

## 一、这份方案为什么要单独写

之前的方案重点是：

- 把 `model-family` 尽量变透明
- 给 Claude Code 开 strict lane
- 再做粘性路由和 cookie 侧治理

但新增线索改变了优先级：

1. 使用日志几乎是串行的，说明“并发打爆 cookie”不是这次事故的首要解释
2. 日志出现了明确的协议错误：

```text
status_code=400, ***.***.content.0: Invalid `signature` in `thinking` block
```

这说明当前问题里，已经存在一个**确定性的协议破坏点**：

**Claude 的 `thinking` block 在中转链路里被改坏了。**

这件事比“有没有并发”更硬，也更应当优先处理。

---

## 二、核心判断

### 结论 1

**`thinking` 流量不能再走 Claude <-> OpenAI 兼容转换链。**

原因：

- `model-family` 在 Claude 流式响应里遇到 `signature_delta` 时，并没有保留结构化签名，而是塞进了 `reasoning_content` 占位内容
- `model-family` 在 Claude 完整响应里也只保留 `thinking` 文本，不保留 `signature`
- `clewdr` 的 OpenAI 兼容转换也同样只保留 `reasoning_content`

所以只要一条会话中：

1. 上一轮 assistant 返回了 Claude 原生 `thinking + signature`
2. 中间层把它降格为 OpenAI 风格 `reasoning_content`
3. 下一轮又试图把这段历史重新送回 Claude 原生接口

就非常容易出现：

`Invalid signature in thinking block`

### 结论 2

**`透传请求体` 是关键开关，但只能用于 Claude 原生通道。**

原因：

- 在 `relay/claude_handler.go` 中，`pass_through_body_enabled` 打开后，会直接把原始请求体送往上游 Claude 接口
- 但在 OpenAI 兼容 handler 中，raw body 仍然是 OpenAI 格式，请求目标却可能是 Claude `/v1/messages`

因此：

- `Claude 原生 lane` 开 `透传请求体` 是对的
- `OpenAI 兼容 lane` 不能靠这个开关“变成 thinking-safe”

### 结论 3

**截图里的“系统提示词 / 系统提示词拼接”对 thinking-safe lane 必须关闭。**

这是一个很容易忽略的细节。

在 `relay/claude_handler.go` 里，系统提示词注入发生在 `pass_through_body_enabled` 判断之前。也就是说：

- 即使你开启了 `透传请求体`
- 只要渠道里配置了系统提示词或系统提示词拼接
- 请求体还是会先被改写

所以 thinking-safe lane 必须满足：

- `系统提示词` 为空
- `系统提示词拼接` 关闭

---

## 三、最终架构

建议把 `model-family` 下的 Claude 相关流量拆成 **两条 lane**。

### Lane A：Claude Native / Thinking-Safe

用途：

- Claude Code CLI
- 任何会保留 Claude 原生 `thinking` 历史的客户端
- 任何需要真实回放 assistant `thinking + signature` 的会话

要求：

- 请求和响应都必须保持 Claude 原生形态
- 不经过 OpenAI 兼容格式重建
- 不经过 `reasoning_content` 文本化回写

### Lane B：OpenAI Compatibility / Non-Thinking

用途：

- 只会说 OpenAI `chat/completions` 的客户端
- 不需要回放 Claude 原生 `thinking` 历史的调用

要求：

- 不承诺支持 Claude thinking 历史回放
- 不允许把 assistant `reasoning_content` 当成 Claude thinking 历史送回上游
- 最稳妥做法是：**直接禁用 thinking 模型**

---

## 四、你截图里这些开关，应该怎么设

下面这张表就是最终建议值。

| 开关 | Lane A: Claude Native / Thinking-Safe | Lane B: OAI Compatibility / Non-Thinking | 说明 |
|------|---------------------------------------|------------------------------------------|------|
| Claude 强制 beta=true | 关 | 关 | 不是修复 `signature` 问题的手段，先减少变量 |
| 思考内容转换 | 关 | 关 | 会把 `reasoning_content` 进一步文本化，必须关闭 |
| 透传请求体 | 开 | 关 | 只对 Claude 原生通道有意义 |
| 代理地址 | 按需 | 按需 | 与本次 `signature` 问题无直接关系 |
| 系统提示词 | 留空 | 留空或极谨慎使用 | Lane A 必须留空 |
| 系统提示词拼接 | 关 | 关 | Lane A 必须关闭 |

补一句最关键的话：

**Lane A 即使开了 `透传请求体`，只要系统提示词不为空，`model-family` 还是会先改 body。**

所以 Lane A 的系统提示词必须是空。

---

## 五、`model-family` 侧的详细方案

### P0.1 建立两条独立通道

至少要分成：

1. `Claude Native / Thinking-Safe`
2. `OpenAI Compatibility / Non-Thinking`

不要再让同一条渠道同时承载：

- Claude 原生 thinking 会话
- OpenAI 兼容 chat/completions 会话

### P0.2 Lane A 只收 Claude 原生请求

这条 lane 的标准是：

- 上游入站就是 Claude 原生 body
- 下游出站也是 Claude 原生 body
- 不做 OpenAI -> Claude 的 `RequestOpenAI2ClaudeMessage()` 改写

为什么要这么严格：

- `RequestOpenAI2ClaudeMessage()` 会改 `tools`
- 会改 `system`
- 会改 `messages`
- 甚至会补 `"..."` 占位消息

这些在非 thinking 场景还只是“指纹漂移风险”，在 thinking 场景就会变成“历史语义损坏风险”。

### P0.3 Lane A 开 `透传请求体`

这条 lane 上必须开启 `pass_through_body_enabled`。

原因：

- Claude handler 中，开启后走原始 request body 直发
- 这样至少不会再走 `ConvertClaudeRequest()` 之后的重新序列化和字段重组

但要注意：

- 这只对 Claude 原生通道有意义
- 不能指望靠它让 OpenAI 兼容 lane 变 safe

### P0.4 Lane A 禁止任何 body 注入

必须全部关闭：

- `系统提示词`
- `系统提示词拼接`
- `思考内容转换`

原因：

- 前两项会直接动 body
- 后一项会改变 response 中 reasoning 的表达方式

### P0.5 Lane B 直接禁用 thinking 模型

如果某客户端只能走 OpenAI 兼容通道，那么最稳妥的方案不是“想办法让它也支持 thinking”，而是：

- 映射 `*-thinking` 到非 thinking 同款模型
- 或直接拒绝带 `-thinking` 的模型请求

因为在当前链路里，OpenAI 兼容格式没有一个稳定的结构化容器来保存 Claude `thinking.signature`。

### P0.6 两条 lane 都保持 `RetryTimes = 0`

这条不变，继续保留。

原因：

- 自动重试会放大 400/429/5xx
- 尤其是 thinking 场景下，如果 body 已经损坏，重试只会重复送错请求

### P1.1 Header passthrough 最大化

这条仍然有价值，但现在是第二优先级。

推荐尽量透传：

- `User-Agent`
- `anthropic-beta`
- `anthropic-version`
- `Origin`
- `Referer`
- `x-stainless-*`

原因：

- 它解决的是“看起来不像客户端”的问题
- 但当前最致命的问题是“thinking 历史被改坏”

所以 header passthrough 重要，但不应压过 lane 隔离。

### P1.2 做强粘性路由

建议做：

- `downstream_user/session -> 固定 model-family lane`
- `downstream_user/session -> 固定 clewdr 实例`
- `downstream_user/session -> 固定上游主体`

这条继续保留。

但现在它的定位从“修 thinking 签名错误”变成了“减少会话漂移和主体聚合噪声”。

### P1.3 做主体级限流

如果 `model-family` 必须保留，就不要只按下游用户限流。

至少要在逻辑上感知：

- 上游账号
- 上游组织
- 上游 cookie

否则多人串行轮流打一个主体，仍然会形成明显的主体级异常。

---

## 六、`clewdr` 侧的详细方案

新增 `signature` 线索后，`clewdr` 的优先级也有调整。

### P0

1. 对 OpenAI 兼容链路，谨慎对待 thinking
   - 如果会话需要回放 previous assistant thinking 历史，不要走 OAI 兼容通道

2. 对 `count_tokens` / usage / `1M probe` 先保持保守
   - 先减少额外变量

### P1

1. cookie 租约
2. per-cookie single-flight
3. 429 预防性冷却

这些仍然该做，但它们不再是这次事故的最强解释。

原因很简单：

- 你现在已经看到串行日志
- 又看到了确定性的 400 协议错误

所以这次更像：

**先有协议层损坏，再叠加主体级聚合风险**

而不是：

**纯粹因为并发把 cookie 打爆**

### P1.1 为什么“日志基本串行”了，还是要做 cookie 串行化

这是一个容易误判的点。

虽然你现在看到的顶层调用日志几乎是串行的，但这并不意味着 cookie 层没有竞争风险。原因有三类：

1. **隐藏并发**
   - 顶层 chat 请求看起来串行，不代表内部没有额外请求
   - 当前 `clewdr` 里同一轮逻辑请求可能还会触发：
     - `get_organization`
     - `exchange_code`
     - `exchange_token`
     - `refresh_token`
     - `count_tokens`
     - `1M probe`

2. **会话漂移**
   - 现在的 cookie 分配并不是“租出去就占住”
   - `dispatch()` 命中缓存后直接返回 clone，没有占用态
   - `system_prompt_hash` 也会影响 cookie 命中

3. **未来量变**
   - 即使这次事故不是并发主因，后续只要流量稍微升高
   - 当前 cookie actor 的行为就会立刻变成新的放大器

所以：

**cookie 串行化现在不是事故的第一解释，但仍然是必须补的防御性设计。**

### P1.2 当前代码里，为什么需要这套设计

当前代码里有三处直接支撑这个设计：

1. `src/services/cookie_actor.rs`
   - `dispatch()` 只是返回 cookie clone，不建立租约

2. `src/middleware/claude/request.rs`
   - Claude Code 请求会计算 `system_prompt_hash`

3. `src/claude_code_state/chat.rs`
   - 取到 cookie 后，可能继续跑 token 检查、authorize、refresh 等状态流

换句话说，当前的问题不是“完全没有 cookie 管理”，而是：

**有 cookie 管理，但没有“占用 / 串行 / single-flight”这三层保护。**

### P1.3 目标状态

新的目标状态不是“尽量平均分配 cookie”，而是：

1. **一个活跃会话在同一时刻只占一个 cookie**
2. **一个 cookie 在同一时刻只服务一个活跃 Claude Code 会话**
3. **同一 cookie 上所有认证状态变更都走 single-flight**
4. **`system_prompt_hash` 只作为提示，不再是强绑定依据**

### P1.4 设计总览

建议拆成两层。

#### 第一层：Cookie Lease（会话租约层）

用途：

- 保证同一 cookie 不被多个会话同时拿走
- 保证同一会话在整个对话周期内尽量稳定地复用同一个 cookie

建议状态结构：

```text
ManagedCookie {
  cookie_id
  upstream_subject_id
  leased_to_session
  lease_id
  lease_expires_at
  cooldown_until
  queue_len
  health_state
}
```

关键规则：

- `leased_to_session == null` 时，cookie 才能被新会话拿走
- 同一 session 再次请求时，可以续租原 cookie
- 不同 session 命中同一 cookie 时，要么排队，要么快速失败

#### 第二层：Auth Single-Flight（认证状态层）

用途：

- 防止同一个 cookie 上重复执行状态变更请求

必须纳入 single-flight 的操作：

- `get_organization`
- `exchange_code`
- `exchange_token`
- `refresh_token`
- `count_tokens_allowed` 状态刷新
- `claude_1m_support` 状态刷新

这一层的目标不是“限制业务请求数量”，而是：

**保证同一 cookie 的认证状态变更永远串行。**

### P1.5 Lease 的详细规则

#### 规则 1：分配依据从 hash 优先改成 session 优先

当前更合理的顺序应该是：

1. 先看 `session -> cookie` 现有绑定
2. 没有现有绑定时，再考虑 `system_prompt_hash` 作为提示
3. 最后才做池内选择

原因：

- `system_prompt_hash` 适合做“可能相关”的弱提示
- 不适合做长期强绑定
- 真正稳定的绑定单位应该是 `downstream session`

#### 规则 2：同一 cookie 只允许一个活跃 session

严格模式下：

- `max_active_sessions_per_cookie = 1`

不要做“偶尔放两个”的灰色模式。

因为这会让整个设计从“确定性串行”重新退回“不知道什么时候撞车”。

#### 规则 3：队列要浅，不要深

建议：

- 同 cookie 排队长度最多 `1`
- 等待时间最多 `2-5 秒`
- 超时直接返回 `429` 或 `503`

不要让 `clewdr` 在本地排很深的队列。

原因：

- 深队列只会隐藏问题
- 也会把上游冷却、429、会话超时全堆在一起

### P1.6 Single-Flight 的详细规则

#### 规则 1：认证状态和业务请求分开锁

不要用一把全局大锁把整个 cookie 全锁死。

建议拆成：

1. `lease lock`
   - 保护 cookie 是否被某个 session 占用

2. `auth lock`
   - 保护 token / bootstrap / refresh / capability probe

这样做的原因是：

- lease 关注“谁能用”
- auth 关注“状态怎么变”

语义更清楚，也更容易调试。

#### 规则 2：refresh 失败不要立即重复打

对同一 cookie：

- 一次 refresh 失败后，写入短冷却
- 冷却窗口内不要再次尝试同类操作

否则即使外部日志是串行的，内部也会形成“失败 -> 重试 -> 再失败”的局部风暴。

### P1.7 流式请求的生命周期

流式请求要额外处理好 lease 生命周期。

建议规则：

1. 发送上游请求前获取 lease
2. 流开始后定期续租
   - 比如每 `15-30 秒` 刷新一次 `lease_expires_at`
3. 在以下时机释放 lease
   - SSE 正常结束
   - 客户端断开
   - 明确错误返回
   - watchdog 检测到超时

如果没有 watchdog，进程异常或客户端异常断开后，cookie 很容易被“永久占住”。

### P1.8 与 `model-family` 的配合方式

这套设计不能只在 `clewdr` 里自说自话，还要和 `model-family` 对齐。

建议做法：

1. `model-family` 先确定稳定的 `downstream session key`
2. 这个 session key 传给 `clewdr`
3. `clewdr` 以这个 session key 做 lease 绑定

推荐的绑定链：

```text
downstream_user/session
  -> model-family lane
  -> fixed clewdr instance
  -> fixed cookie lease
```

如果 `model-family` 自己还在随机漂移实例或主体，`clewdr` 的 lease 设计价值会被削弱。

### P1.9 观测与日志

这套设计必须配日志，不然很难知道它到底有没有起作用。

至少记录：

- `request_id`
- `downstream_session`
- `cookie_id`
- `lease_id`
- `lease_acquire_ms`
- `queue_wait_ms`
- `auth_singleflight_hit`
- `refresh_attempt`
- `count_tokens_remote/local`
- `1m_probe_attempt`

重点不是日志多，而是：

**能把一次请求完整追到“它拿了哪个 cookie、等了多久、有没有撞上认证状态流”。**

### P1.10 推荐的落地顺序

建议按这个顺序做：

1. 先补日志
2. 再补 lease
3. 再补 auth single-flight
4. 最后再考虑让 `system_prompt_hash` 降级为 hint

不要一上来同时改所有逻辑。

因为这样你很难分辨：

- 是 lease 起作用了
- 还是 single-flight 起作用了
- 还是只是流量刚好低了

---

## 七、立即执行清单

下面这份清单是“今天就可以做”的。

### 今天必须做

1. 新建一条 `Claude Native / Thinking-Safe` 渠道
2. 这条渠道设置：
   - `Claude 强制 beta=true = 关`
   - `思考内容转换 = 关`
   - `透传请求体 = 开`
   - `系统提示词 = 空`
   - `系统提示词拼接 = 关`
3. 所有 Claude Code / Claude 原生 thinking 会话切到这条渠道
4. OpenAI 兼容渠道直接禁用 thinking 模型
5. `RetryTimes` 保持 `0`

### 本周内完成

1. header passthrough 配齐
2. sticky route 配齐
3. 按上游主体做限流和统计
4. `clewdr` 侧把 cookie 租约和 single-flight 补上
5. `system_prompt_hash` 从强粘连降级为弱提示

---

## 八、验证方法

修完以后，不要只看“能不能出字”，要看这三类验证。

### 验证 1：thinking-safe lane 不再出现 400 签名错误

方法：

1. 用会返回 thinking 的模型发起一轮对话
2. 取 assistant 历史继续追问下一轮
3. 确认不再出现：

```text
Invalid `signature` in `thinking` block
```

### 验证 2：OpenAI 兼容 lane 不再允许 thinking 历史回放

方法：

1. 对 OAI lane 发 `-thinking` 模型
2. 预期：
   - 被模型映射到非 thinking
   - 或直接被拒绝

### 验证 3：Lane A 没有被偷偷改 body

重点检查：

- 渠道系统提示词是否为空
- 是否仍在做系统提示词拼接
- `透传请求体` 是否真的开启

---

## 九、一句话结论

在 `model-family` 不能去掉的前提下，真正的止血方案不是“继续优化一条通用中转链”，而是：

**把 Claude thinking 会话从兼容转换链里剥离出来，做成一条 `Claude 原生 + 透传请求体 + 零系统注入` 的 thinking-safe lane。**

如果做不到这条 lane，那么在 `model-family` 路径上最现实的临时方案就是：

**先禁用 thinking 模型。**
