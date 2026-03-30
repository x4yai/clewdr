# GPT-5.4 Review - Keep model-family

> 日期：2026-03-30
> 前提：`model-family` 不能去除
> 目标：在保留 `model-family` 的情况下，将 Claude Code 链路的破坏性降到最低，并给出可实施的改造顺序

---

## 一、结论

如果 `model-family` 必须保留，正确目标不是“继续让它做 Claude 协议适配，然后尽量伪装”，而是：

**让 `model-family` 在 Claude Code 这条链路中，从“协议改写层”退化为“鉴权 / 配额 / 粘性路由 / 审计层”。**

也就是说：

- `model-family` 可以保留
- 但 Claude Code 这条 lane 上，`model-family` 应尽量少改 body、少改 header、少重试、少切换上游
- 所有需要“拟态 Claude Code”的事情，尽量收敛到 `clewdr`

这是因为 `model-family` 当前的 Claude 链路默认并不透明：

- Claude 请求会经过 `ClaudeHelper`
- 可能走请求转换、参数覆盖、system prompt 注入、模型映射
- 默认也存在统一的 relay/retry/选路逻辑

相关代码位置：

- `model-family/relay/claude_handler.go:24`
- `model-family/relay/claude_handler.go:112`
- `model-family/relay/claude_handler.go:129`
- `model-family/controller/relay.go:199`

---

## 二、推荐的目标拓扑

推荐拓扑如下：

```text
Client
  -> model-family
       (auth / quota / sticky routing / audit only)
  -> clewdr /code strict lane
  -> Claude API
```

不推荐的拓扑：

```text
Client
  -> model-family
       (OpenAI/Claude body conversion + param override + retries)
  -> clewdr
  -> Claude API
```

核心原则：

1. `model-family` 保留，但只做“控制面”
2. Claude Code lane 上避免二次语义转换
3. 同一用户会话固定到同一 `clewdr` 实例、同一上游主体
4. 先修“并发争抢”和“中间层破坏”，再修“长得像不像”

---

## 三、model-family 侧的详细方案

### 3.1 新增一条 `Claude Code Strict Lane`

为 Claude Code 流量新增专门 lane，不与普通聊天 / RP / 通用 OpenAI 兼容流量混用。

建议要求：

- 使用 Claude relay format
- 开启 channel 级 `PassThroughBodyEnabled`
- 关闭这条 lane 上的 system prompt override
- 关闭 param override
- 关闭 model mapping，或只允许恒等映射
- 关闭 “chat via responses” 之类的额外转换捷径

原因：

- `ClaudeHelper` 在 `PassThroughBodyEnabled` 打开时，能够直接使用原始请求体，而不是重新 `Marshal` 转换后的请求
- 这是当前代码里最接近“保留 model-family 但减少 body 破坏”的现成能力

关键代码：

- `model-family/relay/claude_handler.go:129`
- `model-family/relay/claude_handler.go:130`
- `model-family/relay/claude_handler.go:137`

需要注意：

- 即使打开了 `PassThroughBodyEnabled`，`ClaudeHelper` 前面仍然会经过模型映射、system prompt 注入判断、responses 分支判断
- 所以 strict lane 不能只开 pass-through，还要把这些“可能改请求”的功能一起收住

关键代码：

- `model-family/relay/claude_handler.go:39`
- `model-family/relay/claude_handler.go:87`
- `model-family/relay/claude_handler.go:112`

### 3.2 不要让这条 lane 走当前重转换逻辑

当前 `RequestOpenAI2ClaudeMessage()` 的改写很重，包括：

- 重写 tools schema
- 重写 system 消息结构
- 重写 messages 结构
- 在某些情况下插入 `"..."` 占位 user message

关键代码：

- `model-family/relay/channel/claude/relay-claude.go:47`
- `model-family/relay/channel/claude/relay-claude.go:268`
- `model-family/relay/channel/claude/relay-claude.go:294`
- `model-family/relay/channel/claude/relay-claude.go:310`

结论：

**Claude Code strict lane 不应依赖这条转换链作为常态路径。**

如果客户端本来就发 Claude 风格请求，应优先保留原始 body；如果客户端发 OpenAI 风格请求，也应优先只做一次必要转换，避免 `model-family -> clewdr` 双重改写。

### 3.3 头部透传要显式配置

`model-family` 当前具备 header passthrough 机制，支持：

- `*`
- `re:` / `regex:`
- `{client_header:<name>}`

关键代码：

- `model-family/relay/channel/api_request.go:163`
- `model-family/relay/channel/api_request.go:168`
- `model-family/relay/channel/api_request.go:219`
- `model-family/relay/channel/api_request.go:260`

对 Claude Code strict lane，至少应考虑保留：

- `User-Agent`
- `anthropic-beta`
- `anthropic-version`
- `Origin`
- `Referer`
- `Accept`
- `Content-Type`
- `x-stainless-*`（如果客户端会带）

这里的目标不是“完全不动任何 header”，而是：

**让 `model-family` 明确知道哪些头必须来自客户端原值，不能再靠默认逻辑猜。**

### 3.4 禁用重试和跨 channel 漂移

Claude Code strict lane 上，`RetryTimes` 必须保持 `0`，不要让 `model-family` 在 4xx/5xx/429 后自动重放请求。

关键代码：

- `model-family/common/constants.go:114`
- `model-family/controller/relay.go:199`
- `model-family/controller/relay.go:257`

原因：

- 重试会放大本来已经敏感的上游行为
- 重试还可能触发跨 channel / 跨实例切换，使同一会话的上游画像更混乱

建议：

- Claude Code strict lane 独立配置“永不自动重试”
- 出错优先向下游返回，而不是代为补发

### 3.5 做强粘性路由，不做按请求级别均衡

这一层是保留 `model-family` 时最重要的补偿措施之一。

建议：

- `downstream_user_id/session_id -> 固定 clewdr instance`
- `clewdr instance -> 固定上游账号池`
- 同一会话内不要跨实例迁移
- 同一实例内不要让会话在多个上游主体之间漂移

原则：

**负载均衡可以发生在“用户/会话分配时”，不要发生在“每个请求发出时”。**

否则你会得到：

- 同一会话命中多个 `clewdr`
- 多个 `clewdr` 又去抢同一上游 cookie
- 整体画像比单点部署更乱

### 3.6 限流必须向“上游主体”靠拢

保留 `model-family` 时，限流不能只按下游 userId。

需要补的不是“更细的前台配额”，而是“更接近上游 Anthropic 主体的保护阀”。

建议至少增加以下键之一：

- `upstream_account_id`
- `upstream_org_id`
- `upstream_cookie_id`
- `clewdr_instance + upstream_cookie_id`

控制目标：

- 每小时请求数
- 每小时 token 量
- 并发数
- `count_tokens` / `messages` 比例
- 429 冷却窗口

---

## 四、clewdr 侧的详细方案

即使 `model-family` 保留，这部分仍然是必须修的。

### 4.1 给 cookie 加租约

当前 `dispatch()` 命中缓存后直接返回 clone，不记录 in-flight，不建立占用态。

关键代码：

- `clewdr/src/services/cookie_actor.rs:184`

必须改成：

- 一个活跃 Claude Code 会话持有一个 cookie
- cookie 在归还前不可再次借出
- 至少先保证“同一 cookie 不被并发命中”

### 4.2 给 per-cookie token 流程加 single-flight

当前同一 cookie 上可能并发发生：

- `authorize`
- `exchange_token`
- `refresh_token`
- `count_tokens` 权限状态更新
- `1M` 支持状态刷新

相关代码：

- `clewdr/src/claude_code_state/chat.rs:62`
- `clewdr/src/claude_code_state/chat.rs:289`
- `clewdr/src/claude_code_state/chat.rs:371`
- `clewdr/src/claude_code_state/chat.rs:615`

建议：

- 为每个 cookie 建立单独的 async mutex / single-flight registry
- token 类流程只允许一个请求在飞
- 其他并发请求等待结果，不重复向上游打

### 4.3 重新审视 `system_prompt_hash` 粘连

当前请求 cookie 时会带 `system_prompt_hash`，而这个 hash 来源于 system 中带 `cache_control` 的块。

相关代码：

- `clewdr/src/middleware/claude/request.rs:383`
- `clewdr/src/claude_code_state/mod.rs:119`

这在“多人共享 + 相似客户端”场景下很容易让多个用户长期粘到同一个 cookie。

建议：

- 如果是共享部署，默认降低这条粘性策略的优先级
- 或把 hash 只作为弱偏好，不作为强绑定
- 前提仍然是 cookie 租约先落地

### 4.4 暂时压低附加协议流量

在稳定前，对以下行为采取保守策略：

- 自动 `count_tokens`
- usage 拉取
- `1M` probe/fallback

相关代码：

- `clewdr/src/claude_code_state/chat.rs:139`
- `clewdr/src/claude_code_state/chat.rs:246`
- `clewdr/src/claude_code_state/chat.rs:289`
- `clewdr/src/claude_code_state/chat.rs:384`

原因：

- 当 `model-family` 还在前面时，这些额外请求更容易被放大成高频协议噪音
- 在租约和 single-flight 没落地前，先减压比先拟态更重要

---

## 五、推荐的实施顺序

### P0：必须先做

1. `model-family` 新增 Claude Code strict lane
2. strict lane 开启 `PassThroughBodyEnabled`
3. strict lane 关闭 retries
4. strict lane 关闭 system override / param override / model mapping / responses 分支
5. `model-family` 做 user/session 级粘性路由
6. `clewdr` 补 cookie 租约
7. `clewdr` 补 per-cookie single-flight

### P1：本月内完成

1. `model-family` 显式配置关键 header passthrough
2. `model-family` 增加上游主体感知限流
3. `clewdr` 收紧自动 `count_tokens` / usage / 1M probe
4. `clewdr` 实现 429 预防性冷却

### P2：稳定后再做

1. `clewdr` 的 beta 白名单
2. `clewdr` 的 JSON 顺序审计
3. `clewdr` 的 RequestNormalizer
4. API 初始化序列补齐

---

## 六、验证方案

### 6.1 透传验证

验证目标：

- `model-family` strict lane 是否真的没有重写 Claude Code body
- 关键 headers 是否保留原值
- 是否仍有额外 responses / param override / system override

建议记录：

- 进入 `model-family` 前的 body hash
- `model-family` 发往 `clewdr` 前的 body hash
- 关键 header 快照
- `use_channel` 链路长度

成功标准：

- body hash 一致
- `use_channel` 长度始终为 1
- 同一会话不跨实例

### 6.2 并发验证

验证目标：

- 同一 cookie 是否仍被并发借出
- 同一 cookie 是否仍出现并发 refresh / exchange / count_tokens

建议记录：

- `request_id`
- `session_id`
- `system_prompt_hash`
- `cookie_id`
- `in_flight_count`
- `token_refresh_in_flight`

成功标准：

- 任一时刻同 cookie 的活跃会话数 <= 1
- token 流程 single-flight 命中率接近 100%

### 6.3 行为验证

观察 48-72 小时：

- 429 频率
- 上游错误率
- 单 cookie 请求数
- 单 cookie token 消费量
- `count_tokens/messages` 比例

目标：

- 先让错误率和 429 降下来
- 再评估是否需要继续做更重的拟态增强

---

## 七、不能自欺的边界

即使全部按上面做完，下面这些边界仍然存在：

1. `model-family` 仍然是额外一层，理论上总会增加复杂度和风险
2. 多用户共享同一上游主体，仍然存在账号/组织级聚合风险
3. `clewdr` 当前并不是为“大规模共享多租户”设计的，需要主动补控制面
4. 如果 `model-family` 未来继续给 strict lane 增加新的 body 级转换，风险会重新升高

所以这份方案的真实目标不是“做到完全不可见”，而是：

**在不能去掉 `model-family` 的前提下，把它对 Claude Code 链路的伤害压到最低。**

---

## 八、一句话结论

**保留 `model-family` 不是不能做，但前提是把它从“Claude 协议改写器”改造成“尽量透明的前置控制层”；否则你修多少 `clewdr`，中间层都会持续把画像重新打坏。**
