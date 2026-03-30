# GPT-5.4 Review

> 日期：2026-03-30
> 范围：`round5_red_team.md`、`round5_referee_final.md`、当前 `clewdr` / `model-family` 代码
> 目标：评估红队最终方案是否抓住了这次真实事故的主要根因，并给出更贴近当前代码现实的修复优先级

---

## 一、结论

红队最终方案的**战略方向是对的**：

- 接受 `1:1` 是唯一可持续模式
- 去掉 `model-family` 中间层是最务实的单点建议
- 将 `clewdr` 的定位从“省钱工具”调整为“兼容性网关”是成熟判断

但如果目标是解释这次“多人使用 20 小时内被取消套餐/封禁”的真实事故，并指导第一批修复，红队方案的 **P0 优先级排布不够准确**。

当前代码里最强、最直接、最能解释事故的触发器，不是 JSON 顺序、probe、甚至也不只是 `model-family`，而是：

1. **同 cookie 可被并发重复借出**
2. **`system_prompt_hash` 会把多个相似 Claude Code 请求粘到同一个 cookie**
3. **同一 cookie 上没有 token refresh / authorize / count_tokens 的 single-flight 保护**
4. **现有代码已经存在不少额外协议流量，再继续补“伴随流量”可能先放大风险**

换句话说：

**红队方案方向正确，但对当前代码里的“现势 P0”识别还不够狠。**

---

## 二、主要发现

### Finding 1（最高优先级）

**红队没有把“同 cookie 并发复用 + hash 粘连”明确提升为 P0。**

红队在 Layer 2 中提到 Cookie 池管理和用户绑定，但落点仍偏抽象，缺少对当前实现缺陷的直接命名和优先级强调。

文档位置：

- `docs/red_blue_adversarial/round5_red_team.md:88`
- `docs/red_blue_adversarial/round5_red_team.md:101`

当前代码问题更具体，也更危险：

- `src/services/cookie_actor.rs:184` 的 `dispatch()` 命中缓存后直接返回 clone，不标记占用，不建立租约
- `src/middleware/claude/request.rs:383` 会按 `system` 中可缓存块计算 `system_prompt_hash`
- `src/claude_code_state/mod.rs:119` 请求 cookie 时会带上这个 hash

这意味着多人使用时，只要 system prompt 足够相似，就可能长期命中同一 cookie；而且这个 cookie 还能被并发借出，导致同一账号上出现并发消息、并发换 token、并发 `count_tokens`。

这条链路对“单人长期稳定，多人 20 小时内出事”的解释力极强，应当是 **P0 中的 P0**。

### Finding 2（高优先级）

**文档中若干“已落地”判断与当前代码不一致。**

最明显的一处是 `anthropic-beta` 白名单。

文档写法：

- `docs/red_blue_adversarial/round5_red_team.md:56`
- `docs/red_blue_adversarial/round5_red_team.md:489`

当前代码实际情况：

- `src/middleware/claude/request.rs:195` 的 `extract_anthropic_beta_header()` 只是提取和拼接，没有白名单
- `src/claude_code_state/chat.rs:615` 的 `merge_anthropic_beta_header()` 会把 `CLAUDE_BETA_OAUTH` 合并进普通消息请求
- `src/claude_code_state/chat.rs:23` 注释又明确写了 OAuth beta “used only in token exchange flows”

这说明文档对“哪些已经做好，哪些只是建议”区分得还不够严。

### Finding 3（高优先级）

**红队高估了“补 API 初始化 / 补 companion count_tokens”在当前代码阶段的净收益。**

文档建议：

- 首次使用先做 `GET organizations -> GET models -> count_tokens`
- 每 1-3 轮插入一次 `count_tokens`

文档位置：

- `docs/red_blue_adversarial/round5_red_team.md:94`
- `docs/red_blue_adversarial/round5_red_team.md:502`

但当前 `clewdr` 其实已经不“轻”了：

- `src/claude_code_state/chat.rs:62` 会做 token 检查与换取
- `src/claude_code_state/chat.rs:246` 还有 usage 请求路径
- `src/claude_code_state/chat.rs:289` 有 `count_tokens`
- `src/claude_code_state/chat.rs:139` / `src/claude_code_state/chat.rs:384` 还有 `1M` probe/fallback

在没有先解决 per-cookie 串行化之前，继续人为增加“更像客户端”的附加请求，可能先把问题放大，而不是先把风险降下来。

### Finding 4（中高优先级）

**“去掉 model-family”是对的，但它不是唯一根因，也不应遮蔽 clewdr 内部并发缺陷。**

红队与裁判都把 `model-family` 定为 30% 左右的根因，这个方向成立。

文档位置：

- `docs/red_blue_adversarial/README.md:48`
- `docs/red_blue_adversarial/round5_red_team.md:135`
- `docs/red_blue_adversarial/round5_referee_final.md:157`

代码侧也支持这一点：

- `model-family/relay/channel/api_request.go:28` 默认只补基础头
- `model-family/relay/channel/claude/adaptor.go:51` 会自行设置 Claude 头
- `model-family/relay/common/relay_info.go:469` 虽然保留原始请求头，但不是天然透明透传

但需要强调的是：

**即使完全拿掉 `model-family`，当前 clewdr 的同 cookie 并发复用问题依然存在。**

所以正确表达应当是：

- `model-family` 是“放大器”
- `clewdr` 内部 cookie/refresh 争抢是“底层火源”

### Finding 5（中优先级）

**红队最成熟、最值得采纳的部分，是它对边界的承认。**

这些判断我基本认同：

- 多用户共享最终会被逼到 `1:1`
- 经济学是决定性战场
- `clewdr` 更适合作为兼容性/访问层

文档位置：

- `docs/red_blue_adversarial/round5_red_team.md:321`
- `docs/red_blue_adversarial/round5_red_team.md:330`
- `docs/red_blue_adversarial/round5_red_team.md:583`

这是整份方案里最成熟的部分，因为它不再假设“通过足够多的协议拟态就能把多人共享稳定伪装成单用户”。

---

## 三、我对优先级的重排

下面这版更贴近当前代码现实，也更适合作为真实修复路线。

### P0：先止血

1. **给 cookie 加租约 / 占用态**
   - 同一时刻一个 cookie 只能被一个活跃 Claude Code 会话持有
   - 至少先做到 “不可并发借出”

2. **给 per-cookie token 流程加 single-flight**
   - `authorize`
   - `exchange_token`
   - `refresh_token`
   - `count_tokens` 权限状态刷新

3. **降低附加协议流量**
   - 在稳定前，谨慎对待自动 `count_tokens`
   - 在稳定前，谨慎对待 usage 查询
   - 在稳定前，谨慎对待 `1M` probe/fallback

4. **从 Claude Code 链路中移除 `model-family`**
   - 直连 `clewdr`
   - 或只保留纯 TCP 层代理

### P1：修正明显指纹问题

1. **真正实现 `anthropic-beta` 白名单**
2. **不要把 OAuth beta 合并到普通消息请求**
3. **重新审视 billing/system 注入策略**
4. **补 429 预防性降速与 cookie 冷却**

### P2：再做拟态增强

1. **RequestNormalizer**
2. **JSON key 顺序审计**
3. **版本自动追踪**
4. **必要时再评估 API 初始化序列是否值得补**
5. **必要时再做 probe 标签检测**

关键原则是：

**先解决“多人共享导致同一 cookie 被打爆”的真实问题，再解决“请求长得像不像”的拟态问题。**

---

## 四、对红队方案的总体评价

### 我认同的部分

- 战略转向是正确的
- 去掉 `model-family` 是最务实的单点建议
- 接受 `1:1` 是诚实且成熟的判断
- 对经济学边界的承认比继续堆“完美伪装”更有价值

### 我不认同或保留意见的部分

- 对当前代码里并发 cookie 复用问题强调不够
- 若干“已落地”描述与代码不完全一致
- 对 companion `count_tokens` / 初始化流量的收益估计偏乐观
- 过早把注意力放在 JSON 顺序、probe、NLP 分流等次级问题上

### 最终判断

**这份红队方案适合当“长期定位文档”，不适合直接当“当前事故第一版修复单”。**

如果要把它变成真正能指导你下一步改代码的版本，需要补上一句最重要的话：

> 当前事故的第一根因，不是“还不够像 Claude Code”，而是“多人流量在 clewdr 内部被错误地复用到同一个 cookie，并在 OAuth / count_tokens / probe 上发生争抢”。  

---

## 五、建议的后续动作

如果继续推进，建议按这个顺序：

1. 先补观测
   - 记录 `request_id -> user/session -> system_prompt_hash -> cookie_id -> in_flight`
   - 记录 per-cookie 的 `authorize / refresh / count_tokens / 1M probe`

2. 再补控制
   - cookie 租约
   - per-cookie single-flight
   - 429 预防性冷却

3. 最后补拟态
   - beta 白名单
   - JSON 顺序
   - RequestNormalizer
   - API 初始化序列

---

## 六、一句话结论

**红队方案的方向是成熟的，但当前版本对你这次真实事故的 P0 命中还差最后一刀。那一刀就是：把“同 cookie 并发复用 + hash 粘连 + token/count_tokens 争抢”明确升到最高优先级。**
