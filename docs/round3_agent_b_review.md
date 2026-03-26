# Round 3 - Agent B: V3 评审 + 自我修正

## 指数退避撤回验证

**结论维持：per-request 退避无意义，但补充并发场景考量。**

重试循环中 429 → `return_cookie` → exhausted → `continue` → 新 cookie。pool 空时 `dispatch` 返回 `NoCookieAvailable`，重试循环立即终止（非 `InvalidCookie`，不 `continue`）。

**新发现的并发风险**：N 个并发请求同时 `dispatch`，可能在毫秒内各自拿到不同 cookie，然后全部被 429——瞬时耗尽而非加速耗尽。需要"池水位保护"而非退避。

## state/self 不同步 Bug 确认

**确认为真实 P0 bug。**

`transform_response` 中：
- `self.cookie` = None → `persist_usage_totals` 跳过 → usage 统计丢失
- `self.last_params` = None → `try_code_count_tokens` 返回 None → token 计数失效

注意 `ClaudeCodeState::try_chat` **不受此影响**——它的流程不同。

## Cookie-Proxy 亲和性重评

**在当前单 proxy 架构下是伪需求。** 所有 cookie 天然绑定同一 proxy，亲和性无从谈起。需先实现 proxy 池。

`CookieStatus` 的 `PartialEq`/`Hash`/`Ord` 只基于 `cookie` 字段（cookie.rs:132-156），新增 `proxy` 字段不影响集合行为——向后兼容。

## 最终优先级

| 优先级 | 项目 | 状态 |
|--------|------|------|
| **P0** | try_chat state/self bug | 两方一致确认 |
| P1 | 并发池水位保护 | `dispatch` 中加最小 valid 阈值检查 |
| P1 | Bootstrap 缓存 | 减少请求模式指纹 |
| P2 | Proxy 池基础设施 | 多 proxy 配置支持 |
| P2 | Per-cookie Emulation 绑定 | 同一 cookie 同一 TLS 指纹 |
| P3 | Cookie-Proxy 亲和性 | 依赖 P2 |
| P3 | SUPER_CLIENT Emulation | 防御性修复 |
| P3 | Emulation 多样化 | 收益有限 |
