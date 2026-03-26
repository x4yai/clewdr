# Round 4 - Agent B: 最终质量评审

## P0 Bug 确认

**确认为真实 bug。** `claude_web_state/chat.rs` 第 50 行 `self.transform_response(r)` 应改为 `state.transform_response(r)`。

### 影响
- `self.cookie` = None → `persist_usage_totals` 跳过 → **usage 统计完全失效**
- `self.last_params` = None → `try_code_count_tokens` 返回 None → **token 计数失效**
- 非 streaming 模式同样受影响

### Claude Code 路径
**不受影响。** `send_chat` 内部调用 `self.handle_success_response()`，此处 `self` 就是 `state`。

### 修复安全性
改一个词即可，`state` 是 `self` 的完整克隆 + request 阶段写入的状态。**不存在"修一个 bug 引入两个新 bug"的风险。**

---

## Bootstrap 缓存评审

**降级为 P3。** 当前无缓存、无风险，只有性能损耗。加缓存的一致性风险（stale 数据）需要仔细处理。建议先修 P0，缓存后续视需求决定。

---

## 池水位保护评审

**不需要。** 原因：
- 当前不是"借出-归还"模式，cookie 用完立即 push_back
- 只有 429/ban 时才移入 exhausted
- 单 cookie 场景完全合法
- 无误判风险

---

## 其他发现

### streaming usage spawn 竞态（P3）
`claude_code_state/chat.rs` 第 483-489 行 `tokio::spawn` 做 usage 持久化，可能与新请求的 `return_cookie` 竞争。ractor 单线程 Actor 保证无数据竞态，但消息顺序可能导致旧 usage 覆盖新 usage。轻微 usage 不准确，不影响功能。

### `CookieStatus` 的 PartialEq/Hash 只看 cookie 字段
`exhausted.insert(cookie)` 如果已存在同 cookie 的条目，新 usage 数据被丢弃。设计决策，非 bug。

---

## 最终判定

| 问题 | 严重程度 | 行动 |
|------|---------|------|
| `self.transform_response` → `state.transform_response` | **P0** | 立即修复 |
| Bootstrap 缓存 | P3 | 可选优化 |
| 池水位保护 | N/A | 不需要 |
| streaming usage 竞态 | P3 | 可接受 |

**核心结论：唯一需要立即修复的是 P0 bug——改一个词。其余均为可选优化。**
