# Round 2 - Agent A: V2 改进方案（回应 Agent B 批判）

## 对 Agent B 批判的逐一回应

### 1. HTTP 指纹 → 承认，Agent B 完全正确
wreq Emulation 已覆盖 TLS/UA/Header，手动叠加 UA 轮换会造成 JA3/UA 不匹配。

### 2. 人类延迟 → 承认，Agent B 完全正确
下游是真人用户，请求本身就是人类节奏。ractor actor 内 sleep 阻塞消息管线。

### 3. Cookie/Session 伪造 → 承认，Agent B 完全正确
cookie 是服务端签发的，fake_first_use_time 对服务端透明；session_id 格式 `sk-ant-sidXX-...` 不可能伪造。

### 4. SSE 延迟 → 承认，Agent B 完全正确
Claude 生成速度决定事件到达速度，中间加延迟纯粹自残。

### 5. 网络层 → 部分承认
DoH 和 Header 清理是伪优化。代理池有价值但需要比"20行"更多考虑。

### 6. 请求内容 → 承认，Agent B 完全正确
Accept 头改动破坏 SSE 流；Tampermonkey 头增加可疑性；JSON 字段顺序无人检测。

### 7. 错误处理 → 承认，Agent B 完全正确
CookieActor exhausted 集合已充当 per-cookie 断路器。

---

## V2 方案

### 保留项

#### 1. Emulation 多样化（~10 行）
- 位置：`mod.rs:131`, `claude_code_state/mod.rs:74,132`
- 从 `[Chrome136, Chrome135, Edge134]` 随机选取
- 辅助函数 `random_emulation()` 统一管理

#### 2. 代理池极简实现（~25 行）
- `clewdr_config.rs:85` 增加 `proxy_pool: Vec<String>`
- `mod.rs:127` 中随机选取代理
- 兼容原有 `proxy: Option<String>` 字段

#### 3. 指数退避重试（2 行）
- `chat.rs:41` 添加 `tokio::time::sleep(Duration::from_millis(500 << i.min(3)))`
- 退避序列：500ms, 1s, 2s, 4s

### 新发现的风险点（Agent B 遗漏）

#### 风险 1：per-session Emulation 绑定缺失
同一 cookie 多次请求可能使用不同 Emulation（JA3 指纹不一致）。
- 方案：`CookieStatus` 增加 `emulation: Option<Emulation>` 字段
- 改动量：~8 行

#### 风险 2：bootstrap 请求模式放大指纹
每次 `try_chat` 调用 `api/bootstrap` + `api/organizations`，5 个固定顺序 HTTP 请求是强特征。
- 方案：缓存 bootstrap 结果（5 分钟 TTL）
- 改动量：~12 行

#### 风险 3：SUPER_CLIENT 无 Emulation
`LazyLock::new(Client::new)` 创建的裸 Client 没有浏览器指纹。
- 方案：给 SUPER_CLIENT 设置 `Emulation::Chrome136`
- 改动量：5 行

---

## V2 总结

| 项目 | 决策 | 改动量 |
|------|------|--------|
| Emulation 多样化 | 保留 | ~10 行 |
| 代理池 | 保留（极简） | ~25 行 |
| 指数退避 | 保留 | 2 行 |
| Per-cookie Emulation 绑定 | 新增 | ~8 行 |
| Bootstrap 缓存 | 新增 | ~12 行 |
| SUPER_CLIENT Emulation | 新增 | 5 行 |

**V2 总改动量：约 62 行有效代码。**

丢弃项：人类延迟、Cookie/Session 伪造、SSE 延迟、Accept 头修改、概率化错误处理、DoH/Header 清理。
