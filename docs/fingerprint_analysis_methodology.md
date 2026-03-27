# 客户端指纹差异分析方法论

## 概述

本文档记录了如何系统性地发现 clewdr 与真实 Claude Code 客户端（CLI、VS Code、JetBrains）之间的请求特征差异。

---

## 一、当前环境信息

### 真实 Claude Code 客户端安装情况

| 客户端 | 路径 | 版本 |
|--------|------|------|
| CLI | `~/.local/share/claude/versions/2.1.84` | 2.1.84 |
| VS Code 扩展 | `~/.vscode/extensions/anthropic.claude-code-2.1.84-darwin-arm64` | 2.1.84 |
| 配置目录 | `~/.claude/` | — |

### clewdr 模拟版本

| 常量 | 值 | 位置 |
|------|-----|------|
| `CLAUDE_CODE_VERSION` | `2.1.76` | `src/config/constants.rs:21` |
| `CLAUDE_CODE_USER_AGENT` | `claude-code/2.1.76` | `src/config/constants.rs:22` |
| `CLAUDE_CODE_BILLING_SALT` | `59cf53e54c78` | `src/config/constants.rs:23` |
| `CC_CLIENT_ID` | `9d1c250a-e61b-44d9-88ed-5944d1962f5e` | `src/config/constants.rs:18` |
| `CLAUDE_API_VERSION` | `2023-06-01` | `src/claude_code_state/chat.rs:26` |
| `CLAUDE_BETA_BASE` | `oauth-2025-04-20` | `src/claude_code_state/chat.rs:23` |

**已知版本差异**：clewdr 硬编码 `2.1.76`，真实版本已到 `2.1.84`（差 8 个小版本）。

---

## 二、clewdr 的 Claude Code 请求特征

### Header 完整清单

| Header 名称 | 值 | 代码位置 | 类型 |
|-----------|-----|------|------|
| `User-Agent` | `claude-code/2.1.76` | `constants.rs:22` | 硬编码 |
| `Origin` | `https://api.anthropic.com/` | `constants.rs:14` | 硬编码 |
| `Referer` | `https://api.anthropic.com/new` | `claude_code_state/mod.rs:104` | 格式化 |
| `Authorization` | `Bearer <access_token>` | `claude_code_state/chat.rs:191` | Bearer Auth |
| `anthropic-beta` | `oauth-2025-04-20[,context-1m-2025-08-07]` | `chat.rs:23-24,593-618` | 动态合并 |
| `anthropic-version` | `2023-06-01` | `chat.rs:26` | 硬编码 |
| `Cookie` | `<cookie_value>` | `claude_code_state/mod.rs:107` | 动态 |
| `x-anthropic-billing-header` | 动态生成 | `middleware/claude/request.rs:120-140` | 动态 |

### 请求构建核心代码

**build_request**（`claude_code_state/mod.rs:98-110`）：
```rust
pub fn build_request(&self, method: Method, url: impl ToString) -> RequestBuilder {
    let mut req = self.client
        .request(method, url.to_string())
        .header(ORIGIN, CLAUDE_ENDPOINT)
        .header(REFERER, format!("{CLAUDE_ENDPOINT}new"))
        .header(USER_AGENT, CLAUDE_CODE_USER_AGENT);
    if !self.cookie_header_value.as_bytes().is_empty() {
        req = req.header(COOKIE, self.cookie_header_value.clone());
    }
    req
}
```

**execute_claude_request**（`chat.rs:174-203`）：
```rust
self.client
    .post(endpoint)
    .bearer_auth(access_token)
    .header(USER_AGENT, CLAUDE_CODE_USER_AGENT)
    .header("anthropic-beta", beta_header)
    .header("anthropic-version", CLAUDE_API_VERSION)
    .json(body)
    .send()
```

### 计费 Header 生成逻辑

`middleware/claude/request.rs:120-140`：
```
x-anthropic-billing-header: cc_version=2.1.76.<hash_prefix>; cc_entrypoint=cli; cch=375ea;
```

- `cc_version`：版本 + SHA256 前 3 位（基于 salt + 消息采样 + 版本号）
- `cc_entrypoint`：环境变量 `CLAUDE_CODE_ENTRYPOINT` 或默认 `cli`
- `cch`：固定值

---

## 三、差异分析方法论

### 第一层：静态分析（直接读源码/二进制）

**真实客户端路径**：
```
~/.local/share/claude/versions/2.1.84           # CLI 二进制
~/.vscode/extensions/anthropic.claude-code-2.1.84-darwin-arm64/extension.js  # VS Code 扩展
```

**提取目标**：
- User-Agent 精确格式
- 所有 HTTP Header 名称和值
- API 版本、Beta 标识
- 请求体字段顺序和可选字段
- entrypoint 标识（cli / vscode / jetbrains 的区别）

### 第二层：动态抓包对比

```bash
# 用 mitmproxy 分别录制真实客户端和 clewdr 的全部请求
mitmproxy -w real.flow    # 配置真实 claude CLI 走代理
mitmproxy -w clewdr.flow  # 录制 clewdr 的请求

# 导出并对比
mitmdump -r real.flow --set flow_detail=3 > real.txt
mitmdump -r clewdr.flow --set flow_detail=3 > clewdr.txt
diff real.txt clewdr.txt
```

**对比重点**：
| 维度 | 说明 |
|------|------|
| Header 集合 | clewdr 缺少或多了哪些 header |
| Header 值 | 版本号、entrypoint 等是否匹配 |
| Header 顺序 | HTTP/1.1 下有检测意义 |
| 请求时序 | bootstrap 调用模式、token 刷新间隔 |

### 第三层：TLS 指纹对比

```bash
# ja3/ja4 指纹对比
# 真实 CLI 是 Rust 原生二进制 → 可能用 rustls 或 native-tls
# clewdr 用 wreq + Emulation（模拟 Chrome 浏览器指纹）
# 如果真实 CLI 不模拟浏览器，两者 TLS 指纹完全不同
```

**关键问题**：真实 Claude Code CLI 是否也使用浏览器 TLS 指纹？如果不是（大概率），那 clewdr 的 Chrome 模拟反而是一个异常——Claude Code 客户端不应该有浏览器的 TLS 指纹。

### 第四层：行为特征对比

| 维度 | 对比方法 |
|------|---------|
| 请求频率分布 | 录制 N 次对话的请求时间间隔，做统计分布对比 |
| 错误后行为 | 故意触发 429，观察真实客户端的重试策略 |
| 会话生命周期 | 真实客户端的 token 刷新间隔 vs clewdr |
| 并发模式 | 真实客户端是否并行发送某些请求 |
| entrypoint 值 | CLI vs VS Code vs JetBrains 各自发送什么 |

---

## 四、已识别的差异点

| 差异 | clewdr | 真实客户端 | 风险 |
|------|--------|-----------|------|
| 版本号 | `2.1.76` | `2.1.84` | 高——版本过旧可被检测 |
| TLS 指纹 | Chrome136 模拟 | 原生 Rust/Node.js | 高——Claude Code 不应有浏览器指纹 |
| Header 顺序 | 固定 | 待验证 | 中 |
| entrypoint | 默认 `cli` | 区分 cli/vscode/jetbrains | 中 |
| 计费 salt | `59cf53e54c78` | 待验证是否随版本变化 | 中 |
| Referer | 固定 `{ENDPOINT}new` | 待验证 | 低 |

---

## 五、待验证项

1. 真实 CLI 2.1.84 的精确 User-Agent 格式
2. 真实客户端的 TLS 栈（rustls? native-tls? BoringSSL?）
3. VS Code 扩展的 entrypoint 值（`vscode`? `editor`?）
4. JetBrains 插件的 entrypoint 值
5. 计费 salt 是否随版本更新
6. anthropic-beta header 在新版本中是否有变化
7. 真实客户端是否发送额外的未知 header
