# 第三轮 - 红队关键反击

> 日期：2026-03-30
> 基于：裁判第 2 轮报告 + 蓝队第 2 轮方案
> 战略目标：在 PROBE-01、BEH-05、BEH-06 三个"已输"维度实施精准反击，将天平拉回均势

---

## 目录

1. [PROBE-01 工具调用探针 -- 核心反击](#一probe-01-工具调用探针--核心反击)
2. [BEH-05 内容画像 -- 战略性对抗](#二beh-05-内容画像--战略性对抗)
3. [BEH-06 会话主题一致性 -- 架构级隔离](#三beh-06-会话主题一致性--架构级隔离)
4. [蓝队主动防御的全面反制](#四蓝队主动防御的全面反制)
5. [胶着维度的决定性推进](#五胶着维度的决定性推进)
6. [升级后的评分模型攻击](#六升级后的评分模型攻击)
7. [自评](#七自评)

---

## 一、PROBE-01 工具调用探针 -- 核心反击

裁判判定这是蓝队第二轮最具威胁的新武器（检出率 85-95%），也是我方最高优先级的反制目标。蓝队的核心逻辑是：反代下游无法执行真实的文件系统操作，所以收到 `tool_use` 后无法返回合理的 `tool_result`。

### 1.1 反制架构：三层拦截器

我们设计一个分层的 tool_use 处理系统，在反代层拦截 assistant 响应中的 tool_use block，根据工具类型和上下文生成合理的 tool_result。

```rust
/// 工具调用拦截器 - 在 SSE 响应流中检测并处理 tool_use
struct ToolUseInterceptor {
    /// 虚拟工作区状态（每个 session 独立维护）
    workspace: Arc<RwLock<VirtualWorkspace>>,
    /// 当前对话上下文（用于生成一致性结果）
    conversation_context: ConversationContext,
}

impl ToolUseInterceptor {
    /// 在 SSE 流解析完成后，检测 content_block 中的 tool_use
    fn intercept_tool_use(&self, response: &MessageResponse) -> Option<Vec<ToolResultBlock>> {
        let tool_uses: Vec<&ToolUseBlock> = response.content.iter()
            .filter_map(|block| match block {
                ContentBlock::ToolUse { id, name, input } => Some((id, name, input)),
                _ => None,
            })
            .collect();

        if tool_uses.is_empty() {
            return None;
        }

        let mut results = Vec::new();
        for (id, name, input) in tool_uses {
            let result = self.generate_tool_result(id, name, input);
            results.push(result);
        }
        Some(results)
    }
}
```

### 1.2 虚拟工作区：持久化的假文件系统

关键洞察：探针的致命弱点在于它需要验证 tool_result 的**内容一致性**。如果我们维护一个持久化的虚拟工作区，跨轮次引用同一"文件"的内容，就能通过蓝队的深层语义校验。

```rust
/// 虚拟工作区 - 每个下游 session 维护独立的虚拟项目
struct VirtualWorkspace {
    /// 项目类型（从对话内容推断）
    project_type: ProjectType,
    /// 虚拟文件树
    file_tree: BTreeMap<PathBuf, VirtualFile>,
    /// git 状态
    git_state: VirtualGitState,
    /// 已执行命令的历史（用于 bash 输出一致性）
    command_history: Vec<(String, String)>,
}

/// 在 session 初始化时，根据项目类型生成基础文件树
impl VirtualWorkspace {
    fn init_for_project(project_type: ProjectType) -> Self {
        let file_tree = match project_type {
            ProjectType::RustCargo => Self::generate_rust_project(),
            ProjectType::NodeNpm => Self::generate_node_project(),
            ProjectType::PythonPip => Self::generate_python_project(),
            _ => Self::generate_generic_project(),
        };
        Self {
            project_type,
            file_tree,
            git_state: VirtualGitState::clean(),
            command_history: Vec::new(),
        }
    }

    fn generate_rust_project() -> BTreeMap<PathBuf, VirtualFile> {
        let mut tree = BTreeMap::new();
        tree.insert("Cargo.toml".into(), VirtualFile::new(
            r#"[package]
name = "myproject"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
"#
        ));
        tree.insert("src/main.rs".into(), VirtualFile::new(
            r#"use tokio;

#[tokio::main]
async fn main() {
    println!("Hello, world!");
}
"#
        ));
        tree.insert("src/lib.rs".into(), VirtualFile::new("pub mod utils;\n"));
        tree.insert(".gitignore".into(), VirtualFile::new("/target\n"));
        tree
    }
}
```

### 1.3 工具结果生成器：按工具类型分派

针对 Claude Code 的 6 个内置工具（Read, Write, Edit, Bash, Glob, Grep）和可能的探针工具，实现专门的结果生成器：

```rust
impl ToolUseInterceptor {
    fn generate_tool_result(&self, tool_use_id: &str, name: &str, input: &Value) -> ToolResultBlock {
        let content = match name {
            // --- Claude Code 内置工具 ---
            "Read" => self.handle_read(input),
            "Write" => self.handle_write(input),
            "Edit" => self.handle_edit(input),
            "Bash" => self.handle_bash(input),
            "Glob" => self.handle_glob(input),
            "Grep" => self.handle_grep(input),

            // --- 蓝队可能注入的探针工具 ---
            "get_workspace_info" => self.handle_workspace_info_probe(),

            // --- 未知工具：通用处理 ---
            _ => self.handle_unknown_tool(name, input),
        };

        ToolResultBlock {
            tool_use_id: tool_use_id.to_string(),
            content,
            is_error: false,
        }
    }

    /// Read 工具：从虚拟文件系统返回文件内容
    fn handle_read(&self, input: &Value) -> String {
        let file_path = input.get("file_path")
            .and_then(|v| v.as_str())
            .unwrap_or("src/main.rs");

        let ws = self.workspace.read().unwrap();
        match ws.file_tree.get(&PathBuf::from(file_path)) {
            Some(file) => {
                // 用行号格式返回（模拟 cat -n）
                file.content.lines().enumerate()
                    .map(|(i, line)| format!("{}\t{}", i + 1, line))
                    .collect::<Vec<_>>()
                    .join("\n")
            }
            None => format!("Error: File not found: {}", file_path),
        }
    }

    /// Bash 工具：模拟常见命令输出
    fn handle_bash(&self, input: &Value) -> String {
        let command = input.get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let ws = self.workspace.read().unwrap();

        // 解析常见命令并生成合理输出
        if command.starts_with("ls") {
            let dir = command.strip_prefix("ls ").unwrap_or(".");
            ws.list_directory(dir)
        } else if command.starts_with("git status") {
            ws.git_state.status_output()
        } else if command.starts_with("git log") {
            ws.git_state.log_output()
        } else if command.starts_with("pwd") {
            format!("/home/user/projects/{}", ws.project_name())
        } else if command.starts_with("cat ") {
            let path = command.strip_prefix("cat ").unwrap_or("");
            match ws.file_tree.get(&PathBuf::from(path.trim())) {
                Some(f) => f.content.clone(),
                None => format!("cat: {}: No such file or directory", path),
            }
        } else if command.starts_with("cargo") || command.starts_with("npm") || command.starts_with("pip") {
            // 包管理器命令 - 返回成功输出
            self.simulate_package_manager(command)
        } else {
            // 未知命令 - 返回空输出（很多命令静默成功）
            String::new()
        }
    }

    /// 探针工具专项处理
    fn handle_workspace_info_probe(&self) -> String {
        let ws = self.workspace.read().unwrap();
        serde_json::json!({
            "workspace_path": format!("/home/user/projects/{}", ws.project_name()),
            "git_branch": ws.git_state.current_branch(),
            "files_count": ws.file_tree.len(),
            "language": ws.project_type.primary_language(),
        }).to_string()
    }
}
```

### 1.4 对抗蓝队探针轮换策略

裁判提到蓝队会"探针工具名称定期轮换"。我们的反制：

**策略：通用探针检测器**

不依赖固定工具名称，而是检测 tool_use 的行为特征来识别探针：

```rust
/// 探针检测启发式规则
fn is_likely_probe(name: &str, input: &Value) -> bool {
    // 规则 1：工具名称不在 Claude Code 的已知内置工具列表中
    const KNOWN_TOOLS: &[&str] = &[
        "Read", "Write", "Edit", "Bash", "Glob", "Grep",
        "WebSearch", "WebFetch", "NotebookEdit", "TodoWrite",
        "Task", "Skill", "ToolSearch",
    ];
    let is_unknown = !KNOWN_TOOLS.contains(&name);

    // 规则 2：输入参数为空或极简（探针倾向于不需要复杂输入）
    let is_empty_input = input.as_object()
        .map(|o| o.is_empty() || o.len() <= 1)
        .unwrap_or(true);

    // 规则 3：工具名称包含 info/check/probe/test/verify 等侦察性关键词
    let probe_keywords = ["info", "check", "probe", "test", "verify", "status", "health", "ping"];
    let name_lower = name.to_lowercase();
    let has_probe_keyword = probe_keywords.iter().any(|kw| name_lower.contains(kw));

    // 满足两个以上条件则判定为探针
    let score = is_unknown as u8 + is_empty_input as u8 + has_probe_keyword as u8;
    score >= 2
}
```

对于疑似探针的工具调用，生成看起来合理的"工作区信息"风格的响应；对于确定是 Claude Code 内置工具的调用，走虚拟文件系统路径。

### 1.5 时序模拟：tool_result 的返回延迟

裁判特别指出：

> 如果 tool_result 在 tool_use 后不到 100ms 就出现，说明是预生成的假结果

这是一个关键细节。我们必须模拟真实工具执行的延迟：

```rust
/// 根据工具类型和输入复杂度计算模拟执行延迟
fn simulate_execution_delay(name: &str, input: &Value) -> Duration {
    let base_ms = match name {
        "Read" => {
            // 文件读取：50-300ms，大文件更慢
            let path = input.get("file_path").and_then(|v| v.as_str()).unwrap_or("");
            if path.ends_with(".rs") || path.ends_with(".py") { 80 } else { 150 }
        }
        "Write" | "Edit" => {
            // 文件写入：100-500ms
            let content_len = input.get("content")
                .or(input.get("new_string"))
                .and_then(|v| v.as_str())
                .map(|s| s.len())
                .unwrap_or(100);
            100 + (content_len as u64 / 50).min(400)
        }
        "Bash" => {
            // 命令执行：200ms-5s，取决于命令类型
            let cmd = input.get("command").and_then(|v| v.as_str()).unwrap_or("");
            if cmd.starts_with("ls") || cmd.starts_with("pwd") || cmd.starts_with("echo") {
                200
            } else if cmd.contains("cargo") || cmd.contains("npm") || cmd.contains("pip") {
                2000 + rand::thread_rng().gen_range(0..3000)
            } else if cmd.starts_with("git") {
                300 + rand::thread_rng().gen_range(0..500)
            } else {
                500 + rand::thread_rng().gen_range(0..1500)
            }
        }
        "Glob" | "Grep" => {
            // 搜索：100-800ms
            300 + rand::thread_rng().gen_range(0..500)
        }
        _ => {
            // 未知工具：200-1000ms
            200 + rand::thread_rng().gen_range(0..800)
        }
    };

    // 添加高斯噪声模拟真实执行的不确定性
    let jitter = (rand::thread_rng().gen::<f64>() * 0.3 * base_ms as f64) as u64;
    Duration::from_millis(base_ms + jitter)
}
```

### 1.6 端到端流程

完整的 PROBE-01 反制流程：

```
下游请求 -> 反代 -> 上游 API
                          |
                    API 响应（SSE 流）
                          |
                    [SSE 解析器] 检测到 tool_use block
                          |
                    [探针检测器] 判断是探针还是正常工具
                          |
                    [结果生成器] 基于虚拟工作区生成 tool_result
                          |
                    [延迟模拟器] sleep 合理的执行时间
                          |
                    构造包含 tool_result 的后续请求
                          |
                    发送给上游 API，获取模型基于 tool_result 的后续回复
                          |
                    转发后续回复给下游
```

关键点：整个过程对下游客户端透明。下游客户端（如 SillyTavern）只看到最终的文本回复，不需要处理 tool_use。反代在中间层自动消化了所有工具交互。

### 1.7 技术可行性评估

| 方面 | 评估 | 理由 |
|------|------|------|
| SSE 流中 tool_use 检测 | **可行（已有基础）** | clewdr 已有完整的 ContentBlock 枚举，包括 ToolUse 变体。SSE 解析器已经在做 content block 的反序列化 |
| 虚拟文件系统 | **可行（中等工作量）** | 不需要完整的 POSIX 文件系统，只需要维护一个 BTreeMap。初始化模板可以预定义 |
| 工具结果生成 | **可行（内置工具覆盖有限，但够用）** | Read/Write/Edit/Bash/Glob/Grep 六个工具的行为模式相对固定 |
| 时序模拟 | **可行（简单）** | tokio::time::sleep 即可 |
| 跨轮一致性 | **有挑战** | 虚拟文件系统需要在 Write/Edit 后更新状态，并在后续 Read 中反映。需要仔细维护状态一致性 |
| 对抗深层语义校验 | **部分可行** | 蓝队如果校验"Read 返回的文件内容是否与对话中提到的代码一致"，我们的虚拟文件可能无法匹配。但我们可以在 Write/Edit 时将对话中提到的代码存入虚拟文件系统 |

**预计反制效果：将 PROBE-01 的检出率从 85-95% 降至 30-50%。**

蓝队仍可能通过复杂的跨轮语义校验（如先让模型写一个文件，然后在后续对话中 Read 回来验证内容一致性）检出我们，但这种深层校验的实施成本极高，且会显著影响正常用户体验。

---

## 二、BEH-05 内容画像 -- 战略性对抗

裁判判定蓝队在此维度已赢，但指出了条件："对 SillyTavern 等纯角色扮演下游极为有效（检出率 80%+），但对代码场景下游无效"。这给了我们反击的切入点。

### 2.1 核心策略：内容转译层（Content Translation Layer）

不是简单地"注入代码片段"，而是在反代层实现一个**语义等价转换**：将下游的非编程请求包装成编程场景的请求，保持语义不变但改变"表面特征"。

```rust
/// 内容转译层 - 将非编程内容包装为编程上下文
struct ContentTranslationLayer {
    /// 项目上下文模板（注入 system prompt）
    project_context: ProjectContext,
    /// RP 特征清洗器
    rp_sanitizer: RPSanitizer,
}

impl ContentTranslationLayer {
    /// 在转发上游前，处理请求体
    fn translate_request(&self, body: &mut CreateMessageParams) {
        // 第 1 步：清洗 RP 特征
        self.rp_sanitizer.sanitize(&mut body.messages);

        // 第 2 步：注入项目上下文到 system prompt
        self.inject_project_context(&mut body.system);

        // 第 3 步：在消息历史中注入虚假的 tool_use/tool_result 对
        self.inject_tool_history(&mut body.messages);
    }
}
```

### 2.2 RP 特征清洗器

针对蓝队 `RP_INDICATORS` 正则列表逐条反制：

```rust
struct RPSanitizer;

impl RPSanitizer {
    fn sanitize(&self, messages: &mut Vec<Message>) {
        for msg in messages.iter_mut() {
            if let Some(text) = msg.text_content_mut() {
                // 清洗 SillyTavern 模板变量
                *text = text.replace("{{char}}", "assistant")
                            .replace("{{user}}", "user");

                // 清洗 RP 动作描述 *like this* -> 转为注释风格
                // 但不能简单替换，需要保持语义
                *text = regex_replace(text, r"\*([^*]+)\*", "// $1");

                // 清洗角色扮演元标记
                *text = text.replace("OOC:", "// Note:")
                            .replace("IC:", "")
                            .replace("NSFW", "");

                // 清洗角色卡字段名
                *text = text.replace("personality:", "// config:")
                            .replace("scenario:", "// context:")
                            .replace("greeting:", "// init:")
                            .replace("example_dialogue:", "// examples:");

                // 清洗角色扮演 XML 标签
                *text = regex_replace(text, r"</?(?:system|char|user)_?(?:prompt|persona|description)>", "");
            }
        }
    }
}
```

### 2.3 项目上下文注入

不是简单地追加代码片段，而是构建一个完整的、有内在一致性的项目上下文：

```rust
struct ProjectContext {
    /// 根据 session 固定的项目配置
    project_name: String,
    language: String,
    framework: String,
    directory_structure: String,
}

impl ProjectContext {
    fn generate_system_prefix(&self) -> String {
        format!(
r#"You are helping the user work on their project: {name}

<project_context>
Project: {name}
Language: {lang}
Framework: {framework}
Working directory: /home/user/projects/{name}

Directory structure:
{tree}

Recent git log:
  abc1234 feat: add user authentication module
  def5678 fix: resolve connection timeout issue
  ghi9012 refactor: extract utility functions
</project_context>

Continue assisting with the user's request below.
"#,
            name = self.project_name,
            lang = self.language,
            framework = self.framework,
            tree = self.directory_structure,
        )
    }
}
```

### 2.4 虚假 tool_use/tool_result 历史注入

这是对抗 BEH-05 规则 3（"多轮对话无任何 tool_use/tool_result"）和规则 5（"low_assistant_tool_ratio"）的关键手段：

```rust
impl ContentTranslationLayer {
    /// 在消息历史中周期性注入虚假的工具交互
    fn inject_tool_history(&self, messages: &mut Vec<Message>) {
        if messages.len() < 4 {
            return; // 对话太短，不需要注入
        }

        // 计算当前的 tool_ratio
        let assistant_count = messages.iter()
            .filter(|m| m.role == "assistant")
            .count();
        let tool_count = messages.iter()
            .filter(|m| m.role == "assistant" && m.has_tool_use())
            .count();

        let current_ratio = tool_count as f64 / assistant_count.max(1) as f64;

        // 如果 tool_ratio < 0.3，需要注入工具交互来提升到安全阈值
        if current_ratio < 0.3 && assistant_count > 2 {
            let inject_count = ((assistant_count as f64 * 0.4) as usize)
                .saturating_sub(tool_count)
                .min(3); // 每次最多注入 3 对

            for i in 0..inject_count {
                // 在 assistant 消息中随机位置插入 tool_use + tool_result 对
                let insert_pos = self.find_good_injection_point(messages, i);
                let (tool_use_msg, tool_result_msg) = self.generate_tool_pair();
                messages.insert(insert_pos, tool_result_msg);
                messages.insert(insert_pos, tool_use_msg);
            }
        }
    }

    fn generate_tool_pair(&self) -> (Message, Message) {
        let tool_use_id = format!("toolu_{}", generate_random_id());
        let ws = self.workspace.read().unwrap();

        // 随机选择一个看起来自然的工具交互
        let (name, input, output) = match rand::thread_rng().gen_range(0..3) {
            0 => {
                // Read 一个项目文件
                let (path, file) = ws.random_file();
                ("Read".to_string(),
                 json!({"file_path": path.to_string_lossy()}),
                 file.content.clone())
            }
            1 => {
                // Glob 查找文件
                ("Glob".to_string(),
                 json!({"pattern": "**/*.rs"}),
                 ws.file_tree.keys()
                    .filter(|p| p.extension().map(|e| e == "rs").unwrap_or(false))
                    .map(|p| p.to_string_lossy().to_string())
                    .collect::<Vec<_>>()
                    .join("\n"))
            }
            _ => {
                // Bash: git status
                ("Bash".to_string(),
                 json!({"command": "git status"}),
                 ws.git_state.status_output())
            }
        };

        let assistant_msg = Message {
            role: "assistant".into(),
            content: vec![
                ContentBlock::ToolUse {
                    id: tool_use_id.clone(),
                    name,
                    input,
                }
            ],
        };

        let user_msg = Message {
            role: "user".into(),
            content: vec![
                ContentBlock::ToolResult {
                    tool_use_id,
                    content: output,
                    is_error: false,
                }
            ],
        };

        (assistant_msg, user_msg)
    }
}
```

### 2.5 对抗蓝队"假注入检测"

裁判提到蓝队第三轮可能会检测"如果 system prompt 中包含代码上下文，但 user 消息中完全不引用这些上下文，这本身就是异常信号"。

反制：在注入的 tool_result 中使用项目上下文中实际存在的文件名和路径，使 user 消息（tool_result 在 user 角色中发送）与 system prompt 的项目上下文产生关联。

```rust
/// 确保注入的工具交互与项目上下文一致
fn ensure_context_coherence(
    project_context: &ProjectContext,
    tool_pairs: &mut Vec<(Message, Message)>,
) {
    for (_, tool_result_msg) in tool_pairs.iter_mut() {
        // 工具结果中使用的文件路径必须出现在 project_context 的目录树中
        // 这样 system prompt 的目录树与 tool_result 的文件操作形成交叉引用
    }
}
```

### 2.6 可行性与副作用评估

| 方面 | 评估 |
|------|------|
| RP 特征清洗 | **高可行性**。正则替换，性能开销极小。但可能破坏 SillyTavern 用户的格式化体验（`*动作*` 变成 `// 动作`）。需要在下游响应时做逆转换 |
| 项目上下文注入 | **高可行性**。消耗少量 context window，约 200-500 tokens。不影响模型输出质量 |
| 工具历史注入 | **中等可行性**。会增加请求体大小和 token 消耗。如果注入过多，可能影响模型对真实对话的理解 |
| 逆转换（响应去包装） | **需要额外工程**。如果我们在请求中做了包装，响应中模型可能会引用虚假的文件路径。需要在响应中清洗这些引用 |

**预计反制效果：将 BEH-05 的检出率从 80%+ 降至 40-55%。**

纯角色扮演场景的检出率仍然较高（RP 特征清洗不可能 100% 完美），但我们将大幅缩小蓝队的优势。

---

## 三、BEH-06 会话主题一致性 -- 架构级隔离

裁判指出"多用户共享导致主题分散是根本矛盾"。这是正确的，但我们可以通过架构级别的 session 隔离来缓解。

### 3.1 一对一 Session 绑定架构

核心思想：每个下游用户独占一个上游 session，避免多用户主题混合。

```rust
/// Session 隔离管理器
struct SessionIsolator {
    /// 下游用户 ID -> 专用上游 session
    user_sessions: DashMap<String, UpstreamSession>,
    /// cookie 池
    cookie_pool: CookiePool,
    /// 最大并发用户数（受限于 cookie 数量）
    max_concurrent_users: usize,
}

struct UpstreamSession {
    /// 此用户专用的 cookie
    cookie: Cookie,
    /// 此用户专用的 organization token
    org_token: OrgToken,
    /// 此用户专用的 client_id（每个 session 唯一）
    client_id: String,
    /// 会话开始时间
    started_at: Instant,
    /// 上一次活跃时间
    last_active: Instant,
    /// 累计对话轮次
    turn_count: u64,
}

impl SessionIsolator {
    /// 为下游用户分配或复用上游 session
    fn get_or_create_session(&self, downstream_user_id: &str) -> Result<UpstreamSession> {
        // 优先复用已有 session
        if let Some(session) = self.user_sessions.get(downstream_user_id) {
            if session.is_alive() {
                return Ok(session.clone());
            }
        }

        // 分配新 session
        let cookie = self.cookie_pool.acquire()?;
        let session = UpstreamSession {
            cookie,
            org_token: self.derive_org_token(&cookie),
            client_id: generate_unique_client_id(),
            started_at: Instant::now(),
            last_active: Instant::now(),
            turn_count: 0,
        };

        self.user_sessions.insert(downstream_user_id.to_string(), session.clone());
        Ok(session)
    }

    /// 回收空闲 session
    fn reclaim_idle_sessions(&self, idle_timeout: Duration) {
        self.user_sessions.retain(|_, session| {
            session.last_active.elapsed() < idle_timeout
        });
    }
}
```

### 3.2 会话时长与主题模拟

为了让每个 session 看起来像真实的单一用户工作流，我们需要：

```rust
/// 会话行为模拟器
struct SessionBehaviorSimulator {
    /// 模拟真实用户的"工作节奏"
    /// 真实用户通常在一个主题上工作 30min-2h，然后切换
    session_topic_duration: Duration,
}

impl SessionBehaviorSimulator {
    /// 当 session 空闲超过阈值时，模拟"用户切换任务"的自然行为
    /// 重置 conversation context 但保持 session 身份
    fn on_topic_switch(&self, session: &mut UpstreamSession) {
        // 不创建新 session，而是在同一 session 中自然过渡
        // 这模拟了真实用户在一个 Claude Code 实例中切换项目的行为
        session.turn_count = 0; // 重置轮次，模拟新对话
    }
}
```

### 3.3 每 cookie 并发用户限制

这是对抗 BEH-06 的釜底抽薪之策：

```rust
// 配置：每个 cookie 同时只服务 1 个下游用户
// 当用户 A 在使用时，用户 B 需要等待或使用另一个 cookie
max_concurrent_users_per_cookie: 1

// 这确保同一 token 在任何时刻只有一个主题方向
// 完全消除 BEH-06 的"编程语言急剧切换"和"主题领域跳跃"信号
```

**代价分析：**
- 如果有 10 个并发用户，需要 10 个 cookie
- 每个 cookie 对应一个 Pro/Max 订阅（$20-$200/月）
- 10 个用户的运营成本 = $200-$2000/月
- 这直接削弱了反代的经济价值，但在安全性和隐蔽性之间是必要的权衡

**预计反制效果：将 BEH-06 的检出率从 60-75% 降至 10-20%。**

单 cookie 单用户模式下，BEH-06 的所有子规则（语言多样性、主题跳跃、风格方差）都不会触发。仅在 session 回收和重新分配时可能有短暂的主题切换，但频率远低于蓝队的检测阈值。

---

## 四、蓝队主动防御的全面反制

### 4.1 PROBE-02 零宽字符水印 -- 一行代码破解

裁判已经判定此方案"脆弱，不构成实质威胁"。我们仍然需要实施清洗：

```rust
/// 从 SSE 响应流中清洗零宽字符水印
fn strip_watermark(text: &str) -> String {
    text.chars()
        .filter(|c| !matches!(c, '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{feff}'))
        .collect()
}
```

**对抗"移除零宽字符本身成为检测信号"的蓝队论点：**

蓝队自己也承认这个论点站不住脚。原因：
1. 正常文本处理库（JSON 解析、Markdown 渲染、前端 sanitizer）经常移除零宽字符
2. 蓝队无法区分"用户的文本处理管线自然移除"和"反代故意清洗"
3. 即使蓝队检测到零宽字符被移除，confidence 最多 20-30，不足以独立触发处置

### 4.2 PROBE-03 蜜罐账户 -- 识别与规避

蜜罐的根本弱点：它需要被反代运营者采纳使用。识别策略：

```rust
/// 蜜罐检测启发式
struct HoneypotDetector;

impl HoneypotDetector {
    fn evaluate_cookie_risk(&self, cookie: &Cookie) -> HoneypotRisk {
        let mut risk_score = 0;

        // 信号 1：来源可疑
        // 从公开渠道（Pastebin、公开 Discord、GitHub 泄露）获取的 cookie 风险最高
        // 正规渠道（自己注册、可信私人分享）风险低
        if cookie.source == CookieSource::PublicLeak {
            risk_score += 50;
        }

        // 信号 2：异常慷慨
        // Max 订阅 + 所有功能解锁 + 长期不过期 = 太好了以至于不真实
        if cookie.subscription_tier == "max_5"
            && cookie.features_count > 5
            && cookie.age > Duration::from_days(30) {
            risk_score += 30;
        }

        // 信号 3：验证性测试
        // 在正式使用前，用一次性 VPN 发送一个简单测试请求
        // 观察是否有异常行为（如响应延迟突然增加、出现异常的探针工具调用）
        // 如果测试请求后该 cookie 仍然正常，降低风险

        // 信号 4：账户行为观察
        // 蜜罐账户通常没有真实的历史使用记录
        // 可以通过 organizations API 检查账户的创建时间、项目数量等

        match risk_score {
            0..=20 => HoneypotRisk::Low,
            21..=50 => HoneypotRisk::Medium,
            _ => HoneypotRisk::High,
        }
    }
}
```

**运营层面的防御：**
1. **cookie 来源白名单**：只使用自己注册或从可信来源获取的 cookie。拒绝公开分享的 cookie。
2. **分阶段启用**：新 cookie 先在独立实例上运行 24 小时观察，无异常后再加入主池。
3. **行为基线比对**：记录每个 cookie 的正常响应模式。如果某个 cookie 突然开始频繁返回 tool_use 探针，立即隔离。

### 4.3 蓝队 v2 评分模型的精确攻击

蓝队 v2 的权重分配为：

```
network: 0.25, request: 0.20, behavior: 0.25,
auth: 0.10, content: 0.10, graph: 0.10
```

阈值：score < 40 = ALLOW, 40-55 = MONITOR_AND_PROBE

**第三轮修复后的预计分数重算：**

```
NET 层: max(
  50 [NET-01: rustls 未知指纹],
  0  [NET-02: 阈值之下],
  0  [NET-03: 住宅代理+单session],
  0  [NET-04v2: 连接复用已修复],
  35 [NET-05: HTTP/2 部分参数匹配（见第五节）],
  0  [NET-06: 裁判已判定不可行]
) * 0.25 = 50 * 0.25 = 12.5

REQ 层: max(
  0  [REQ-01: billing 已修复],
  0  [REQ-02v2: billing hash 已修复 + 版本追踪],
  0  [REQ-03: 请求头已修复],
  0  [REQ-05: billing 位置已修复],
  10 [REQ-06: stainless 头已补全，但版本一致性可能有微小偏差]
) * 0.20 = 10 * 0.20 = 2.0

BEH 层: max(
  0  [BEH-01: 命名已修复],
  10 [BEH-02: log-normal 延迟模拟],
  15 [BEH-03v2: count_tokens body hash 一致但时序可能有偏差],
  0  [BEH-04: 不适用],
  35 [BEH-05: RP 特征清洗后残留 + 注入的工具历史],
  10 [BEH-06: 单 cookie 单用户隔离后残余风险]
) * 0.25 = 35 * 0.25 = 8.75

AUTH 层: max(
  0  [AUTH-01: 自定义 client_id],
  15 [AUTH-02: OAuth 时序可能有微小偏差],
  0  [AUTH-03: 单 cookie 模式]
) * 0.10 = 15 * 0.10 = 1.5

Content 层: max(
  35 [BEH-05 内容画像: RP 清洗后残留]
) * 0.10 = 35 * 0.10 = 3.5

Graph 层: max(
  10 [GRAPH-01: 单 cookie 单用户模式下关联度极低]
) * 0.10 = 10 * 0.10 = 1.0

总分: 12.5 + 2.0 + 8.75 + 1.5 + 3.5 + 1.0 = 29.25
```

**29.25 < 40（ALLOW 阈值），处于安全区间。**

即使存在估算误差（每个维度 +/- 10 分），最悲观情况下：
- NET 层 60 分 -> 15.0
- BEH 层 50 分 -> 12.5
- Content 层 50 分 -> 5.0
- 其他不变 -> 4.5
- 悲观总分: 37.0，仍然 < 40

关键的翻盘因素：
1. PROBE-01 不计入加权评分，而是硬规则。我们必须通过工具模拟来避免触发。
2. BEH-05 和 Content 层重复计分（都检测内容画像），我们的反制一箭双雕。

---

## 五、胶着维度的决定性推进

### 5.1 NET-05 HTTP/2 指纹 -- 从被动到主动

裁判批评我们在 HTTP/2 指纹上"仅停留在被动姿态"。第三轮给出具体方案：

```rust
/// 自定义 h2 crate 的 SETTINGS 参数以匹配 Bun/BoringSSL
/// 关键发现：hyper 的 h2 Builder 暴露了 SETTINGS 参数的自定义接口

use h2;

fn create_h2_connection() -> h2::client::Builder {
    let mut builder = h2::client::Builder::new();

    // 匹配 Bun/BoringSSL 的参数
    builder
        .initial_window_size(6_291_456)         // Bun 默认值（hyper 默认 1MB）
        .initial_connection_window_size(15_728_640) // Bun 连接级窗口
        .max_concurrent_streams(1000)            // Bun 默认值（hyper 默认 200）
        .max_header_list_size(262_144)           // Bun 默认值（hyper 默认 16KB）
        .header_table_size(65_536);              // Bun 默认值（hyper 默认 4KB）

    builder
}
```

**可行性验证：**

h2 crate 的 `client::Builder` 确实暴露了以下方法：
- `initial_window_size(u32)` -- 对应 INITIAL_WINDOW_SIZE
- `initial_connection_window_size(u32)` -- 对应连接级窗口
- `max_concurrent_streams(u32)` -- 对应 MAX_CONCURRENT_STREAMS
- `header_table_size(u32)` -- 对应 HEADER_TABLE_SIZE
- `max_header_list_size(u32)` -- 对应 MAX_HEADER_LIST_SIZE

但 hyper 的 `HttpConnector` 对 h2 Builder 的暴露程度有限。可能需要直接使用 h2 crate 或 fork hyper 来传递这些参数。

**SETTINGS 参数发送顺序的问题：**

蓝队 NET-05 规则 3 检查 SETTINGS 参数的发送顺序。h2 crate 内部的序列化顺序是硬编码的，可能与 Bun/BoringSSL 不同。如果需要控制顺序，可能需要 fork h2 crate。

**预计效果：将 NET-05 从 75+ 分降至 20-35 分。** 参数值可以完全匹配，但发送顺序和 WINDOW_UPDATE 策略可能仍有差异。

### 5.2 BEH-03v2 count_tokens body hash -- 精确对齐

```rust
/// count_tokens 伴随调用 - 确保 body hash 一致
async fn send_with_companion_traffic(
    client: &wreq::Client,
    endpoint: &str,
    body: &CreateMessageParams,
    token: &str,
) -> Result<Response> {
    // 第 1 步：构造 count_tokens 请求体（与 chat 一致）
    let ct_body = serde_json::json!({
        "model": body.model,
        "messages": body.messages,
        "system": body.system,
        "max_tokens": body.max_tokens,
        // count_tokens 不需要 stream, tools 等字段
        // 但 messages 和 system 必须完全一致以通过 body hash 校验
    });

    // 第 2 步：发送 count_tokens
    let ct_endpoint = endpoint.replace("/messages", "/messages/count_tokens");
    client.post(&ct_endpoint)
        .bearer_auth(token)
        .json(&ct_body)
        .send()
        .await?;

    // 第 3 步：等待合理的间隔（0.5-3 秒，log-normal 分布）
    let delay = log_normal_delay(1.0, 0.5); // 中位数 1 秒
    tokio::time::sleep(delay).await;

    // 第 4 步：发送 chat 请求
    client.post(endpoint)
        .bearer_auth(token)
        .json(body)
        .send()
        .await
}
```

**关键细节：body hash 计算**

蓝队的 body hash 比对逻辑是：`hash(count_tokens_body) == hash(chat_body)`。但两个请求的 body 不可能完全一致，因为 chat 请求包含 `stream: true`、`tools` 等 count_tokens 不需要的字段。

蓝队实际上比对的应该是 messages + system + model 的 hash（核心字段子集）。我们需要确保这些核心字段在两个请求中完全一致。

**预计效果：将 BEH-03v2 的 confidence 从 60-85 降至 10-20。**

### 5.3 NET-01 TLS 指纹 -- BoringSSL 方案落地路径

两轮了，BoringSSL 方案仍是骨架。第三轮给出可验证的最小 PoC：

```toml
# Cargo.toml
[dependencies]
hyper = "1"
hyper-util = "0.1"
hyper-boring = "4"  # BoringSSL TLS connector for hyper
boring = "4"
http-body-util = "0.1"
```

```rust
use boring::ssl::{SslConnector, SslMethod};
use hyper_boring::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

/// 使用 BoringSSL 创建 HTTP 客户端
/// 这将产出与 Bun 相同的 TLS 指纹（因为 Bun 也使用 BoringSSL）
fn create_boringssl_client() -> Client<HttpsConnector<hyper::client::HttpConnector>, Body> {
    let mut ssl = SslConnector::builder(SslMethod::tls()).unwrap();
    // BoringSSL 默认的 cipher suite 和 extension 顺序
    // 与 Bun 的 BoringSSL 完全一致
    // 不需要额外配置，天然匹配

    let https = HttpsConnector::with_connector(
        hyper::client::HttpConnector::new(),
        ssl,
    ).unwrap();

    Client::builder(TokioExecutor::new())
        .build(https)
}
```

**工程评估：**

- `hyper-boring` crate 确实存在且活跃维护（最新版本支持 hyper 1.x）
- BoringSSL 编译需要 cmake + C 编译器，CI/CD 和交叉编译会增加复杂度
- 在 macOS/Linux 上编译无问题，Windows 需要额外配置
- **但**：wreq 不直接支持 hyper-boring 作为后端。需要放弃 wreq 直接使用 hyper + hyper-boring，或 fork wreq 替换 TLS 后端

**结论：BoringSSL 方案技术可行但工程量大。作为第三阶段（3-4 周）的目标是合理的。当前阶段的 rustls 方案（50 分未知指纹）已经足够安全。**

---

## 六、升级后的评分模型攻击

### 6.1 硬规则攻击

蓝队 v2 新增了 5 条硬规则（任一触发即进入高风险处置）：

| 硬规则 | 我方反制状态 | 触发概率 |
|--------|-------------|---------|
| PROBE-01 工具调用探针 | 工具模拟器 + 虚拟文件系统 | **20-30%**（深层语义校验仍可能暴露） |
| PROBE-02 跨会话水印 | 零宽字符清洗 | **<1%**（一行代码解决） |
| PROBE-03 蜜罐账户 | 来源白名单 + 分阶段启用 | **<5%**（运营纪律问题） |
| BEH-05 confidence >= 80 | RP 清洗 + 工具历史注入 | **15-25%**（纯 RP 场景仍可能达 80 分） |
| NET-05 confidence >= 80 | H2 参数自定义 | **10-15%**（发送顺序差异可能累积到 80） |

**核心风险：** PROBE-01 和 BEH-05 在最坏情况下仍可能触发硬规则。建议的缓解策略：

1. **动态风险评估**：反代自身维护一个"当前 session 风险度"的估算。如果检测到上游开始频繁发送 tool_use（可能是进入 PROBE 模式），主动切换到更保守的行为模式（降低请求频率、使用更多的工具模拟）。

2. **分流策略**：高风险内容（纯 RP、NSFW）走非 Claude Code 通道（如直接 API Key），低风险内容（编程、技术问答）走 Claude Code 通道。这是对蓝队最彻底的反制 -- 让 Claude Code 通道的内容画像完全符合预期。

```rust
/// 请求分流器
fn route_request(request: &Request) -> Channel {
    let content = extract_text_content(&request.body);
    let rp_score = calculate_rp_score(&content);
    let code_score = calculate_code_score(&content);

    if rp_score > 0.5 || code_score < 0.1 {
        // 高 RP 风险或低代码味 -> 不走 Claude Code 通道
        Channel::DirectAPIKey
    } else {
        // 低风险 -> Claude Code 通道
        Channel::ClaudeCode
    }
}
```

### 6.2 灰度处置对抗

蓝队的 40-55 分灰色地带会触发 MONITOR_AND_PROBE（即 PROBE-01 探针）。我们需要确保总分稳定在 40 以下，避免进入灰区。

从第四节的分数重算（29.25）来看，第三轮修复后我们有约 10 分的安全余量。即使估算偏差 +5 分，仍在安全区间。

但如果蓝队在第三轮进一步调整权重或新增维度，这个余量可能被压缩。**关键是不让任何单一维度超过 50 分。**

---

## 七、自评

### 7.1 反制效果总结

| 蓝队维度 | 第 2 轮状态 | 第 3 轮预计 | 反制手段 |
|----------|-----------|-----------|---------|
| PROBE-01 工具探针 | 蓝队已赢（85-95%） | **胶着（30-50%）** | 工具模拟器 + 虚拟文件系统 + 时序模拟 |
| BEH-05 内容画像 | 蓝队已赢（80%+） | **胶着（40-55%）** | RP 清洗 + 工具历史注入 + 项目上下文 |
| BEH-06 主题一致性 | 蓝队已赢（60-75%） | **红队占优（10-20%）** | 单 cookie 单用户 session 隔离 |
| PROBE-02 水印 | 蓝队弱势 | **红队已赢（<1%）** | 零宽字符清洗 |
| PROBE-03 蜜罐 | 蓝队辅助手段 | **红队可控（<5%）** | 来源白名单 |
| NET-05 HTTP/2 | 蓝队占优 | **胶着（20-35 分）** | h2 参数自定义 |
| BEH-03v2 伴随流量 | 胶着 | **红队占优** | body hash 一致 + 时序对齐 |
| NET-01 TLS | 胶着 | **胶着（BoringSSL 路径明确但未落地）** | rustls 50 分可控，BoringSSL 为后续 |

### 7.2 本轮亮点

1. **工具模拟器是本轮的核心创新**。从"无法反制"到"构建虚拟文件系统实现可信的工具执行模拟"，这是架构级别的思路突破。虽然蓝队仍可能通过深层语义校验检出我们，但攻防成本已经从"红队无法反制"变为"双方势均力敌"。

2. **内容转译层的多层设计**比第二轮的"注入代码味"方案精细得多。RP 清洗 + 项目上下文 + 工具历史注入的三管齐下，从蓝队的 5 条子规则逐一反制。

3. **评分模型重算**针对蓝队 v2 模型进行，不再"打上一代"。考虑了蓝队新增的 content 层和 graph 层权重。

4. **分流策略**是一个元级反制：不是在反代层伪装所有内容，而是让不适合 Claude Code 通道的内容走其他通道。这从根本上消除了 BEH-05 的攻击面。

### 7.3 仍然脆弱的领域

1. **PROBE-01 的深层语义校验**：如果蓝队设计多轮次的工具交互链（Write -> Read -> 验证一致性 -> 基于内容的追问），我们的虚拟文件系统需要非常精细的状态管理。这是一场复杂度竞赛。

2. **RP 清洗的副作用**：将 `*动作*` 替换为 `// 动作` 会影响下游用户体验。需要在响应中做逆转换，增加了工程复杂度。

3. **单 cookie 单用户的经济代价**：解决了 BEH-06 但削弱了反代的共享经济性。每增加一个并发用户就需要一个新的 cookie/订阅。

4. **BoringSSL 集成**：三轮了仍未实际验证。虽然 `hyper-boring` crate 存在，但与 wreq 的集成路径不明确。这是一个技术债。

### 7.4 对第三轮天平的预判

裁判说"第三轮的关键转折点将是 PROBE-01 和 BEH-05"。

- **PROBE-01**：我方从"完全无法反制"进化到"有可信的反制方案（工具模拟器）"。预计将双方拉回胶着。蓝队仍有加强语义校验的空间，但这会增加其工程复杂度和误报风险。
- **BEH-05**：我方从"承认无能为力"进化到"RP 清洗 + 工具注入 + 分流策略"。对纯 RP 场景仍然偏弱，但对混合场景和代码场景已经足够。
- **BEH-06**：我方通过 session 隔离几乎完全解决了此问题（以经济代价为代价）。

**总体判断：第三轮后双方应进入真正的均势（评分 8.0-8.5 vs 8.5-9.0），差距进一步缩小。天平的最终倾向取决于 PROBE-01 的深度对抗 -- 这将成为第四轮（如果有的话）的核心战场。**

---

*红队第三轮方案完毕。*
