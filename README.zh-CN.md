# RepoLocus

> 用项目地图、可复现架构图和文件行号证据，快速读懂陌生代码库。

RepoLocus 是一个只读、本地优先的代码库理解工具。它不会执行仓库命令，而是在本地
安全扫描源码、建立 SQLite/FTS 索引、生成结构稳定的 `PROJECT_MAP.md`、输出经过校验的
Mermaid 图，并为代码问题检索可核验的源码证据。

当前仓库实现的是 CLI 优先的 v0.1 基线。静态依赖与调用关系是近似结果；路线图中的
公共仓库 Web Demo 尚未包含在本版本中。

## 快速开始

```bash
pipx install repolocus
cd 你的仓库
repolocus scan
repolocus map
repolocus ask "配置在哪里校验？"
repolocus diagram
```

默认的 `local` 问答不会联网。使用 Ollama 时显式指定模型：

```bash
repolocus ask "请求如何进入核心循环？" --model ollama/qwen3-coder
```

只有回环地址上的 Ollama 被视为本地服务；如果把 Ollama 地址配置到其他主机，RepoLocus
会将它按远程供应商处理并要求授权。

云模型调用前，RepoLocus 会展示将发送的源码片段、文件列表和估算 Token 数。可用
`--allow-cloud` 仅授权本次调用，或同时使用 `--remember-consent` 为当前仓库记住该供应商。
`repolocus ask ... --follow-up` 可在当前进程内继续追问；输入空行即结束，问答历史不会落盘。

## 已实现能力

- 安全扫描：遵循 `.gitignore`，排除二进制、大文件、密钥文件、构建产物和符号链接；
- 增量索引：仓库外 SQLite/FTS5 缓存，按文件哈希更新；
- 项目地图：固定章节、源码链接和 `Confirmed` / `Inferred` / `Needs review` 标签；
- 证据问答：符号、全文与依赖邻居混合检索，模型引用需经过校验；
- 架构图：确定性生成 Mermaid，并附节点到源码的证据表；
- 模型适配：无模型提取式回答、Ollama、OpenAI-compatible、Anthropic；
- 隐私控制：默认关闭遥测，云端逐次授权或按仓库记忆授权，可预览与撤回；
- 自托管 API：安装 `api` 可选依赖后运行 `repolocus serve`。

API 默认只监听回环地址、只允许访问 `--root` 指定目录之下的仓库，并禁用云模型。
对外监听必须显式使用 `--allow-remote`，且应放在具备认证和授权的网关之后；服务端若要
开放云模型，还需显式使用 `--allow-cloud-api`。

## 明确边界

RepoLocus 不修改业务代码、不执行测试或构建脚本、不提交 Git、不自动创建 PR。仓库内的
README、注释和测试数据都按不可信输入处理。当前 Python 使用标准 AST，TypeScript、
JavaScript、Go、Rust、Java、C/C++ 使用保守的启发式解析器；动态调用、反射、依赖注入
和生成代码可能无法被静态分析还原。

完整命令、架构、测试与开发说明以英文 [README.md](README.md) 为准。隐私与安全细节见
[PRIVACY.md](PRIVACY.md) 和 [SECURITY.md](SECURITY.md)，路线图见 [ROADMAP.md](ROADMAP.md)。
