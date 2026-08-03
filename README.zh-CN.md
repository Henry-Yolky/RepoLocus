# RepoLocus

> 用项目地图、可复现架构图和文件行号证据，快速读懂陌生代码库。

RepoLocus 是一个只读、本地优先的代码库理解工具。它不会执行仓库命令，而是在本地
安全扫描源码、建立 SQLite/FTS 索引、生成结构稳定的 `PROJECT_MAP.md`、输出经过校验的
Mermaid 图，并为代码问题检索可核验的源码证据。

当前仓库实现的是 CLI 优先的 v0.1 基线。静态依赖与调用关系是近似结果；路线图中的
公共仓库 Web Demo 尚未包含在本版本中。

## 快速开始

RepoLocus 需要 Python 3.10 或更高版本。对于已经发布到 PyPI 的 tag 版本：

```bash
pipx install repolocus
```

如果所需版本尚未发布到 PyPI，请从源码检出安装：

```bash
git clone https://github.com/Henry-Yolky/RepoLocus.git
pipx install ./RepoLocus
```

然后进入需要分析的仓库：

```bash
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
会将它按远程供应商处理并要求授权。明文 HTTP 仅允许用于回环地址，所有非回环供应商
端点都必须使用 HTTPS；提示词会在发送前再次脱敏。

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

## Agent Skill

仓库内置
[`skills/repolocus-analyze-repo`](https://github.com/Henry-Yolky/RepoLocus/tree/main/skills/repolocus-analyze-repo)，
可供 Codex 等具备 Shell 能力的 Agent 调用。它提供 `doctor`、`scan`、`ask`、`map` 和
`diagram`，强制使用本地提取式回答，并让项目地图和架构图输出到 stdout，避免自动写入
目标仓库。

GitHub Release 会单独提供 `repolocus-analyze-repo-VERSION.zip`。请将其解压为
`$CODEX_HOME/skills/repolocus-analyze-repo`；未设置 `CODEX_HOME` 时默认使用
`~/.codex`。也可以从源码检出安装：

```bash
pipx install .
export CODEX_HOME="${CODEX_HOME:-$HOME/.codex}"
mkdir -p "$CODEX_HOME/skills"
cp -R skills/repolocus-analyze-repo "$CODEX_HOME/skills/"
```

PowerShell 等价命令：

```powershell
pipx install .
if (-not $env:CODEX_HOME) { $env:CODEX_HOME = Join-Path $HOME ".codex" }
New-Item -ItemType Directory -Force (Join-Path $env:CODEX_HOME "skills") | Out-Null
Copy-Item -Recurse -Force "skills/repolocus-analyze-repo" (Join-Path $env:CODEX_HOME "skills")
```

复制后请重启 Codex；如果宿主提供 Skill 注册表重载操作，也可以执行重载。之后以
`$repolocus-analyze-repo` 调用。该 Skill 不暴露云端授权参数，Agent 不能通过这条路径
静默把仓库内容发送给远程模型。

## 自托管 API

安装 API 可选依赖，并把服务限制在一个允许的仓库目录树中：

```bash
pipx install 'repolocus[api]'
repolocus serve --root /path/to/allowed/repositories
```

API 默认只监听回环地址、只允许访问 `--root` 指定目录之下的仓库，并禁用云模型。
对外监听必须显式使用 `--allow-remote`，且应放在具备认证和授权的网关之后；服务端若要
开放云模型，还需显式使用 `--allow-cloud-api`。

## 明确边界

RepoLocus 不修改业务代码、不执行测试或构建脚本、不提交 Git、不自动创建 PR。仓库内的
README、注释和测试数据都按不可信输入处理。当前 Python 使用标准 AST，TypeScript、
JavaScript、Go、Rust、Java、C/C++ 使用保守的启发式解析器；动态调用、反射、依赖注入
和生成代码可能无法被静态分析还原。

索引和授权记录均保存在仓库之外。POSIX 平台会收紧文件权限；Windows 上尚未实现原生
ACL 检查，因此 `doctor --security` 会明确将 ACL 状态报告为“未验证”，不会声称检查成功。

完整命令、架构、测试与开发说明以英文
[README.md](https://github.com/Henry-Yolky/RepoLocus/blob/main/README.md) 为准。隐私与安全
细节见 [PRIVACY.md](https://github.com/Henry-Yolky/RepoLocus/blob/main/PRIVACY.md) 和
[SECURITY.md](https://github.com/Henry-Yolky/RepoLocus/blob/main/SECURITY.md)，路线图见
[ROADMAP.md](https://github.com/Henry-Yolky/RepoLocus/blob/main/ROADMAP.md)。
