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

云模型调用前，RepoLocus 会展示模型、规范化目的端点、精确序列化 payload 字节数、源码
片段、文件列表和估算 Token 数。可用 `--allow-cloud` 仅授权本次调用，或同时使用
`--remember-consent` 为当前仓库记住该供应商端点。v2 授权会绑定规范仓库路径、供应商、
scheme、host、有效端口和完整请求路径；compatible endpoint 变化后必须重新授权。升级前的
v1 供应商级授权会按 fail-closed 原则失效，需要重新 grant。
`map`、`diagram` 和 `ask` 默认使用 `--refresh auto`：优先读取最近一次兼容的已提交 snapshot，
仅在不存在兼容 snapshot 时扫描。`--refresh always` 会先扫描，`--refresh never` 禁止扫描并在
没有兼容 snapshot 时失败。

`repolocus ask ... --follow-up` 可在当前进程内继续追问；首次回答会固定 index generation，
后续问题关闭 refresh 并要求同一 generation，若其他扫描推进 generation 则 fail closed。输入
空行即结束，问答历史不会落盘。

## 已实现能力

- 安全扫描：遵循 `.gitignore`，排除二进制、大文件、密钥文件、构建产物和符号链接；
- 增量索引：仓库外 SQLite/FTS5 缓存，按文件哈希更新；
- 项目地图：固定章节、源码链接和 `Confirmed` / `Inferred` / `Needs review` 标签；
- 证据问答：符号、FTS5/BM25、term 索引与依赖邻居混合检索；term 索引拆分
  camelCase、snake_case 和路径，并为连续 CJK 文本建立 bigram/trigram；用户可通过
  `REPOLOCUS_QUERY_SYNONYMS` 的 JSON 显式增加同义词，仓库配置无权设置；
- 模型校验：每个实质 claim 后必须紧跟相同 citation 和源码原文子串的 `Evidence quote`；
  校验只确认地址和原文子串，不判断语义支持关系，通过后 confidence 仍为 `needs_review`；
- 架构图：确定性生成 Mermaid，并为每个节点附代表源码、为每条边附一条具体 import 证据；
- 模型适配：无模型提取式回答、Ollama、OpenAI-compatible、Anthropic；
- 隐私控制：默认关闭遥测，云端逐次授权或按仓库和端点记忆授权，可预览与撤回；
- 自托管 API：安装 `api` 可选依赖后运行 `repolocus serve`。
- 评测：输出 recall@k、MRR、nDCG@k、any/all-path、citation recall、no-answer
  precision/accuracy 及按语言汇总；当前仍只是小型 regression set。

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
静默把仓库内容发送给远程模型。Skill 压缩包只包含 adapter，不内置 RepoLocus runtime；
必须预先提供兼容的已安装 runtime 或已同步的可信源码环境，adapter 全程 offline/no-sync，
缺失或版本不兼容时直接 fail closed，不会自行下载依赖。

## 自托管 API

安装 API 可选依赖，并把服务限制在一个允许的仓库目录树中：

```bash
pipx install 'repolocus[api]'
repolocus serve --root /path/to/allowed/repositories
```

API 默认只监听回环地址、只允许访问 `--root` 指定目录之下的仓库，并禁用云模型。每次
启动会生成随机 Bearer token 并在 stderr 只显示一次；如需固定 token，可设置
`REPOLOCUS_API_TOKEN`。所有请求都必须携带 `Authorization: Bearer TOKEN` 和允许的 `Host`；
服务还会限制请求体大小与并发数，并为 `/v1/` 响应设置 `Cache-Control: no-store`。

开放云模型还需服务端显式使用 `--allow-cloud-api`，客户端先调用
`POST /v1/ask/preview` 获取短时、单次使用的 `preview_id`，再调用
`POST /v1/ask/previews/{preview_id}/approve`。批准时发送的是预览阶段冻结的同一份证据与
序列化请求体，不会重新扫描；API 客户端不能创建持久云授权。

非回环监听必须同时提供 `--allow-remote`、至少一个 `--allowed-host`，以及
`--ssl-certfile` / `--ssl-keyfile` TLS 证书和密钥。预览存储位于单进程内存中，因此该
两阶段流程适用于 `repolocus serve` 默认启动的单 worker 服务。

## 明确边界

RepoLocus 不修改业务代码、不执行测试或构建脚本、不提交 Git、不自动创建 PR。仓库内的
README、注释和测试数据都按不可信输入处理。当前 Python 使用标准 AST，TypeScript、
JavaScript、Go、Rust、Java、C/C++ 使用保守的启发式解析器；动态调用、反射、依赖注入
和生成代码可能无法被静态分析还原。

索引和授权记录均保存在仓库之外。POSIX 平台会收紧文件权限；Windows 上尚未实现原生
ACL 检查，因此 `doctor --security` 会明确将 ACL 状态报告为“未验证”，不会声称检查成功。

扫描器默认排除识别出的 RepoLocus 生成文档；索引仍为迁移或显式导入的记录保留
`generated` provenance。不完整或暂时不可读的扫描会把旧 facts 保留为 `stale`。默认查询只使用 `source` 且非 `stale` 的已提交 snapshot，确认删除后
才移除对应行。每次提交通过单调 generation 做 compare-and-swap，拒绝旧扫描覆盖新结果。
这属于安全重读、内容哈希和 parser-fact 复用，不是 manifest-delta watcher。

完整命令、架构、测试与开发说明以英文
[README.md](https://github.com/Henry-Yolky/RepoLocus/blob/main/README.md) 为准。隐私与安全
细节见 [PRIVACY.md](https://github.com/Henry-Yolky/RepoLocus/blob/main/PRIVACY.md) 和
[SECURITY.md](https://github.com/Henry-Yolky/RepoLocus/blob/main/SECURITY.md)，路线图见
[ROADMAP.md](https://github.com/Henry-Yolky/RepoLocus/blob/main/ROADMAP.md)。
