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
repolocus ask "设置值由哪个模块检查？"
repolocus diagram
```

默认的 `local` 问答不会联网。使用 Ollama 时显式指定模型：

```bash
repolocus ask "请求如何进入核心循环？" --model ollama/qwen3-coder
```

只有回环地址上的 Ollama 被视为本地服务；如果把 Ollama 地址配置到其他主机，RepoLocus
会将它按远程供应商处理并要求授权。明文 HTTP 仅允许用于回环地址，所有非回环供应商
端点都必须使用 HTTPS；提示词会在发送前再次脱敏。

云模型调用前，RepoLocus 会展示模型、规范化目的端点、精确序列化 payload 字节数、无凭据
传输路由、源码片段、文件列表和估算 Token 数。默认忽略环境中的代理变量；只有显式选择
`--proxy-mode environment`，或使用 `--proxy-mode explicit --proxy-url URL` 才会走代理，回环
服务始终直连。可用 `--allow-cloud` 仅授权本次调用，或同时使用 `--remember-consent` 记住精确
端点与路由。v4 授权绑定仓库身份、规范路径、供应商、完整端点和无凭据代理路由身份；代理
凭据既不参与授权身份，也不写入预览或授权文件。仓库、端点、代理模式或路由变化后必须重新
授权；同一路由的凭据轮换不需要重新授权。旧的 v1-v3 授权按 fail-closed 原则失效。

`map`、`diagram` 和 `ask` 默认使用 `--refresh auto`：查询前执行有界增量刷新；精确 cache hit
不读源码正文，也不写 SQLite 事务。`always` 会安全重读并哈希所有候选文件但可复用 parser
facts，`rebuild` 会重新解析所有源码，`never` 只读取最近一次兼容 snapshot。`repolocus status`
分别报告影响检索证据的 content generation 与仅诊断变化的 scan revision。

`repolocus ask ... --follow-up` 可在当前进程内继续追问；首次回答会固定 content generation，
后续问题关闭 refresh 并要求同一 generation。检索可见 facts 变化时 fail closed，仅诊断性的
scan revision 不会让证据 snapshot 失效。输入空行即结束，问答历史不会落盘。

## 常用命令

| 命令 | 用途 |
|---|---|
| `repolocus scan [PATH]` | 安全扫描并增量更新本地索引 |
| `repolocus status [PATH]` | 查看 content generation、scan revision 和组件指纹 |
| `repolocus map [PATH]` | 生成 `PROJECT_MAP.md`，或通过 `--stdout` 输出 |
| `repolocus ask QUESTION [PATH]` | 检索带源码位置的证据，并可选调用模型 |
| `repolocus diagram [PATH]` | 在 `ARCHITECTURE.md` 中生成经过校验的 Mermaid 图 |
| `repolocus privacy status` | 查看当前仓库记忆的供应商、端点和路由授权 |
| `repolocus doctor --security` | 检查运行时、FTS5、cache 权限与本地模型连接 |
| `repolocus clean` | 经确认后删除当前仓库的外部索引 |
| `repolocus serve` | 启动可选的自托管 FastAPI 服务 |

## 已实现能力

- 安全扫描：遵循 `.gitignore`，排除二进制、大文件、密钥文件、构建产物和符号链接；
- 增量索引：仓库外 SQLite/FTS5 缓存，按文件哈希更新；
- 配置安全：用户、仓库与环境设置合并后执行类型和边界校验，仓库配置只能收紧资源限制；
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
- 评测：自仓库 smoke set 之外，固定六个独立合成仓库和 18 条 qrels 作为 CI gate；报告
  recall@k、MRR、nDCG@k、citation、no-answer、`must_not_return` 及按仓库等维度的汇总；
  release gate 要求 citation recall 达到 1.0。

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
必须预先提供 `>=0.1.5,<0.2.0` 的已安装 runtime 或已同步的可信源码环境，adapter 全程 offline/no-sync，
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
才移除对应行。提交分别维护 content generation 与 scan revision，并通过双 compare-and-swap
拒绝旧扫描覆盖新结果；follow-up 只绑定前者。
`ask` 的兼容分析版本刷新使用 metadata-only manifest，跳过未变化文件的正文和 parser facts；
Python API 的 `RepoLocusService.scan()` 对未变化文件同样只返回 metadata 和已缓存的 fact
计数。需要物化 facts 时应调用 `map()`、`diagram()` 或 `evidence()`。变化文件会安全读取、
哈希并重新解析。
扫描同时限制文件/entry 数、总字节、目录深度、chunks、symbols，并在有界操作前后检查总耗时；
阻塞的文件系统调用或第三方 parser 可能在下一次检查前超时。检测到预算耗尽时，未完成范围会
标为 `stale`，而不是确认删除旧 facts。

`map` 和 `diagram` 的文件输出在目标父目录内原子替换。POSIX 使用 descriptor-relative 遍历
和原子名称交换；Windows 在句柄支持的替换前后检查 reparse point 与目录/目标身份，检测到
竞态即失败，但不宣称达到 POSIX 的目录句柄级约束。若提交后的对象身份无法确认，RepoLocus
会报告并保留可恢复的临时或备份名称，而不会删除未经验证的对象。

完整命令、架构、测试与开发说明以英文
[README.md](https://github.com/Henry-Yolky/RepoLocus/blob/main/README.md) 为准。隐私与安全
细节见 [PRIVACY.md](https://github.com/Henry-Yolky/RepoLocus/blob/main/PRIVACY.md) 和
[SECURITY.md](https://github.com/Henry-Yolky/RepoLocus/blob/main/SECURITY.md)，路线图见
[ROADMAP.md](https://github.com/Henry-Yolky/RepoLocus/blob/main/ROADMAP.md)。
