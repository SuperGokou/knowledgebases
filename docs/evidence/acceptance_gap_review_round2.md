# 企业终验防伪复审（Round 2）

> 复审日期：2026-07-13
> 复审模式：共享工作树只读审查；仅新增本报告
> 目标规格：Linux amd64/x86_64，8 vCPU，16 GB RAM，300 GB SSD；企业内网数据库、Redis、对象存储与业务数据
> 复审基线：唯一 final 于 2026-07-13T13:52:52Z 完成；Git HEAD `38627430eee7ec5bd2e5388c5d86c8daf1928a59`
> 安全边界：未读取 `.env`，未联网，未部署，未连接云主机，未运行破坏性存储测试
> 身份说明：final 运行时工作树为 dirty；本报告创建后内容指纹会再次变化，因此该次指纹只用于本轮问题复现，不能签署

## 1. 严格结论

当前项目仍为 **NO-GO / FAIL**，不能签署企业终验通过。

第二轮复审确认了一项完整修复：功能验收脚本不再提供名为 `final` 的 profile，企业唯一 final 入口已经统一为：

```text
scripts/acceptance.py --profile final
```

但其余 8 项原 P0 均存在残留。最关键的四类问题是：

1. 验收政策仍可自我缩减。删除一个真实 requirement 后合同仍可 `PASS`。
2. runner 仍可被重绑到一个测试，并通过伪造的最低通过数得到 `PASS`。
3. 当前 SHA-256 链没有受信签名或不可预测 challenge，人工构造的完整“当前证据”仍可通过。
4. 企业 final 的 E2E gate 没有启用 enterprise profile，只运行默认 4 个 smoke，却把 `E2E-P0-001` 标为 `passed`。

本机重跑唯一 final 的结果为：

```text
verdict=FAIL
exit=1
```

其中 `OFFLINE-P0-001`、`HOST-P0-001`、`STORAGE-WATERMARK-P0-001`、`CAPACITY-P0-001`、`MALWARE-P0-001`、`DR-P0-001`、`SECURITY-SCAN-P0-001` 与 `WORKTREE-P0-001` 均未通过。`E2E-P0-001` 虽显示 `passed`，但属于本报告复现的错误通过，不能作为验收证据。

## 2. 最终矩阵

分类语义：

- `fixed`：原问题已关闭，未发现同类可重放残留。
- `code-complete-runtime-blocked`：代码与 final 集成完整，只缺目标环境实证。
- `residual`：仍存在代码、集成、证据可信度或交付声明缺口；即使部分子项已完成，也不能关闭原 GAP。

| GAP | Round 2 状态 | 已完成部分 | 阻断或残留 |
|---|---|---|---|
| GAP-P0-001 | `residual` | 空 requirements、test_commands、external_evidence 已 fail-closed | 删除 `FUNC-OFFLINE-001` 后合同仍 `PASS 12/12`；缺独立签名政策、精确必需 ID 集与 policy SHA |
| GAP-P0-002 | `residual` | 命令与 required nodes 字符串绑定；最低通过数和 skip 拒绝已实现 | 全部自动化证据可重绑到一个测试并 `PASS`；无逐节点结果、JUnit/Vitest 结果校验、锁定环境与原始结果哈希 |
| GAP-P0-003 | `residual` | 旧 commit、陈旧时间、缺 artifact、哈希篡改已被拒绝 | 人工构造当前 git/content/artifact/哈希链仍可 `PASS`；无签名/challenge；E2E reporter 与正式 v2 证据格式不兼容 |
| GAP-P0-004 | `fixed` | 功能脚本仅 `source/runtime-functional`；无测试为 UNVERIFIED/BLOCKED；旧 final 被拒绝 | 未发现第二个可输出企业 final verdict 的入口 |
| GAP-P0-005 | `residual` | 企业 E2E 已可收集 18 项；缺拓扑明确 `E2E_BLOCKED` | 唯一 final 默认只收集并运行 4 个 smoke，却把 E2E gate 标为 passed；若干业务场景仍只校验 BFF JSON 或缺角色/Multipart/UI/恢复闭环 |
| GAP-P0-006 | `residual` | 存储验证器要求可销毁卷、25 场景、原始工件哈希及泄漏检查 | final 未传 `--chain-evidence`；直接脚本入口导入失败；仓库没有真实 25 场景水位构造 harness |
| GAP-P0-007 | `residual` | 主机采集器已包含 SSD 身份与四类有界 fio | final 未传 `--io-evidence`；直接采集命令导入失败；无目标 Linux SSD/IO 证据 |
| GAP-P0-008 | `residual` | env 不再被 shell source；symlink、owner、mode、未知键、命令替换与公网 host 已 fail-closed | final 不运行 `preflight-offline.sh`；无全容器 socket/DNS/路由/防火墙证据和断网冷启动业务 smoke |
| GAP-P0-009 | `residual` | 9 种扩展均进入统一能力门；解析单元/集成测试通过 | 标准镜像缺 PDF/旧 Office 运行工具；全格式预检 BLOCKED；final/manifest 无 FORMAT/PARSER gate；README 与部分文档陈旧 |

本轮没有任何 GAP 可归类为纯粹的 `code-complete-runtime-blocked`。GAP-P0-005～009 均包含真实运行阻断，但同时存在 final 接线或交付声明残留，因此整体必须使用更严格的 `residual`。

## 3. 防伪攻击重放

### 3.1 空清单

已通过回归测试确认以下空清单不再静默通过：

| 攻击 | 当前结果 |
|---|---|
| `requirements=[]` | `FAIL` |
| `test_commands=[]` | `FAIL` |
| `external_evidence=[]` | `BLOCKED` |

这只关闭了“全部清空”路径，没有关闭“删除部分必需政策”的路径。

### 3.2 删除一个真实 requirement

在内存副本中删除 `FUNC-OFFLINE-001` 后重跑 `evaluate_contract`：

```text
removed=FUNC-OFFLINE-001
verdict=PASS
requirement_count=12
failed=0
```

根因是必需 requirement、runner 和 external evidence ID 仍由同一个可编辑 manifest 自我声明。代码没有精确的不可缩减 ID 集，也没有独立签名政策或受信 policy digest。

### 3.3 runner 重绑

把所有 automated test evidence 重绑到 `tests/test_functional_acceptance.py` 的一个测试，设置 `minimum_passed_tests=1` 并把 covers 改为全部 requirement 后：

```text
contract=PASS
requirements=13/13
runtime runner=passed
passed_tests=1
```

当前实现能保证 command 字符串包含 manifest 自己声明的 required nodes，却不能证明原有业务测试节点实际执行并逐项通过。原 GAP 要求的 JUnit/Vitest 逐节点结果、原始产物 SHA-256、开始/结束时间、工具版本、退出码与锁定环境证明仍未完成。

### 3.4 手工证据

当前验证器可以拒绝：

- 陈旧采集时间；
- 旧 Git commit；
- 缺少原始 artifact；
- artifact 大小或 SHA-256 不一致；
- attestation 链被篡改。

但是，使用当前 `git_head`、当前 `content_fingerprint`、人工生成的 artifact 与重新计算的 `sha256-chain-v1`，完整手写证据仍可被判定为 `PASS`。SHA-256 只能证明内容一致，不能证明“谁在什么受控环境里执行了测试”。缺少受信 CI/collector 签名或不可预测 challenge 时，GAP-P0-003 不能关闭。

### 3.5 E2E reporter 与正式证据格式断裂

`web/e2e/support/evidence-reporter.ts` 当前输出：

```text
schema_version=1
kind=browser-e2e
status=passed|failed|blocked
```

而 `scripts/functional_acceptance.py` 与 `docs/functional_acceptance_manifest.json` 要求：

```text
schema_version=2
evidence_id
collector.id/version
target.git_head/content_fingerprint
artifacts
checks.*.artifact_ids
attestation.type/digest
```

因此，即使 18 项企业浏览器测试全部通过，当前 reporter 的 JSON 也不能被 runtime-functional 正式证据验证器接受，最终仍会 `BLOCKED`。

## 4. 唯一 final 重放

执行：

```powershell
uv run --frozen --no-sync python scripts/acceptance.py `
  --profile final `
  --report-dir artifacts/acceptance/round2-final
```

结果：

| Gate | 结果 | Round 2 解释 |
|---|---|---|
| CODE-P0-001 | passed | Ruff 通过 |
| FUNCTIONAL-P0-001 | passed | source 功能门禁实际执行后 93 backend + 78 frontend 通过；runtime evidence 仍 BLOCKED |
| TYPE-P1-001 | passed | MyPy 通过 |
| FRONTEND-P0-001 | passed | 25 files / 167 tests 通过 |
| FRONTEND-P1-001 | passed | ESLint 通过 |
| BUILD-P0-001 | passed | Next.js production build 通过 |
| BACKEND-P0-001 | passed | runner 报告 439 tests、0 skipped |
| TOKEN-GOV-P0-001 | passed | runner 报告 7 checks、0 skipped |
| OFFLINE-P0-001 | blocked | 缺目标离线 env/images；且 final 没有运行安全 env preflight |
| HOST-P0-001 | blocked | 当前为 Windows；无目标 Linux SSD/fio 证据 |
| E2E-P0-001 | **错误 passed** | 只运行默认 4 个 smoke；18 项 enterprise tests 被 `grepInvert` 排除 |
| STORAGE-WATERMARK-P0-001 | blocked | 无目标 Linux 与 chain evidence |
| CAPACITY-P0-001 | blocked | 无 1000 用户、50 亿 token/日容量证明 |
| MALWARE-P0-001 | blocked | 无绑定当前内容指纹的正式目标链路证据 |
| DR-P0-001 | blocked | 无计时恢复演练与 RPO/RTO 证据 |
| SECURITY-SCAN-P0-001 | blocked | 无绑定当前内容指纹的正式完成报告 |
| WORKTREE-P0-001 | blocked | 工作树不干净，不可签署 |

最终输出仍为 `verdict=FAIL`、退出码 1。这个 fail-closed 总判定是正确的；但 E2E 子门禁的错误 passed 会掩盖浏览器验收缺失，必须单独修复。

## 5. GAP-P0-005：浏览器 E2E 复审

### 已确认

- `KB_E2E_PROFILE=enterprise` 时收集 18 tests：桌面 9、移动端 9。
- 缺企业拓扑配置时 preflight 抛出 `E2E_BLOCKED`，Playwright 退出 1。
- 自定义 reporter 在缺配置时输出顶层 `blocked`。
- E2E TypeScript 中未发现 `page.route`、`route.fulfill` 或 `route.continue` 浏览器 mock。
- E2E 范围 ESLint、TypeScript 与 diff-check 通过。

### 仍存在的缺口

1. `scripts/acceptance.py` 的 `E2E-P0-001` 只执行 `npm run test:e2e`，没有设置 `KB_E2E_PROFILE=enterprise`。
2. 默认 Playwright 配置使用 `grepInvert: /@enterprise/`，所以 final 实际只收集旧的 4 个 smoke。
3. 没有内容管理员登录落地场景。
4. 文件场景只有小文件单段上传，没有 Multipart。
5. 聊天来源、审核拒绝和表格主要通过 BFF JSON 判断，没有完整验证聊天窗口真实渲染。
6. 没有明确逐一切换 DeepSeek、Qwen、MiniMax。
7. API Key 使用说明 UI 未被验收。
8. quality fixture 只监听主 page，不监听额外创建的成员 page。
9. 没有明确的移动端横向溢出断言。
10. 模型与故障模式恢复没有放入 `finally`，测试中断可能污染预生产验收状态。

因此 GAP-P0-005 必须保持 `residual`，不能仅写“等待目标拓扑”。

## 6. GAP-P0-006/007：存储和主机证据

### 存储水位

验证器已经从 100 字节内存模拟升级为真实证据校验，要求：

- 专用可销毁卷；
- 25 个边界/并发/Multipart 场景；
- 原始工件 SHA-256；
- MinIO 与文件系统双向核对；
- quota、对象和 Multipart 无泄漏。

但是 final 构造 storage gate 时没有传 `--chain-evidence`。即使目标机已经生成合格证据，唯一 final 也无法消费。仓库当前也只有严格验证器，没有能构造 69/70/79/80/89/90% 并执行 25 个真实 API 场景的安全 harness。

另外，文档/runner 使用 `python3 scripts/storage_watermark_preflight.py` 直接执行时会出现：

```text
ModuleNotFoundError: No module named 'app'
```

模块入口 `python -m scripts.storage_watermark_preflight ...` 才能得到正确的 `status=blocked`、退出码 2。

### 主机 SSD/IO

采集器已覆盖：

- 挂载与块设备身份；
- SSD/non-rotational 或云盘规格证明；
- `sequential_write`、`random_read`、`random_write`、`fsync` 四类有界 fio；
- P95/P99、IOPS 与阈值工件；
- 专用目录、challenge、测试文件和运行时间上限。

但是 final 构造 host gate 时没有传 `--io-evidence`。目标机即使完成 fio，也无法让唯一 final 消费该证据。

文档中的 `python3 scripts/collect_host_io_evidence.py` 直接入口同样会因包导入失败退出 1；需要改为模块入口或修正 import bootstrap。

当前 Windows 复审机执行 host preflight 得到：

```text
status=blocked
exit=2
reason=preflight must run on the target Linux host
```

## 7. GAP-P0-008：离线 env 与网络

源代码子项已有明显改进：

- source 前拒绝 symlink；
- 要求 root 所有；
- 权限只接受 `0400` 或 `0600`；
- env 按数据逐行解析，不再 shell source；
- 固定键白名单；
- 拒绝重复键、未知键、命令替换与 shell 元字符；
- URL/host 仅允许私网、回环或链路本地地址；
- Compose 网络声明为 internal；
- 离线环境关闭 external LLM。

但唯一 final 的 `OFFLINE-P0-001` 只调用 `verify-offline-images.sh verify`，没有运行 `preflight-offline.sh`。因此上面的 env 防注入校验并未进入正式 final。

仍缺目标主机证据：

- 所有容器公网 socket；
- DNS 查询与解析路径；
- 默认路由与网络命名空间；
- 防火墙状态；
- 宿主机断网后的冷启动；
- 登录、RBAC、知识 ACL、上传、扫描、OKF、审批、下载、问答和重启持久化 smoke。

## 8. GAP-P0-009：全格式解析能力

解析代码已经覆盖 `.txt/.doc/.docx/.xls/.xlsx/.csv/.pdf/.ppt/.pptx` 全部 9 种扩展：

- TXT/CSV 与 OOXML 使用内置离线解析器；
- PDF 使用受控 Poppler `pdftotext`；
- 旧 Office 使用受控 LibreOffice 转换；
- 宏、主动内容、外部关系、加密包、路径穿越、解压炸弹和超限输出均有 fail-closed 规则；
- OKF conversion 已接入统一能力门与 parser provenance。

48 个文档解析定向测试通过。但当前运行环境执行：

```powershell
uv run --frozen --no-sync python -m app.document_parser_preflight --require-all
```

得到：

```text
status=blocked
exit=2
missing=.doc,.xls,.ppt,.pdf
```

当前标准 Docker runtime 没有安装 `bwrap`、`prlimit`、`pdftotext` 与 `libreoffice`，而离线 API/maintenance 复用该镜像，因此镜像本身不能闭合 PDF 和旧 Office。

机器门禁也没有闭合：

- `scripts/acceptance.py` 没有 FORMAT/PARSER gate；
- 功能 manifest 没有 format requirement，也没有绑定 document parser 测试；
- `--require-all` 只写在解析安全文档，没有进入 CI、部署预检或唯一 final；
- 浏览器 E2E 只有 TXT fixture，没有 9 格式上传、解析、OKF、审批、检索与引用闭环。

文档仍有冲突：README、商业审计与知识流水线文档继续声明“仅 TXT/CSV，Office/PDF 待建设”；README 的测试数量、覆盖率与最新自测链接也已过期；功能验收标准仍称 Playwright 只有登录/性能测试。

## 9. 验证命令与结果

| 命令/检查 | 结果 |
|---|---|
| 聚焦 P0 回归：functional、acceptance、host IO、storage、offline env、document parser | 全部通过 |
| `tests/test_functional_acceptance.py` + `tests/test_acceptance_runner.py` | 41 passed |
| 空清单/runner/手写证据/旧 final 8 项防伪回归 | 8 passed |
| host/storage/offline 相关聚焦测试 | 52 passed |
| document parser/preflight/OKF pipeline | 48 passed |
| `scripts/functional_acceptance.py --profile source --json`，不运行测试 | exit 2；source=UNVERIFIED |
| `scripts/functional_acceptance.py --profile runtime-functional --json`，不运行测试 | exit 2；runtime=BLOCKED |
| `scripts/functional_acceptance.py --profile final --json` | exit 2；invalid choice |
| enterprise Playwright collection | exit 0；18 tests |
| default Playwright collection | exit 0；4 tests |
| enterprise preflight without topology | exit 1；`E2E_BLOCKED` |
| enterprise reporter without topology | top-level `blocked` |
| host preflight on current Windows host | exit 2；blocked |
| storage preflight on current Windows host | exit 2；blocked |
| parser `--require-all` | exit 2；blocked，缺 4 类运行能力 |
| 唯一 enterprise final | exit 1；verdict=FAIL |
| E2E scoped ESLint/TypeScript/diff-check | passed |
| E2E browser interception search | none |

## 10. 必须修复的顺序

1. 在代码或独立受信政策中固化精确 requirement/runner/external evidence ID 集和版本；manifest 只能扩展，不能缩减；报告记录受信 policy digest。
2. runner 改为消费真实 JUnit/Vitest JSON/JUnit 节点结果，核对每个必需 node；保存原始结果哈希、工具版本、时间、退出码与锁定依赖身份。
3. 正式证据增加受信 collector 签名或不可预测 challenge；不能只依赖可人工重算的 SHA-256 链。
4. 把 E2E reporter 升级到 functional evidence schema v2，输出正确 evidence ID、collector、完整 content fingerprint、artifact 引用和 attestation。
5. 让唯一 final 显式运行 enterprise Playwright profile，并把缺拓扑视为 blocked；禁止默认 smoke 满足 E2E-P0-001。
6. 补内容管理员、Multipart、真实聊天 UI、三供应商切换、API 使用说明、次级 page 质量监听、移动端溢出和 `finally` 恢复场景。
7. 为 final 增加 `--host-io-evidence` 与 `--storage-chain-evidence` 输入，并传给对应验证器；修正文档中的模块入口。
8. 提供可销毁卷上的真实 25 场景存储 harness，并保存前后 df、MinIO、Multipart、quota 与 API 证据。
9. 把安全 env preflight、容器出站审计和断网冷启动 smoke 接入 OFFLINE-P0-001。
10. 在标准镜像安装并固定受控 parser 依赖；把 `document_parser_preflight --require-all` 接入部署预检、CI 和 final；补 9 格式真实 E2E。
11. 修正 README 与交付文档中的格式、E2E、测试数量、覆盖率、云厂商命名和最新证据链接。
12. 在干净工作树、精确 Git/content fingerprint、不可变镜像 digest 和目标 Linux 主机上重跑唯一 final。

## 11. 本轮未证明的内容

本报告没有证明以下项目通过：

- 目标 Linux 8C/16G/300G SSD 主机适配；
- 真实 SSD IOPS、P95/P99 与 fsync；
- 70/80/90% 和 180 GB 存储水位链；
- 真实浏览器 18 项企业业务链；
- 9 格式真实文件闭环；
- 完全断网冷启动；
- 1000 用户和 50 亿 token/日容量；
- 恶意文件全链路；
- DR RPO/RTO；
- 完成态安全扫描、SBOM、许可证和法律签署。

因此，本报告本身是问题复审证据，不是企业交付签署文件。
