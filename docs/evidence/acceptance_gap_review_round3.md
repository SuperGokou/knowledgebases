# 企业终验防伪复审（Round 3）

> 复审日期：2026-07-13
> 复审模式：共享工作树只读攻击重放；仅新增本报告
> 目标规格：Linux amd64/x86_64，8 vCPU，16 GB RAM，300 GB SSD；数据库、Redis、对象存储与业务数据均位于企业内网
> Git HEAD：`38627430eee7ec5bd2e5388c5d86c8daf1928a59`
> 报告写入前内容指纹：`dea0a93ba2cbea9bf5f460997fb6d0dcfae1783e61791e85237d85d242bf45d9`
> 受信策略 SHA-256：`66550db68a42d423b25a68c6ba9cd08a81255c92cb2ca0404d93583f84c6922c`
> 安全边界：未读取 `.env`，未联网，未连接或部署到云主机，未运行破坏性存储测试，未伪造任何外部 `PASS`

## 1. 严格结论

Round 2 的 9 个代码与验收可信度缺口均已完成代码侧闭环：GAP-P0-001 至 GAP-P0-004 判定为 `fixed`；GAP-P0-005 至 GAP-P0-009 判定为 `code-complete-runtime-blocked`。本轮没有在这 9 个 GAP 内发现新的代码级残留。

项目当前整体仍为 **NO-GO / FAIL**，不能签署企业生产终验通过。原因不是本轮代码回归失败，而是以下目标环境证据尚不存在：

1. 真实其他云 Linux 8C/16G/300G SSD 主机及四类 fio 证据；
2. 真实企业拓扑上的 18 项 Playwright 企业业务闭环及 Ed25519 正式证据；
3. 专用可销毁卷上的 25 场景存储水位链；
4. 完全断网冷启动、全容器出站审计与重启持久化链；
5. 目标 Linux 固定工具链下九格式、ClamAV 与解析沙箱运行证据；
6. 1000 人、50 亿 Token/日容量证据、DR 演练、完成态安全扫描与干净工作树签署证据。

所有外部证据缺失均保持 `blocked`，没有被本地单元测试替代或降级为通过。

## 2. Round 3 最终矩阵

状态语义：

- `fixed`：原缺口已经关闭，攻击重放未发现同类绕过路径；
- `code-complete-runtime-blocked`：代码、门禁和唯一 final 接线完整，仅缺真实目标环境执行证据；
- `residual`：仍有代码、接线、证据可信度或交付声明缺口。

| GAP | Round 3 状态 | 本轮确认的闭环 | 仍需外部完成的证据 |
|---|---|---|---|
| GAP-P0-001 | `fixed` | 精确固化 requirement、runner、external evidence ID 集；manifest 只能扩展不能缩减；受信 policy digest 固化在代码中 | 无 |
| GAP-P0-002 | `fixed` | runner 消费真实 JUnit/Vitest 逐节点结果，绑定必需节点、退出码、开始/结束时间、锁文件身份、原始工件哈希和内容指纹；聚合字符串不能伪造通过 | 无 |
| GAP-P0-003 | `fixed` | 正式 v2 证据采用 root 保护的 Ed25519 key、固定 key ID 和一次性 challenge；SHA-only、自签名、篡改与重放均拒绝；Node reporter 与 Python verifier 已互操作 | 无 |
| GAP-P0-004 | `fixed` | 功能验收只保留 `source` / `runtime-functional`；企业唯一 final 为 `scripts/acceptance.py --profile final`；旧 final 被拒绝 | 无 |
| GAP-P0-005 | `code-complete-runtime-blocked` | final 强制 enterprise profile；严格收集 18 项；覆盖统一登录/角色路由、账号生命周期、知识 ACL 撤权、九格式闭环、真实聊天 UI/来源/表格/审核拒绝、三模型切换、API Key/说明、错误状态、移动端及 `finally` 恢复；Playwright 退出 0 后仍须正式签名证据通过 | 真实前端、API、故障控制面、测试账号、受信密钥与一次性 challenge |
| GAP-P0-006 | `code-complete-runtime-blocked` | final 已接入 `--storage-chain-evidence`；真实 HTTP collector 声明并校验 69/70/79/80/89/90% × single/multipart/retry/concurrent，加 180 GB stop-line 共 25 场景；校验 filesystem/MinIO/quota/multipart/API 双向一致性 | 目标 Linux 专用可销毁卷、受控 storage acceptance endpoint 和一次性 challenge |
| GAP-P0-007 | `code-complete-runtime-blocked` | final 已接入 `--host-io-evidence`；直接脚本入口可用；采集 SSD/云盘身份和 sequential write、random read、random write、fsync 四类有界 fio | 目标 Linux 8C/16G/300G SSD 主机实测 |
| GAP-P0-008 | `code-complete-runtime-blocked` | final 已接入安全 env preflight、离线镜像校验和 `--offline-runtime-evidence`；采集器包含 socket/DNS/路由/防火墙、断网冷启动、登录/RBAC/ACL/上传/扫描/OKF/审批/下载/问答、重启持久化和恢复 | 目标 Linux root 控制的离线环境、镜像清单、控制计划和一次性 challenge |
| GAP-P0-009 | `code-complete-runtime-blocked` | final 新增 `FORMAT-P0-001`；Docker 固定 Poppler/LibreOffice/bubblewrap/prlimit 版本；CI 和部署预检执行 `--require-all`；生成器提供 6 种确定性内建样本及 3 种 sandboxed legacy Office 样本；enterprise E2E 对九格式逐一执行上传→clean→OKF→审批→检索→聊天引用→来源位置闭环 | 目标 Linux 固定、root-owned 工具链及真实九格式运行证据 |

## 3. 防伪攻击重放

### 3.1 策略缩减与 runner 重绑定

以下攻击全部被拒绝：

- 删除 `FUNC-OFFLINE-001`；
- 删除标准绑定以绕过策略；
- 删除一个必需 external evidence；
- 把全部 requirements 重绑定到同一个测试节点；
- 用无关的 `1 passed` 文本满足最低通过数；
- 仅提交聚合通过数、不提供逐节点机器工件。

精确回归结果：12 项防伪测试全部通过，其中包含策略缩减、runner 重绑定、逐节点工件、签名 challenge、SHA-only 拒绝、浏览器证据和 final 接线。

### 3.2 签名、篡改与重放

正式证据链要求：

1. schema v2；
2. 精确 evidence ID；
3. 当前 Git HEAD 与内容指纹；
4. 每个检查绑定原始工件 ID、大小和 SHA-256；
5. 固定 collector ID/version；
6. 根信任库中的 Ed25519 公钥和固定 key ID；
7. 未使用、未过期、绑定 evidence/target 的一次性 challenge；
8. 验签成功后原子消费 challenge。

重放结果：首次合规签名证据通过；同一 challenge 第二次使用被拒绝；SHA-only 证据、自签名、工件篡改、指纹漂移及缺证据均被拒绝。

### 3.3 E2E 错误通过攻击

- enterprise profile 收集：18 项（桌面 9 + 移动 9）；
- smoke profile 收集：4 项，不可满足企业 E2E；
- 缺全部企业拓扑时：Playwright 退出 1，并明确输出 `E2E_BLOCKED`；
- 浏览器进程退出 0 但没有已验证正式证据：`blocked`；
- final 只验证唯一 `EXT-BROWSER-E2E-001`，同时仍受完整 trusted policy 约束。

## 4. 九格式链复审

### 4.1 样本生成与版权边界

- TXT、CSV、DOCX、XLSX、PPTX、PDF 使用项目自有的确定性合成内容；
- DOC、XLS、PPT 由自有 OOXML 样本在固定 Linux 沙箱中转换；
- manifest 声明 `CC0-1.0`、`original-synthetic-test-data`、`network_required=false`；
- 每个格式具有唯一 token、预期来源位置、字节数和 SHA-256；
- 禁止 placeholder、dummy、lorem ipsum、TODO；
- 拒绝 symlink、祖先 symlink、路径越界、manifest 越界、扩展名伪造、hash/contract drift；
- OOXML ZIP 宿主元数据固定，避免 Windows/Linux 生成哈希漂移；
- legacy 转换固定使用 `/usr/bin/bwrap`、`/usr/bin/prlimit`、`/usr/bin/libreoffice`，断网、清空环境并限制 CPU、地址空间、文件大小和文件描述符；工具缺失、超时或转换失败一律 `BLOCKED`。

### 4.2 企业业务闭环

九格式 enterprise 用例不只校验“可以上传”，而是逐格式确认：

1. 文件通过前端上传控件进入指定知识库；
2. 文件状态达到 `processing:clean`；
3. 最新 OKF conversion 达到 `succeeded`；
4. 审批接口成功且内容可发布；
5. token 检索命中对应 `source_file_id`；
6. 聊天返回绑定同一源文件的 citation；
7. citation entry 保留 token、source identity 和预期 paragraph/worksheet/page/slide 定位。

## 5. 运行证据

| 命令/检查 | 结果 |
|---|---|
| 聚焦 acceptance/host/storage/offline/parser/OKF 回归 | 174 passed |
| 精确防伪攻击重放 | 12 passed |
| Python fixture 独立回归 | 14 passed |
| Web 全量 Vitest | 27 files / 176 tests passed |
| fixture + enterprise contract 定向 Vitest | 9 passed |
| Ruff（验收、采集器、fixture 范围） | passed |
| strict MyPy（验收、fixture 范围） | passed |
| TypeScript `tsc --noEmit` | passed |
| ESLint `--max-warnings=0` | passed |
| `git diff --check` | passed |
| enterprise Playwright `--list` | 18 tests |
| smoke Playwright `--list` | 4 tests |
| enterprise preflight（无拓扑） | exit 1，`E2E_BLOCKED` |
| host preflight（当前 Windows 审查机） | exit 2，`blocked` |
| storage preflight（当前 Windows 审查机） | exit 2，`blocked` |
| parser `--require-all`（当前 Windows 审查机） | exit 2，缺 `.doc/.xls/.ppt/.pdf`，`blocked` |
| storage collector `--list-plan` | 25 scenarios，dry-run，未执行破坏性操作 |
| host/storage/offline/fixture 直接脚本入口 | `--help` 全部 exit 0 |

## 6. 不能签署的外部阻断

| Gate | 当前结论 | 解除条件 |
|---|---|---|
| `E2E-P0-001` | `blocked` | 真实拓扑上 18 项通过并生成可验签、不可重放的 v2 证据 |
| `HOST-P0-001` | `blocked` | 目标 Linux 8C/16G/300G SSD 与四类 fio 达标 |
| `STORAGE-WATERMARK-P0-001` | `blocked` | 专用可销毁卷 25 场景全部达标且无配额/对象/multipart 泄漏 |
| `OFFLINE-P0-001` | `blocked` | 完全断网冷启动、全容器出站审计、业务闭环与持久化恢复通过 |
| `FORMAT-P0-001` | `blocked` | 目标镜像 `--require-all` 通过，九格式真实企业 E2E 证据验签成功 |
| `CAPACITY-P0-001` | `blocked` | 1000 用户及 50 亿 Token/日容量、成本、限流、排队与降级实测 |
| `MALWARE-P0-001` | `blocked` | 目标 ClamAV 数据库、恶意样本隔离、审计与恢复链通过 |
| `DR-P0-001` | `blocked` | 计时备份恢复演练满足已批准 RPO/RTO |
| `SECURITY-SCAN-P0-001` | `blocked` | 当前内容指纹绑定的完成态扫描、SBOM、许可证与处置报告 |
| `WORKTREE-P0-001` | `blocked` | 工作树清洁、依赖锁定、镜像 digest 固化并由授权验收人签署 |

特别说明：8C/16G/300G 主机可以承载控制面、数据库、Redis、对象存储和有限并发 Worker，但不能据此证明本机能够提供 50 亿 Token/日推理能力。该规模必须依赖独立推理集群或经过批准的模型服务，并提交真实容量和成本证据。

## 7. 下一次终验顺序

1. 在目标 Linux 主机完成只读 host preflight；不达标立即停止。
2. 固化离线镜像 digest，校验本地 PostgreSQL、Redis、MinIO、ClamAV 和解析工具链。
3. 使用专用可销毁卷执行 storage 25 场景并完成清理核对。
4. 生成根保护的 trust store、签名 key 和一次性 challenges。
5. 执行完全断网冷启动、九格式链和 18 项 enterprise Playwright。
6. 执行容量、恶意文件、DR 与完成态安全扫描。
7. 在干净工作树上运行唯一 final：

```bash
uv run --frozen --no-sync python scripts/acceptance.py --profile final \
  --report-dir /var/lib/heyi-acceptance/final \
  --host-io-evidence /var/lib/heyi-acceptance/evidence/host-io.json \
  --storage-chain-evidence /var/lib/heyi-acceptance/evidence/storage-chain.json \
  --offline-env-file /etc/heyi/offline.env \
  --offline-image-manifest /var/lib/heyi-acceptance/evidence/offline-images.txt \
  --offline-runtime-evidence /var/lib/heyi-acceptance/evidence/offline-runtime.json \
  --e2e-evidence /var/lib/heyi-acceptance/evidence/browser-e2e.json \
  --functional-trust-store /root/heyi-acceptance/trust-store.json \
  --functional-challenge-store /root/heyi-acceptance/challenges \
  --e2e-signing-key-path /root/heyi-acceptance/browser-e2e.key \
  --e2e-signing-key-id heyi-browser-e2e-prod-v1 \
  --malware-evidence /var/lib/heyi-acceptance/evidence/malware.json \
  --security-scan-evidence /var/lib/heyi-acceptance/evidence/security-scan.json
```

参数名称必须以目标版本 `scripts/acceptance.py --help` 为准；密钥、challenge、账号和 SSH 信息不得写入仓库、报告或日志。

## 8. 报告身份说明

本报告是 Round 3 缺口复审与攻击重放记录，不是企业终验签署文件。报告自身写入工作树后会改变内容指纹，因此顶部指纹明确标记为“报告写入前内容指纹”，不可用它签署报告写入后的工作树。正式签署必须在全部改动提交、工作树清洁后重新采集内容指纹并重新运行唯一 final。
