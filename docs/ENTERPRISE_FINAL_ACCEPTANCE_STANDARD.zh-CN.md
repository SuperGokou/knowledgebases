# 企业知识中台最终交付验收标准

版本：1.1

适用对象：江苏和熠光显有限公司企业知识中台

基础标准：[企业知识库超级详细验收标准](./ENTERPRISE_ACCEPTANCE_STANDARD.zh-CN.md)

## 1. 验收原则

本文件是最终交付的发布判定层，不替代基础标准中的逐项 Gate。所有结论必须由可重复执行的测试、真实环境观测、恢复演练或经复核的审计证据支持。

- `PASS`：全部 P0、P1 Gate 有效通过，且没有到期豁免；
- `CONDITIONAL`：全部 P0 通过，但存在未完成或未验证的 P1；
- `FAIL`：任一 P0 失败、阻断或缺少证据；
- 未执行、工具不可用、环境不足、仅有设计文档，一律记为 `blocked`，不得记为通过；
- 单元测试通过不等于系统性能、安全、容灾或版权验收通过；
- “零瑕疵”“绝对安全”“零版权风险”不是可审计结论。最终报告必须写明残余风险和证据边界。

## 2. 强制规模模型

### 2.1 业务假设

| 指标 | 最终验收口径 |
|---|---:|
| 注册/可授权用户 | 1,000 |
| Token 日消耗目标 | 5,000,000,000 |
| 当前交付主机 | Linux amd64/x86_64、8 vCPU、16 GB RAM、300 GB SSD |
| 当前单机对象停止线 | 180 GB；70% 预警、80% 停止批量上传、90% 拒绝新上传 |
| 未来存储扩展目标 | 10 TB 独立企业内网存储集群，不属于当前 300 GB 单机 P0 |
| 数据出网 | 默认禁止；任何外部模型调用必须显式批准、可审计并完成数据分级 |

### 2.2 不可回避的物理约束

- 50 亿 Token/日等于 24 小时平均约 `57,870 token/s`；若集中在 8 小时业务窗口，平均约 `173,611 token/s`。单台 8 vCPU、无 GPU 主机不能承担该推理吞吐。
- 当前发布必须在目标 Linux 主机本机执行只读预检：架构为 amd64/x86_64、可见逻辑 CPU 不少于 8、可见内存不少于 15 GiB、目标数据文件系统物理总量不少于 300 GB（十进制），且部署前可用空间不少于 240 GB。任一条件不满足均为 P0 失败；没有在目标主机执行则为 P0 `blocked`。
- 当前 300 GB 单机是本次部署的正式硬件基线，而不是 10 TB 集群的缩小容量证明。对象数据建议在 180 GB 触发停止线，并执行 70%/80%/90% 水位策略，给操作系统、镜像、PostgreSQL、WAL、Multipart 暂存、日志与升级回滚留出空间。
- 10 TB 调整为未来独立企业内网存储集群扩展目标，不再作为当前 300 GB 单机验收的 P0。启用该扩展前仍须单独完成冗余、校验、生命周期、备份恢复和扩容验收。
- 50 亿 Token/日仍须由企业内网 GPU 推理集群或获批准的模型服务提供容量证据。8C16G 无 GPU 单机不得被描述为具备该本地推理能力。

详细计算和压测方法见 [性能与容量模型](./PERFORMANCE_CAPACITY_MODEL.zh-CN.md)。

## 3. P0 发布阻断清单

| Gate | 验收对象 | 通过条件 |
|---|---|---|
| `FINAL-P0-001` | 身份与会话 | Refresh Token 轮换、令牌族重放封锁、即时撤销和并发双花在真实 PostgreSQL/Redis 上通过 |
| `FINAL-P0-002` | RBAC/ACL | 动态角色、权限提升防护、过期角色、知识库 ACL 双门禁、API Key 权限交集全部通过越权矩阵 |
| `FINAL-P0-003` | 文件安全 | MIME/签名识别、恶意代码扫描、宏/PDF 脚本/加密包/解压炸弹隔离；扫描故障 fail closed；未清洁文件不可审批或下载 |
| `FINAL-P0-004` | 文件完整性 | 单段和 Multipart 完整对象摘要可验证；错误分片、缺片、重放和竞态全部拒绝 |
| `FINAL-P0-005` | 知识发布 | 文件可下载状态与知识可检索状态分离；模型草稿可预览、可审查，未经独立内容审批不得发布 |
| `FINAL-P0-006` | 格式闭环 | TXT、DOC、DOCX、XLS、XLSX、CSV、PDF、PPT、PPTX 均有隔离解析黄金样本、页码/工作表/幻灯片定位和资源限制证据 |
| `FINAL-P0-007` | 检索质量 | 固定中文黄金集达到 Recall@5、MRR、nDCG、无答案准确率和 ACL 泄漏阈值；10 TB 方案不得依赖全表 `%ILIKE%` |
| `FINAL-P0-008` | 防幻觉 | 每个事实和每个表格行可追溯；非法引用接受率 0%；审核故障确定性降级；独立审核或确定性 claim/evidence 校验 |
| `FINAL-P0-009` | Token/成本 | 调用前原子预留、调用后按供应商 usage 结算；用户/知识库/租户/模型/供应商多级日预算和成本熔断可对账 |
| `FINAL-P0-010` | 容量 | 当前主机控制面压测与 1,000 用户模型完整；50 亿 Token/日由独立推理服务提供实测容量、限额与成本证据，且实测与模型值明确区分 |
| `FINAL-P0-011` | 目标主机与本地存储 | 目标 Linux amd64/x86_64 主机通过 8 vCPU、15 GiB 可见内存、300 GB 总量和部署前 240 GB 可用空间预检；`STORAGE-WATERMARK-P0-001` 在目标主机实测 180 GB 对象停止线及 70%/80%/90% 水位策略，无法采集真实证据时必须 blocked/FAIL |
| `FINAL-P0-019` | 离线镜像与病毒库 | 镜像清单由 `docker compose config --images` 生成并验证，包含 ClamAV；`main`/`daily` 病毒库只读挂载，存在性、可读权限、SHA-256、更新时间和 `sigtool --info` 兼容性预检全部通过 |
| `FINAL-P0-012` | 数据一致性 | 配额、刷新令牌、任务领取、角色替换、幂等上传在真实 PostgreSQL/Redis 并发测试中无超卖、双发和丢失更新 |
| `FINAL-P0-013` | 审计 | 关键操作可按权限查询导出；运行时账号不能更新/删除审计日志；敏感字段 0 泄漏；完整性可验证 |
| `FINAL-P0-014` | 离线隔离 | PostgreSQL、Redis、对象存储、应用和日志均在企业受控环境；断网冷启动与全流程通过；无批准的公网调用为 0 |
| `FINAL-P0-015` | 安全审查 | 深度扫描、威胁模型、攻击面验证、依赖/容器漏洞扫描完成；Critical=0、High=0 或有正式限期豁免 |
| `FINAL-P0-016` | 容灾 | 独立备份、PostgreSQL PITR、对象版本/复制、全新主机恢复演练满足 RPO≤15 分钟、RTO≤4 小时，1000 对象哈希一致率 100% |
| `FINAL-P0-017` | 供应链与版权 | 源码/镜像 SBOM、许可证策略、第三方通知、Logo/字体/截图权属证明、镜像 digest/签名和可复现离线包齐全 |
| `FINAL-P0-018` | 业务 E2E | 桌面与移动端覆盖登录、权限、上传、扫描、转换、内容审批、检索、来源、表格、模型故障和退出；严重无障碍问题为 0 |

## 4. P1 生产质量清单

| Gate | 验收对象 | 通过条件 |
|---|---|---|
| `FINAL-P1-001` | 可观测性 | 结构化日志、指标、trace、请求关联、队列年龄、Token/成本、数据库/Redis/对象存储告警齐全 |
| `FINAL-P1-002` | 可靠性 | 有界队列、超时预算一致、取消传播、指数退避、熔断、舱壁和优雅停止通过故障注入 |
| `FINAL-P1-003` | 发布 | 镜像不可变、迁移互斥、升级前克隆演练、健康摘流、自动回滚；不影响同机其他应用 |
| `FINAL-P1-004` | 数据生命周期 | 过期令牌、配额窗口、上传分片、审计归档、文件删除与法律保留策略自动执行 |
| `FINAL-P1-005` | 运维 | Runbook、值班、容量告警、密钥轮换、季度恢复演练、事故响应和责任人明确 |
| `FINAL-P1-006` | 性能 | 30 分钟稳态与峰值压测满足 API/检索 P95/P99、错误率和资源阈值，且没有 OOM、重启、死锁和 Redis eviction |

## 5. 必须交付的证据包

最终证据包至少包含：

1. 精确 Git SHA、分支、构建镜像 digest 和签名；
2. 后端、前端、类型、静态、迁移、浏览器 E2E 和 Compose/容器测试原始结果；
3. CycloneDX 或 SPDX SBOM、依赖漏洞报告、许可证清单和第三方通知；
4. 脱敏的威胁模型、深度安全扫描报告、修复复测和残余风险签字；
5. 真实 Linux 8C16G/300GB 主机的只读预检 JSON、资源曲线、负载数据集、P50/P95/P99、错误率和故障注入结果；
6. 50 亿 Token/日容量模型、供应商或内网推理服务的实测吞吐、限额和成本对账；
7. 当前单机 180 GB 停止线、70%/80%/90% 水位、数据校验和恢复证据；未来启用 10 TB 独立存储集群时另附集群容量、冗余、扩容和恢复证据；
8. 全新环境恢复报告、RPO/RTO、1000 个对象哈希抽检；
9. 项目代码版权声明、素材授权、许可证审批记录；
10. 最终自检报告，逐项给出 `passed/failed/blocked`，不得省略失败项。

所有证据禁止包含 `.env` 值、密码、JWT、Refresh Token、API Key、数据库连接串、完整公网 IP、企业文档正文、Cookie 或完整预签名 URL。

## 6. 自动化入口

```bash
sudo -H bash <<'ROOT'
set -euo pipefail
umask 077

SOURCE_CHECKOUT='/srv/heyi-knowledgebases-offline/acceptance-source/REPLACE_WITH_40_CHAR_GIT_SHA'
BUNDLE_ROOT='/srv/heyi-knowledgebases-offline/artifacts/REPLACE_WITH_RELEASE_ID/offline-registry-bundle'
RUNTIME_ENV='/srv/heyi-knowledgebases-offline/shared/runtime.env'
RELEASE_ENV="$BUNDLE_ROOT/release.env"
EVIDENCE_ROOT='/srv/heyi-knowledgebases-offline/evidence'
TRUST_ROOT='/etc/heyi-acceptance'
RELEASE_ID='REPLACE_WITH_40_CHAR_GIT_SHA'
NODE_EXECUTABLE='/usr/local/lib/heyi-acceptance/node'
DEPLOYMENT_BASE_URL='https://knowledge.example.internal'
BROWSER_EVIDENCE="$SOURCE_CHECKOUT/artifacts/acceptance/functional/browser-e2e.json"
LINUX_HOST_EVIDENCE="$SOURCE_CHECKOUT/artifacts/acceptance/functional/linux-host.json"

test -d "$SOURCE_CHECKOUT/.git" || test -f "$SOURCE_CHECKOUT/.git"
test -f "$RELEASE_ENV"
test -f "$RELEASE_ENV.images"
test "$RELEASE_ID" != 'REPLACE_WITH_40_CHAR_GIT_SHA'
cd -- "$SOURCE_CHECKOUT"

install -d -o root -g root -m 0755 /usr/local/lib/heyi-acceptance
install -o root -g root -m 0755 "$(command -v node)" "$NODE_EXECUTABLE"
install -d -o root -g root -m 0750 "$(dirname "$BROWSER_EVIDENCE")"

PYTHONPATH="$SOURCE_CHECKOUT" /usr/bin/python3 scripts/acceptance.py \
  --profile final \
  --host-disk-path /srv \
  --host-io-evidence "$EVIDENCE_ROOT/host-io.json" \
  --storage-chain-evidence "$EVIDENCE_ROOT/watermark-chain.json" \
  --offline-runtime-env-file "$RUNTIME_ENV" \
  --offline-release-env-file "$RELEASE_ENV" \
  --offline-runtime-evidence "$EVIDENCE_ROOT/offline-runtime/offline-runtime-evidence.json" \
  --e2e-evidence "$BROWSER_EVIDENCE" \
  --linux-host-evidence "$LINUX_HOST_EVIDENCE" \
  --functional-trust-store "$TRUST_ROOT/functional-trust.json" \
  --functional-challenge-store /var/lib/heyi-acceptance/challenges \
  --e2e-signing-key-path "$TRUST_ROOT/browser-e2e-ed25519.key" \
  --e2e-signing-key-id browser-e2e-ed25519 \
  --linux-host-signing-key-path "$TRUST_ROOT/linux-host-ed25519.key" \
  --deployment-base-url "$DEPLOYMENT_BASE_URL" \
  --malware-evidence "$EVIDENCE_ROOT/malware.json" \
  --security-scan-evidence "$EVIDENCE_ROOT/security-scan.json" \
  --release-id "$RELEASE_ID" \
  --capacity-evidence "$EVIDENCE_ROOT/capacity/enterprise-capacity.json" \
  --capacity-evidence-signature "$EVIDENCE_ROOT/capacity/enterprise-capacity.sig" \
  --capacity-evidence-public-key "$TRUST_ROOT/operational-ed25519.pub" \
  --disaster-recovery-evidence "$EVIDENCE_ROOT/dr/enterprise-disaster-recovery.json" \
  --disaster-recovery-evidence-signature "$EVIDENCE_ROOT/dr/enterprise-disaster-recovery.sig" \
  --disaster-recovery-evidence-public-key "$TRUST_ROOT/operational-ed25519.pub" \
  --supply-chain-attestation "$TRUST_ROOT/release-rights-attestation.json" \
  --supply-chain-artifact-root "$EVIDENCE_ROOT/supply-chain" \
  --node-executable "$NODE_EXECUTABLE" \
  --report-dir "$EVIDENCE_ROOT/reports/final"
ROOT
```

上面是 `final` Profile 的唯一完整入口示例。`SOURCE_CHECKOUT` 必须是与目标 40 位 Git SHA 绑定的干净源码检出，只用于运行验收器；`BUNDLE_ROOT` 必须是同一发布身份的已验签、只读运输 bundle，`RELEASE_ENV` 固定来自该 bundle。二者都不是 `/releases/<contract-sha256>` 的运行时物化目录；物化目录没有 `.git`、`runtime.env` 或 `release.env`。替换占位符时，`RELEASE_ID` 必须逐字等于源码 Git HEAD，且该 SHA、bundle 的 `RELEASE_ID`/`RELEASE_GIT_SHA`、供应链权利声明以及容量/灾备签名信封必须属于同一候选发布。镜像清单不单独传参，验收器只从 `"$RELEASE_ENV.images"` 派生；若为兼容调用显式提供 `--offline-image-manifest`，其值也必须逐字等于该路径。`DEPLOYMENT_BASE_URL` 必须是本次被测部署的规范 HTTPS origin；浏览器和 Linux 主机证据必须分别写入源码检出内固定的 `artifacts/acceptance/functional/browser-e2e.json` 与 `linux-host.json`，两份签名证据的发布 SHA、canonical contract 摘要、镜像清单摘要、URL 与主机身份必须完全一致。最终 JSON 只保存 canonical contract 与镜像清单的 SHA-256，不保存环境或清单正文；报告自身的规范 SHA-256 仍需由仓库外的签名发布包封装后才能作为正式交付证据。

`final` Profile 必须在目标 Linux 主机执行，并把 `HOST-P0-001` 作为 P0。脚本只读取操作系统、架构、CPU、内存和指定路径所在文件系统，不读取 `.env`、IP 或凭据。Windows 或非目标环境返回 `blocked` 和退出码 2；目标 Linux 不符合规格返回退出码 1；通过返回 0。存在任何 P0 `failed/blocked` 时最终 verdict 必须为 `FAIL`。

`local` 与 `ci` 只属于开发 Smoke，不是可签署交付证据。`final` 报告会记录 Git HEAD、工作树脏状态、状态分类计数、tracked diff SHA-256、untracked manifest/content SHA-256 与综合内容指纹；工作树不干净或无法采集身份时强制 `FAIL`。报告只记录计数与哈希，不记录未跟踪文件名、文件内容、`.env` 值或凭据。

`E2E-P0-001` 固定运行 enterprise Profile，必须运行 24 项企业桌面/移动业务检查（每个项目 12 项，包含严格 TLS 身份与有效期验证）以及桌面、移动各 1 项失败关闭预检，共 26 个测试实例；默认 4 项 Smoke 不能满足终验。Playwright 退出 0 后仍必须通过 `scripts.functional_acceptance` 对唯一 `EXT-BROWSER-E2E-001` 执行正式 `ed25519-challenge-v1` 验签并原子消费一次性 challenge；只有两步都成功才可通过。缺拓扑、缺证据、SHA-only、自签名、签名/指纹/工件不匹配或 challenge 重放均为 `blocked`，普通业务断言失败为 `failed`。签名私钥路径、固定 key id 和选中的 browser challenge 文件只通过显式子进程环境 `KB_E2E_SIGNING_KEY_PATH`、`KB_E2E_SIGNING_KEY_ID`、`KB_E2E_CHALLENGE_PATH` 交给 reporter，不读取项目 `.env`、不输出私钥内容。

`--functional-trust-store` 必须是仓库外 root 所有的 `0400/0600` 非符号链接普通文件；`--functional-challenge-store` 必须是仓库外 root 所有的 `0700` 非符号链接目录，内部 challenge 为 `0400/0600` 普通文件；`--e2e-signing-key-path` 与 `--linux-host-signing-key-path` 同样必须是仓库外 root 所有的受保护普通文件。`LINUX-HOST-EVIDENCE-P0-001` 必须先采集并签署实际运行容器、发布回执、Compose origin、TLS 链、证书续期/重载和缓存替换证据；之后 `E2E-P0-001` 才能采集浏览器证据，最后 `FUNCTIONAL-P0-001` 对两份证据执行严格部署身份交叉绑定。任一证据缺失、旧部署混绑、字段不一致或 challenge 重放均为 `blocked/FAIL`。`HOST-P0-001` 和 `STORAGE-WATERMARK-P0-001` 分别以模块入口消费显式的 `--host-io-evidence` 与 `--storage-chain-evidence`。`OFFLINE-P0-001` 必须先以 root 执行 `preflight-offline.sh`，`OFFLINE-IMAGES-P0-001` 再执行 `verify-offline-images.sh verify`；`OFFLINE-RUNTIME-P0-001` 独立验签 `--offline-runtime-evidence` 中的断网冷启动、业务闭环、持久化和网络恢复证据。只完成 RepoDigest、Compose 渲染或单元测试 fake runner 不能通过离线终验。`FORMAT-P0-001` 必须在内容寻址 API 镜像内执行 `python -m app.document_parser_preflight --require-all`；缺少 PDF/旧版 Office 工具或隔离沙箱时返回码 2 并记为 `blocked`。

`--node-executable` 必须指向仓库外的绝对规范路径。`final`/`ci` 会要求该 Node 普通文件及全部祖先目录由 root 所有、不可被组或其他用户写入，并拒绝符号链接；验收器在净化子进程环境前计算可执行文件 SHA-256，再把规范路径和摘要传给功能验收器，并在实际启动 Node 前复核文件身份与摘要。绑定缺失、路径不可信或运行期间被替换时，`FUNCTIONAL-P0-001` 必须 `blocked`。

所有目标证据路径必须由命令行显式给出为 Linux 绝对路径。验收器不读取开发机 `.env` 推断路径或秘密；输入证据在运行前必须存在且是非符号链接的普通文件，下游验证器还会核对数据挂载、采集范围、原始工件哈希与目标内容指纹。离线运行态证据还必须来自 `subprocess-v1`、`result=passed`，匹配当前 Git、内容和同一次 Linux 启动的主机指纹，全部 11 项检查与原始工件 SHA-256/字节数/整体 attestation 均有效且不超过 24 小时。缺参数、Windows、非 root、test-only/fake、证据缺失或证据不属于目标运行均为 `blocked`，不得误报 `PASS`。`MALWARE-P0-001` 与 `SECURITY-SCAN-P0-001` 使用内容寻址的正式证据文档，并要求目标 Git/工作树内容指纹完全匹配。证据格式见 [终验正式证据格式](./ACCEPTANCE_EVIDENCE_FORMAT.zh-CN.md)。

`CAPACITY-P0-001` 必须同时验证控制面报告、真实模型稳态吞吐以及供应商/私有推理集群配额；控制面桩测试不得提升为模型容量证明。`DR-P0-001` 必须验证全新隔离主机的真实恢复、RPO/RTO、数据库一致性、1,000 对象哈希与业务闭环。两项均使用 detached Ed25519 签名，并绑定同一个当前 Git HEAD、工作树内容指纹和显式 `--release-id`。缺任一证据、签名或公钥时保持 `blocked/FAIL`，不会回退到静态声明、旧版升级备份证据或模拟结果。详细契约见 [终验正式证据格式](./ACCEPTANCE_EVIDENCE_FORMAT.zh-CN.md)。

## 7. 签署规则

需要产品负责人、技术负责人、安全负责人、运维负责人和数据/法务负责人共同签署。签署人只能对其复核过的证据负责；不得以风险接受替代法律要求、数据安全红线或未经授权的数据出网。
