# 通用 Linux 离线部署就绪审计

> 审计对象：其他云 Linux 单机，8 vCPU / 16 GB RAM / 300 GB SSD，通过 VPN 访问；PostgreSQL、Redis、MinIO、ClamAV、API、Web 与反向代理全部本机运行，并且不得影响同机其他应用。
> 审计方式：仅对仓库配置、脚本、测试和文档进行静态只读审查；未读取任何 `.env`，未联网，未连接目标服务器，未执行部署。
> 审计日期：2026-07-13
> 最终结论：**BLOCKED（配置基线通过，目标服务器上线签署被阻塞）**

> [!NOTE]
> 本文件保留为部署前静态审计记录，不代表部署后的最终验收结论。后续实现已改为三网络隔离并收紧资源预算；目标服务器实测证据应以对应 release 的运行时验收产物为准。

## 1. 执行摘要

`deploy/tencent/compose.offline.yml` 已具备可迁移到其他云 Linux 的单机离线基线：项目名、端口、数据目录、网络和镜像均有独立边界；数据库、Redis、MinIO 控制台及 API 不发布宿主机端口；`frontend` 与 `backend` 为 `internal: true`，仅 Caddy 连接非 internal 的 `edge` 网络以发布宿主机端口；基础镜像和应用镜像要求使用 SHA-256 摘要；生产数据使用独立 bind mount；环境文件、病毒库、磁盘水位和解析工具链均有失败关闭的预检。

但当前只能认定为**静态配置就绪**，不能认定为可正式上线。目标服务器尚未提供 VPN、安全组、主机防火墙、既有应用资源、实际磁盘、离线镜像、冷启动、备份恢复和业务链路证据；后续收紧后的稳态容器上限合计为 **4.80 vCPU / 8.75 GiB**，仍必须用目标机证据证明与其他应用共存。所有阻塞项关闭前，不得执行正式流量切换。

## 2. 审计边界与能力声明

- 本报告只评价 8 核 / 16 GB / 300 GB 的**单机验收与内部试运行**能力，不证明 10 TB 存储能力。
- 当前离线配置强制 `KB_EXTERNAL_LLM_ENABLED=false`，没有部署本地 LLM 推理服务。因此 PostgreSQL、Redis、MinIO、ClamAV 和业务服务可以全部本地化，但 DeepSeek、Qwen、MiniMax 在线推理不可用。
- 无 GPU 的 8 核 / 16 GB 主机不具备每天 50 亿 Token 的企业推理能力；该容量目标必须使用独立推理集群和独立容量验收，不能由本单机配置宣称通过。
- 单节点 PostgreSQL、单节点 Redis、单盘 MinIO 和单块 SSD 均存在单点故障；它们可用于当前交付模拟，但不能替代高可用架构或独立备份。

## 3. 已通过的静态基线

| 检查域 | 状态 | 审计结论 |
|---|---|---|
| Compose 作用域 | PASS | 项目名固定为 `heyi-kb-offline`，未使用全局 `container_name`，资源由 Compose 项目命名空间隔离。 |
| 宿主机端口 | PASS | 只发布 `19443/tcp` 和 `19444/tcp`；PostgreSQL、Redis、API、ClamAV、MinIO 控制台均不发布宿主机端口。 |
| 容器网络 | PASS | `backend` 与 `frontend` 为 `internal: true`；仅 Caddy 同时连接固定 CIDR 的 `edge` 网络以发布端口。 |
| 数据目录 | PASS | 数据固定写入 `/srv/heyi-knowledgebases-offline/data` 下的独立子目录，未复用现有项目目录或命名卷。 |
| 数据本地化 | PASS | API 只连接 Compose 内的 PostgreSQL、Redis 与 MinIO；外部 LLM 被失败关闭。 |
| 镜像确定性 | PASS | 基础服务使用摘要固定镜像；API/Web 镜像必须为 `repository@sha256:<digest>`，并由清单和本地 RepoDigest 双重核验。 |
| 环境文件 | PASS | 预检拒绝符号链接、非 root 所有、非 `0400/0600` 权限、未知键、重复键、命令替换和 Shell 元字符。 |
| 容器最小权限 | PASS（有残余） | API、Web、维护任务和 ClamAV 使用只读根文件系统、`no-new-privileges` 与 capability 收缩；数据服务仍保留官方镜像启动所需权限。 |
| 日志限制 | PASS | 使用 Docker `local` 日志驱动，每个服务限制 `20m × 5`；对象预签名入口刻意不记录完整 URI，避免签名泄漏。 |
| 健康依赖 | PASS（有残余） | PostgreSQL、Redis、MinIO、ClamAV、API 和 Web 有健康检查，关键依赖使用 `service_healthy` 或 `service_completed_successfully`。 |
| 恶意文件防护 | PASS | ClamAV 数据库以只读方式挂载，预检强制 main/daily 签名族、更新时间、权限、SHA-256 和引擎兼容性。 |
| 文件解析工具链 | PASS | API 镜像固定包含 Bubblewrap、LibreOffice、Poppler 与 `prlimit`，预检要求九类文档工具链完整。 |
| 存储水位 | PASS | 至少 240 GB 部署前可用空间；70% 告警、80% 停止批量上传、90% 拒绝新上传，MinIO 对象增长在 180 GB 停止。 |
| 数据库身份 | PASS | 迁移所有者与运行时账号分离；运行时角色无集群管理权限，审计日志写入后不可更新或删除。 |

## 4. 资源与共享主机影响评估

### 4.1 稳态资源上限

| 服务 | CPU 上限 | 内存上限 |
|---|---:|---:|
| PostgreSQL | 1.00 | 2.00 GiB |
| Redis | 0.25 | 0.75 GiB |
| MinIO | 0.75 | 1.25 GiB |
| Multipart GC | 0.05 | 0.125 GiB |
| ClamAV | 0.50 | 1.75 GiB |
| API | 1.25 | 1.50 GiB |
| Maintenance | 0.25 | 0.50 GiB |
| Web | 0.60 | 0.75 GiB |
| Caddy | 0.15 | 0.125 GiB |
| **合计** | **4.80** | **8.75 GiB** |

该合计尚未包含 Docker 守护进程、Linux 内核、文件系统缓存、宿主机监控、SSH、备份任务、迁移/管理员初始化任务，以及同机其他应用。理论余量约为 3.20 vCPU / 7.25 GiB，但不得据此替代目标机共存和峰值证据。

**结论：BLOCKED。** 上线前必须取得目标服务器的现有容器峰值、宿主机峰值和故障恢复余量证据。若其他应用已长期占用明显内存，应降低本项目上限、停用非必需组件、增加内存，或改为独占主机。不得依赖 Linux OOM Killer 作为资源隔离机制。

### 4.2 未受限与不可观测服务

- `minio-init` 没有 CPU、内存和 PID 上限。
- `clamav-db-preflight` 没有 CPU、内存和 PID 上限。
- `proxy`、`maintenance` 和 `minio-multipart-gc` 没有容器级健康检查；只能由外部探针、业务指标或进程状态补足。
- 迁移和 bootstrap 虽有限额，但不得与批量导入、备份或其他应用发布同时执行。

**结论：BLOCKED。** 正式部署前应为一次性容器补齐资源上限，并为代理、维护任务和 Multipart GC 建立可告警的运行状态证据；临时以变更窗口和宿主机 cgroup 包裹命令只能作为一次性上线控制，不能替代代码基线修复。

## 5. 网络、VPN 与入口审计

静态配置默认把 `19443/19444` 绑定到 `0.0.0.0`。这不等于公网开放，但如果云安全组或主机防火墙配置错误，会把登录和对象入口暴露到所有宿主机网卡。

正式上线必须满足：

1. 优先把 `KB_BIND_ADDRESS` 设置为目标服务器的 VPN/企业私网地址；确需使用 `0.0.0.0` 时，必须以云安全组和主机防火墙证据证明只允许批准的 VPN CIDR。
2. `19443/tcp`、`19444/tcp` 只允许 VPN 网段；SSH 只允许堡垒机或管理网段；禁止 `0.0.0.0/0`。
3. 宿主机公网出站默认拒绝；仅按审批放行内部 DNS、NTP、日志和独立备份目的地。
4. 必须保存变更前后规则快照，不得清空、替换或重载归属不明的既有规则。
5. Caddy 内部 CA 根证书必须通过企业受控渠道分发，禁止让用户长期使用浏览器“忽略证书错误”。

**结论：BLOCKED。** VPN 尚未连接，目标云安全组、主机防火墙、监听地址和出站阻断均未取证。

## 6. 卷、磁盘与数据安全

已具备的控制：

- PostgreSQL、Redis、MinIO、Caddy 数据和 ClamAV 病毒库使用不同子目录。
- API 和维护任务只读挂载容量探针目录。
- Docker 日志有界，MinIO 不完整分片和 staging 对象有定期清理。
- 预检要求至少 240 GB 可用空间，并有 180 GB 对象停止线和文件系统水位策略。

上线前仍需关闭的缺口：

- 证明 `/srv/heyi-knowledgebases-offline/data` 及其父目录不是符号链接、不是其他应用目录、没有未知 bind mount，并记录真实设备号、文件系统 UUID、挂载参数、所有者和权限。
- 证明容量探针目录、MinIO 对象目录和目标 300 GB SSD 位于同一受控文件系统。
- 证明 PostgreSQL WAL、Redis AOF、Docker 镜像、Caddy CA、ClamAV 数据库和升级回滚空间在最坏情况下不会突破 90% 拒绝线。
- 禁止 `docker system prune`、未指定项目名的 `docker compose down` 以及任何 `down -v`。

**结论：BLOCKED。** 需要目标主机的磁盘身份、fio、25 场景水位链和部署前后目录快照证据。

## 7. 备份、恢复与回滚

当前 Compose 不包含 PostgreSQL 备份、WAL 归档、MinIO 复制、审计归档或恢复作业。单盘上的第二份文件不是备份；备份也不能与生产数据只放在同一 300 GB SSD。

正式上线至少需要：

- 明确并批准 PostgreSQL 与对象数据的 RPO/RTO。
- PostgreSQL：一致性逻辑备份；正式生产还需 base backup 与连续 WAL 归档。备份写入独立受控介质或企业内网备份目标。
- MinIO：将 bucket 复制或镜像到独立介质，保留对象校验和、版本/时间点和访问控制记录。
- 配置与密钥：可恢复，但与数据备份分开加密保管；不得把明文 `.env` 放进普通备份目录。
- 恢复演练：在隔离目录或隔离实例恢复 PostgreSQL 和 MinIO，抽样核对 `file.object_key`、大小、状态、校验和与来源引用。
- 回滚：保留上一版摘要固定镜像和 Compose 文件；数据库采用 expand/contract，禁止未经验证的 Alembic downgrade。

**结论：BLOCKED。** 尚无目标服务器的成功备份、恢复演练、RPO/RTO 和独立介质证据。

## 8. 离线镜像与供应链

当前预检可以证明 Compose 使用的每个镜像都有摘要、镜像已在本地加载、RepoDigest 与清单一致。这可以防止可变 tag 和误拉取，但上线过程仍应补强：

- 受控构建机输出镜像清单、镜像 tar SHA-256、SBOM、漏洞扫描报告和审批记录。
- 通过受控介质/VPN 内部制品库传输，并在目标机再次验证哈希。
- 启动命令显式使用 `--pull never --no-build`，避免预检后因镜像缺失而尝试联网拉取或在共享主机现场构建。
- 镜像清单、Git HEAD、工作树内容指纹和最终运行容器 Image ID 必须形成同一证据链。
- ClamAV 病毒库应有离线更新节奏；超过允许年龄必须告警并阻止新的正式发布。

**结论：BLOCKED。** 静态摘要验证已通过，但目标机镜像集合、制品来源、SBOM/扫描、实际容器 Image ID 与断网冷启动尚未举证。

## 9. 健康、可观测性与业务验收

目标机上线后必须同时证明：

- PostgreSQL、Redis、MinIO、ClamAV、API、Web 健康检查连续通过，Caddy 两个 HTTPS 入口可用。
- API `/health/live` 与 `/health/ready` 语义正确；依赖故障时 readiness 返回非 2xx。
- `maintenance` 和 `minio-multipart-gc` 正在推进任务，不是仅有容器进程存活。
- 日志轮转、CPU、内存、PID 和磁盘告警生效，日志中不存在密码、Token、完整数据库连接串或预签名 URL。
- 登录、角色权限、知识库 ACL、九类文件上传、病毒扫描、OKF 转换、审批、问答、来源引用、下载和重启持久化通过。
- 断开公网后业务仍可启动，API 和容器不能建立公网连接；问答不得静默调用 DeepSeek、Qwen 或 MiniMax。
- 部署前记录的其他应用容器、端口、网络、卷、CPU/内存与健康状态在部署后保持不变。

**结论：BLOCKED。** 上述均需 VPN 连接后的真实服务器证据，开发机或测试替身结果不能用于最终签署。

## 10. 目标服务器上线证据清单

### A. 连接与变更前快照

- [ ] VPN 已连接，SSH 仅通过批准的管理路径建立。
- [ ] OS、内核、架构、8 个可见逻辑 CPU、至少 15 GiB 可见内存证据。
- [ ] `docker version`、`docker compose version`、时钟同步状态。
- [ ] 现有 `docker ps`、`docker compose ls`、网络、卷、镜像、监听端口和防火墙只读快照。
- [ ] 其他应用 15 分钟以上 CPU、RSS、磁盘 IO、网络与健康基线。
- [ ] 目标目录真实路径、设备号、文件系统 UUID、挂载选项、所有者、权限和非符号链接证明。

### B. 容量与存储

- [ ] 300 GB 目标文件系统总量与至少 240 GB 部署前可用空间。
- [ ] SSD 身份及有界 fio 延迟/吞吐/IOPS 证据。
- [ ] MinIO 与容量探针同文件系统交叉核验。
- [ ] 25 个真实水位场景、原始工件哈希、清理完成和无配额/对象泄漏证据。
- [ ] 70%/80%/90% 告警与拒绝策略实际触发证明。

### C. 网络隔离

- [ ] 云安全组和主机防火墙只允许 VPN CIDR 访问 `19443/19444`。
- [ ] SSH 仅允许堡垒机/管理网段。
- [ ] PostgreSQL、Redis、MinIO 控制台、API、ClamAV 没有宿主机监听端口。
- [ ] Compose 两个网络在运行时均为 `Internal=true`。
- [ ] 宿主机和容器公网 DNS、路由、连接与出站探测失败的原始证据。
- [ ] 防火墙变更前后 diff，证明未删除或覆盖其他应用规则。

### D. 配置与制品

- [ ] 生产环境文件位于发布目录外，为 root 所有的非符号链接普通文件，权限 `0400/0600`。
- [ ] 环境白名单预检、Compose `config --quiet` 和完整解析工具链预检通过。
- [ ] 镜像清单、tar SHA-256、SBOM、漏洞扫描与制品审批记录。
- [ ] 每个运行容器的镜像摘要与批准清单一致。
- [ ] ClamAV main/daily 数据库 SHA-256、年龄、权限和 `sigtool --info` 证据。

### E. 数据与恢复

- [ ] PostgreSQL 迁移、所有者/运行时角色分离和审计表不可变权限验证。
- [ ] PostgreSQL 备份成功、恢复成功、恢复后应用一致性验证。
- [ ] MinIO 独立介质备份、恢复成功及对象抽样校验。
- [ ] RPO/RTO、备份保留期、加密、访问权限和责任人记录。
- [ ] 服务和宿主机重启后 PostgreSQL、Redis、MinIO、Caddy CA 与业务数据仍存在。

### F. 业务、性能与共存

- [ ] 企业 E2E 由目标主机运行并使用一次性 challenge 与受保护信任库验签。
- [ ] 真实 PostgreSQL 并发、幂等、RBAC/ACL 撤权、审计与迁移验收证据。
- [ ] 九类文档上传到问答来源引用的完整链路。
- [ ] 稳态、上传、解析、病毒扫描、备份和恢复期间的 CPU、内存、磁盘 IO 与延迟证据。
- [ ] 部署后其他应用容器 ID、端口、网络、卷和健康状态与变更前一致。
- [ ] 上一版本回滚、业务冒烟和其他应用存活验证。

## 11. 通过条件

只有同时满足以下条件，结论才能从 `BLOCKED` 更新为 `PASS`：

1. 本报告第 4 至第 9 节的所有阻塞项均有代码修复或目标服务器正式证据关闭。
2. VPN、云安全组、主机防火墙和出站控制证明仅允许批准的企业路径。
3. 共享主机资源峰值证明本项目不会导致其他应用触发 OOM、CPU 饥饿或磁盘 IO 失控。
4. PostgreSQL 与 MinIO 的独立备份和恢复演练成功。
5. 离线镜像、病毒库、真实冷启动、业务链路与回滚证据全部匹配同一 Git HEAD 和内容指纹。
6. 部署前后的其他应用资源快照一致，且未执行任何全局 Docker 清理、守护进程重启或无归属防火墙修改。

## 12. 本次静态验证记录

| 验证 | 结果 |
|---|---|
| 离线 Compose、环境预检、ClamAV、主机、存储水位和离线运行证据测试 | **58 passed** |
| `preflight-offline.sh`、镜像校验、PostgreSQL/MinIO/ClamAV 脚本 `sh -n` | **PASS** |
| 使用 `offline.env.example` 执行 Compose 合并解析（未读取真实 `.env`） | **PASS** |
| 真实目标服务器、VPN、云防火墙、备份恢复、冷启动和业务 E2E | **BLOCKED：尚未连接和执行** |

本报告没有执行部署，没有改变服务器、Docker、网络、防火墙、卷或现有应用状态。
