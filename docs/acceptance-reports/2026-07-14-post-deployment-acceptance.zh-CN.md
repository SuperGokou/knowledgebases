# 2026-07-14 部署后验收报告

## 1. 执行摘要

**总体判定：`FAILED / NO-GO`，不得签署“全部功能通过”或“企业终验通过”。**

本次目标版本已成功部署到指定 Linux 8 核 / 16 GB / 300 GB SSD 内网服务器。源码门禁、真实 PostgreSQL 集成、离线运行时、TLS、容器健康、公开只读端点、登录页浏览器矩阵和服务器本地只读性能均有 `PASS` 证据，可继续用于受控内网试运行。

正式企业终验仍不通过：VPN + HTTP/1.1 客户端吞吐实测未达到本轮 2 RPS 观察目标，记为 `FAILED`；完整认证业务 E2E、外部大模型真实调用、1,000 用户与每日 50 亿 Token 容量、容灾恢复演练及当前提交的正式安全 diff / validation 证据缺失，记为 `BLOCKED`。按照项目终验规则，任何 P0 `FAILED` 或 `BLOCKED` 都会使总体结论保持 `FAILED`。

## 2. 状态定义与证据边界

| 状态 | 定义 |
|---|---|
| `PASS` | 已在声明的环境和版本上实际执行，结果满足本次检查条件，并保留可追溯证据。 |
| `FAILED` | 已实际执行，但至少一项结果未达到声明的目标或阈值。 |
| `BLOCKED` | 因测试环境、受控凭据、依赖服务、故障注入能力或正式证据缺失而未能安全执行；不得解释为通过。 |

本报告只证明列明的版本、环境、端点和测试范围。它不证明未执行的功能、容量、恢复或安全项目。报告不记录密码、Token、Cookie、API Key、数据库连接串或任何 `.env` 值。

## 3. 版本与部署摘要

| 项目 | 已验证值 | 状态 |
|---|---|---|
| Git 分支 | `codex/enterprise-final-acceptance` | `PASS` |
| Git 提交 | `b9e4f03f21355fadddce72f0807a80a2c19d89ba` | `PASS` |
| 发布归档 SHA-256 | `51A92D06359F698408E6F1C25CFF50541A0629BEA4842723B72D31CF1E2B8D92` | `PASS` |
| Compose 项目 | `heyi-kb-offline` | `PASS` |
| API / maintenance 镜像 | `heyi-kb-offline-api@sha256:4322336283779c1877fc654022b1a96bf8b5450a0ea9441f68367593c0a0e76b` | `PASS` |
| 目标主机 | Linux amd64，8 vCPU，约 15.6 GiB 内存，约 295 GB 根卷，部署时约 269 GB 可用 | `PASS` |
| 数据库 Schema | `20260712_0013` | `PASS` |
| 运行模式 | 严格隔离模式；PostgreSQL、Redis、MinIO 与应用均在本地 Compose 边界内 | `PASS` |
| 对外监听 | 仅反向代理绑定指定私网地址的 `19443` 与 `19444` 端口 | `PASS` |

本次运行时差异只涉及认证刷新令牌并发修复和 Caddy HSTS 配置。部署过程仅重建 `api`、`maintenance`、`proxy`；`web`、PostgreSQL、Redis、MinIO、ClamAV 与 `minio-multipart-gc` 清理任务容器 ID 保持不变，未执行全局清理、数据卷删除或影响同机其他应用的操作。

受限证据包保留了以下脱敏产物，用于复核本报告中的数字；这些运行产物不包含在公开仓库中：

| 产物 | 证明范围 |
|---|---|
| `post-deploy-runtime-final.json` | 发布身份、镜像、容器、网络、Schema、日志、端点与离线运行时 |
| `postdeploy-browser-summary.json` | Edge / Chromium 桌面与移动端 4 项浏览器结果 |
| `postdeploy-server-performance.json` | 服务器本地严格 TLS 只读性能 |
| `postdeploy-readonly-perf.json` | Windows / VPN 顺序 HTTP/1.1 观测 |
| `postdeploy-readonly-perf-concurrent.json` | Windows / VPN 并发 HTTP/1.1 观测 |
| `offline-recovery-receipt.json` | 离线恢复包的归档身份与校验值 |

## 4. 源代码质量门禁

| 门禁 | 结果 | 状态 |
|---|---:|---|
| 功能验收合同 | 14 / 14 | `PASS` |
| 后端功能合同检查 | 163 项 | `PASS` |
| 前端功能合同检查 | 84 项 | `PASS` |
| 后端测试 | 534 passed，覆盖率约 85% | `PASS` |
| 前端 Vitest | 197 / 197 | `PASS` |
| 前端 ESLint | 0 error | `PASS` |
| TypeScript 类型检查 | 通过 | `PASS` |
| Next.js 生产构建 | 通过，9 / 9 页面完成构建 | `PASS` |
| 本机生产构建 Smoke | 4 / 4 | `PASS` |

以上门禁证明源码的可执行子集满足当前回归要求，但不能替代真实业务账号、生产数据链路、外部模型、容量、故障注入或恢复演练。

## 5. 真实 PostgreSQL 集成

真实 PostgreSQL 验收共 21 项，结果为 **21 / 21 passed，0 skip**，状态为 `PASS`。覆盖范围包括刷新令牌并发轮换、跨令牌族重放封锁以及相关数据库一致性路径。

该结果证明指定集成场景在真实 PostgreSQL 上成立；它不等同于完整生产业务 E2E，也不等同于 1,000 用户并发或长稳容量证明。

## 6. 部署、TLS、离线与容器证据

### 6.1 部署与容器

| 检查 | 证据摘要 | 状态 |
|---|---|---|
| 不可变发布 | 发布归档哈希、镜像 RepoDigest、运行容器内补丁哈希与目标提交一致 | `PASS` |
| 容器健康 | API 健康；本次重建容器 restart count 为 0，OOM 状态为 false | `PASS` |
| 非变更服务隔离 | Web、PostgreSQL、Redis、MinIO、ClamAV 等容器未被重建 | `PASS` |
| 日志检查 | 未发现 traceback、完整性错误、fatal、OOM；代理 5xx 为 0 | `PASS` |
| 回滚与恢复载荷 | 生成可离线加载的 API 镜像归档并验证结构与 `docker image load` | `PASS` |

离线恢复镜像归档 SHA-256 为 `daf29353c0ee04d0b69ba8c3d35779c7d6fc8c2b92ca8df1000e579b3689b5da`。该归档可恢复应用镜像，但**不是** PostgreSQL、MinIO 和 Redis 业务数据的容灾恢复证明。

### 6.2 TLS 与边缘安全

| 检查 | 结果 | 状态 |
|---|---|---|
| TLS 握手 | Edge 与 Chromium 在不忽略证书错误的条件下使用 TLS 1.3 | `PASS` |
| 证书信任 | Caddy 内部 CA 已导入当前测试用户信任库；主机名 / 地址校验通过 | `PASS` |
| HSTS | HTTPS 响应包含预期 HSTS | `PASS` |
| 浏览器安全头 | CSP、frame、nosniff、referrer 与 permissions policy 符合预期 | `PASS` |
| CSRF / Origin | 恶意 Origin 的写请求返回 403 | `PASS` |
| 管理文档暴露 | `/docs` 与 `/redoc` 返回 404 | `PASS` |

已知限制：内部 CA 当前未提供 CRL / OCSP 撤销服务，因此 Windows Schannel 的“完整撤销检查”仍会告警。浏览器和 OpenSSL 严格证书链验证已通过，但如企业安全基线要求强制在线撤销检查，应改用具备 CRL / OCSP 的企业 PKI 后重新验收。

### 6.3 严格离线运行

| 检查 | 结果 | 状态 |
|---|---|---|
| 镜像清单 | Compose 所需镜像与离线清单一致 | `PASS` |
| 网络边界 | 后端和前端网络为 internal；仅 edge 网络承担私网入口 | `PASS` |
| 本地依赖 | PostgreSQL、Redis、MinIO、ClamAV 均使用本地容器服务 | `PASS` |
| 文档解析预检 | TXT、DOC、DOCX、XLS、XLSX、CSV、PDF、PPT、PPTX 九种格式预检通过 | `PASS` |
| 恶意文件特征库 | ClamAV 签名存在、可读且兼容性检查通过 | `PASS` |
| 外部 LLM | 隔离配置明确关闭外部 LLM 访问 | `PASS`（隔离策略） |

严格离线模式下，本地确定性检索与本地 OKF 链路可运行；DeepSeek、Qwen、MiniMax 等外部 Provider 的真实请求不会执行。外部模型端到端能力因此另列为 `BLOCKED`，不得由“模型切换 UI 可操作”推断为真实 Provider 可用。

上述 `PASS` 证明当前运行拓扑、依赖位置和出网策略符合隔离配置，不等同于“整台共享宿主机断网冷启动”终验证据。现有正式采集器会检查或变更宿主机级网络状态，且要求所有项目网络为 internal；当前 edge 网络需承担私网入口，不能在共享宿主机上安全执行该采集流程。因此宿主机级断网冷启动与网络恢复另列为 `BLOCKED`。

## 7. 公开端点与浏览器验收

### 7.1 公开端点 Smoke

| 端点 / 行为 | 期望与实测 | 状态 |
|---|---|---|
| 登录页 | 200 | `PASS` |
| `/health/live` | 200，`status=ok` | `PASS` |
| `/health/ready` | 200，`status=ready` | `PASS` |
| `/openapi.json` | 200，包含要求的公开路径 | `PASS` |
| 未认证会话 | 返回 `authenticated=false` | `PASS` |
| 未认证管理 BFF | 401 | `PASS` |
| 绕过 BFF 的直接用户端点 | 404 | `PASS` |
| MinIO live / ready | 200 / 200 | `PASS` |

### 7.2 浏览器矩阵

部署后浏览器验收为 **4 / 4 passed**：Edge 桌面、Edge 移动、Chromium 桌面、Chromium 移动。

共同结果：

- TLS 1.3，导航响应 200；
- 0 条 console error、page error、request failure 和错误响应；
- 无 mixed content、无横向溢出、无破损图片；
- 公司名称、Logo 与站点图标正常显示；
- axe `serious=0`、`critical=0`。

暖连接观测值如下，仅代表登录页浏览器路径，不代表业务容量：

| 浏览器 / 视口 | TTFB | FCP | DOM 完成 |
|---|---:|---:|---:|
| Edge 桌面 | 217.8 ms | 476 ms | 677 ms |
| Edge 移动 | 222.5 ms | 444 ms | 640.6 ms |
| Chromium 桌面 | 259.6 ms | 540 ms | 772.9 ms |
| Chromium 移动 | 264.0 ms | 304 ms | 768.7 ms |

冷首次连接 TTFB 为 1.03 至 1.25 秒，高于本轮 1 秒**非门禁诊断参考值**，不影响浏览器 4 / 4 的功能判定。该现象可能包含 VPN、首次 TLS / PKI 和连接建立成本，仍需在正式支持的内网客户端路径上复测。

## 8. 性能结果

### 8.1 服务器本地只读性能

服务器本地以严格 TLS 对四类只读端点执行 40 次请求，全部返回 200，状态为 `PASS`。

| 端点 | P50 总耗时 | P95 总耗时 |
|---|---:|---:|
| 登录页 | 12.61 ms | 45.23 ms |
| health live | 6.08 ms | 14.96 ms |
| health ready | 5.58 ms | 10.68 ms |
| OpenAPI | 6.55 ms | 13.46 ms |

该结果证明服务器、反向代理和应用的只读基础路径没有明显本机性能瓶颈。它不是写入、检索、上传、OKF、聊天或 1,000 用户容量测试。

### 8.2 VPN + HTTP/1.1 客户端路径

| 场景 | 请求 | 错误 | 吞吐 | 目标 | 状态 |
|---|---:|---:|---:|---:|---|
| Windows / VPN 顺序 HTTP/1.1 | 60 | 0 | 0.785 RPS | 2 RPS | `FAILED` |
| Windows / VPN 并发 HTTP/1.1 | 40 | 0 | 1.081 RPS | 2 RPS | `FAILED` |

两次测试期间均未出现容器重启或 OOM。服务器本地低延迟、浏览器 HTTP/2 暖连接正常，而 Windows / VPN Python HTTP/1.1 路径吞吐不足，说明问题更可能位于 VPN、客户端协议 / 连接复用或链路层，但当前证据不足以单独归因。该支持路径在重新测试达到阈值前保持 `FAILED`。

## 9. 未完成的企业业务 E2E

完整 enterprise 浏览器套件需要覆盖登录与角色路由、账号生命周期、知识库授权与撤销、九格式上传 / 扫描 / OKF / 审批 / 下载 / 检索 / 对话、至少 100 MiB Multipart、引用与无答案、回答审核、数据表格、模型切换与降级、API Key、限流以及 5xx / 超时 / 加载状态。

当前状态为 `BLOCKED`，原因如下：

1. 目标部署未包含 enterprise E2E 所需的 fault-controller，无法确定性制造 Provider、超时、5xx 与审核失败场景；
2. 没有专用于本轮验收、可销毁且最小权限的合成账号凭据；不得猜测、重置或复用生产管理员密码；
3. 套件会写入 PostgreSQL、MinIO 与 Redis，并且现有流程没有完整、经过验证的清理闭环；
4. 直接在当前生产数据栈执行会产生测试用户、文件、对象、会话与审计记录，存在数据污染风险；
5. 尚未建立与生产网络、端口、CIDR 和数据目录完全隔离的一次性验收栈，也没有可用的签名 challenge 证据链。
6. 当前离线预检固定正式 Compose 项目名、数据根目录、所有权标记和 CIDR，不能直接复用于第二套验收栈；必须先提供参数化、默认拒绝越界的独立验收预检。

因此，当前只能证明匿名入口和只读公共链路正常，不能证明登录后的账号、RBAC、文件、知识库、问答、回答审核、API Key 和模型管理全流程在本次部署上全部通过。

## 10. FAILED 与 BLOCKED 清单

| 编号 | 项目 | 状态 | 判定依据 |
|---|---|---|---|
| `POST-PERF-001` | VPN + HTTP/1.1 支持路径 | `FAILED` | 0.785 / 1.081 RPS，均低于 2 RPS 观察目标。 |
| `POST-E2E-001` | 完整认证业务 E2E | `BLOCKED` | 无 fault-controller、无合成凭据、缺少可验证的无污染清理闭环。 |
| `POST-LLM-001` | DeepSeek / Qwen / MiniMax 真实调用与切换 | `BLOCKED` | 严格离线策略禁止外部 Provider 出网；无批准的内网推理服务。 |
| `POST-OFFLINE-001` | 宿主机级断网冷启动与恢复 | `BLOCKED` | 共享宿主机上不能安全执行会检查或变更全局网络状态的正式采集流程。 |
| `POST-CAP-001` | 1,000 用户容量 | `BLOCKED` | 未执行专用环境峰值、稳态与长稳测试。 |
| `POST-CAP-002` | 50 亿 Token / 日 | `BLOCKED` | 无内网推理集群或获批 Provider 的实测吞吐、配额与成本证据。 |
| `POST-DR-001` | 数据容灾 | `BLOCKED` | 未执行 PostgreSQL PITR、对象数据恢复和全新主机恢复演练。 |
| `POST-SEC-001` | 当前提交安全复核 | `BLOCKED` | 旧提交深扫已完成，但无与本 Git SHA 和镜像 digest 匹配的正式 diff / validation 产物。 |
| `POST-SUPPLY-001` | 最终镜像供应链与许可签署 | `BLOCKED` | 最终镜像漏洞、敏感信息、SBOM / 许可和素材授权仍需正式签署证据。 |

安全扫描证据边界：提交 `4adeb470` 的 Codex Security deep scan 已于 2026-07-13 完成，共记录 32 项发现（1 High、19 Medium、12 Low）。该产物不对应当前提交 `b9e4f03f...`，本报告截点也未获得当前版本正式完成的 diff scan、发现验证和影响追踪证据，因此不能据此把当前版本记为 `PASS`。

## 11. 解除阻塞的精确条件

### 11.1 完整业务 E2E

必须同时满足：

1. 创建独立 Compose 项目，使用与现有部署不重叠的端口、CIDR、数据根目录和证书信任；
2. 实现独立、参数化且默认拒绝越界的验收预检，不能通过删除正式预检的项目名、目录和所有权校验来绕过保护；
3. 加入受控 fault-controller，至少支持 Provider 失败、超时、5xx、审核拒绝和降级模式；
4. 在临时栈内创建可销毁的管理员、普通用户和最小权限用户；不得使用生产管理员账号；
5. 准备九格式固定 fixture、种子知识库、Multipart 文件、签名密钥和一次性 challenge；
6. 对 PostgreSQL、MinIO、Redis 和容器建立测试前快照及测试后清理校验；
7. 执行完整 enterprise Profile，所有断言通过，并生成与 Git SHA、镜像 digest 和 challenge 绑定的证据；
8. 销毁临时项目后验证生产容器 ID、数据量、网络、端口和健康状态未发生变化。

### 11.2 外部模型

选择并批准以下一种路径后才能复测：

- 在企业内网部署兼容的推理服务；或
- 由数据与安全负责人批准受控出网，并完成文档分级、脱敏、审计、配额和成本策略。

随后分别验证 DeepSeek、Qwen、MiniMax 的真实连通、模型切换、超时、限流、熔断、降级、引用和回答审核，且测试证据不得包含密钥或企业文档正文。

### 11.3 性能与容量

1. 明确支持的客户端协议和网络路径；若 VPN + HTTP/1.1 属于支持范围，必须复测并达到目标，否则需正式排除并给出客户端要求；
2. 在独立压测环境执行 1,000 用户模型的峰值、30 分钟稳态及至少 4 小时长稳；
3. 覆盖登录、检索、上传、下载、OKF、聊天和管理 API，而非只读健康端点；
4. 记录 P50 / P95 / P99、错误率、吞吐、CPU、内存、磁盘、数据库池、Redis、对象存储、重启、OOM 与队列年龄；
5. 每日 50 亿 Token 目标必须由获批推理服务提供吞吐、配额、限流和成本对账证据。

### 11.4 容灾与安全

1. 启用并验证 PostgreSQL PITR、对象存储版本 / 备份和独立介质；
2. 在全新主机恢复，记录 RPO、RTO，并抽样校验至少 1,000 个对象哈希；
3. 对精确 Git SHA 和最终镜像 digest 完成安全 diff scan、发现验证、影响追踪，以及源码、依赖、容器、敏感信息、攻击路径与许可证扫描；
4. Critical / High 必须为 0，或具有责任人、截止时间和补偿控制的正式例外；
5. 如要求强制证书撤销检查，部署具备 CRL / OCSP 的企业 PKI 并重跑全部 TLS 验收。
6. 在独占验收主机或受控网络命名空间内执行断网冷启动、完整业务流和网络恢复；共享宿主机不得运行会变更全局路由、防火墙或 DNS 的采集器。

## 12. 最终签署建议

| 决策 | 当前建议 |
|---|---|
| 受控内网试运行 | 可继续；仅限已验证的部署、匿名入口、严格离线和本地确定性链路。 |
| 对外宣称“全部功能通过” | 禁止。 |
| 正式企业生产终验 | `NO-GO`。 |
| 重新验收入口 | 完成第 11 节全部适用前置条件后，重新执行部署后验收与最终 enterprise Profile。 |

当前可签署的结论仅为：**目标版本已成功部署，基础运行时和公开只读链路通过；企业全功能、容量、容灾、安全和外部模型验收尚未完成。**
