<div align="center">
  <h1>企业知识中台 · 文档中心</h1>
  <p><strong>架构、部署、运维、安全、验收、容量与法律交付的统一索引</strong></p>
  <p>
    <a href="../README.md">项目首页</a> ·
    <a href="./ARCHITECTURE.zh-CN.md">架构设计</a> ·
    <a href="./TENCENT_OFFLINE_ENTERPRISE_DEPLOYMENT.zh-CN.md">通用 Linux 离线部署</a> ·
    <a href="./ENTERPRISE_FINAL_ACCEPTANCE_STANDARD.zh-CN.md">企业终验标准</a> ·
    <a href="../SECURITY.md">安全报告</a>
  </p>
</div>

> [!IMPORTANT]
> 本目录是当前文档的发现入口，不是通过证明。功能、容量、灾备或安全结论只有在证据绑定当前 Git 身份、内容指纹、目标环境且通过对应签名门禁后才成立。测试数量必须由最终冻结候选版本动态收集；“已收集”不等于通过，最终状态仍以同一候选版本的新签名验收产物为准。当前应用要求的 Alembic Schema head 为 `20260715_0021`。

> [!CAUTION]
> 当前商业发行、敏感数据正式交付、每日 50 亿 token 容量和 10 TB 存储认证均为 `NO-GO` 或 `UNVERIFIED`：项目许可证、第三方依赖/资产授权、整盘/WAL/快照/备份静态加密、目标机容量及恢复证据尚未全部签署。历史自测或旧部署报告不能覆盖这些阻断项。

## 阅读路径

| 角色 | 建议顺序 |
|---|---|
| 项目负责人 / 验收人 | [企业终验标准](./ENTERPRISE_FINAL_ACCEPTANCE_STANDARD.zh-CN.md) → [证据格式](./ACCEPTANCE_EVIDENCE_FORMAT.zh-CN.md) → [性能与容量模型](./PERFORMANCE_CAPACITY_MODEL.zh-CN.md) → 法律交付文档 |
| 架构师 / 后端工程师 | [架构设计](./ARCHITECTURE.zh-CN.md) → [知识流水线](./KNOWLEDGE_PIPELINE.zh-CN.md) → [API 与模型管理](./API_AND_MODEL_MANAGEMENT.zh-CN.md) |
| 平台运维 / SRE | [通用 Linux 离线部署](./TENCENT_OFFLINE_ENTERPRISE_DEPLOYMENT.zh-CN.md) → [运维手册](./OPERATIONS.zh-CN.md) → [内部 CA](./TLS_INTERNAL_CA_OPERATIONS.zh-CN.md) → [断网冷启动验收](./OFFLINE_RUNTIME_ACCEPTANCE.zh-CN.md) |
| 安全 / 合规 / 法务 | [威胁模型](./THREAT_MODEL.zh-CN.md) → [依赖许可证审计](./DEPENDENCY_LICENSE_AUDIT.zh-CN.md) → [资产来源](./ASSET_PROVENANCE.zh-CN.md) → [第三方声明](./THIRD-PARTY-NOTICES.md) |
| QA / 浏览器验收 | [功能验收标准](./FUNCTIONAL_ACCEPTANCE_STANDARD.zh-CN.md) → [证据信任模型](./FUNCTIONAL_ACCEPTANCE_TRUST.zh-CN.md) → [浏览器套件](../web/e2e/README.md) |

## 核心设计与产品能力

| 文档 | 内容与边界 |
|---|---|
| [架构设计](./ARCHITECTURE.zh-CN.md) | 元数据/对象分离、RBAC、限额、扫描、OKF、检索、RAG、状态机与 10 TB 目标拓扑 |
| [知识编译、OKF 与聊天架构](./KNOWLEDGE_PIPELINE.zh-CN.md) | 原始来源、派生知识、引用协议、LLM-Wiki 演进边界 |
| [OKF 第一阶段与模型增强](./OKF_DEEPSEEK_PHASE1.zh-CN.md) | 持久任务、租约、草稿、发布门禁与外部处理策略 |
| [API 与模型管理](./API_AND_MODEL_MANAGEMENT.zh-CN.md) | API Key、账号密码、不可逆账号退休、角色 CAS/安全删除、审计查询导出、模型切换、受控出口与调用示例 |
| [LLM token 与费用治理](./LLM_TOKEN_COST_GOVERNANCE.zh-CN.md) | 供应商价格、token/费用预算、原子预留、结算与停止边界 |
| [RAG 检索评估](./RAG_RETRIEVAL_EVALUATION.zh-CN.md) | 来源、召回与确定性评估方法；不得替代目标数据集实测 |

## 通用国内云 Linux 部署与运维

| 文档 | 用途 |
|---|---|
| [Linux 8C16G/300GB 离线企业部署](./TENCENT_OFFLINE_ENTERPRISE_DEPLOYMENT.zh-CN.md) | 供应商中立的离线安装、固定镜像、4 个 internal 网络、可选受控模型出口、升级与失败关闭回滚 |
| [共享服务器部署基线](./TENCENT_SHARED_HOST_DEPLOYMENT_BASELINE.zh-CN.md) | 同机多应用的端口、网络、资源和变更隔离；文件名为历史兼容路径 |
| [运维手册](./OPERATIONS.zh-CN.md) | 启停、账号/角色操作、扫描审批、备份恢复、容量和故障排查 |
| [内部 CA 与 TLS 运维](./TLS_INTERNAL_CA_OPERATIONS.zh-CN.md) | 私有 CA 安装、短生命周期叶证书续期、严格 SAN/有效期验收、证书轮换、客户端信任与禁止降级要求 |
| [离线 Registry Bundle 构建](./OFFLINE_REGISTRY_BUNDLE_BUILD.zh-CN.md) | 回环 Registry、精确摘要、SBOM、签名与离线镜像运输 |
| [断网冷启动验收](./OFFLINE_RUNTIME_ACCEPTANCE.zh-CN.md) | 无 GitHub、Vercel、COS、公共 Registry/npm/PyPI 依赖的真实冷启动证据 |
| [主机隔离守卫](./HOST_ISOLATION_GUARD.zh-CN.md) | 防止部署影响同机其他应用和越界修改宿主资源 |
| [主机与存储验收](./HOST_STORAGE_ACCEPTANCE.zh-CN.md) | 8C16G/300GB、SSD、fio、水位与证据格式 |
| [旧离线部署纳管](./LEGACY_OFFLINE_ADOPTION.zh-CN.md) | 对既有部署进行失败关闭的受控接管 |

> [!NOTE]
> `deploy/tencent/` 与两份 `TENCENT_*` 文档名仅为历史兼容路径；当前目标是国内任意云厂商或自建机房的通用 Linux 服务器。COS 可用于首次制品传输加速，但不是数据库、对象存储、运行、重启、回滚或冷恢复依赖。

## 安全、数据与供应链

| 文档 | 用途 |
|---|---|
| [威胁模型](./THREAT_MODEL.zh-CN.md) | 身份、文件、对象、模型出口、供应链与运维攻击面 |
| [文档解析安全边界](./DOCUMENT_PARSER_SECURITY.zh-CN.md) | 九格式能力矩阵、Zip Bomb/主动内容、沙箱与失败关闭 |
| [聊天回放加密运维](./CHAT_REPLAY_ENCRYPTION.zh-CN.md) | AES-256-GCM 密钥环、轮换、AAD 与不可逆迁移 `20260714_0020` |
| [发布供应链证据](./RELEASE_SUPPLY_CHAIN_EVIDENCE.zh-CN.md) | 九镜像 SBOM、摘要清单、签名验证、权利声明与发布 NO-GO 边界 |
| [依赖许可证审计](./DEPENDENCY_LICENSE_AUDIT.zh-CN.md) | 依赖许可风险及法律签署阻断项 |
| [资产来源与授权](./ASSET_PROVENANCE.zh-CN.md) | Logo、Icon 和其他资产的来源、审批与缺口 |
| [第三方声明草案](./THIRD-PARTY-NOTICES.md) | 工程清单草案；未经法务批准不得作为商业授权结论 |

应用层聊天 replay 加密不等于整库加密。正式敏感数据交付必须另行证明 PostgreSQL/MinIO 数据卷、WAL、快照与备份的静态加密、密钥托管、恢复及销毁流程。

## 验收、性能与证据

| 文档 | 用途 |
|---|---|
| [企业终验标准](./ENTERPRISE_FINAL_ACCEPTANCE_STANDARD.zh-CN.md) | 当前最严格的验收范围、失败关闭规则和证据门禁 |
| [企业验收标准](./ENTERPRISE_ACCEPTANCE_STANDARD.zh-CN.md) | 早期企业验收基线；与终验冲突时以后者为准 |
| [功能验收标准](./FUNCTIONAL_ACCEPTANCE_STANDARD.zh-CN.md) | 登录、账号、角色、ACL、文件、聊天、模型与 API Key 业务闭环 |
| [功能证据信任模型](./FUNCTIONAL_ACCEPTANCE_TRUST.zh-CN.md) | Ed25519 challenge、内容指纹、重放防护与真实性判定 |
| [终验证据格式](./ACCEPTANCE_EVIDENCE_FORMAT.zh-CN.md) | 目标主机、离线运行、浏览器、容量和灾备的机器可读证据要求 |
| [性能与容量模型](./PERFORMANCE_CAPACITY_MODEL.zh-CN.md) | 1,000 用户、50 亿 token/日、8C16G/300GB 与未来 10 TB 的建模及 NO-GO 门禁 |
| [文档验收样本](./DOCUMENT_ACCEPTANCE_FIXTURES.zh-CN.md) | 九格式合成黄金样本、摘要和隔离要求 |
| [浏览器企业验收套件](../web/e2e/README.md) | 桌面/移动企业档案、严格 TLS 与业务闭环、证据检查 ID 和签名产物；实际 collection 以冻结候选版本为准 |

机器可读策略和 Schema 位于：

- [功能验收清单](./functional_acceptance_manifest.json)
- [功能验收策略](./functional_acceptance_policy.json)
- [`schemas/`](./schemas/) 下的证据 JSON Schema

## 历史报告与证据保全

| 文档 | 状态 |
|---|---|
| [2026-07-11 商业版审计](./COMMERCIAL_READINESS_REVIEW.zh-CN.md) | 历史快照；包含已过期缺口和数量，不代表当前候选版本 |
| [2026-07-11 本地自测](./acceptance-reports/2026-07-11-local-self-test.zh-CN.md) | 历史快照 |
| [2026-07-12 企业终验自测](./acceptance-reports/2026-07-12-enterprise-final-self-test.zh-CN.md) | 历史快照 |
| [2026-07-14 部署后验收](./acceptance-reports/2026-07-14-post-deployment-acceptance.zh-CN.md) | 绑定当时 Git 身份的历史部署证据，不自动适用于当前候选版本 |

历史报告不得覆盖或回填新结论。当前候选版本完成最终 Gate 后，应新增绑定当前 Git SHA、内容指纹、目标主机和签名链的报告，而不是修改旧报告正文。

## 文档维护规则

1. 当前事实以代码、不可变配置、迁移和机器可读 Schema 为第一来源；文档冲突时先修正文档，不得放宽代码门禁。
2. `MEASURED`、`MODELLED`、`UNVERIFIED` 必须分开使用；收集到测试不等于测试通过，代码回归不等于目标机容量证明。
3. 新增、删除或更名文档时同步更新本索引和项目根 README。
4. 历史报告只增加醒目的快照声明，不改写正文结论；新结论写入新报告。
5. 不在文档、截图或工件中保存 `.env`、密码、API Key、模型密钥、私钥或完整预签名 URL。
6. 项目许可证、资产权利、第三方声明和静态加密证据未完成签署前，商业发布保持 `NO-GO`。
