# 企业功能验收反假通过审查

> 审查日期：2026-07-13
> 审查模式：独立只读审查；仅新增本报告
> 目标环境：通用云 Linux amd64/x86_64，8 vCPU / 16 GB RAM / 300 GB SSD；数据库、Redis、对象存储与业务数据位于企业内网
> 业务规模：1,000 用户；每日 5,000,000,000 token 的推理能力由独立、获批准的推理服务提供证明
> 安全边界：未读取 `.env`，未联网，未连接或部署任何云主机

## 1. 结论

当前代码的功能源合同和精选自动化测试可以通过，但**不能据此签署企业终验 PASS**。本次复核实测得到：

| 检查 | 实测结果 | 可证明的边界 |
|---|---:|---|
| 功能源合同 | 13/13 PASS | 声明的文件、文字标记和测试映射存在 |
| 功能后端精选集 | 88 passed，0 skipped | 精选的本地功能路径通过 |
| 功能前端精选集 | 78 passed，0 skipped | 精选的 Vitest 逻辑/组件路径通过 |
| 后端全量收集 | 352 tests | 测试可被收集 |
| 后端本机全量执行 | 345 passed，7 skipped | 7 项均为必须在真实 PostgreSQL 上执行的并发/迁移测试 |
| 前端全量执行 | 25 files，167 passed | Vitest 全量通过 |
| 功能 final | BLOCKED | 缺真实浏览器业务链和通用 Linux 目标主机证据 |

因此当前发布判定仍为 **NO-GO / BLOCKED**。`docs/FUNCTIONAL_ACCEPTANCE_STANDARD.zh-CN.md` 正确写明了缺少浏览器和目标主机证据时必须阻断；这一诚实边界应保留。

但是，验收器本身仍存在可复现的“假通过”路径。若不先修复，下游人员可以通过空清单、脱离测试文件的 runner 或手工 JSON 得到并不真实的 PASS。

## 2. 已复现的假 PASS

本次使用内存副本和临时目录复现，未改动产品文件：

| 场景 | 实际输出 | 风险 |
|---|---|---|
| `requirements=[]`、`test_commands=[]`、`external_evidence=[]` | `contract=PASS`、`external=PASS`、`source=PASS`、`final=PASS` | 清单被误删或恶意缩减时整个验收静默通过 |
| 保留全部声明，但把两个 runner 改为只打印 `1 passed` | 合同 PASS；两个 runner 均 PASS，各计 1 test | 测试证据文件与实际执行命令没有绑定 |
| 手写 `status=passed` 且把 required checks 全标 passed 的浏览器 JSON | external PASS | 没有 Git 身份、采集器、时间、原始产物或哈希，也能冒充真实 E2E |

复现对应的实现位置：

- `scripts/functional_acceptance.py:193-249` 没有最小需求数或代码内固定的必需 ID 集；空需求列表自然得到 0 failed；
- `scripts/functional_acceptance.py:273-325` 只根据退出码、输出中的 skip 和 pass 数字判定 runner，不要求 pass 数大于 0，也不核对实际执行的测试节点；
- `scripts/functional_acceptance.py:328-409` 只验证外部 JSON 的状态与 required check 名称；
- `scripts/functional_acceptance.py:418` 对空测试结果执行 `all(...)`，结果为 true；未传 `--run-tests` 时仍可输出 `source_verdict=PASS`；
- `_payload` 在 source 失败时把 `final_verdict` 记为 BLOCKED，而不是 FAIL，报告语义也不够严格。

## 3. P0 代码级整改项

### GAP-P0-001 固化不可自我缩减的验收政策

当前 manifest 同时定义“要验什么”和“怎么验”。修改同一个文件即可删除要求并让检测器认可新清单。

整改要求：

1. 在验收器代码或独立签名政策文件中固化必需 requirement ID、runner ID、外部证据 ID 和标准版本；
2. 要求 ID 集精确匹配或只能增加，禁止空列表、重复项和未知严重度；
3. 要求至少一个需求、至少一个 runner、至少一个 final 外部证据；
4. 为正式政策记录 SHA-256，并把政策摘要写入报告；
5. 为“删除一个 requirement”“清空三个列表”“重复 ID”“未知 ID”增加失败回归测试。

### GAP-P0-002 把测试声明绑定到真实执行节点

当前 `automated_test.path + contains` 只证明测试源码里有文字；runner 的 `covers` 只是自我声明。两者没有证明指定测试真的被执行。

整改要求：

1. 后端生成 JUnit XML，前端使用 Vitest JSON/JUnit reporter；
2. manifest 中记录精确 test node ID，而不是仅记录文件内字符串；
3. 验收器逐项核对 required node 均出现且 passed；
4. 每个 runner 设置代码内最小通过数，并拒绝 0 passed；
5. 保存脱敏结果文件的 SHA-256、开始/结束时间、工具版本和退出码；
6. runner 使用锁定环境，例如 `uv run --frozen --no-sync` 与 `npm ci` 生成的锁定依赖环境。

### GAP-P0-003 强化外部证据，拒绝自报状态

`browser-e2e.json` 和 `linux-host.json` 目前是自证明文件。文档虽禁止手工伪造，但代码没有执行这一规则。

整改要求：

1. 复用 `scripts/acceptance.py` 的工作树身份：`git_head + content_fingerprint`；
2. 证据必须含 `kind`、`producer`、`producer_version`、`started_at`、`finished_at`、目标环境随机 challenge；
3. 每个 check 必须引用仓库内相对 artifact，并校验 SHA-256、大小上限、非符号链接和路径不越界；
4. 浏览器证据引用 Playwright JSON、截图、trace、console/network 摘要；主机证据引用预检 JSON、Compose 渲染摘要、容器/主机采集物；
5. 证据目标必须与当前内容指纹一致，超过批准有效期即失效；
6. 正式环境应由受控 CI runner、验收容器或签名采集器生成，不能接受人工编辑 JSON；
7. 增加手写全 passed、旧 commit、旧时间、哈希不符、符号链接、缺 artifact 的拒绝测试。

### GAP-P0-004 消除两个相互冲突的“final”

`scripts/functional_acceptance.py --profile final` 只要求浏览器与主机两个外部文档；它没有纳入容量、容灾、安全扫描、恶意文件、真实 PostgreSQL、性能和供应链。它理论上可 PASS，而 `scripts/acceptance.py --profile final` 仍会因 P0 阻断失败。

整改要求：

- 将功能脚本的 profile 改名为 `source` / `runtime-functional`，禁止使用可被误解为交付终验的 `final`；或
- 让功能 final 委托给唯一的 `scripts/acceptance.py --profile final`，并在报告中只保留一个最终 verdict；
- source 未执行测试时输出 `UNVERIFIED/BLOCKED`，不要输出 PASS；
- source FAIL 时 final 必须是 FAIL，而不是 BLOCKED。

### GAP-P0-005 建立完整浏览器业务 E2E

当前 `web/e2e` 只有两个测试场景：登录页可访问/无障碍，以及登录页性能。桌面与移动 project 会把它们扩展为 4 次执行，但仍不是四条业务链。

必须补齐并留证：

1. 管理员、内容管理员、聊天用户、无权限用户统一登录与按权限落地；
2. 账号创建、角色替换、撤销、刷新与退出；
3. 知识库创建、授权、撤权后立即不可见；
4. 单段/Multipart 上传、扫描、OKF、内容审批、下载；
5. 聊天逐事实来源、无答案、审核拒绝、来源表格逐行引用；
6. DeepSeek/Qwen/MiniMax 切换及故障降级；
7. API Key 一次性明文、scope、KB scope、撤销和使用示例；
8. loading、empty、401/403/409/429/5xx、超时、重试；
9. 每步检查 console error、失败网络请求、可访问性和移动端布局。

这部分可以先在本地合成环境建设脚本，但最终 PASS 必须来自目标拓扑或等价预生产环境的真实浏览器运行。

### GAP-P0-006 把存储水位从纯函数检查升级为真实链路

`scripts/storage_watermark_preflight.py:39-65` 使用内存中的 100 字节虚拟 filesystem 验证 70/80/90；`70-101` 只检查当前状态是否低于停止线。它没有在真实 API 上传链路上触发任何水位。

整改要求：

1. 在专用、可销毁的目标测试卷上构造 69/70/79/80/89/90% 状态；
2. 分别发起普通上传、Multipart、重试与并发预留，验证 HTTP 状态、reason code、quota 回滚和对象无泄漏；
3. 验证 180 GB 对象停止线；
4. 使用 MinIO 指标/管理接口与文件系统指标双向核对，不只累加目录项 `st_size`；
5. 保存测试前后 df、对象字节、Multipart 会话和 API 结果，防止仅凭纯函数得到 PASS。

### GAP-P0-007 目标主机检查没有证明 SSD 与 IO 能力

`scripts/host_preflight.py` 验证 Linux、架构、逻辑 CPU、可见内存、文件系统总量与可用量，但没有验证 SSD 类型、挂载类型、IOPS、延迟、fsync 或持续写入能力。因此 HDD、低速网络盘或严重超分配卷也可能通过“300 GB SSD”检查。

整改要求：

- 采集块设备、文件系统、挂载参数与云盘标识；
- 在专用测试文件上运行有界 fio，不触碰业务数据；
- 记录随机/顺序、读写、fsync 的 P95/P99 延迟与 IOPS；
- 阈值由实际业务压测反推，不使用拍脑袋值；
- 云虚拟盘无法可靠报告 rotational 时，以 fio 和云厂商卷规格证明为准。

### GAP-P0-008 离线预检以 root source 未验证的 env 文件

`deploy/tencent/preflight-offline.sh:20-27` 要求 root 执行并直接 source 操作员 env 文件；没有先拒绝符号链接、非 root 所有者或组/其他人可写文件。`80` 行只匹配少量已知服务域名，也不能证明不存在其他外部地址。

整改要求：

1. source 前要求 regular file、非 symlink、root 所有、权限不宽于 0600；
2. 使用严格键值解析器或受控键白名单，避免把配置文件当 shell 脚本执行；
3. 对 URL/host 类变量做允许列表，而不是已知域名黑名单；
4. 为所有运行容器执行无公网 socket、DNS 和路由验证；
5. 在宿主机断网后执行冷启动和完整业务 smoke，并保存网络命名空间/防火墙/连接采集证据。

### GAP-P0-009 宣称的文件范围尚未形成知识闭环

当前允许上传 `.txt/.doc/.docx/.xls/.xlsx/.csv/.pdf/.ppt/.pptx`，但 `app/services/okf_conversion.py:44` 只支持 `.txt/.csv`；PDF、Word、Excel、PowerPoint 在 `190-192` 进入 `unsupported/parser_required`。这符合诚实降级设计，但不符合“所有支持格式均可进入知识问答”的完整交付目标。

整改要求：

- 在无网络、低权限、资源有界的隔离解析器中实现所有格式；
- 拒绝宏、脚本、加密包、外部链接、路径穿越和解压炸弹；
- 为每种格式提供黄金样本、损坏样本、恶意样本和超限样本；
- 保留 PDF 页码、Excel 工作表/单元格、PPT 幻灯片、Word 页/标题来源定位；
- 全格式未完成前，UI 和交付范围必须继续明确显示“可存储但暂不可检索”。

## 4. P1 代码级整改项

### GAP-P1-001 精选功能集不等于全量回归

功能 runner 本次通过 88+78=166 项；前端全量实际为 167 项，后端全量为 352 项。功能 gate 只选择了业务主路径，未覆盖全部安全边界与回归。正式 source gate 应组合全量测试、静态检查、类型、构建、数据库专用门禁，而不是让精选集成为唯一证据。

### GAP-P1-002 通用云命名仍有历史残留

部署目录和文档仍大量使用 `deploy/tencent` / `TENCENT_*`；部分验收提示曾写“腾讯主机”。Compose 实现本身基本云中立，但命名会误导运维人员。应新增云中立 `deploy/offline` 或明确该目录只是历史兼容入口，不能据目录名推断云厂商。

### GAP-P1-003 CAPACITY 与 DR 是永久 blocked 占位符

`scripts/acceptance.py` 的 `CAPACITY-P0-001` 与 `DR-P0-001` 目前是固定 `blocked_reason`。这能防止假 PASS，但即使未来已有真实证据也没有机器可消费的通过路径。

应为两项定义与恶意文件/安全扫描同等级的内容寻址证据格式、采集器、哈希校验、目标身份、有效期和指标阈值。

### GAP-P1-004 主机预检与离线预检口径需统一

Python 主机预检要求 300 GB 文件系统总量和 240 GB 可用；shell 预检只检查 CPU、内存和 240 GB 可用，没有再次验证总量、架构和目标为 Linux。应由 shell 调用同一个 Python 采集器，避免两套标准漂移。

## 5. 必须在目标主机、浏览器或推理服务证明的项目

以下项目不能由源代码、单元测试或本机 Compose 解析替代：

| 证据域 | 必须证明的内容 | 当前状态 |
|---|---|---|
| 真实浏览器 | 第 3 节列出的完整业务链；桌面/移动；console/network/trace/截图 | BLOCKED |
| 通用 Linux 主机 | 8 vCPU、16 GB、300 GB SSD、240 GB 初始可用、IO、挂载、容器资源与同机其他应用隔离 | BLOCKED |
| PostgreSQL/Redis/MinIO/ClamAV | 真实并发、迁移、锁、配额、刷新、上传、扫描、审批、下载和重启持久化 | 本轮本机全量有 7 项 PostgreSQL skip；目标证据 BLOCKED |
| 无公网运行 | 断网冷启动；所有容器无未批准出站；本地 DB/Redis/对象存储；日志无敏感数据 | BLOCKED |
| 1,000 用户控制面 | 30 分钟稳态、峰值、8–24 小时长稳、故障注入；API/检索 P95/P99 和资源阈值 | BLOCKED |
| 50 亿 token/日 | 推理服务配额、吞吐、并发、上下文、429/5xx、成本预算、账本与停止开关 | BLOCKED |
| 存储水位 | 70/80/90%、180 GB 停止线、并发 Multipart、无超卖/无泄漏 | BLOCKED |
| DR | PostgreSQL PITR、对象版本/复制、独立备份、RPO≤15 分钟、RTO≤4 小时、1000 对象哈希 100% | BLOCKED |
| 供应链/法务 | 最终镜像 SBOM、漏洞、签名、许可证、Logo/字体/素材授权 | BLOCKED/需责任人签署 |

## 6. 50 亿 token/日的正确边界

5,000,000,000 token/日意味着：

- 24 小时平均约 57,870 token/s；
- 集中在 8 小时业务窗约 173,611 token/s；
- 按当前容量模型的 5 倍峰值约 868,056 token/s；
- 每次 RAG 回答还包含生成与审核两次上游调用。

8C16G/300GB、无 GPU、完全隔离的应用主机不能提供该推理吞吐。当前离线 Compose 显式关闭外部 LLM，因此其 LLM 能力是 0 token/日，只能验证控制面和确定性检索。

最终必须二选一并写入验收拓扑：

1. 应用、数据库、Redis、MinIO 全部在企业内网，另接获批准的企业内网 GPU 推理集群；或
2. 书面降低/取消 50 亿 LLM token 指标，按完全检索型离线系统验收。

若使用公网模型服务，就不再满足“业务数据完全不连接外网”的当前边界，必须重新进行数据分级、脱敏、驻留、跨境和供应商安全评审。

## 7. 建议修复顺序与通过条件

1. **先修验收器可信度**：关闭空清单、空 tests、runner 脱钩、手工外部 JSON 四类假 PASS；
2. **统一唯一 final**：功能源门禁只能是总验收的一部分；
3. **补真实浏览器 E2E 与全格式闭环**；
4. **补主机 SSD/IO、env 权限、无出站与真实水位链路**；
5. **提供真实 PostgreSQL/Redis/MinIO/ClamAV 证据**；
6. **建设负载、长稳、故障注入与 DR 采集器**；
7. **取得独立推理服务 50 亿 token/日容量与成本证明**；
8. **在干净工作树、精确 Git SHA 和不可变镜像 digest 上重跑唯一 final**。

只有满足以下条件才能把本报告结论改为 PASS：

- 代码级 P0 假通过路径全部有失败回归测试；
- 所有 P0/P1 自动门禁无 skip、无 failed、无 blocked；
- 浏览器、目标主机、性能、推理、DR、供应链证据均绑定同一 Git/content fingerprint；
- 原始 artifact 哈希可复核；
- 技术、安全、运维、数据/合规与法务责任人完成签署。

## 8. 本轮未执行项

按照任务边界，本轮没有：

- 读取 `.env` 或任何凭据；
- 联网、访问云厂商或启动远程部署；
- 伪造浏览器、目标主机、供应商容量或恢复演练证据；
- 把 7 项真实 PostgreSQL skip 记为通过；
- 把源合同 PASS 改写成企业终验 PASS。
