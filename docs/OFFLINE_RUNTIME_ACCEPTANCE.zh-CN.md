# 离线运行时验收与断网冷启动

> 适用目标：通用云 Linux `amd64/x86_64`，不绑定任何云厂商；最低 8 逻辑 CPU、15 GiB 可见内存（对应 16 GB 标称配置）、300 GB 文件系统与 240 GB 可用空间。

`scripts/collect_offline_runtime_evidence.py` 用于关闭 `GAP-P0-008` 的运行时证据缺口。默认入口只输出计划，不读取 `.env`、不运行容器命令、不修改防火墙、不断网。在 Linux 上计划还会用只读系统身份文件输出当前 `observed_host_fingerprint`，供受控计划绑定：

```bash
python3 -m scripts.collect_offline_runtime_evidence
python3 -m scripts.collect_offline_runtime_evidence --egress-mode controlled_gateway
```

第一条命令输出严格离线计划；第二条只输出受控出口计划。计划输出的 `egress_mode`、`required_command_steps` 与网络拓扑是正式执行合同的一部分，并不启动采集。

## 采集范围

执行模式必须在一次性 challenge 和专用 `kb-acceptance-*` 测试租户下完成下列闭环：

1. 固定探针采集宿主机与所有项目容器的 `ss` socket，全部路由、默认路由、DNS 配置、network namespace、`nftables` 规则和 Compose 网络。
2. 按控制计划绑定的出口模式校验精确 Compose 拓扑，而不是笼统要求所有网络均为内部网络。
3. 先验证恢复通道，再武装独立 rollback watchdog，然后才允许断网。
4. 严格离线模式下，隔离后外部 DNS 解析必须失败，宿主机及项目容器不得留有公网 peer socket；受控出口模式下只允许 `llm-egress` 出现已被 L3/L4 策略证明允许的公网 peer。
5. 只使用服务器本地保存的源码包、完整镜像归档、病毒库和持久化数据执行冷加载与冷启动；不得访问 GitHub、Vercel、COS、公共镜像仓库或公共 CDN。
6. 执行登录、公共 API、OpenAPI、RBAC、知识库 ACL、上传、审批、下载、知识问答、持久化写入、重启与持久化复核。
7. 浏览器网络记录、宿主机 socket 与容器 socket 均不得出现未批准的公网连接；仅在受控出口模式中允许经证据绑定的模型出口。
8. 无论业务步骤是否成功，只要已尝试断网就必须恢复网络；恢复或 rollback 验证失败时永远是 `BLOCKED`。

## 出口模式与精确拓扑

### `strict_offline`

- 项目网络必须精确为 `backend`、`edge`、`frontend`、`llm-control` 四个逻辑网络，且四者均为 `Internal=true`。
- 不得存在 `llm-uplink` 网络，也不得存在运行中或已停止但仍物化的 `llm-egress` Compose 服务容器。
- 隔离阶段宿主机和全部项目容器均不得存在公网 peer，外部 DNS 必须失败。

### `controlled_gateway`

- 项目网络必须精确为上述四个内部网络加 `llm-uplink`；只有 `llm-uplink` 可以是 `Internal=false`。
- 必须精确存在一个运行中的 `llm-egress` Compose 服务；它只能连接 `llm-control` 与 `llm-uplink`。
- `llm-uplink` 的容器 endpoint 必须且只能属于该 `llm-egress` 实例，其他项目容器不得连接该网络，也不得出现公网 peer。
- 仅证明上述 Compose 拓扑仍不足以证明宿主机出口受控。正式 `PASS` 还必须在断网冷启动后执行 `controlled_egress_policy` harness，并由采集器直接解析现场 `nft -j list ruleset`，证明 `llm-uplink` bridge 的精确 L3/L4 allowlist 与末尾默认丢弃规则；业务链（含重启）结束后必须对新的现场 ruleset 再执行一次同一闭环，且规范化 allowlist 不得变化。原始 ruleset 中的动态计数器可以变化，但两次都必须独立通过规则语义验证和现场哈希绑定。缺少、过宽、与对应现场 ruleset 哈希不一致、业务期间 allowlist 发生变化或无法覆盖已观测公网 peer 时必须返回 `BLOCKED`。

`controlled_gateway` 是“允许受控模型出口的隔离部署”，不是无公网出口的严格离线模式。证据中必须保存 `target.egress_mode`，验收方不得把两种模式的结论互换。

## 控制计划合同

控制计划是 root 所有、组/其他用户不可写、小于 256 KiB 的 JSON 常规文件。`commands` 必须精确包含计划模式输出的 `required_command_steps`，不允许缩减或额外命令。每个命令仅接受直接 argv，第一个参数必须是 root 所有、非可写、可执行的绝对路径；每条 argv 必须显式包含当前 challenge 和测试租户；禁止 shell、`env`、`sudo`和其他间接启动器。

```json
{
  "schema_version": 1,
  "challenge": "<24-128 位一次性值>",
  "test_tenant": "kb-acceptance-<id>",
  "project_name": "<compose-project>",
  "egress_mode": "strict_offline",
  "host_fingerprint": "<64 hex>",
  "git_head": "<40-64 hex>",
  "content_fingerprint": "<64 hex>",
  "commands": {
    "recovery_preflight": {
      "argv": ["/opt/heyi-acceptance/recovery-preflight", "<challenge>", "<tenant>"],
      "timeout_seconds": 60
    }
  }
}
```

上例仅展示严格离线命令形状，真实文件必须包含计划输出中的全部必需步骤。`egress_mode` 必须与 CLI 参数完全相同；严格离线计划不允许额外的受控出口命令，受控出口计划必须额外且仅额外包含 `controlled_egress_policy`。每个 harness 的 stdout 必须只输出以下 JSON，不得输出 token、密码、Cookie 或凭据：

```json
{
  "status": "passed",
  "check": "login",
  "challenge": "<active-challenge>",
  "test_tenant": "kb-acceptance-<id>",
  "observations": {"verified": true}
}
```

`controlled_egress_policy` 的 `observations` 必须使用以下精确结构。`nftables_ruleset_sha256` 是 harness 已验证的同一份 `nft -j list ruleset` stdout 的 SHA-256；采集器会与现场探针结果逐字节计算的哈希比对。allowlist 必须为 1–64 条精确 CIDR/协议/端口规则；IPv4 不得宽于 `/24`，IPv6 不得宽于 `/48`。下例地址仅说明格式，不代表生产允许项：

```json
{
  "policy_engine": "nftables",
  "default_action": "drop",
  "endpoint_service": "llm-egress",
  "enforcement_scope": "llm-uplink-forward",
  "nftables_ruleset_sha256": "<64 hex>",
  "allowed_destinations": [
    {"protocol": "tcp", "cidr": "8.8.8.8/32", "port": 443}
  ]
}
```

采集器不会相信 harness 对 `default_action` 或 allowlist 的单方面声明，也不会从 Caddy 配置、DNS 结果或当前 socket 反推并“生成”宿主机 allowlist。它会在原始 ruleset 中要求以下精确、可机读合同：

- `inet` 表名固定为 `heyi_kb_egress`；基础链名固定为 `heyi_llm_egress_forward`，类型 `filter`、hook `forward`、priority `-5`、chain policy `accept`。chain policy 保持共享宿主机的其他应用不受影响。
- 该链前 N 条规则必须一一对应声明的 allowlist。每条规则必须同时精确匹配采集器从 `llm-uplink` Docker 网络 ID 推导/读取的 bridge interface、`meta l4proto`、IPv4/IPv6 目的 CIDR、传输层目的端口，并以 `accept` 结束。
- 链的最后且唯一剩余规则必须只匹配同一 bridge interface 并执行 `drop`，形成仅对 `llm-uplink` 的 scoped default-deny；规则 comment 固定为 `heyi-controlled-egress`。
- 规则可以含只读 `counter` 表达式；采集器只忽略其非负 `packets/bytes` 动态值，不忽略任何其他表达式。多余 accept、错误 interface、缺失末尾 drop、重复规则或未知表达式全部 `BLOCKED`。

这项证明的边界仅为项目 `llm-uplink` bridge 上的转发流量。宿主机进程自身的 output 流量（包括 Docker 嵌入式 DNS 在宿主机侧产生的流量）不属于本证据结论，而属于宿主机/root 管理员信任边界；不得从 `llm-uplink-forward` 推断宿主机 output 已被默认拒绝。若验收范围要求宿主机 output 同样执行 default-deny，必须新增独立的 output-chain 现场采集、原始 ruleset 解析与回归测试后才能作出该结论。

每次 socket/拓扑采集结束前还会再次枚举并 inspect 项目全部运行容器、全部物化容器和全部 Compose 网络；ID 集合或精确 attachment/状态在窗口内发生变化时立即 `BLOCKED`。策略 harness 缺失、原始 nft 合同不匹配或重枚举不稳定时，受控出口证据不能生成 `PASS`。

## 执行门禁

正式执行需要同时提供 `--execute`、精确 confirmation、challenge、测试租户、Compose 项目名、`--egress-mode`、目标主机指纹、仓库、数据盘、控制计划和未存在的证据输出目录。出口模式、指纹与计划中的 Git HEAD/工作树内容指纹必须和执行时现场一致。一次性 challenge 会使用 `O_EXCL` 在 mode `0700` 的 root 状态目录中预留，重放必须失败。

不应在 SSH 唯一恢复路径未独立验证时执行。应先建立云控制台/VNC/带外通道，并用系统 watchdog 设置有界自动恢复。采集器不会自动修改业务环境，只编排经审批的直接执行 harness。

## 证据与判定

成功产物位于指定输出目录：

- `raw/*.json`：每个系统探针或业务步骤的有界原始产物，逐项记录 SHA-256 和字节数；单次最多 256 件，每件最多 1 MiB。
- `offline-runtime-evidence.json`：绑定 challenge、专用租户、出口模式、主机/Git/内容指纹、逐检查 artifact 引用、`result_sha256` 和整体 `sha256-chain-v1` attestation。
- 格式契约：`docs/schemas/offline-runtime-evidence-v1.schema.json`。

单元测试中的 fake runner 只验证编排、证据链和 fail-closed，不得产生可被最终验收消费的正式证据。真实 `PASS` 只能由 CLI 中不可注入的 `SubprocessCommandRunner` 在目标 Linux 主机上产生。缺少工具、权限、精确容器/网络集合，严格离线模式无法证明 DNS/socket 断网，受控出口模式无法证明 L3/L4 宿主机 allowlist，业务步骤失败，或恢复失败，全部严格返回 `BLOCKED` 和退出码 `2`。
