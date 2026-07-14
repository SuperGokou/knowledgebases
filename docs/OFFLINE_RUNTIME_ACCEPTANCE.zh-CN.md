# 离线运行时验收与断网冷启动

> 适用目标：通用云 Linux `amd64/x86_64`，不绑定任何云厂商；最低 8 逻辑 CPU、15 GiB 可见内存（对应 16 GB 标称配置）、300 GB 文件系统与 240 GB 可用空间。

`scripts/collect_offline_runtime_evidence.py` 用于关闭 `GAP-P0-008` 的运行时证据缺口。默认入口只输出计划，不读取 `.env`、不运行容器命令、不修改防火墙、不断网。在 Linux 上计划还会用只读系统身份文件输出当前 `observed_host_fingerprint`，供受控计划绑定：

```bash
python3 -m scripts.collect_offline_runtime_evidence
```

## 采集范围

执行模式必须在一次性 challenge 和专用 `kb-acceptance-*` 测试租户下完成下列闭环：

1. 固定探针采集宿主机与所有项目容器的 `ss` socket，全部路由、默认路由、DNS 配置、network namespace、`nftables` 规则和 Compose 网络。
2. 要求项目容器与网络集合非空，并且每个项目网络都是 `Internal=true`。
3. 先验证恢复通道，再武装独立 rollback watchdog，然后才允许断网。
4. 断网后外部 DNS 解析必须失败，宿主机及项目容器不得留有公网 peer socket。
5. 只使用服务器本地保存的源码包、完整镜像归档、病毒库和持久化数据执行冷加载与冷启动；不得访问 GitHub、Vercel、COS、公共镜像仓库或公共 CDN。
6. 执行登录、公共 API、OpenAPI、RBAC、知识库 ACL、上传、审批、下载、知识问答、持久化写入、重启与持久化复核。
7. 浏览器网络记录、宿主机 socket 与容器 socket 均不得出现未批准的公网连接。
8. 无论业务步骤是否成功，只要已尝试断网就必须恢复网络；恢复或 rollback 验证失败时永远是 `BLOCKED`。

## 控制计划合同

控制计划是 root 所有、组/其他用户不可写、小于 256 KiB 的 JSON 常规文件。`commands` 必须精确包含计划模式输出的 `required_command_steps`，不允许缩减或额外命令。每个命令仅接受直接 argv，第一个参数必须是 root 所有、非可写、可执行的绝对路径；每条 argv 必须显式包含当前 challenge 和测试租户；禁止 shell、`env`、`sudo`和其他间接启动器。

```json
{
  "schema_version": 1,
  "challenge": "<24-128 位一次性值>",
  "test_tenant": "kb-acceptance-<id>",
  "project_name": "<compose-project>",
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

上例仅展示命令形状，真实文件必须包含全部必需步骤。每个 harness 的 stdout 必须只输出以下 JSON，不得输出 token、密码、Cookie 或凭据：

```json
{
  "status": "passed",
  "check": "login",
  "challenge": "<active-challenge>",
  "test_tenant": "kb-acceptance-<id>",
  "observations": {"verified": true}
}
```

## 执行门禁

正式执行需要同时提供 `--execute`、精确 confirmation、challenge、测试租户、Compose 项目名、目标主机指纹、仓库、数据盘、控制计划和未存在的证据输出目录。指纹与计划中的 Git HEAD/工作树内容指纹必须和执行时现场一致。一次性 challenge 会使用 `O_EXCL` 在 mode `0700` 的 root 状态目录中预留，重放必须失败。

不应在 SSH 唯一恢复路径未独立验证时执行。应先建立云控制台/VNC/带外通道，并用系统 watchdog 设置有界自动恢复。采集器不会自动修改业务环境，只编排经审批的直接执行 harness。

## 证据与判定

成功产物位于指定输出目录：

- `raw/*.json`：每个系统探针或业务步骤的有界原始产物，逐项记录 SHA-256 和字节数。
- `offline-runtime-evidence.json`：绑定 challenge、专用租户、主机/Git/内容指纹、逐检查 artifact 引用、`result_sha256` 和整体 `sha256-chain-v1` attestation。
- 格式契约：`docs/schemas/offline-runtime-evidence-v1.schema.json`。

单元测试中的 fake runner 只验证编排、证据链和 fail-closed，不得产生可被最终验收消费的正式证据。真实 `PASS` 只能由 CLI 中不可注入的 `SubprocessCommandRunner` 在目标 Linux 主机上产生。缺少工具、权限、容器或内部网络集合，无法证明 DNS/socket 断网，业务步骤失败，或恢复失败，全部严格返回 `BLOCKED` 和退出码 `2`。
