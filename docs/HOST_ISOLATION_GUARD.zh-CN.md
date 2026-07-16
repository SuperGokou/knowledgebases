# 共享云主机非项目资源隔离门禁

> 本文是正式部署编排的独立文档片段。门禁只读 Docker、systemd、`/proc` 与 cgroup 状态，不停止、重启、删除或修改任何服务/容器，也不连接外部服务。

## 目标与判定

在部署知识库前封存共享主机基线，部署后对同一 Docker daemon 和宿主机关键服务进行精确复核。下列目标项目允许变化：

- Compose project：`heyi-kb-offline`
- Compose project：`heyi-kb-acceptance`
- Compose project 前缀：`heyi-kb-acceptance-`

除此之外，所有 Docker 容器均属于受保护资源。端口 `10050` 的实际保护主体是宿主机 `zabbix-agent.service`，不是知识库 Docker 项目。建立基线必须同时证明该 unit 已加载、已启用且处于 `active/running`，并证明 TCP `10050` 的全部监听 socket 由该 unit 的 cgroup 进程持有；Docker owner 可以为空。

受保护容器的以下任一字段发生变化，部署后门禁均返回 `FAIL`：

- 容器 ID、名称、Compose project 和镜像 ID/镜像引用；
- 创建时间、启动时间、结束时间、运行状态、退出码、重启次数和健康状态；
- restart policy、network mode、配置端口和运行时端口；
- 挂载类型、名称、源、目标、驱动、读写模式和传播模式；
- 网络 ID、endpoint ID、IP/MAC、网关、别名、DNS 名称和安全 IPAM 字段；
- Docker daemon ID、名称、版本、操作系统和架构；
- 受保护镜像是否仍存在，以及 `10050` 端口所有者集合。

`zabbix-agent.service` 的以下任一字段变化同样返回 `FAIL`：

- unit 的 load/active/sub 状态、启用状态、restart count、InvocationID、control group、User/Group 与 DynamicUser；
- MainPID、ExecMainPID、cgroup 全部 PID、每个进程的 `/proc` 启动 ticks；
- unit 文件及全部受保护进程可执行文件的解析路径、设备号、inode、大小、所有者、权限与 SHA-256；
- TCP `10050` 的协议族、监听地址、UID、socket inode、owner unit 与 owner PID 集合。

PID 与 socket inode 默认采用精确比较，策略明确绑定为 `service_restart_tolerance: none`。部署过程不应触碰 Zabbix，因此即使服务能自动恢复，发生重启也必须失败并调查；当前没有“自动忽略良性重启”的隐式例外。

门禁不采集容器/服务环境变量、命令行、ExecStart 内容、通用 Labels、Docker secrets、网络 `DriverOpts` 或挂载对象的未知扩展字段。systemd unit 文件与进程可执行文件只输出哈希和文件身份，不输出文件内容。差异清单只记录字段路径与变更前后值的 SHA-256，不把原值复制进诊断区。

## 正式操作流程

HMAC 密钥必须位于代码仓库和发布包之外，仅由部署账户读取：

```bash
sudo install -d -m 0700 /srv/heyi-kb-evidence
sudo sh -c 'umask 077; openssl rand 32 > /srv/heyi-kb-evidence/host-isolation.hmac'
sudo chmod 0600 /srv/heyi-kb-evidence/host-isolation.hmac
```

部署前建立基线：

```bash
python3 scripts/host_isolation_guard.py snapshot \
  --output /srv/heyi-kb-evidence/host-isolation-before.json \
  --hmac-key-file /srv/heyi-kb-evidence/host-isolation.hmac
```

只有退出码为 `0`、JSON `status` 为 `CAPTURED`，且 `required_port_owners["10050"].systemd_units` 精确等于 `["zabbix-agent.service"]` 时，才可继续部署。`docker_containers` 在当前服务器上预期为空。

完成目标项目部署和健康检查后复核：

```bash
python3 scripts/host_isolation_guard.py verify \
  --baseline /srv/heyi-kb-evidence/host-isolation-before.json \
  --output /srv/heyi-kb-evidence/host-isolation-after.json \
  --hmac-key-file /srv/heyi-kb-evidence/host-isolation.hmac
```

退出码语义：

| 退出码 | JSON 状态 | 含义 | 后续动作 |
| ---: | --- | --- | --- |
| `0` | `PASS` / `CAPTURED` | 快照成功或非项目资源完全一致 | 可进入下一门禁 |
| `1` | `FAIL` | 至少一个受保护字段变化 | 停止发布，只回滚目标项目并调查 |
| `2` | `BLOCKED` | Docker/systemd/`/proc` 不可用、证据/HMAC 无效、路径不安全或快照不完整 | 不得发布，先修复证据链 |

## 证据安全边界

- HMAC-SHA-256 覆盖完整规范化 JSON，证据只保存 HMAC 和密钥 ID，不保存密钥或密钥路径。
- 未提供密钥时工具仍以 SHA-256 绑定证据，但它只能发现意外损坏，不能证明证据未被有写权限的攻击者重算；正式验收必须使用 HMAC。
- Linux/POSIX 上输入文件必须是可信所有者持有的普通文件，不得 group/world 可写；HMAC 密钥必须是 `0600` 或更严格。
- 输出使用同目录随机临时文件、`O_EXCL`、`O_NOFOLLOW`、`0600`、文件 `fsync`、原子替换和目录 `fsync`；父路径或目标为 symlink/reparse point 时失败关闭。
- Docker 命令的 stdout/stderr 不写入错误报告；Docker 失败只返回固定错误码，避免守护进程错误带出路径或凭据。
- Linux 上只从固定系统目录解析 root 持有且不可组/其他写的 Docker CLI，并显式绑定本机 root 持有、不可 world-write 的 Unix socket；调用环境会移除 `DOCKER_HOST`、`DOCKER_CONTEXT` 和凭据目录等远程/外部上下文变量。
- systemctl 同样使用固定系统目录内 root 持有且不可组/其他写的绝对路径，只读取显式白名单属性；子进程环境不继承 pager、远程 Docker 上下文或凭据变量，stdout/stderr 不写入错误证据。
- systemd 快照前后会重复读取 unit 与 cgroup PID 集合，并复核每个 PID 的启动 ticks；采集中发生进程变化会返回 `BLOCKED`，不会封存混合时点基线。
- 基线和复核必须由同一受控部署账户在同一主机执行；证据和 HMAC 密钥不得上传 COS、GitHub、Vercel 或放入发布包。

## 运维约束

门禁故意采用“零漂移”语义。即使变化来自预期的主机重启、旧应用自动更新或人工维护，也必须先判定 `FAIL`，由验收人确认原因后重新开始完整的“部署前快照—部署—部署后复核”周期，禁止编辑基线或忽略差异。

该工具覆盖 Docker 管理的共享资源，以及当前已登记的 `zabbix-agent.service`/TCP `10050`。它不等价于全主机所有 systemd unit、宿主机防火墙、磁盘、用户、内核参数和任意文件的完整性监控。正式交付仍需同时执行主机预检、备份恢复、网络出口、TLS 和运行时验收。
