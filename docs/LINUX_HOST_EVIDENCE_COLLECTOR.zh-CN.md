# Linux 主机正式验收证据采集器运维手册

本文说明如何在目标离线 Linux 企业主机上运行 `EXT-LINUX-HOST-001` 正式证据采集器。采集器只接受实际命令探针的观测结果，不接受人工填写的 `passed`、截图、口头确认或手改日志。

> 结论边界：只要 12 项检查中任意一项缺失、失败或无法可靠证明，采集结果就是 `BLOCKED`。尤其是全新部署尚未出现 **Caddy 真实续期成功事件** 时，即使当前 HTTPS 可访问、叶证书仍有效，也不得宣称自动续期通过。

## 1. 固定身份与适用范围

| 项目 | 固定值 |
| --- | --- |
| Evidence ID | `EXT-LINUX-HOST-001` |
| Collector | `heyi-linux-host@1.0.0` |
| Key ID | `linux-host-ed25519` |
| 运行用户 | `root`，不支持普通用户或 `sudo` 权限不完整的代理账号 |
| 操作系统 | Linux |
| 架构 | `amd64` / `x86_64` |
| 目标规格 | 8 个可用逻辑 CPU、16G 规格内存、300 GB 文件系统、至少 240 GB 可用空间 |
| 正式输出 | `<repository>/artifacts/acceptance/functional/linux-host.json` |
| 阻断诊断 | `<repository>/artifacts/acceptance/functional/linux-host.blocked.json` |

采集器不提供参数覆盖 Evidence ID、collector、key ID、检查名称或输出路径。不得通过复制旧证据、修改 manifest、降低阈值或替换探针来改变结果。

内存门槛按 16G 云主机规格核验，采集器使用项目统一的可见内存下限（15 GiB），用于容纳固件、内核和云平台保留量；磁盘总量与可用空间分别按 300 GB、240 GB 的十进制容量门槛核验。

## 2. 信任边界

### 2.1 私钥

签名私钥必须同时满足：

- Ed25519、PEM 编码、PKCS#8 私钥；
- 位于代码仓库、发布目录、容器镜像和 `.env` 之外；
- 普通文件且不是符号链接；
- `root:root` 所有；
- 权限只能是 `0400` 或 `0600`；
- 不得出现在命令行内容、日志、工件、备份清单、工单或聊天记录中。

本版本的信任模型把目标机 `root` 与仓库外的软件签名私钥视为可信计算基；它能阻止普通账号、旧证据和跨批次重放，但不能抵御已经恶意控制 `root` 的操作者自行签发伪造证据。若验收范围必须覆盖恶意 root，应改用外部签名服务或 TPM/HSM 密封密钥，并把 collector 制品度量纳入签名策略；完成该升级前不得宣称具备抗恶意 root 的硬件级证明能力。

推荐固定路径：

```text
/etc/heyi-acceptance/private/linux-host-ed25519.pem
```

首次初始化示例。必须在受控终端执行，执行前关闭 shell tracing；已存在私钥时立即停止，不得覆盖：

```bash
sudo -i
set +x
umask 077
install -d -o root -g root -m 0700 /etc/heyi-acceptance/private
test ! -e /etc/heyi-acceptance/private/linux-host-ed25519.pem
openssl genpkey -algorithm ED25519 \
  -out /etc/heyi-acceptance/private/linux-host-ed25519.pem
chown root:root /etc/heyi-acceptance/private/linux-host-ed25519.pem
chmod 0400 /etc/heyi-acceptance/private/linux-host-ed25519.pem
openssl pkey \
  -in /etc/heyi-acceptance/private/linux-host-ed25519.pem \
  -check -noout
exit
```

`openssl pkey -check -noout` 只能用于结构校验；禁止使用会打印私钥参数的 `-text`。公钥由验收管理员通过独立安全流程登记到仓库外信任存储，collector ID 与 key ID 必须分别为 `heyi-linux-host`、`linux-host-ed25519`。轮换密钥必须走策略变更和双人复核，不能在现场临时改名绕过。

### 2.2 一次性 challenge

challenge 必须由验收方在采集前签发，并同时精确绑定：

- `evidence_id=EXT-LINUX-HOST-001`；
- 当前目标仓库的 `git_head`；
- 当前工作树的 `content_fingerprint`；
- 本次唯一的 `run_id`；
- 不可预测 nonce、签发时间和过期时间。

challenge 文件必须位于仓库外，例如：

```text
/var/lib/heyi-acceptance/challenges/<challenge-id>.json
```

目录必须为 `root:root 0700`，文件必须为 `root:root 0400/0600`、普通文件且不是符号链接。challenge 最长有效期受信任策略限制；当前验收器接受的窗口不超过 24 小时。不得复制、续写、手改时间、手改 target 或重复使用已消费的 challenge。

准备目录：

```bash
sudo install -d -o root -g root -m 0700 \
  /var/lib/heyi-acceptance/challenges
```

先生成本次 `run_id`，再由验收方针对同一 `run_id` 和代码身份签发 challenge：

```bash
RUN_ID="linuxhost_$(date -u +%Y%m%dT%H%M%SZ)_$(openssl rand -hex 8)"
printf '本次 run_id：%s\n' "$RUN_ID"
```

`run_id` 必须为 8–80 个字母、数字、下划线或连字符。它不是秘密，但必须唯一。验收方签发 challenge 后，运维人员只安装文件并校验元数据，不得 `cat`、`tee` 或把内容复制到日志：

```bash
sudo chown root:root /var/lib/heyi-acceptance/challenges/<challenge-id>.json
sudo chmod 0400 /var/lib/heyi-acceptance/challenges/<challenge-id>.json
sudo stat -c '%U:%G %a %F %n' \
  /var/lib/heyi-acceptance/challenges/<challenge-id>.json
```

若采集失败，建议废弃本次 challenge，修复后使用新的 `run_id` 和新 challenge 重试。正式验收器成功验签后会消费 challenge；已消费 challenge 不能用于第二份证据。

## 3. 12 项强制检查

| 检查 ID | 可通过的机器证据 | 典型阻断原因 |
| --- | --- | --- |
| `linux_amd64` | 内核实际报告 Linux，架构为 `amd64/x86_64` | 非 Linux、ARM、架构无法识别 |
| `cpu_8` | 当前进程可使用的逻辑 CPU 不少于 8 | 容器/cgroup/亲和性只暴露少于 8 核 |
| `memory_16g` | 可见内存满足项目的 16G 规格门槛 | 虚拟机规格不足或 cgroup 限制 |
| `filesystem_300g` | `--disk-path` 所在文件系统总量不少于 300 GB | 扩容后未扩展分区/文件系统，或路径落在小盘 |
| `free_space_240g` | 同一文件系统可用空间不少于 240 GB | 镜像、日志、备份或旧发布占用过多 |
| `offline_images` | 固定离线镜像验证器确认所有镜像 digest、config ID 与 `linux/amd64` 平台完全匹配 | 使用 tag/`latest`、digest 不符、镜像缺失、试图远程拉取 |
| `clamav_database` | ClamAV 数据库预检真实执行成功，运行中的 `clamd` 健康 | 病毒库缺失/过期/权限错误、守护进程不健康 |
| `health_readiness` | Web 与对象存储 readiness 端点经严格 HTTPS 探针返回约定状态 | 服务未就绪、严格 CA 校验失败、返回结构不符 |
| `business_smoke` | 固定业务入口/接口探针真实执行并满足预期状态 | 仅容器 running、仅端口开放、业务路由失败 |
| `caddy_ca_persistent_storage` | Caddy `/data` 使用持久存储，内部 CA 位于该持久根并满足身份、权限及本次采集前后指纹稳定性约束 | 匿名临时卷、CA 位于容器可写层、采集期间 CA 被替换或不可验证 |
| `caddy_automatic_certificate_management` | Caddy 运行时配置实际启用受管理的内部证书自动化，且配置与当前运行实例/持久 `/data` 一致 | 只有静态配置文本、手工证书、自动化策略未生效 |
| `caddy_renewal_health` | 当前 Caddy 运行证据中存在由 Caddy 产生的真实证书 **续期成功事件**，并通过采集器的固定关联与健康规则 | 只有首次签发、只有“维护任务已启动”、没有成功续期事件、存在续期错误或证据无法关联 |

上述状态全部由采集器内部的固定可执行探针产生。命令输出先在内存中解析，只把允许字段、摘要、计数、时间和状态写入原始工件；任何 `.env` 值、凭据、文档正文、Cookie、Token、数据库连接串或完整敏感日志都不得落盘。

### 3.1 TLS 硬性条件

TLS 是 readiness、业务 smoke 与 Caddy 三项检查的交叉门禁。三个业务入口（Web、公共 API、对象存储）必须同时满足：

- 使用明确的受信 CA 严格验链，禁止跳过证书验证；
- SAN 与实际连接主机名精确匹配；
- 当前时间位于叶证书有效期内，`notBefore` 不允许异常未来偏移；
- 叶证书剩余有效时间至少 1 小时；
- 使用项目允许的 TLS 协议与完整签发链。

`curl -k`、`--insecure`、`NODE_TLS_REJECT_UNAUTHORIZED=0`、忽略 SAN 或只检查端口连通性都不能形成通过证据。

### 3.2 新部署的续期等待期

首次签发证书不等于续期。Caddy 配置含 `tls internal`、证书位于 `/data`、当前叶证书有效，以及日志中出现“证书维护已启动”，都只能证明配置或初始状态，不能替代真实续期成功事件。

因此，全新部署可能在全部业务功能正常时仍得到 `BLOCKED`。这是预期的安全行为：

1. 保持 Caddy、持久 `/data` 与日志链路连续运行；
2. 等待 Caddy 按其证书生命周期完成一次真实续期；
3. 确认期间没有清空 Caddy 数据、重建临时卷或截断审计日志；
4. 使用新的 `run_id` 和 challenge 再次采集。

不得为了赶验收而修改系统时间、缩短证书生命周期、伪造/粘贴日志、手工改证书时间、重放旧事件或把首次签发标记成续期。若无法可靠证明真实续期，最终结论必须保持 `BLOCKED`。

> v1 边界：当前检查证明的是持久 bind、当前 CA 身份以及本次探针窗口内 CA 未变化；它不单独证明“服务器重建前后”的历史 CA 连续性。若交付要求跨重建连续性，必须另有与 active release 绑定的签名接管/迁移 CA 指纹收据，并由后续契约显式校验。不得把当前检查解释成该历史收据。

## 4. 运行前检查

以下命令不读取 `.env`，也不输出私钥或 challenge 内容：

```bash
sudo -i
set +x
test "$(id -u)" -eq 0
test "$(uname -s)" = Linux
case "$(uname -m)" in x86_64|amd64) ;; *) exit 1 ;; esac

REPOSITORY=/absolute/release/repository
DISK_PATH=/srv/heyi-knowledgebases-offline
SIGNING_KEY=/etc/heyi-acceptance/private/linux-host-ed25519.pem
CHALLENGE=/var/lib/heyi-acceptance/challenges/<challenge-id>.json

test -d "$REPOSITORY/.git" -o -f "$REPOSITORY/.git"
test -d "$DISK_PATH"
stat -c '%U:%G %a %F %n' "$SIGNING_KEY" "$CHALLENGE"
```

运行前还应确认：

- `REPOSITORY` 是本次待验收发布的绝对仓库路径，不是另一个 checkout；
- challenge 绑定的 Git HEAD、内容指纹和 `RUN_ID` 正是该路径的当前身份；
- 离线部署已完成，Docker/Caddy/ClamAV 和业务服务正在目标主机运行；
- Caddy `/data` 与内部 CA 没有在采集前被清理或替换；
- 没有启用 `set -x`、命令审计参数展开或会收集进程环境的调试代理；
- 当前目录及输出目录不允许非 root 用户篡改正式证据。

只要仓库内容在 challenge 签发后发生变化，就必须重新生成内容指纹并签发新 challenge，不能继续使用旧文件。

## 5. 正式采集命令

在待验收仓库根目录执行。下列参数名和输出位置是固定接口：

```bash
cd -- "$REPOSITORY"

RELEASE_ID="$(git -C "$REPOSITORY" rev-parse HEAD)"
OFFLINE_CONTRACT_SHA256='REPLACE_WITH_ACTIVE_CONTRACT_SHA256'
IMAGE_MANIFEST_SHA256='REPLACE_WITH_ACTIVE_IMAGE_MANIFEST_SHA256'
BASE_URL='https://knowledge.example.internal'

sudo -H /usr/bin/env -i \
  PATH=/usr/sbin:/usr/bin:/sbin:/bin \
  LANG=C.UTF-8 \
  /usr/bin/python3 -I scripts/linux_host_evidence_collector.py \
  --repository "$REPOSITORY" \
  --run-id "$RUN_ID" \
  --release-id "$RELEASE_ID" \
  --offline-contract-sha256 "$OFFLINE_CONTRACT_SHA256" \
  --image-manifest-sha256 "$IMAGE_MANIFEST_SHA256" \
  --base-url "$BASE_URL" \
  --signing-key "$SIGNING_KEY" \
  --challenge "$CHALLENGE" \
  --disk-path "$DISK_PATH"
RC=$?

case "$RC" in
  0)  echo '正式主机证据已原子发布' ;;
  2)  echo 'BLOCKED：探针或可信证据条件未满足' ;;
  64) echo 'CLI 使用错误：检查参数格式和绝对路径' ;;
  *)  echo '非预期失败：不得手工补写正式证据' ;;
esac
```

`RELEASE_ID` 必须是当前待验收仓库的 40 位 Git HEAD。`OFFLINE_CONTRACT_SHA256` 与
`IMAGE_MANIFEST_SHA256` 必须分别取自同一已提交 active release 的
`contract_sha256` 与 `manifest_sha256`；`BASE_URL` 必须是本次部署的规范 HTTPS origin。
四个值还必须与 challenge 的 deployment target 完全一致，禁止混用另一批发布、旧收据或
非规范 URL。

如果目标系统的 Python 不在 `/usr/bin/python3`，应由发布工程统一安装/固定解释器；不得临时从公网下载依赖，也不得用别名、可写 PATH 或未经审核的解释器替换正式运行时。

### 5.1 退出码

| 退出码 | 含义 | 允许的后续动作 |
| --- | --- | --- |
| `0` | 12 项检查全部由真实探针证明，签名完成，正式证据原子发布 | 进入独立验收器核验 |
| `2` | `BLOCKED`：探针失败、续期未发生、信任材料/目标绑定不满足或工件无法可靠生成 | 保留脱敏诊断，修复后用新 challenge 重采 |
| `64` | CLI 参数或调用方式错误 | 修正调用；不得改 collector 常量或输出文件 |

其他退出码视为运行时异常，同样不得放行。

### 5.2 原子发布与失败行为

成功时，collector 先完成所有探针、原始工件哈希和 Ed25519 签名，再以原子替换方式发布：

```text
artifacts/acceptance/functional/linux-host.json
```

正式文件必须是 root 所有、权限 `0400/0600` 的普通文件，不得为符号链接。任何一步失败时，collector 必须删除可能残留的正式文件，并只写入脱敏诊断：

```text
artifacts/acceptance/functional/linux-host.blocked.json
```

因此，历史 `linux-host.json` 的存在不能代表当前运行成功；退出码、文件身份、签名、challenge 状态及当前 target 必须由验收器共同复核。运维人员不得把 `.blocked.json` 改名为正式文件，也不得复用上一次正式证据。

成功后仅检查元数据，不要把整个 JSON 或原始工件转存到公共日志：

```bash
sudo stat -c '%U:%G %a %F %s %n' \
  "$REPOSITORY/artifacts/acceptance/functional/linux-host.json"
sudo sha256sum \
  "$REPOSITORY/artifacts/acceptance/functional/linux-host.json"
```

## 6. 独立验收核验

collector 的退出码为 0 只是“证据已生成”，不是最终放行。必须由正式验收器使用仓库外公钥信任存储和 challenge store 重新计算：

- 当前 Git HEAD 与内容指纹；
- `run_id` 和 challenge 的精确 target 绑定；
- 每个原始工件的相对路径、大小和 SHA-256；
- 12 项必需检查；
- canonical evidence digest 与 Ed25519 签名；
- 采集时间窗和 challenge 是否仍为 `issued`。

示例：

```bash
cd -- "$REPOSITORY"
sudo -H /usr/bin/env -i \
  PATH=/usr/sbin:/usr/bin:/sbin:/bin \
  LANG=C.UTF-8 \
  /usr/bin/python3 -m scripts.functional_acceptance \
  --profile runtime-functional \
  --run-tests \
  --trust-store /etc/heyi-acceptance/collector-public-keys.json \
  --challenge-store /var/lib/heyi-acceptance/challenges \
  --json
```

验收器成功后会原子消费对应 challenge。同一 challenge 的重复提交、旧工作树证据、工件替换、签名错误或证据超时都必须返回 `BLOCKED`。

## 7. 故障排查

| 现象 | 安全排查方向 | 禁止操作 |
| --- | --- | --- |
| 退出码 `64` | 检查全部必填参数是否齐全、路径是否绝对、`run_id` 是否符合 8–80 字符规则 | 修改脚本常量、通过软链接伪装路径 |
| key/challenge 权限错误 | 用 `stat` 检查 root 所有、普通文件、`0400/0600`；检查父目录是否在仓库外 | 放宽到 `0644/0666`、把私钥复制进仓库 |
| target/challenge 不匹配 | 确认 challenge 是在当前仓库内容冻结后签发，并绑定同一个 `RUN_ID` | 手改 challenge、回滚 target 字段、复用旧 challenge |
| `cpu_8`/`memory_16g` 失败 | 检查 VM 实际规格、cgroup 和 CPU affinity | 修改阈值或把宿主机总资源冒充进程可用资源 |
| 文件系统容量失败 | 确认 `--disk-path` 落在数据盘；扩容后检查分区和文件系统是否真正增长；清理需走备份/保留策略 | 指向无关大盘、删除未确认的数据 |
| `offline_images` 失败 | 使用签名离线发布包补齐正确 digest 和 `linux/amd64` 镜像，再运行项目固定验证流程 | 连接公网临时拉取、用 tag 代替 digest |
| `clamav_database` 失败 | 检查离线病毒库包、所有者/模式、有效期和 `clamd` health | 关闭恶意文件扫描或伪造健康状态 |
| readiness/business smoke 失败 | 检查服务 readiness、反向代理路由、内部 CA、SAN、DNS/hosts 和严格 HTTPS | 使用 `curl -k` 证明“可访问” |
| CA 持久化失败 | 核对 Caddy `/data` 持久挂载、CA 文件身份和本次探针前后稳定性；跨重建连续性需检查独立签名收据 | 把容器内临时文件复制出来冒充持久 CA |
| 自动管理失败 | 核对当前 Caddy 运行配置和证书自动化策略是否真实生效 | 只引用仓库中的 Caddyfile 文本 |
| `caddy_renewal_health` 失败 | 检查持久日志链、系统时间、Caddy 证书维护错误；若只是尚未发生续期则等待真实事件后重采 | 伪造日志、修改证书时间、把首次签发当续期 |
| 只生成 `.blocked.json` | 依据脱敏 failure code 修复根因；使用新 run/challenge 重试 | 改名、手写 `status=complete`、恢复旧正式证据 |
| 正式验收器拒绝证据 | 检查证据年龄、工作树是否变化、challenge 是否已消费、公钥是否登记正确 | 重新开放已消费 challenge 或篡改信任存储 |

若脱敏诊断不足以定位问题，应在受控终端重新运行单项官方运维探针，日志仍按敏感数据政策保存。不得启用会输出 `.env`、Compose 展开后的秘密、HTTP Authorization、Cookie、私钥、challenge nonce 或企业文档正文的调试模式。

## 8. 交付前核对表

- [ ] 目标为 Linux `amd64/x86_64`，collector 以 root 运行。
- [ ] 代码仓库已冻结；challenge 的 Git HEAD、内容指纹和 `run_id` 精确匹配。
- [ ] 私钥为仓库外 Ed25519 PKCS#8，`root:root 0400/0600`，从未进入 `.env`、镜像或日志。
- [ ] challenge 位于仓库外 `0700` 目录，文件为 `root:root 0400/0600`，从未消费或手改。
- [ ] 8 CPU、16G 规格内存、300 GB 文件系统和 240 GB 可用空间由真实探针证明。
- [ ] 离线镜像、ClamAV 数据库/health、readiness 和业务 smoke 全部由固定探针通过。
- [ ] Web、公共 API、对象存储均严格校验 CA/SAN，当前叶证书有效且剩余至少 1 小时。
- [ ] Caddy `/data`、内部 CA 和自动证书管理均由当前运行实例与持久状态证明。
- [ ] 已观察到 Caddy 真实续期成功事件；不是首次签发或“维护任务启动”。
- [ ] collector 退出码为 0，正式文件为 root-only 普通文件，未残留相互矛盾的 blocked/正式结论。
- [ ] 独立验收器已复算工件哈希、签名与 target，并成功消费 challenge。
- [ ] 全流程没有使用公网依赖、`--insecure`、人工 `passed`、手改证据或日志伪造。
