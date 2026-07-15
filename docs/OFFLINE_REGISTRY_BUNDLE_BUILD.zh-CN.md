# Windows 离线 Registry 制品构建说明

本文说明如何在联网的 Windows 发布工作站上，从**干净且已提交的 Git HEAD** 构建只面向 `linux/amd64` 的企业离线制品。构建器为 [build-offline-registry-bundle.ps1](../scripts/build-offline-registry-bundle.ps1)。它不会读取工作区中的 `.env`，不会把发布私钥复制进临时目录、镜像、Registry 数据或输出文件。

## 发布边界

构建器执行以下强制门禁：

- 工作树（含未跟踪文件）必须完全干净；构建开始和发布前会再次核验 HEAD 与状态。
- 源码通过 `git archive HEAD` 冻结，Docker 上下文和 `release/` 合同资产只来自这个快照。
- 输出目录和签名私钥必须使用仓库外的绝对路径；输出目录必须尚不存在。
- API、Migration、Web 分别构建为 `linux/amd64` 镜像；Dockerfile 的基础镜像必须固定 SHA-256。
- `compose.offline.yml` 中所有基础镜像必须固定到回环 Registry 的 SHA-256；镜像复制到临时 `127.0.0.1` Registry 后，digest 只要发生变化就立即失败，绝不改写受信 digest。
- `release.env.images` 每行固定四列：精确镜像引用、config image ID、`linux`、`amd64`，使用 Tab 分隔。
- `bundle.control` 只生成 `REGISTRY_BOOTSTRAP_IMAGE`、`REGISTRY_BOOTSTRAP_IMAGE_ID`、`RELEASE_SEQUENCE`、`RELEASE_ID`、`RELEASE_GIT_SHA`、`RELEASE_SCHEMA_HEAD`、`REGISTRY_UNPACKED_BYTES`、`REGISTRY_UNPACKED_INODES` 八个字段。
- 容量字段基于最终去重 manifest digest 集合生成一次 Docker image archive，并按其中唯一 layer path 逐层校验 DiffID、计算未压缩普通文件逻辑字节，同时统计 layer root、显式路径和隐式父目录 inode。共享层只计算一次；不允许使用压缩 Registry 目录大小或经验倍数代替。
- `release/` 在运行时从 canonical `offline_contract_files` 读取资产清单，逐文件复制已提交 HEAD 的原始字节，不缓存当前工作目录内容。
- bundle 内 `SHA256SUMS` 精确覆盖 `bundle.control`、`release.env`、`release.env.images` 以及 `release/`、`registry/` 下每个普通文件；随后使用 OpenSSL SHA-256 签名。
- 采用排他锁、同卷临时目录和原子目录改名；失败时只清理本次随机 Run ID 所有的临时容器、网络和目录。

## 前置条件

- Windows PowerShell 5.1 或 PowerShell 7；
- Git、Docker Desktop、Docker Buildx、OpenSSL 3、Python 3 和 bsdtar 均可执行；
- Docker 使用 Linux 容器并可构建 `linux/amd64`；
- 仓库已提交且 `git status --porcelain=v1 --untracked-files=all` 无输出；
- 仓库外的 RSA 发布私钥，至少 3072 bit。RSA PKCS#1 v1.5 的 SHA-256 签名是确定性的，有利于同输入制品复核。

私钥示例（必须在仓库外执行并由企业密钥流程保护）：

```powershell
New-Item -ItemType Directory -Path D:\release-keys -Force | Out-Null
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 `
  -out D:\release-keys\heyi-release-rsa.pem
openssl pkey -in D:\release-keys\heyi-release-rsa.pem -pubout `
  -out D:\release-keys\heyi-release-public.pem
```

目标机只安装公钥；私钥不得上传到服务器、COS、Git、制品目录或 Registry。

## 先运行 Dry Run

Dry Run 会验证 Git、工具、私钥类型、Alembic head、Dockerfile 固定镜像、Compose 固定镜像和 canonical release 合同，不会 pull、build、push、sign 或发布制品：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\build-offline-registry-bundle.ps1 `
  -DryRun `
  -OutputDirectory C:\release\heyi-kb-2026.07.14 `
  -SigningPrivateKey D:\release-keys\heyi-release-rsa.pem `
  -ReleaseSequence 202607140001 `
  -ReleaseId 2026.07.14
```

成功输出必须包含 `DRY-RUN OK`、40 位 Git SHA、Schema head、合同资产数、固定镜像数以及 `platform=linux/amd64`。Dry Run 不拉取或构建镜像，因此还会明确输出 `REGISTRY_UNPACKED_BYTES=MEASURED_DURING_FORMAL_BUILD` 与 `REGISTRY_UNPACKED_INODES=MEASURED_DURING_FORMAL_BUILD`；这两个非数字状态只说明正式构建时才会实测，不会写入 bundle，也不会伪造容量。私钥路径不会出现在输出中。

## 构建正式制品

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\build-offline-registry-bundle.ps1 `
  -OutputDirectory C:\release\heyi-kb-2026.07.14 `
  -SigningPrivateKey D:\release-keys\heyi-release-rsa.pem `
  -ReleaseSequence 202607140001 `
  -ReleaseId 2026.07.14
```

`RELEASE_SEQUENCE` 必须是发布方管理的单调递增正整数，最多 18 位，且大于目标服务器已接受的最高序号。相同 Release ID 不等于允许重放旧序号。

正式构建完成镜像推送、精确拉回和 Compose 镜像合同核对后，构建器会对最终 manifest digest 集合去重，并对对应 config ID 集合执行一次 `docker image save`。测量器只读取本次临时 archive：它要求 archive config 集合与最终镜像集合完全一致，逐层验证未压缩 tar 的 SHA-256 等于镜像 config 中的 DiffID，再按唯一 layer path 汇总未压缩字节与 inode。两个结果必须是最多 18 位的正整数，写入 `bundle.control` 后由 `SHA256SUMS.sig` 覆盖。正式发布日志也会输出这两个数字，便于容量复核。目标导入器会在任何镜像 pull 前要求 DockerRootDir 同时容纳该签名上界、40 GiB 回滚空间和 inode 回滚储备。

默认 Bootstrap Registry 源固定为官方 `registry:2.8.3` 的 `linux/amd64` manifest digest。需要变更时必须显式传入同版本、同平台并已审查的精确引用：

```powershell
-RegistryBootstrapSource docker.io/library/registry:2.8.3@sha256:<64位小写摘要>
```

输出目录只包含两组独立运输制品：

```text
heyi-kb-<release-id>-offline-registry-bundle.tar
heyi-kb-<release-id>-offline-registry-bundle.tar.sha256
heyi-kb-<release-id>-offline-registry-bundle.tar.sha256.sig
heyi-kb-<release-id>-registry-bootstrap.tar
heyi-kb-<release-id>-registry-bootstrap.tar.sha256
heyi-kb-<release-id>-registry-bootstrap.tar.sha256.sig
```

Bootstrap tar 独立于 Registry bundle；先验签、再 `docker load`。主 bundle 是可由 Linux root 解压的 POSIX PAX tar，归档内 owner/group 固定为 `root:root`，目录模式为 `0750`、文件模式为 `0444`，mtime 固定为 Git commit timestamp。

## 传输前复核

在发布工作站上用已独立保存的公钥复核两组 checksum 签名：

```powershell
$release = 'C:\release\heyi-kb-2026.07.14'
$publicKey = 'D:\release-keys\heyi-release-public.pem'

openssl dgst -sha256 -verify $publicKey `
  -signature "$release\heyi-kb-2026.07.14-registry-bootstrap.tar.sha256.sig" `
  "$release\heyi-kb-2026.07.14-registry-bootstrap.tar.sha256"
openssl dgst -sha256 -verify $publicKey `
  -signature "$release\heyi-kb-2026.07.14-offline-registry-bundle.tar.sha256.sig" `
  "$release\heyi-kb-2026.07.14-offline-registry-bundle.tar.sha256"
```

还必须按两个 `.sha256` 文件复核 tar 本身。运输介质、COS 或内网制品库只承担传输，不能替代签名校验。

## Linux 目标机导入顺序

以下命令只展示制品边界；实际目录必须纳入 root-only 发布流程：

```bash
sudo install -d -o root -g root -m 0700 /srv/heyi-knowledgebases-offline/artifacts
cd /srv/heyi-knowledgebases-offline/artifacts

# 1. 使用受信公钥验证两个 checksum 签名及 tar SHA-256。
# 2. 先加载独立 Bootstrap Registry 镜像。
sudo docker load --input heyi-kb-<release-id>-registry-bootstrap.tar

# 3. 解压主 bundle；PAX tar 可由 Linux root 正确恢复数值 owner/mode。
sudo tar --extract --file heyi-kb-<release-id>-offline-registry-bundle.tar

# 4. 继续执行部署文档中的 import-offline-registry-bundle.sh。
```

导入器会再次验证 bundle 内 `SHA256SUMS.sig`、精确文件清单、八字段 control、四列镜像清单、签名容量上界、release 资产逐字节一致性、`linux/amd64`、config ID、RepoDigest 和防降级序号。任何一项不一致都必须视为发布失败，不能通过手工改写 `release.env`、容量字段或 digest 绕过。
