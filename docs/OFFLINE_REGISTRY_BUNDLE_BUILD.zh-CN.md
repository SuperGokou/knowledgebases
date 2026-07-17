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
- 镜像引用中的摘要是 Registry manifest digest，第二列是该 manifest 的 `config.digest`。构建器从临时 Registry 读取原始 manifest 与 config blob，分别复算内容摘要、描述符大小及 `linux/amd64` 平台；二者不得混用。Docker 29 的 containerd image store 可能把本机 `.Id` 暴露为 manifest digest，而旧 image store 通常把 `.Id` 暴露为 config digest，因此 `.Id` 只作为构建机本地保存和扫描的临时定位符，绝不写入签名清单冒充 config digest。
- `bundle.control` 只生成 `REGISTRY_BOOTSTRAP_IMAGE`、`REGISTRY_BOOTSTRAP_IMAGE_ID`、`RELEASE_SEQUENCE`、`RELEASE_ID`、`RELEASE_GIT_SHA`、`RELEASE_SCHEMA_HEAD`、`REGISTRY_UNPACKED_BYTES`、`REGISTRY_UNPACKED_INODES` 八个字段。
- 容量字段基于最终去重 manifest digest 集合生成一次 Docker image archive，并按其中唯一 layer path 逐层校验 DiffID、计算未压缩普通文件逻辑字节，同时统计 layer root、显式路径和隐式父目录 inode。共享层只计算一次；不允许使用压缩 Registry 目录大小或经验倍数代替。
- `release/` 在运行时从 canonical `offline_contract_files` 读取资产清单，逐文件复制已提交 HEAD 的原始字节，不缓存当前工作目录内容。
- bundle 内 `SHA256SUMS` 精确覆盖 `bundle.control`、`release.env`、`release.env.images` 以及 `release/`、`registry/`、`sbom/` 下每个普通文件；随后使用 OpenSSL SHA-256 签名。
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
$releaseId = '<release-id>'
$releaseSequence = '<canonical-release-sequence>'
$outputDirectory = Join-Path 'C:\release' "heyi-kb-$releaseId"

powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\build-offline-registry-bundle.ps1 `
  -DryRun `
  -OutputDirectory $outputDirectory `
  -SigningPrivateKey D:\release-keys\heyi-release-rsa.pem `
  -ImageSbomScanner D:\release-tools\syft.exe `
  -ImageSbomScannerSha256 <approved-lowercase-sha256> `
  -ReleaseSequence $releaseSequence `
  -ReleaseId $releaseId
```

成功输出必须包含 `DRY-RUN OK`、40 位 Git SHA、Schema head、合同资产数、固定镜像数以及 `platform=linux/amd64`。Dry Run 不拉取或构建镜像，因此还会明确输出 `REGISTRY_UNPACKED_BYTES=MEASURED_DURING_FORMAL_BUILD` 与 `REGISTRY_UNPACKED_INODES=MEASURED_DURING_FORMAL_BUILD`；这两个非数字状态只说明正式构建时才会实测，不会写入 bundle，也不会伪造容量。私钥路径不会出现在输出中。

## 构建正式制品

```powershell
$releaseId = '<release-id>'
$releaseSequence = '<canonical-release-sequence>'
$outputDirectory = Join-Path 'C:\release' "heyi-kb-$releaseId"

powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\build-offline-registry-bundle.ps1 `
  -OutputDirectory $outputDirectory `
  -SigningPrivateKey D:\release-keys\heyi-release-rsa.pem `
  -ImageSbomScanner D:\release-tools\syft.exe `
  -ImageSbomScannerSha256 <approved-lowercase-sha256> `
  -ReleaseSequence $releaseSequence `
  -ReleaseId $releaseId
```

`RELEASE_SEQUENCE` 必须是发布方管理的 canonical 十进制正整数：只能使用 `1-9` 开头的 1–18 位 ASCII 数字，不得带前导零，最大值为 `999999999999999999`；新发行必须大于目标服务器已接受的最高序号。`RELEASE_ID` 必须为 1–128 个字符，只允许 ASCII 字母、数字、点、下划线和连字符，并且首尾必须是字母或数字，因此 `.`、`..`、路径分隔符以及首尾标点均会被拒绝。相同 Release ID 不等于允许重放旧序号。运输或响应丢失后可以重试同一已签名 bundle：只有目标机最高状态、精确回执、固定信任根和九个本机镜像全部与本次 bundle 一致时，导入器才返回 `AUDITED_NOOP`；同序号但任一内容不同都会失败关闭。

正式构建完成镜像推送、精确拉回和 Compose 镜像合同核对后，构建器会对最终 manifest digest 集合去重，以当前 Docker 后端可寻址的本机内容 ID 执行一次 `docker image save`，同时要求 archive 中真实 config digest 集合与签名清单完全一致。测量器只读取本次临时 archive：它逐层验证压缩 blob 内容地址、解压后 tar 的 SHA-256 与镜像 config 中的 DiffID，再按唯一 layer path 汇总未压缩字节与 inode。两个结果必须是最多 18 位的正整数，写入 `bundle.control` 后由 `SHA256SUMS.sig` 覆盖。正式发布日志也会输出这两个数字，便于容量复核。目标导入器会在任何镜像 pull 前要求 DockerRootDir 同时容纳该签名上界、40 GiB 回滚空间和 inode 回滚储备。

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

必须区分三种身份和目录边界：

- `RELEASE_GIT_SHA` 是 40 位源码提交溯源，只证明构建来源，不是服务器目录名；
- 已签名 bundle 是运输制品，包含控制字段、两个发布环境文件、`release/` 控制面、`registry/` 镜像数据、`sbom/` 和签名清单；
- 安装、升级或接管入口创建的 canonical contract 还会加入服务器上的 `runtime.env`，其 64 位 contract SHA-256 是 `files.sha256` 的摘要。入口只把 contract 中的 `release/*` 物化到 `/srv/heyi-knowledgebases-offline/releases/<contract-sha256>`；该目录不包含 `runtime.env`、`release.env`、Registry 或 SBOM，不能把 bundle 整体复制进去，也不能用 Git SHA 或含义不明的“content SHA”代替 contract SHA。

## 传输前复核

在发布工作站上用已独立保存的公钥复核两组 checksum 签名：

```powershell
$releaseId = '<release-id>'
$release = Join-Path 'C:\release' "heyi-kb-$releaseId"
$artifactStem = "heyi-kb-$releaseId"
$publicKey = 'D:\release-keys\heyi-release-public.pem'

openssl dgst -sha256 -verify $publicKey `
  -signature "$release\$artifactStem-registry-bootstrap.tar.sha256.sig" `
  "$release\$artifactStem-registry-bootstrap.tar.sha256"
openssl dgst -sha256 -verify $publicKey `
  -signature "$release\$artifactStem-offline-registry-bundle.tar.sha256.sig" `
  "$release\$artifactStem-offline-registry-bundle.tar.sha256"
```

还必须按两个 `.sha256` 文件复核 tar 本身。运输介质、COS 或内网制品库只承担传输，不能替代签名校验。

## Linux 目标机导入顺序

以下命令是 Linux 目标机的 canonical 顺序：先固定并复核信任根，再对 Bootstrap tar 和主 bundle tar **分别**验证外层 `.sha256.sig`，随后使用 `sha256sum --check --strict` 验证 tar 本体；只有四项全部成功，才允许 `docker load`、解包和导入。`RELEASE_ID` 必须替换为本次已批准的发行号，不能从文件名猜测；六个运输文件必须先由 root 放入该发行专属目录。

固定发布公钥路径为 `/etc/heyi-release/trusted-release-public.pem`，当前批准的公钥文件 SHA-256 为 `a927ab4fdfe9febd10a5aeb5b78507ddfe7734e2fb46131524eaca00162967fa`。该指纹必须同时从独立 CMDB/密钥托管渠道复核，不能从制品目录、COS 或 `.sha256` 文件取得。公钥轮换必须走独立变更流程并同步更新本节；普通发行不得覆盖该文件。

```bash
RELEASE_ID='<release-id>'
EXPECTED_RELEASE_PUBLIC_KEY_SHA256='a927ab4fdfe9febd10a5aeb5b78507ddfe7734e2fb46131524eaca00162967fa'

sudo install -d -o root -g root -m 0700 \
  "/srv/heyi-knowledgebases-offline/artifacts/${RELEASE_ID}"

sudo env \
  RELEASE_ID="$RELEASE_ID" \
  EXPECTED_RELEASE_PUBLIC_KEY_SHA256="$EXPECTED_RELEASE_PUBLIC_KEY_SHA256" \
  /bin/sh -eu <<'VERIFY_AND_IMPORT'
fail() {
  printf 'release verification failed: %s\n' "$1" >&2
  exit 1
}

TRUSTED_RELEASE_PUBLIC_KEY=/etc/heyi-release/trusted-release-public.pem
ARTIFACT_DIR="/srv/heyi-knowledgebases-offline/artifacts/${RELEASE_ID}"
ARTIFACT_STEM="heyi-kb-${RELEASE_ID}"
BOOTSTRAP_TAR="${ARTIFACT_STEM}-registry-bootstrap.tar"
BUNDLE_TAR="${ARTIFACT_STEM}-offline-registry-bundle.tar"

[ -d "$ARTIFACT_DIR" ] || fail 'artifact directory is missing'
[ -f "$TRUSTED_RELEASE_PUBLIC_KEY" ] || fail 'trusted release public key is missing'
[ ! -L "$TRUSTED_RELEASE_PUBLIC_KEY" ] || fail 'trusted release public key is a symlink'
case "$(/usr/bin/stat -c '%U:%G:%a:%h:%F' -- "$TRUSTED_RELEASE_PUBLIC_KEY")" in
  'root:root:400:1:regular file'|'root:root:444:1:regular file') ;;
  *) fail 'trusted release public key metadata is unsafe' ;;
esac

actual_key_sha256=$(/usr/bin/sha256sum -- "$TRUSTED_RELEASE_PUBLIC_KEY")
actual_key_sha256=${actual_key_sha256%% *}
[ "$actual_key_sha256" = "$EXPECTED_RELEASE_PUBLIC_KEY_SHA256" ] || \
  fail 'trusted release public key SHA-256 does not match the independently approved fingerprint'

cd "$ARTIFACT_DIR"
for file in \
  "$BOOTSTRAP_TAR" "$BOOTSTRAP_TAR.sha256" "$BOOTSTRAP_TAR.sha256.sig" \
  "$BUNDLE_TAR" "$BUNDLE_TAR.sha256" "$BUNDLE_TAR.sha256.sig"
do
  [ -f "$file" ] && [ ! -L "$file" ] || fail "unsafe or missing artifact: $file"
done

# 两个外层签名必须先于任何 docker load、解包或导入验证。
/usr/bin/openssl dgst -sha256 -verify "$TRUSTED_RELEASE_PUBLIC_KEY" \
  -signature "$BOOTSTRAP_TAR.sha256.sig" "$BOOTSTRAP_TAR.sha256"
/usr/bin/sha256sum --check --strict -- "$BOOTSTRAP_TAR.sha256"

/usr/bin/openssl dgst -sha256 -verify "$TRUSTED_RELEASE_PUBLIC_KEY" \
  -signature "$BUNDLE_TAR.sha256.sig" "$BUNDLE_TAR.sha256"
/usr/bin/sha256sum --check --strict -- "$BUNDLE_TAR.sha256"

# 验签和 tar 摘要全部通过后才加载、解包并调用导入器。
[ ! -e offline-registry-bundle ] || fail 'bundle extraction directory already exists'
/usr/bin/docker load --input "$BOOTSTRAP_TAR"
/usr/bin/tar --extract --file "$BUNDLE_TAR" --directory "$ARTIFACT_DIR"

BUNDLE_ROOT="$ARTIFACT_DIR/offline-registry-bundle"
/bin/sh "$BUNDLE_ROOT/release/deploy/tencent/import-offline-registry-bundle.sh" \
  "$BUNDLE_ROOT" \
  "$TRUSTED_RELEASE_PUBLIC_KEY" \
  "$BUNDLE_ROOT/release.env"
VERIFY_AND_IMPORT
```

`import-offline-registry-bundle.sh` 只会再次验证主 bundle **内部**的 `SHA256SUMS.sig`、精确文件清单、八字段 control、四列镜像清单、签名容量上界、release 资产逐字节一致性和防降级序号；它不会验证两个运输 tar 的外层 `.sha256.sig`，也不会替代 Bootstrap tar 的外层验签。因此，跳过上面任一条 `openssl dgst` 或 `sha256sum --check --strict` 命令都属于 **FAIL / NO-GO**。

每次 pull 前，导入器从只读回环 Registry 读取 manifest/config 原始字节，复算两级摘要、config 大小和 `linux/amd64`；pull 后再校验精确 RepoDigest、平台以及兼容当前 Docker 后端的本机内容身份。任何一项不一致都必须视为发布失败，不能通过手工改写 `release.env`、容量字段或 digest 绕过。正常导入先持久化 Registry 回执和目录，再推进最高发行状态；因此 receipt→highest 或 highest→响应两个断电窗口都能通过原命令安全恢复。相同序号只允许完全一致的审计 no-op，不会创建临时 Registry 网络/容器或重新 pull。导入完成后，当前只允许从同一 bundle 的 `release/deploy/tencent/` 执行首次安装或 legacy adoption，并把 bundle 根的 `release.env` 作为参数；常规升级入口仅为合同占位，受 `active_upgrade` **NO-GO / fail-closed** 门禁约束，禁止执行。获准入口会自行创建 contract 和物化不可变 worker，不得预先手工创建 `/releases/<contract-sha256>`。
