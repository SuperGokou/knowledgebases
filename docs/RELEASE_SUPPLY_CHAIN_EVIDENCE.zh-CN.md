# 离线发布供应链证据

正式离线制品的技术证据链由构建器、镜像 SBOM 生成器、供应链门禁和 Linux 导入器共同完成。任何单独的扫描报告都不能替代这一闭环。

## 构建输入

构建器除发布私钥外，必须显式接收仓库外的 Syft 可执行文件及其经审批的 64 位小写 SHA-256：

```powershell
-ImageSbomScanner D:\release-tools\syft.exe `
-ImageSbomScannerSha256 <approved-lowercase-sha256>
```

路径必须是绝对路径、不得位于 Git 仓库内、不得经过符号链接或重解析点，文件摘要不匹配时构建立即失败。构建器不下载扫描器，也不会启用扫描器的更新检查或代理环境变量。

## 签名覆盖范围

最终 `release.env.images` 必须精确包含 9 个 `linux/amd64` 镜像。构建器在生成 `SHA256SUMS` 前，为每个最终 manifest digest 生成一个确定化 CycloneDX 1.6 JSON，并写入：

```text
sbom/image-<manifest-digest>.cdx.json
sbom/image-sbom-index.json
```

索引绑定 clean Git HEAD、Release ID、`release.env.images` 摘要、扫描器摘要、镜像 manifest digest 和 config ID。`sbom/` 下全部文件与 `release/`、`registry/`、control 文件一起进入精确 `SHA256SUMS`，再由发布私钥签名；因此不能在签名后替换、增加或删除 SBOM。

Linux 导入器会先验证 `SHA256SUMS.sig` 和每个对象摘要，再要求索引与 9 行镜像清单、`bundle.control` 的 Git SHA/Release ID 以及每个 SBOM 摘要一致。缺失、重复、额外、路径漂移或摘要漂移均阻断导入。

## 法务与权利边界

技术制品成功不等于可正式发布。正式发布还必须执行：

```bash
python scripts/supply_chain_gate.py \
  --mode release \
  --repo <clean-source-root> \
  --artifact-root <verified-bundle-root> \
  --attestation <approved-release-rights.json> \
  --expected-release-id <40-character-clean-git-head>
```

`compliance/release-rights.template.json` 只是待签模板。状态为 `pending`、占位内容、缺少项目许可证、人工许可证审查、素材权利、第三方声明、权利人或法务签署证据时，门禁必须保持 `FAIL`；工程流程不得代替权利人或法务填写、批准或伪造证明。

当前仓库模板仍未获得上述人工批准，因此只能形成可验证的技术 bundle，不能宣称 `release_eligible=true`。
