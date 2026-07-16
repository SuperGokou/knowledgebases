# 九格式文档验收样本

`FORMAT-P0-001` 使用一组完全合成、可内容寻址的黄金样本验证 `.txt`、`.csv`、`.doc`、`.docx`、`.xls`、`.xlsx`、`.pdf`、`.ppt`、`.pptx`。样本正文为本项目原创测试数据，清单声明 `CC0-1.0`，不得混入客户文件、第三方模板、演示文稿素材或生产数据。

## 安全边界

- 生成器默认只输出计划，不联网，不读取 `.env`，也不访问验收根目录之外的文件。
- TXT、CSV、DOCX、XLSX、PPTX、PDF 使用 Python 标准库确定性生成。
- DOC、XLS、PPT 只能在目标 Linux 上由固定路径 `/usr/bin/libreoffice` 生成；LibreOffice、`bwrap` 与 `prlimit` 必须是 root 所有、非组/全局可写的普通可执行文件。
- 旧版 Office 转换运行在 `bwrap --unshare-all` 隔离环境中。缺少任一工具、生成物不是 OLE 文件、样本缺失、哈希不符、符号链接或占位内容时，命令以退出码 `2` 返回 `BLOCKED`。
- 正式 Playwright 企业档案必须显式提供样本根目录和清单路径；不允许回退到仓库内的单个 TXT 示例。

## 目标 Linux 生成与验证

以下路径必须是专用、可清理的验收目录，不得指向业务上传目录：

```bash
python -m scripts.generate_document_acceptance_fixtures plan \
  --root /var/lib/knowledge-base/acceptance/document-fixtures

python -m scripts.generate_document_acceptance_fixtures generate \
  --root /var/lib/knowledge-base/acceptance/document-fixtures

python -m scripts.generate_document_acceptance_fixtures verify \
  --root /var/lib/knowledge-base/acceptance/document-fixtures \
  --manifest /var/lib/knowledge-base/acceptance/document-fixtures/document-fixtures-v1.json
```

企业 E2E 仅通过进程环境显式接收路径：

```bash
export KB_E2E_DOCUMENT_FIXTURE_ROOT=/var/lib/knowledge-base/acceptance/document-fixtures
export KB_E2E_DOCUMENT_FIXTURE_MANIFEST=/var/lib/knowledge-base/acceptance/document-fixtures/document-fixtures-v1.json
export KB_E2E_PROFILE=enterprise
npm --prefix web run test:e2e
```

清单契约见 [`schemas/document-acceptance-fixtures-v1.schema.json`](./schemas/document-acceptance-fixtures-v1.schema.json)。每个条目包含唯一检索 token、预期来源定位、字节数与 SHA-256。

## 通过条件

桌面与移动项目都必须对九个真实文件逐一完成：上传、恶意软件扫描为 `clean`、OKF 转换成功、审批、知识检索命中同一 `source_file_id`、聊天返回绑定该文件的 citation，并从引用条目元数据中核对预期 `source_locations`。任何格式失败或工具缺失均使 `EXT-BROWSER-E2E-001` 保持 `BLOCKED/FAILED`；本地 `--list` 或单元测试不能替代目标 Linux 上的真实闭环。
