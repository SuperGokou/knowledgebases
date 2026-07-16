# 文档解析能力与安全边界

本页描述 OKF 转换前的文档解析门禁。“允许上传”不等于“能解析”；每个文件只有在当前运行环境通过能力检查并完成有界解析后，才能进入 OKF 编译。

## 能力矩阵

| 格式 | 实现 | 安全策略 | 当前代码状态 |
| --- | --- | --- | --- |
| TXT | 内置 UTF-8 解码 | BOM 兼容、字节/字符上限、空文档拒绝 | PASS |
| CSV | 内置 UTF-8 解码 | 与 TXT 相同，附加 `row:n` 来源定位 | PASS |
| DOCX | ZIP + defusedxml | 拒绝宏、嵌入对象、外部关系、加密包、路径穿越和 Zip Bomb；保留段落/表格定位 | PASS |
| XLSX | ZIP + defusedxml | 与 DOCX 相同，不执行公式；保留 `worksheet:name!cell` 定位 | PASS |
| PPTX | ZIP + defusedxml | 与 DOCX 相同，按 presentation 关系顺序解析；保留 `slide:n` 定位 | PASS |
| PDF | Poppler `pdftotext` | 拒绝加密、JavaScript、Launch、嵌入文件、URI 等主动内容；bubblewrap 断网沙箱与 CPU/内存/输出/超时限制；保留 `page:n` 定位 | 环境能力门：未安装即 BLOCKED |
| DOC/XLS/PPT | LibreOffice 转换到 OOXML | OLE 签名与扩展名错配检查；独立临时 profile；bubblewrap 断网沙箱、safe-mode 与资源限制；转换后再执行 OOXML 安全检查 | 环境能力门：未安装即 BLOCKED |

## 部署门禁

目标“其他云 Linux 8C16G300G”镜像必须使用经审批且固定 digest 的镜像构建，包含 root 所有、不可由 group/other 写入的：

- `/usr/bin/bwrap`；
- `/usr/bin/prlimit`；
- `/usr/bin/pdftotext`；
- `/usr/bin/libreoffice`。

验证内建格式：

```bash
python -m app.document_parser_preflight --require .txt .csv .docx .xlsx .pptx
```

在声称全格式支持前必须通过：

```bash
python -m app.document_parser_preflight --require-all
```

命令以 JSON 输出能力矩阵。任一必需能力缺失时返回码为 `2`，部署流程必须停止；Windows 开发机通常会因缺少这些 Linux 隔离工具得到 `BLOCKED`，这是正确结果。不得通过 PATH 查找、可写可执行文件或跳过沙箱来伪造通过。CI 安装同类系统工具后执行该门禁；离线部署则在已经过 RepoDigest 校验的 API 镜像内部执行。

## 资源边界

默认 OKF 源文件上限由 `KB_OKF_SOURCE_MAX_BYTES` 约束。压缩包额外限制条目数、单条目大小、总展开大小、压缩比和页/工作表/幻灯片数。外部解析器使用清空的环境变量、禁用 shell、断网 namespace，并设置 CPU、地址空间、输出文件、文件描述符和 wall-clock 上限。
