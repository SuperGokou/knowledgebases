# GAP-P0-006/007 修复与复验记录

> 日期：2026-07-13
> 范围：目标主机 SSD/IO 证据与存储水位真实链路证据
> 边界：未读取 `.env`、未联网、未连接或部署目标主机

## 修复结论

- GAP-P0-007 的旧容量检查已收紧：Linux 规格、目标挂载/块设备身份、SSD 证明和四类有界 fio 必须同时满足才可通过。
- GAP-P0-006 的 100 字节内存纯函数“边界验证”已移除：必须提交专用可销毁卷的 25 个真实 API 场景、原始产物 SHA-256、quota 回滚、对象/Multipart 无泄漏以及文件系统/MinIO 双向核对。
- 证据缺失统一为 `BLOCKED`；证据存在但 HDD、fio 不达标、场景缺失、哈希错误或发生泄漏统一为 `FAIL`。

## TDD 记录

1. RED：先增加新证据类型和缺证据/HDD/fio 不达标/对象泄漏测试，旧实现于测试收集阶段失败，无法导入新契约。
2. GREEN：实现收紧后的验收逻辑、安全 fio 采集器和水位证据加载器。
3. REFACTOR：增加相对路径限制、非符号链接与文件大小限制、原始产物 SHA-256、raw/manifest 交叉核对和严格 JSON 布尔类型。

复验命令与结果：

```text
python -m pytest -q tests/test_host_preflight.py tests/test_host_io_evidence.py tests/test_storage_watermark_preflight.py tests/test_acceptance_runner.py
46 passed

ruff check <本次脚本与直接测试>
All checks passed

mypy --strict scripts/host_preflight.py
mypy --strict scripts/collect_host_io_evidence.py
mypy --strict scripts/storage_watermark_preflight.py
三项均 Success: no issues found

git diff --check -- <本次文件>
PASS
```

## 当前运行态判定

当前工作机不是目标 Linux 服务器，也没有专用可销毁验收卷。实跑两个门禁均输出 `schema_version=2`、`status=blocked`：

- 主机：缺目标 Linux 块设备/SSD/fio 证据；
- 存储：缺目标 Linux 专用卷及 25 场景真实链路证据。

因此这里只能确认代码级修复与测试通过，不能签署目标主机或存储运行态 PASS。待提供 Linux 8 vCPU/16 GB/300 GB SSD 主机后，必须按 `docs/HOST_STORAGE_ACCEPTANCE.zh-CN.md` 采集并复验。
