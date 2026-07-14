# GAP-P0-005/006/007/008 Final 接线修复记录

日期：2026-07-13
范围：最终验收编排层，不代表目标 Linux 主机已经通过运行时验收。

## 已关闭的误通过路径

| Gap | Final 接线控制 | 缺少目标证据时的结果 |
|---|---|---|
| GAP-P0-005 | `E2E-P0-001` 固定 enterprise Profile；进程退出 0 后仍须以受信公钥和一次性 challenge 验签 `EXT-BROWSER-E2E-001`，并原子消费 challenge；普通断言失败仍为 failed | blocked |
| GAP-P0-006 | `STORAGE-WATERMARK-P0-001` 使用 `python -m scripts.storage_watermark_preflight` 并传递 `--chain-evidence` | blocked |
| GAP-P0-007 | `HOST-P0-001` 使用 `python -m scripts.host_preflight` 并传递 `--io-evidence` | blocked |
| GAP-P0-008 | `OFFLINE-P0-001` 执行 root 离线环境预检；`OFFLINE-IMAGES-P0-001` 独立执行固定镜像 RepoDigest 校验；`OFFLINE-RUNTIME-P0-001` 验签真实断网冷启动、业务闭环、持久化和网络恢复证据 | blocked |

目标证据路径必须在 Final CLI 显式给出为 Linux 绝对路径。执行前统一拒绝缺失文件、符号链接和非普通文件；验收器不会读取开发机 `.env` 自动寻找证据或凭据。主机与存储验证器继续负责核对数据盘、SSD/fio、可销毁卷、25 个真实 API 水位场景和原始工件哈希。离线运行态验证器额外拒绝 Windows、test-only/fake runner、非 `passed`、超过 24 小时、Git/内容/当前启动主机指纹不匹配、检查集合不完整、原始工件字节数或 SHA-256 不符以及 attestation 错误。

## TDD 与静态门禁

```text
uv run pytest -q tests/test_acceptance_runner.py
27 passed

uv run ruff check scripts/acceptance.py tests/test_acceptance_runner.py
All checks passed!

uv run mypy scripts/acceptance.py
Success: no issues found in 1 source file

git diff --check -- <本次文件集合>
通过
```

新增回归精确覆盖：缺少/符号链接证据不得启动命令、enterprise 拓扑缺失必须 blocked、真实 E2E 失败不得降格为 blocked、E2E 进程退出 0 但没有可信签名不得通过、SHA-only 永不接受、真实 Ed25519 正向验签首次通过且 replay 阻断、Final 不提供显式目标证据时六个相关 P0 gate 均在执行前 blocked，以及离线运行态证据的 Windows、fake/test-only、非 passed、指纹错误和工件篡改路径。

## 尚未获得的外部证据

当前开发机不是最终 Linux 8 vCPU / 16 GB / 300 GB SSD 主机，因此本记录不声明以下项目通过：真实 enterprise 浏览器链、目标 SSD/fio、真实存储水位链、root 离线预检、断网冷启动及镜像 RepoDigest。取得 SSH 信息后必须在目标主机用唯一 `--profile final` 命令重新采集和验签。
