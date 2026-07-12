# 依赖、许可证与 SBOM 审计

> 审计日期：2026-07-12
>
> 审计结论：**FAIL / 法务阻断**
>
> 适用范围：Web 生产依赖、Python 生产依赖和项目根包
>
> 声明：本文是工程审计证据，不是法律意见或不侵权保证。

## 执行摘要

两份 CycloneDX 1.6 JSON SBOM 均已生成并通过生成器的 Schema 校验，锁定的 Web 与 Python 生产依赖也已用独立许可证工具盘点。审计发现 LGPL、MPL 和 CC-BY 组件，并且项目根包没有选定许可证：Web 根包被工具标记为 `UNLICENSED`，Python 根组件的 SBOM `licenses` 为空。

因此不能声称“零版权风险”，也不能在当前证据下签署商业发布通过。发布前必须由权利人和法务完成项目许可策略、权属确认、第三方通知与高关注许可义务复核。

## 可复现输入

| 输入 | SHA-256 |
|---|---|
| `web/package.json` | `4BCAF1307F305A42EE2ED01290946410635E1D5726F1EA3245C59DDF01161BBA` |
| `web/package-lock.json` | `3DCD055EEBCD015434DF5D053488A8B5B1F297B5A6E9193E528A466E3D17A34B` |
| `pyproject.toml` | `13686ACA1BBC827EF30C456979518B88FAA990E6908DBF85E6E8781027E478E2` |
| `uv.lock` | `8F4AB2455F848BCC077E36089DC5A738EA329AF314E3F63A6D24A6D449EAC488` |

如果任一输入哈希改变，本报告的包数、许可证结论和 SBOM 哈希必须重新生成，不得沿用。

## 工具与命令

| 工具 | 版本 | 用途 |
|---|---:|---|
| Node.js | 24.15.0 | Web 工具运行时 |
| npm | 11.14.0 | 锁文件解析 |
| `license-checker` | 25.0.1 | Web 已安装生产树许可证盘点 |
| `@cyclonedx/cyclonedx-npm` | 6.0.0 | Web CycloneDX SBOM |
| Python | 3.12.13 | Python 生产扫描环境 |
| uv | 0.11.15 | 从 `uv.lock` 导出与同步生产环境 |
| `pip-licenses` | 5.5.5 | Python 生产环境许可证盘点 |
| `cyclonedx-bom` / `cyclonedx-py` | 7.3.0 | Python CycloneDX SBOM |

扫描工具通过 npm/uv 的隔离工具缓存运行，未写入 `package.json`、`pyproject.toml` 或两份锁文件。Python 许可证扫描使用一个临时虚拟环境，该环境只同步 `uv export --no-dev --no-emit-project` 的生产包，避免把 Ruff、mypy 或 pytest 等开发工具计入生产结论。

```powershell
uv export --frozen --no-dev --no-emit-project --no-hashes `
  --format requirements-txt --output-file $env:TEMP\kb-production-requirements.txt

uv pip sync --python $env:TEMP\kb-license-runtime-20260712\Scripts\python.exe `
  $env:TEMP\kb-production-requirements.txt

uvx --from pip-licenses==5.5.5 pip-licenses `
  --python $env:TEMP\kb-license-runtime-20260712\Scripts\python.exe `
  --from mixed --format json --with-authors --with-urls

npx --yes license-checker@25.0.1 --production --json --start web

npx --yes @cyclonedx/cyclonedx-npm@6.0.0 `
  --package-lock-only --omit dev --spec-version 1.6 `
  --output-reproducible --output-format JSON --validate `
  --output-file artifacts/acceptance/sbom-web.cdx.json web/package.json

uvx --from cyclonedx-bom==7.3.0 cyclonedx-py environment `
  $env:TEMP\kb-license-runtime-20260712\Scripts\python.exe `
  --pyproject pyproject.toml --spec-version 1.6 `
  --output-reproducible --output-format JSON --validate `
  --output-file artifacts/acceptance/sbom-python.cdx.json
```

## SBOM 产物

| 产物 | 格式 | 组件 | 依赖节点 | SHA-256 |
|---|---|---:|---:|---|
| `artifacts/acceptance/sbom-web.cdx.json` | CycloneDX JSON 1.6 | 54 | 57 | `A90A51571435CA05986F976F9CAAADF2F5CF8F3435534D485272D7EFC0DEC5DF` |
| `artifacts/acceptance/sbom-python.cdx.json` | CycloneDX JSON 1.6 | 52 | 53 | `6895E628CDE5244D3654749A9DC631C98E62139C92D928A034ABD84D164D97C9` |

Web SBOM 按锁文件生成，包含 npm 用于跨平台分发的 optional 二进制组件；它的 54 个组件不等于 Windows 开发机或 Linux 运行镜像实际加载的包数。最终容器仍须对构建好的 Linux 镜像生成 image SBOM，并与本锁文件 SBOM 对账。

## Web 生产依赖结果

`license-checker --production` 在当前已安装树中报告 25 个包。许可证分布如下：

| 许可证 | 包数 |
|---|---:|
| MIT | 11 |
| Apache-2.0 | 7 |
| ISC | 2 |
| Apache-2.0 AND LGPL-3.0-or-later | 1 |
| CC-BY-4.0 | 1 |
| BSD-3-Clause | 1 |
| 0BSD | 1 |
| UNLICENSED | 1 |

高关注项：

- `enterprise-knowledge-base-web@0.1.0` 被报告为 `UNLICENSED`。`private: true` 只阻止意外 npm 发布，不是项目许可证。
- `@img/sharp-win32-x64@0.34.5` 报告 `Apache-2.0 AND LGPL-3.0-or-later`；锁文件 SBOM 还包含 Linux 等目标平台的 `sharp-libvips` LGPL 组件。实际 Linux 发布必须以镜像中被选中的二进制为准复核义务。
- `caniuse-lite@1.0.30001803` 使用 CC-BY-4.0，对外分发时需保留合理归属、许可证链接和修改声明。

## Python 生产依赖结果

临时生产虚拟环境安装并扫描 52 个包。许可证分布如下：

| 许可证标识 | 包数 |
|---|---:|
| MIT / MIT License | 24 |
| BSD-3-Clause / BSD License | 11 |
| Apache-2.0 | 5 |
| LGPL-3.0-only | 2 |
| MPL-2.0 | 1 |
| MIT-0 | 1 |
| Apache-2.0 OR BSD-3-Clause | 1 |
| Python Software Foundation License | 1 |
| ISC | 1 |
| Unlicense | 1 |
| MIT AND PSF-2.0 | 1 |
| Apache/BSD 元数据组合 | 2 |
| PSF-2.0 | 1 |

高关注项：

- `psycopg==3.3.4` 和 `psycopg-binary==3.3.4` 元数据标识为 `LGPL-3.0-only`。
- `certifi==2026.6.17` 元数据标识为 `MPL-2.0`。
- `pyproject.toml` 没有 `license`/`license-files` 声明，因而 Python SBOM 根组件没有许可证信息。这是项目自身的法务阻断，不是第三方包的问题。

本轮元数据扫描未报告 AGPL、GPL、SSPL 或 BUSL；这只是对当前锁定依赖元数据的描述，不是对源码文件、镜像 OS 包或云服务条款的全面不存在证明。

## 发布阻断与整改

| ID | 级别 | 现状 | 放行证据 |
|---|---|---|---|
| LIC-P0-001 | P0 | 项目根包未选定许可证，权利人与对外授权范围不明 | 公司签字的权属确认；法务批准的专有许可或开源许可；仓库中的最终 `LICENSE` |
| LIC-P0-002 | P0 | LGPL/MPL/CC-BY 履约尚未由法务复核 | 面向实际发布媒介的义务矩阵、完整许可文本、归属和修改记录 |
| LIC-P0-003 | P0 | 不存在经签字的商标、Logo 和设计素材授权证明 | 见 `ASSET_PROVENANCE.zh-CN.md`；所有待签项转为已核验 |
| LIC-P1-001 | P1 | SBOM 仅覆盖 npm/Python 应用依赖 | 生产镜像 Syft/CycloneDX SBOM，覆盖 Debian/Alpine 包与内嵌二进制 |
| LIC-P1-002 | P1 | CI 没有许可策略门禁 | 锁文件改变时自动生成 SBOM，对未知、禁止和高关注许可阻断合并 |

## 局限性

- `license-checker` 和 `pip-licenses` 主要依赖上游元数据；元数据错误、双重许可或文件级例外可能被遗漏。
- 本轮未对所有上游源码逐文件检查 SPDX Header，也未请法务解释联合许可表达式。
- SBOM 未覆盖 PostgreSQL、Redis、MinIO、Caddy 镜像内的 OS 包，也未覆盖 DeepSeek、Qwen、MiniMax 等 API 商业条款。
- 软件许可证扫描不能证明 Logo、截图、文案、数据集或模型输出的权属。
- 当前 `THIRD-PARTY-NOTICES.md` 是工程盘点草案，不代替随产品发布的完整许可文本集。

## 结论

依赖定版与 SBOM 生成已有可复核证据，但法务授权链尚未闭环。当前只能签署 **FAIL / NO-GO**；不得对客户宣称“零版权风险”、“全部自有”或“无 Copyleft 义务”。
