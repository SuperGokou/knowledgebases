# Design QA — Prism Lab

- **日期：** 2026-07-10
- **结果：** BLOCKED
- **实现：** [生产演示](https://knowledgebases.vercel.app)
- **参考：** Product Design 方案三「棱镜实验台 / Prism Lab」
- **Source visual truth：** [`docs/assets/design-qa/prism-reference.png`](docs/assets/design-qa/prism-reference.png)
- **Implementation screenshot：** [`docs/assets/design-qa/prism-implementation.png`](docs/assets/design-qa/prism-implementation.png)
- **Combined comparison：** [`docs/assets/design-qa/prism-comparison.png`](docs/assets/design-qa/prism-comparison.png)
- **Mobile focused capture：** [`docs/assets/design-qa/prism-mobile.png`](docs/assets/design-qa/prism-mobile.png)

## 对比基线

- 参考图与生产实现以相同的 `1488 × 1058` 桌面视口合并对比；
- 手机端使用 `390 × 844` 视口独立验收；
- 默认主题为 Prism Lab，并验证切换到 Obsidian 后刷新仍能保持，再切回 Prism Lab；
- 使用真实 EFD Logo、江苏和熠光显有限公司名称和现有图标库，没有占位品牌资产。

## 视觉验收

- 空状态下的顶部品牌区、窄侧边栏、珍珠白画布、红色强调色、光谱问候区和悬浮输入区与参考方向一致；
- 字号、字重、留白、圆角、边框与状态色在桌面和手机端保持协调；
- 手机端没有横向溢出，输入框底部高于固定导航栏，没有遮挡；
- 空知识库状态使用真实生产数据，不为了匹配参考图伪造对话；来源选择和独立来源摘录预览已实现，但尚未在生产真实 citation 状态下完成视觉验证。

## Comparison history

| 严重度 | 首轮差异 | 修复 | 修复后证据 | 状态 |
|---|---|---|---|---|
| P1 | 缺少来源选择与右侧摘录区 | 增加可选择 citation 卡片与独立来源摘录预览 | 组件代码、113 个前端测试与生产构建通过 | 待真实回答截图验证 |
| P1 | 小屏输入区可能被底部导航遮挡 | 改为 `100dvh`，扣除顶部与 61px 移动导航并加入 safe area | `390 × 844` focused capture；输入区底部不超过导航顶部 | 已修复 |
| P2 | Prism 问候区缺少参考图光谱氛围 | 增加青紫柔光背景与红色品牌强调 | 同视口 combined comparison | 已修复 |
| P2 | 主题入口与持久化缺失 | 增加三主题选择、白名单、本地持久化与启动脚本 | 切换 Obsidian、刷新保持、恢复 Prism | 已修复 |

## 交互验收

- 单一登录页可正常登录，服务端 RBAC 将超级管理员自动落到 `/admin`；
- 退出登录会清除会话并返回 `/login`；
- 主题选择可键盘操作，并通过白名单与本地持久化保存；
- 管理导航、知识问答入口、知识库/文件/账号/角色/API 与模型入口均可访问；
- 生产演示库已通过 API 返回 2 条 citation、`grounded` 状态和答案来源尾注；
- 生产浏览器控制台错误数为 `0`。

## 工程验收

- Python Ruff、Pytest、Alembic 离线 SQL；
- TypeScript、ESLint、Vitest、Next.js production build；
- Vercel Web/API 生产部署和健康检查；
- 桌面/手机视觉回归、登录/退出与主题持久化回归。

## Blocker

参考图展示的是「完整回答 + 多条来源 + 右侧内容」状态，而当前已归档的生产截图仍是无知识库空状态。演示库现已创建，API 也已返回 2 条真实 citation，但三栏比例、回答排版、来源选择、摘录预览与滚动行为尚未在同一真实状态下合并对比，不能宣称整体视觉已通过。

下一轮以现有演示库在 `1488 × 1058` 补充「回答—来源卡片—来源摘录」完整截图与 focused comparison，即可重新判定最终结果。

**final result: blocked**
