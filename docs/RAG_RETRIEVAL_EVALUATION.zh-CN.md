# 中文 RAG 检索质量门禁

本文定义企业知识库发布前必须执行的确定性检索评测。它只评价授权检索结果，
不调用模型、不评价聊天生成，也不会读取真实企业资料。

## 数据集与版权边界

- 数据集版本：`heyi-synthetic-zh-rag-v1`。
- 全部文本由本项目为自动化测试原创生成，不复制公开文章、客户文件、个人资料或第三方题库。
- 共 120 条中文用例：90 条可回答问句（含“合同 / 报价 / 权限”两字精确检索）、15 条无答案问句、15 条 ACL 隔离问句。
- 共 45 条确定性知识条目：30 条位于授权库，15 条位于隔离库。
- 数据集内容通过 SHA-256 指纹绑定；任何条目、问句或相关性标签变化都必须显式更新基线并重新评审。

评测实现位于 `scripts/rag_retrieval_evaluation.py`。正式测试直接调用
`app/api/v1/routes/knowledge_bases.py::search_entries`，因此同时覆盖路由中的知识库 ACL
检查和实际 `search_knowledge_entries` 检索服务。

## 指标与发布阈值

| 指标 | 定义 | 阈值 |
|---|---|---:|
| Recall@5 | 每个可回答问句在前 5 个结果中召回的相关条目比例，再对问句取均值 | `>= 0.95` |
| MRR | 第一个相关条目排名的倒数均值 | `>= 0.90` |
| nDCG@5 | 前 5 个结果的折损累计增益，使用确定性二元相关性 | `>= 0.90` |
| 无答案准确率 | 无答案问句返回空结果的比例 | `>= 0.95` |
| ACL 泄漏数 | 隔离问句未以 `404 knowledge_base_not_found` 隐藏，或返回任一条目 | `= 0` |

任一指标未达标、用例缺失、重复观测、数据集指纹漂移或 ACL 结果不确定，都必须失败关闭。
评测器还会拒绝未知条目、重复排名、跨知识库作用域结果以及非有限指标，防止证据被构造性抬高。

## PostgreSQL 真实性边界

正式质量结论只能由 PostgreSQL 验收门禁签发。原因是生产服务使用 PostgreSQL，且查询投影、
字符串函数、索引和执行计划与 SQLite 不同。SQLite 单元测试只验证数据集和指标计算器，
代码会明确拒绝使用 SQLite 生成正式通过结论；不得把 SQLite 的结果描述为生产检索质量证明。

`tests/test_rag_retrieval_eval_postgres.py` 只接受验收器创建的回环、随机命名、带随机 marker
的 PostgreSQL 数据库。它不读取普通运行数据库，也不会连接外部服务器。正式入口仍是：

ACL 用例中的未授权账号拥有另一个无关知识库的真实读者角色，但不具有目标隔离库授权，
因此会执行角色授权查询分支，而不是只验证“无任何角色”的简单拒绝路径。

```powershell
uv run python -m scripts.postgres_acceptance `
  --image postgres:17.5-bookworm `
  --expected-git-head <冻结提交> `
  --expected-content-fingerprint <冻结工作树指纹> `
  --acceptance-run-nonce <一次性随机值>
```

PostgreSQL JUnit 原始证据会保存 `rag_retrieval_metrics` 及各项独立属性；
`rag_retrieval_quality` 业务检查只有在 120 条用例全部执行且阈值全部通过时才会标记为 `passed`。
