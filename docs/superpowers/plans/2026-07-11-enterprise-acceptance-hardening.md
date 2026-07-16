# Enterprise Acceptance and Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a measurable enterprise acceptance standard, execute it against the repository and available environments, fix verified high-priority gaps with test-first changes, and publish an evidence-backed release verdict.

**Architecture:** Acceptance is split into independent gates for backend/security, frontend/business workflows, data integrity and AI grounding, and isolated Tencent operations. A repository-owned Python runner executes deterministic local gates and writes machine-readable JSON plus a human-readable Markdown report; environment-only gates remain explicit rather than being silently marked successful.

**Tech Stack:** Python 3.12, pytest, Ruff, MyPy, FastAPI, PostgreSQL 17, Redis 8, Vitest, ESLint, Next.js 16, Docker Compose, Caddy, MinIO, GitHub Actions.

## Global Constraints

- P0 is a release blocker: one failed P0 gate makes the verdict `FAIL`.
- P1 is required for enterprise production: an unverified or failed P1 gate makes the verdict at most `CONDITIONAL`.
- P2 is an improvement: it cannot override a P0/P1 failure.
- No acceptance item may pass without a command result, HTTP evidence, database assertion, screenshot, or signed operator record.
- No production code change is allowed before a failing regression test demonstrates the gap.
- Secrets, document contents, presigned URLs, credentials, `.env` values, and complete server addresses must never appear in reports.
- Tencent offline runtime gates require the real 8 vCPU, 16 GB RAM, 300 GB SSD host; the currently discovered 4 vCPU, 4 GB, 40 GB host must be rejected by preflight.
- Existing `heyi-kb-prod`, Vercel projects, and unrelated Tencent applications must not be restarted, deleted, or reconfigured by acceptance tests.

---

### Task 1: Publish the enterprise acceptance contract

**Files:**
- Create: `docs/ENTERPRISE_ACCEPTANCE_STANDARD.zh-CN.md`
- Modify: `README.md`
- Reference: `docs/COMMERCIAL_READINESS_REVIEW.zh-CN.md`

**Interfaces:**
- Consumes: current product requirements, commercial-readiness blockers, three parallel audit reports.
- Produces: stable gate IDs in the form `AREA-P0-NNN`, with columns for severity, requirement, method, pass threshold, evidence, and owner.

- [ ] **Step 1: Define verdict calculation examples**

```text
PASS        = every P0 and P1 gate passed
CONDITIONAL = every P0 passed, at least one P1 blocked or unverified
FAIL        = at least one P0 failed, or evidence contains a secret/data leak
```

- [ ] **Step 2: Write the acceptance matrix**

Cover authentication, RBAC, knowledge ACL, quota/rate limits, upload/approval/download, OKF, retrieval, citations, hallucination review, API keys/models, auditability, frontend workflows, accessibility, PostgreSQL/Redis/MinIO integrity, isolated networking, capacity, backup/restore, upgrades, rollback, observability, performance, and compliance boundaries. Every criterion must include a numeric threshold or exact expected state.

- [ ] **Step 3: Add a README entry**

```markdown
[企业验收标准](../../ENTERPRISE_ACCEPTANCE_STANDARD.zh-CN.md)：P0/P1/P2 发布门禁、测试方法、证据要求与判定规则。
```

- [ ] **Step 4: Verify documentation integrity**

Run: `rg -n "AREA-P[012]-[0-9]{3}" docs/ENTERPRISE_ACCEPTANCE_STANDARD.zh-CN.md`

Expected: every matrix row has a unique gate ID; no row contains `TBD`, `TODO`, `待补充`, or a credential value.

- [ ] **Step 5: Commit**

```bash
git add docs/ENTERPRISE_ACCEPTANCE_STANDARD.zh-CN.md README.md
git commit -m "docs: define enterprise acceptance standard"
```

### Task 2: Build a deterministic acceptance runner

**Files:**
- Create: `scripts/acceptance.py`
- Create: `tests/test_acceptance_runner.py`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: `AcceptanceGate(id, severity, command, cwd, timeout_seconds)` declarations.
- Produces: `AcceptanceResult` records and verdicts `PASS`, `CONDITIONAL`, or `FAIL`; writes redacted JSON and Markdown reports below `artifacts/acceptance/`.

- [ ] **Step 1: Write failing verdict tests**

```python
def test_failed_p0_forces_fail() -> None:
    results = [result("AUTH-P0-001", "P0", "failed")]
    assert calculate_verdict(results) == "FAIL"


def test_unverified_p1_is_conditional() -> None:
    results = [
        result("AUTH-P0-001", "P0", "passed"),
        result("OPS-P1-001", "P1", "blocked"),
    ]
    assert calculate_verdict(results) == "CONDITIONAL"
```

- [ ] **Step 2: Run tests and confirm RED**

Run: `uv run pytest tests/test_acceptance_runner.py -q`

Expected: import failure because `scripts.acceptance` does not yet exist.

- [ ] **Step 3: Implement immutable result types and verdict logic**

```python
@dataclass(frozen=True, slots=True)
class AcceptanceResult:
    gate_id: str
    severity: Literal["P0", "P1", "P2"]
    status: Literal["passed", "failed", "blocked"]
    duration_seconds: float
    summary: str


def calculate_verdict(results: Sequence[AcceptanceResult]) -> str:
    if any(item.severity == "P0" and item.status != "passed" for item in results):
        return "FAIL"
    if any(item.severity == "P1" and item.status != "passed" for item in results):
        return "CONDITIONAL"
    return "PASS"
```

- [ ] **Step 4: Write failing tests for timeout, redaction, and nonzero exit handling**

Use an injected command executor so tests assert behavior without executing shells. Verify summaries remove bearer tokens, URL passwords, `.env` values, and presigned query strings.

- [ ] **Step 5: Run tests and confirm RED**

Run: `uv run pytest tests/test_acceptance_runner.py -q`

Expected: timeout/redaction/execution tests fail because the runner is incomplete.

- [ ] **Step 6: Implement the minimal runner**

The runner must invoke subprocesses with argument arrays, capture bounded output, enforce per-gate timeouts, never use `shell=True`, and write UTF-8 JSON/Markdown reports atomically.

- [ ] **Step 7: Verify GREEN and static quality**

```bash
uv run pytest tests/test_acceptance_runner.py -q
uv run ruff check scripts/acceptance.py tests/test_acceptance_runner.py
uv run mypy scripts/acceptance.py
```

Expected: all commands exit `0` with no warnings.

- [ ] **Step 8: Commit**

```bash
git add scripts/acceptance.py tests/test_acceptance_runner.py .gitignore
git commit -m "test: add enterprise acceptance runner"
```

### Task 3: Encode repository and Compose gates

**Files:**
- Modify: `scripts/acceptance.py`
- Modify: `tests/test_acceptance_runner.py`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: runner from Task 2.
- Produces: `local` and `ci` profiles covering backend tests/coverage, Ruff, MyPy, frontend lint/tests/build, migration heads, Compose parse, isolated network policy, and secret-safe dependency audit status.

- [ ] **Step 1: Write failing profile inventory tests**

```python
def test_local_profile_contains_required_gates() -> None:
    ids = {gate.gate_id for gate in build_profile("local")}
    assert {
        "CODE-P0-001",
        "BACKEND-P0-001",
        "FRONTEND-P0-001",
        "BUILD-P0-001",
        "OFFLINE-P0-001",
    } <= ids
```

- [ ] **Step 2: Confirm RED, implement exact command arrays, confirm GREEN**

Local commands include `uv run pytest --cov=app --cov-fail-under=80`, `uv run ruff check .`, `uv run mypy app scripts`, `npm run lint`, `npm test`, `npm run build`, and `docker compose ... config --quiet`. CI-only dependency audits remain separate because they require approved registry access.

- [ ] **Step 3: Add the acceptance runner to CI**

Run it after existing backend/frontend jobs have installed dependencies. Upload only redacted reports; do not upload `.env`, test databases, browser cookies, or raw request logs.

- [ ] **Step 4: Verify workflow and profiles**

```bash
uv run pytest tests/test_acceptance_runner.py -q
uv run python scripts/acceptance.py --profile local --report-dir artifacts/acceptance
```

Expected: deterministic report and verdict; real-server gates appear `blocked`, never `passed`.

- [ ] **Step 5: Commit**

```bash
git add scripts/acceptance.py tests/test_acceptance_runner.py .github/workflows/ci.yml
git commit -m "ci: enforce enterprise acceptance gates"
```

### Task 4: Fix verified P0/P1 product gaps through TDD

**Files:**
- Modify: exact backend/frontend files identified by the audit evidence.
- Test: matching `tests/test_*.py` or `web/tests/*.test.ts` file for each gap.
- Modify: `docs/ENTERPRISE_ACCEPTANCE_STANDARD.zh-CN.md` only when a requirement needs clarification, never to weaken a failing gate.

**Interfaces:**
- Consumes: ranked findings from the three audit agents and baseline runner failures.
- Produces: one independently reviewed regression fix per verified gap.

- [ ] **Step 1: Select only reproducible gaps**

For every candidate, record the acceptance gate, current evidence, expected behavior, and smallest owning module. Reject speculative findings that cannot be reproduced.

- [ ] **Step 2: Write one failing regression test per behavior**

Run the narrow test and confirm it fails for the expected missing control or broken workflow, not for fixture/setup errors.

- [ ] **Step 3: Implement the minimum production change**

Do not combine unrelated authorization, UI, deployment, or observability fixes in one patch.

- [ ] **Step 4: Verify narrow and neighboring suites**

Backend example: `uv run pytest tests/test_security.py tests/test_integration_api.py -q`.

Frontend example: `npm test -- chat-sources.test.ts workspace-guard.test.ts` from `web/`.

- [ ] **Step 5: Commit each independent fix**

Use `fix(<area>): <verified behavior>` and include the gate ID in the commit body.

### Task 5: Execute acceptance and publish the evidence report

**Files:**
- Create: `docs/acceptance-reports/2026-07-11-local-self-test.zh-CN.md`
- Modify: `docs/COMMERCIAL_READINESS_REVIEW.zh-CN.md`

**Interfaces:**
- Consumes: redacted acceptance runner results and manual audit evidence.
- Produces: a dated report with commit SHA, environment facts, passed/failed/blocked gates, commands, durations, remediation links, and final verdict.

- [ ] **Step 1: Run the full local profile from a clean tree**

```bash
uv run python scripts/acceptance.py --profile local --report-dir artifacts/acceptance
```

- [ ] **Step 2: Run independent direct verification**

```bash
uv run pytest --cov=app --cov-report=term-missing --cov-fail-under=80
uv run ruff check .
uv run mypy app scripts
cd web && npm run lint && npm test && npm run build
```

- [ ] **Step 3: Publish actual results without upgrading blocked gates**

The report must state that the Tencent server gate is blocked when the only discovered host remains 4 vCPU, 4 GB RAM, and 40 GB disk. It must not infer results for load, restore, or disconnected-runtime tests.

- [ ] **Step 4: Update commercial-readiness verdict**

Keep `DONE_WITH_CONCERNS` or a stricter verdict until every existing P1 blocker has evidence. Do not convert planned controls into completed controls.

- [ ] **Step 5: Commit**

```bash
git add docs/acceptance-reports/2026-07-11-local-self-test.zh-CN.md docs/COMMERCIAL_READINESS_REVIEW.zh-CN.md
git commit -m "docs: publish enterprise self-test evidence"
```

### Task 6: Real 8C16G/300GB offline-server acceptance

**Files:**
- Modify after execution: `docs/acceptance-reports/2026-07-11-local-self-test.zh-CN.md`
- Use: `deploy/tencent/preflight-offline.sh`
- Use: `deploy/tencent/compose.offline.yml`

**Interfaces:**
- Consumes: corrected `.env` SSH destination for the real enterprise server and approved maintenance window.
- Produces: signed operator evidence for capacity, isolation, upload/download, restart persistence, backup/restore, load, upgrade, rollback, and no-egress tests.

- [ ] **Step 1: Prove target identity and capacity read-only**

Required: at least 8 logical CPUs, 15 GB usable RAM, 200 GB free disk, unused `19443/19444`, and no overlap with existing Compose projects.

- [ ] **Step 2: Run preflight and deploy only `heyi-kb-offline`**

Use the exact project-scoped commands from `docs/TENCENT_OFFLINE_ENTERPRISE_DEPLOYMENT.zh-CN.md`.

- [ ] **Step 3: Execute runtime security and resilience tests**

Verify external socket creation fails from API/Web containers; PostgreSQL/Redis/MinIO have no host ports; restart preserves data; backup restores into a disposable project; upgrade and rollback do not modify other applications.

- [ ] **Step 4: Execute load thresholds**

Measure authenticated API P95/P99, concurrent chat retrieval, upload signing, database saturation, Redis memory, disk latency, and container memory under an agreed 30-minute load window. Record the exact dataset and concurrency.

- [ ] **Step 5: Recalculate verdict**

Only replace `blocked` server gates with `passed` when all command outputs and recovery evidence are attached and redacted.

---

## Self-Review

- Spec coverage: acceptance definition, parallel audits, self-test execution, TDD optimization, reporting, and real-server constraints are each mapped to a task.
- Placeholder scan: the plan contains no implementation placeholders; environment-dependent evidence is explicitly represented as `blocked` until executed.
- Type consistency: `AcceptanceGate`, `AcceptanceResult`, `calculate_verdict`, and `build_profile` are defined once and reused consistently.
