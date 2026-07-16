from __future__ import annotations

import re
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
COMPOSE_PATH = REPOSITORY / "deploy/tencent/compose.offline.yml"
ABORT_HELPER_PATH = REPOSITORY / "deploy/tencent/offline-pre-migration-abort.py"
ADOPTION_ENTRYPOINT_PATH = REPOSITORY / "deploy/tencent/adopt-offline.sh"
COMMON_SCRIPT_PATH = REPOSITORY / "deploy/tencent/offline-operation-common.sh"
INSTALL_ENTRYPOINT_PATH = REPOSITORY / "deploy/tencent/install-offline.sh"
LEGACY_GUIDE_PATH = REPOSITORY / "docs/LEGACY_OFFLINE_ADOPTION.zh-CN.md"
LEGACY_TOOL_PATH = REPOSITORY / "scripts/legacy_offline_adoption.py"
OFFLINE_CA_DRILL_PATH = REPOSITORY / "scripts/offline_ca_restore_drill.py"
REGISTRY_IMPORT_PATH = REPOSITORY / "deploy/tencent/import-offline-registry-bundle.sh"
SCHEMA_VERSION_PATH = REPOSITORY / "app/db/schema_version.py"
TLS_GUIDE_PATH = REPOSITORY / "docs/TLS_INTERNAL_CA_OPERATIONS.zh-CN.md"
DEPLOYMENT_GUIDE_PATH = REPOSITORY / "docs/TENCENT_OFFLINE_ENTERPRISE_DEPLOYMENT.zh-CN.md"
RUNBOOK_PATH = REPOSITORY / "deploy/tencent/README.md"
UPGRADE_VERIFIER_PATH = REPOSITORY / "deploy/tencent/verify-upgrade-backup.py"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_ca_host_path_in_guides_is_derived_from_the_compose_bind() -> None:
    compose = _read(COMPOSE_PATH)
    correct_host_directory = (
        "/srv/heyi-knowledgebases-offline/data/caddy-data/caddy/pki/authorities/local"
    )
    stale_host_directory = "/srv/heyi-knowledgebases-offline/data/caddy/pki/authorities/local"

    assert "source: ${KB_DATA_ROOT:?required}/caddy-data" in compose
    assert "target: /data" in compose
    for guide_path in (
        LEGACY_GUIDE_PATH,
        TLS_GUIDE_PATH,
        DEPLOYMENT_GUIDE_PATH,
        RUNBOOK_PATH,
    ):
        guide = _read(guide_path)
        assert correct_host_directory in guide
        assert stale_host_directory not in guide


def test_legacy_data_compatibility_gate_matches_the_target_compose() -> None:
    compose = _read(COMPOSE_PATH)
    legacy_guide = _read(LEGACY_GUIDE_PATH)
    legacy_tool = _read(LEGACY_TOOL_PATH)
    deployment_guide = _read(DEPLOYMENT_GUIDE_PATH)

    for compose_contract in (
        "postgres:17.5-bookworm@sha256:",
        "source: ${KB_DATA_ROOT:?required}/postgres",
        "target: /var/lib/postgresql/data",
        "source: ${KB_DATA_ROOT:?required}/minio",
        "target: /data",
    ):
        assert compose_contract in compose

    for documented_contract in (
        "/srv/heyi-knowledgebases-offline/data/postgres",
        "/var/lib/postgresql/data",
        "SHOW server_version_num",
        "`17`",
        "/srv/heyi-knowledgebases-offline/data/minio",
        "命名卷",
    ):
        assert documented_contract in legacy_guide

    assert "PostgreSQL 17" in deployment_guide
    assert "SHOW server_version_num" in deployment_guide
    assert '"SHOW server_version_num;"' in legacy_tool


def test_llm_egress_documentation_matches_the_compose_default_and_profile() -> None:
    compose = _read(COMPOSE_PATH)
    deployment_guide = _read(DEPLOYMENT_GUIDE_PATH)
    runbook = _read(RUNBOOK_PATH)

    assert "KB_LLM_EGRESS_MODE: ${KB_LLM_EGRESS_MODE:-strict_offline}" in compose
    assert "profiles: [controlled-egress]" in compose

    for document in (deployment_guide, runbook):
        assert "KB_LLM_EGRESS_MODE=strict_offline" in document
        assert "controlled_gateway" in document
        assert "审批" in document
    assert "http://llm-egress:8080" in deployment_guide

    assert "运行时禁止公网模型调用" not in runbook


def test_guides_preserve_external_evidence_as_a_no_go_boundary() -> None:
    for guide_path in (LEGACY_GUIDE_PATH, DEPLOYMENT_GUIDE_PATH, RUNBOOK_PATH):
        guide = _read(guide_path)
        assert "NO-GO" in guide
        assert "磁盘" in guide
        assert "恢复演练" in guide


def test_predictive_adoption_command_matches_the_entrypoint_contract() -> None:
    entrypoint = _read(ADOPTION_ENTRYPOINT_PATH)
    legacy_guide = _read(LEGACY_GUIDE_PATH)

    for option in (
        "--runtime-env",
        "--release-env",
        "--legacy-plan",
        "--legacy-binding-key",
        "--backup-evidence",
        "--backup-signature",
        "--retirement-receipt",
        "--retirement-signature",
        "--host-isolation-baseline",
        "--host-isolation-hmac-key",
        "--confirm-project",
        "--confirm-plan-sha256",
        "--confirm-preserve-data",
    ):
        assert option in entrypoint
        assert option in legacy_guide

    entrypoint_arguments = entrypoint.split('while [ "$#" -gt 0 ]; do', 1)[1].split(
        'case "$confirmed_plan_sha256"', 1
    )[0]
    assert "--evidence-public-key" not in entrypoint_arguments
    assert "--evidence-signing-key" not in entrypoint_arguments
    for trust_contract in (
        "/etc/heyi-adoption/trusted-evidence-public.pem",
        "/etc/heyi-adoption/trusted-evidence-public.sha256",
        "/run/heyi-adoption-signing/evidence-signing.key",
        "独立预置",
        "短时",
        "release_authorization_sha256",
    ):
        assert trust_contract in entrypoint or trust_contract in legacy_guide

    assert "prepare-offline-contract.sh" in entrypoint
    assert "创建并验证目标 canonical contract" in legacy_guide
    assert "predictive-only PASS" in entrypoint
    assert "predictive-only PASS" in legacy_guide
    assert "legacy project unchanged" in entrypoint
    assert "旧栈保持不变" in deployment_guide_and_runbook()


def deployment_guide_and_runbook() -> str:
    return _read(DEPLOYMENT_GUIDE_PATH) + "\n" + _read(RUNBOOK_PATH)


def test_execute_adoption_documents_the_signed_pre_migration_abort_boundary() -> None:
    entrypoint = _read(ADOPTION_ENTRYPOINT_PATH)
    install = _read(INSTALL_ENTRYPOINT_PATH)
    abort_helper = _read(ABORT_HELPER_PATH)
    documents = _read(LEGACY_GUIDE_PATH) + "\n" + deployment_guide_and_runbook()

    assert "target PRE_MIGRATION_ONLY cleanup interface is unavailable" not in entrypoint
    assert "尚未提供可验签" not in documents
    assert "固定以退出码 `69` 阻断" not in documents
    assert "abort_target_pre_migration" in entrypoint
    assert "verify_abort_receipt" in entrypoint
    assert "--abort-pre-migration" in install
    assert "write_install_state migration_invoked" in install
    assert 'RESTORE_BOUNDARY = "PRE_MIGRATION_ONLY"' in abort_helper
    assert '"status": "aborted_pre_migration"' in abort_helper
    assert '"migration_command_invoked": False' in abort_helper
    assert '"bind_data_deleted": False' in abort_helper
    assert '"named_volumes_deleted": False' in abort_helper
    assert '"global_actions": []' in abort_helper

    assert "`--execute`" in documents
    assert "aborted_pre_migration" in documents
    assert "PRE_MIGRATION_ONLY" in documents
    assert "POST_MIGRATION_FORWARD_FIX_ONLY" in documents
    assert "验签" in documents


def test_current_schema_and_canonical_asset_counts_are_derived_from_code() -> None:
    common = _read(COMMON_SCRIPT_PATH)
    match = re.search(
        r"(?ms)^offline_contract_files\(\) \{\r?\n\s*cat <<'EOF'\r?\n"
        r"(?P<body>.*?)\r?\nEOF\r?\n\}",
        common,
    )
    assert match is not None
    entries = match.group("body").splitlines()
    release_assets = [entry for entry in entries if entry.startswith("release/")]

    assert entries[:3] == ["runtime.env", "release.env", "release.env.images"]
    assert len(entries) == 42
    assert len(release_assets) == 39
    assert len(entries) == len(set(entries))
    assert len(release_assets) == len(set(release_assets))
    assert "release/scripts/offline_ca_restore_drill.py" in release_assets

    current_head = "20260715_0021"
    assert f'EXPECTED_ALEMBIC_HEADS = frozenset({{"{current_head}"}})' in _read(SCHEMA_VERSION_PATH)
    assert f'if [ "$value" != {current_head} ]; then' in _read(REGISTRY_IMPORT_PATH)
    for document_path in (LEGACY_GUIDE_PATH, DEPLOYMENT_GUIDE_PATH, RUNBOOK_PATH):
        document = _read(document_path)
        assert current_head in document
        assert "42 个" in document
        assert "39 个" in document

    deployment_guide = _read(DEPLOYMENT_GUIDE_PATH)
    assert f"RELEASE_SCHEMA_HEAD={current_head}" in deployment_guide
    assert "RELEASE_SCHEMA_HEAD=20260714_0020" not in deployment_guide
    assert "总行数必须由构建器按最终目录动态枚举" in deployment_guide


def test_reactivation_command_and_boundary_match_the_legacy_tool() -> None:
    legacy_tool = _read(LEGACY_TOOL_PATH)
    legacy_guide = _read(LEGACY_GUIDE_PATH)

    assert 'REACTIVATION_BOUNDARY: Final = "PRE_MIGRATION_ONLY"' in legacy_tool
    assert '"status": "reactivated-pre-migration-only"' in legacy_tool
    for option in (
        "--plan",
        "--binding-key",
        "--retirement-receipt",
        "--retirement-signature",
        "--target-abort-receipt",
        "--target-abort-signature",
        "--adoption-transaction",
        "--evidence-public-key",
        "--host-isolation-baseline",
        "--host-isolation-hmac-key",
        "--confirm-restore-boundary",
    ):
        assert f'reactivate.add_argument("{option}"' in legacy_tool
        assert option in legacy_guide

    for contract in (
        "PRE_MIGRATION_ONLY",
        "reactivated-pre-migration-only",
        "POST_MIGRATION_FORWARD_FIX_ONLY",
    ):
        assert contract in legacy_guide
        assert contract in deployment_guide_and_runbook()


def test_multi_release_plan_arguments_are_documented() -> None:
    legacy_tool = _read(LEGACY_TOOL_PATH)
    legacy_guide = _read(LEGACY_GUIDE_PATH)

    assert '"schema_version": 4' in legacy_tool
    assert "计划 schema v4" in legacy_guide
    assert "schema v3" in legacy_guide
    assert "fail-closed" in legacy_guide
    assert "REQUIRED_RUNTIME_KEYS" in legacy_guide
    assert "未知键和重复键一律拒绝" in legacy_guide
    assert "不能仅凭“位于 `DATA_ROOT` 下”放行" in legacy_guide
    assert (
        'plan.add_argument("--compose-file", type=Path, action="append", required=True)'
        in legacy_tool
    )
    assert legacy_guide.count("--compose-file") >= 2
    assert "--target-manifest" not in legacy_guide
    assert "--git-sha" not in legacy_guide
    assert "HIGHEST_RELEASE_STATE" in legacy_tool
    assert "TRUSTED_RELEASE_PUBLIC_KEY" in legacy_tool
    assert "com.docker.compose.project.config_files" in legacy_guide
    assert "一次性容器" in legacy_guide


def test_offline_ca_restore_tool_and_v2_signer_binding_are_documented() -> None:
    legacy_tool = _read(LEGACY_TOOL_PATH)
    offline_tool = _read(OFFLINE_CA_DRILL_PATH)
    legacy_guide = _read(LEGACY_GUIDE_PATH)

    assert '"schema_version": 2' in legacy_tool
    assert "ca_attestation_public_key_sha256" in legacy_tool
    assert 'prepare.add_argument("--ca-attestation-public-key"' in legacy_tool
    assert "--ca-attestation-public-key" in legacy_guide
    assert "offline_ca_restore_drill.py" in legacy_guide
    assert "--expected-challenge-public-key-sha256" in legacy_guide
    assert "binding.key" in legacy_guide
    assert "禁止通过网络传输" in legacy_guide
    assert "物理断开" in legacy_guide
    assert "`--network none` 只能作为附加控制" in legacy_guide
    assert "ca_attestation_public_key_sha256" in offline_tool
    assert 'OPENSSL: Final = Path("/usr/bin/openssl")' in offline_tool


def test_upgrade_backup_verifier_uses_the_fixed_schema_v2_release_authorization() -> None:
    verifier = _read(UPGRADE_VERIFIER_PATH)
    legacy_tool = _read(LEGACY_TOOL_PATH)
    assert "authorization = module._current_release_authorization()" in verifier
    assert 'highest.get("schema_version") != 2' in legacy_tool
    assert 'receipt.get("schema_version") != 2' in legacy_tool
    assert '"release_authorization_sha256"' in verifier
    assert "_fixed_release_authorization_binding()" in verifier
    assert (
        'document["release_authorization_sha256"] != expected_release_authorization_sha256'
        in verifier
    )
