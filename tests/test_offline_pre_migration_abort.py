from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPOSITORY = Path(__file__).resolve().parents[1]
DEPLOY = REPOSITORY / "deploy" / "tencent"


def _source(name: str) -> str:
    return (DEPLOY / name).read_text(encoding="utf-8")


def _load_state_module() -> ModuleType:
    path = DEPLOY / "offline-recovery-state.py"
    spec = importlib.util.spec_from_file_location("offline_recovery_state_abort_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_abort_module() -> ModuleType:
    path = DEPLOY / "offline-pre-migration-abort.py"
    name = "offline_pre_migration_abort_test"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_install_closes_the_migration_boundary_before_migrate_argv() -> None:
    install = _source("install-offline.sh")

    boundary = install.index("write_install_state migration_invoked")
    migration = install.index("run --pull never --rm migrate")
    assert boundary < migration
    assert "migration_invoked" in install
    assert '"migration_command_invoked":true' in install


def test_install_resume_never_reopens_an_invoked_migration_boundary() -> None:
    install = _source("install-offline.sh")

    guarded_preflight = (
        'if [ "$resume_migration_invoked" != true ]; then\n'
        "  write_install_state preflight_passed\n"
        "fi"
    )
    assert guarded_preflight in install
    assert 'document["migration_command_invoked"] is True' in install
    assert install.index(guarded_preflight) < install.index("write_install_state migration_invoked")


def test_install_completed_handoff_is_exactly_idempotent() -> None:
    install = _source("install-offline.sh")
    verifier = install.split("verify_completed_install_handoff() (", 1)[1].split(
        "\n)\n\ncleanup_install_contract()", 1
    )[0]
    completed_handoff = install.split('set -- "$state_directory"/installed-*.json', 1)[1].split(
        'if [ -e "$state_file" ]; then', 1
    )[0]

    for required in (
        "validate-installed-receipt",
        'active.get("selection") == "active"',
        'active.get("status") == "committed"',
        'installed.get("adoption_journal_sha256") == sys.argv[7]',
        'installed.get("retirement_receipt_sha256") == sys.argv[9]',
        "offline_verify_project_release_labels",
        "--business-ready-compose-config-stdin",
        "offline_clear_committed_cutover",
    ):
        assert required in verifier
    assert 'if [ "$#" -ne 1 ] || [ "$1" != "$installed_receipt" ]; then' in install
    assert "installation_committed=true" in install
    assert "existing completed offline release is healthy" in install
    assert "verify_completed_install_handoff" in completed_handoff
    assert "exit 0" in completed_handoff
    assert install.index('set -- "$state_directory"/installed-*.json') < install.index(
        "write_install_state migration_invoked"
    )
    assert install.index('set -- "$state_directory"/installed-*.json') < install.index(
        "run --pull never --rm migrate"
    )


def test_install_resume_removes_only_exact_stopped_preflight_residuals() -> None:
    install = _source("install-offline.sh")
    cleanup = install.split("remove_stopped_resume_oneoffs() {", 1)[1].split(
        "\n}\n\nstop_exact_install_services()", 1
    )[0]

    for service in ("api-preflight", "clamav-db-preflight", "llm-egress-preflight"):
        assert service in cleanup
    for binding in (
        "io.heyi.knowledgebases.contract-sha256",
        "io.heyi.knowledgebases.adoption-transaction",
        'oneoff_contract" != "$contract_sha256',
        'oneoff_adoption" != "$adoption_transaction_id',
        "@sha256:[0-9a-f]{64}",
        'oneoff_running" != false',
    ):
        assert binding in cleanup
    assert cleanup.index('oneoff_running" != false') < cleanup.index('docker rm "$oneoff_id"')


def test_install_has_separate_bound_adoption_and_abort_entry_contracts() -> None:
    install = _source("install-offline.sh")
    abort_parser = install.split(
        'elif [ "$#" -eq 9 ] && [ "$1" = "--abort-pre-migration" ]; then', 1
    )[1].split('else\n  echo "usage:', 1)[0]

    for token in (
        "--adoption-journal",
        "--adoption-binding-key",
        "--adoption-transaction",
        "--abort-pre-migration",
        "--confirm-contract-sha256",
        "--confirm-adoption-transaction",
        "--confirm-plan-sha256",
        "--confirm-retirement-receipt-sha256",
        "--confirm-restore-boundary",
        "PRE_MIGRATION_ONLY",
    ):
        assert token in install
    assert "offline-pre-migration-abort.py" in install
    assert "--evidence-public-key" not in abort_parser
    assert "--evidence-signing-key" not in abort_parser
    assert 'python3 -I "$abort_helper" validate-evidence-trust-root >/dev/null' in install
    assert install.index("validate-evidence-trust-root") < install.index(
        "offline_acquire_lock install"
    )


def test_preflight_oneoffs_are_bound_to_the_contract_and_adoption_transaction() -> None:
    preflight = _source("preflight-offline.sh")

    for label in (
        "io.heyi.knowledgebases.contract-sha256",
        "io.heyi.knowledgebases.adoption-transaction",
        "com.docker.compose.oneoff",
        "com.docker.compose.project.config_files",
    ):
        assert label in preflight
    assert "llm-egress-preflight" in preflight
    assert "--adoption-transaction" in preflight
    assert 'document["release_schema_head"] == "20260715_0021"' in preflight


def test_abort_helper_exposes_a_strict_fail_closed_contract() -> None:
    helper = _source("offline-pre-migration-abort.py")
    parser = helper.split("def _parser()", 1)[1].split("\ndef main(", 1)[0]

    for token in (
        "heyi-adoption-transaction-v1",
        "heyi-target-pre-migration-abort-receipt",
        "migration_invoked",
        "PRE_MIGRATION_ONLY",
        "api-preflight",
        "clamav-db-preflight",
        "llm-egress-preflight",
        "heyi-kb-offline-owner-marker",
        "heyi-kb-offline-reconcile.timer",
        "host_isolation_verification",
        "target_resource_counts_after",
        "/etc/heyi-adoption/trusted-evidence-public.pem",
        "/etc/heyi-adoption/trusted-evidence-public.sha256",
        "/run/heyi-adoption-signing/evidence-signing.key",
        "heyi-adoption-evidence-key-pair-v1",
        "validate-evidence-trust-root",
    ):
        assert token in helper
    assert "--evidence-public-key" not in parser
    assert "--evidence-signing-key" not in parser
    for forbidden in (
        "docker system prune",
        "docker volume prune",
        "docker network prune",
        "docker compose down",
        "docker rm -f",
        "systemctl restart docker",
    ):
        assert forbidden not in helper


def test_abort_entry_rejects_operator_selected_evidence_keys_before_mutation(
    tmp_path: Path,
) -> None:
    shell = shutil.which("sh")
    if shell is None:
        pytest.skip("POSIX sh is unavailable")
    mutation_root = tmp_path / "must-remain-empty"
    mutation_root.mkdir()

    rejected = subprocess.run(
        [
            shell,
            str(DEPLOY / "install-offline.sh"),
            "--abort-pre-migration",
            "--adoption-journal",
            str(tmp_path / "journal.json"),
            "--adoption-binding-key",
            str(tmp_path / "binding.key"),
            "--evidence-signing-key",
            str(tmp_path / "attacker.key"),
            "--evidence-public-key",
            str(tmp_path / "attacker.pem"),
            "--host-isolation-baseline",
            str(tmp_path / "baseline.json"),
            "--host-isolation-hmac-key",
            str(tmp_path / "host.key"),
        ],
        cwd=mutation_root,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert rejected.returncode == 64
    assert list(mutation_root.iterdir()) == []


@pytest.mark.parametrize(
    "attack",
    ("wrong_fingerprint", "wrong_private_key"),
)
def test_abort_trust_attacks_fail_before_any_resource_mutation(
    attack: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_abort_module()
    contract = "b" * 64
    public_key = b"trusted public key"
    fingerprint = hashlib.sha256(public_key).hexdigest().encode("ascii") + b"\n"
    signing_key = b"trusted private key"
    if attack == "wrong_fingerprint":
        fingerprint = b"0" * 64 + b"\n"
    elif attack == "wrong_private_key":
        signing_key = b"attacker private key"

    material = {
        module.TRUSTED_EVIDENCE_PUBLIC_KEY: public_key,
        module.TRUSTED_EVIDENCE_PUBLIC_KEY_SHA256: fingerprint,
        module.TRUSTED_EVIDENCE_SIGNING_KEY: signing_key,
    }
    mutation_events: list[tuple[str, ...]] = []

    def protected(path: Path, **_kwargs: object) -> bytes:
        return material[path]

    class MutationTrackingRunner:
        def validate_evidence_key_pair(self, **kwargs: bytes) -> None:
            if kwargs["signing_key"] != b"trusted private key":
                raise module.AbortError(
                    "ephemeral adoption signer does not match the independently trusted public key"
                )

        def run(self, argv: tuple[str, ...], **_kwargs: object) -> str:
            mutation_events.append(argv)
            raise AssertionError("resource command reached before trust validation")

        def docker_json(self, argv: tuple[str, ...]) -> object:
            mutation_events.append(argv)
            raise AssertionError("Docker reached before trust validation")

    monkeypatch.setattr(module, "_require_root_linux", lambda: None)
    monkeypatch.setattr(module, "_self_bound_contract", lambda: contract)
    monkeypatch.setattr(module, "_protected_trust_file", protected)
    monkeypatch.setattr(
        module,
        "validate_journal",
        lambda *_args, **_kwargs: pytest.fail("journal validation reached before trust validation"),
    )
    arguments = module.AbortArguments(
        journal=tmp_path / "journal.json",
        binding_key=tmp_path / "binding.key",
        host_baseline=tmp_path / "baseline.json",
        host_hmac_key=tmp_path / "host.key",
        execute=True,
        project=module.PROJECT,
        contract=contract,
        adoption_transaction="a" * 32,
        plan="c" * 64,
        retirement_receipt="d" * 64,
        restore_boundary=module.RESTORE_BOUNDARY,
    )

    with pytest.raises(module.AbortError):
        module.abort_pre_migration(arguments, runner=MutationTrackingRunner())

    assert mutation_events == []
    assert not (tmp_path / ".target-pre-migration-abort.pending").exists()
    assert not (tmp_path / "target-pre-migration-abort").exists()


def test_fixed_trust_root_real_openssl_challenge_rejects_wrong_private_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if (
        sys.platform != "linux"
        or getattr(os, "geteuid", lambda: -1)() != 0
        or not Path("/usr/bin/openssl").is_file()
    ):
        pytest.skip("the root Linux OpenSSL trust boundary is unavailable")
    trusted_private = tmp_path / "trusted.key"
    trusted_public = tmp_path / "trusted.pem"
    attacker_private = tmp_path / "attacker.key"
    for private in (trusted_private, attacker_private):
        subprocess.run(
            [
                "/usr/bin/openssl",
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                str(private),
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
        private.chmod(0o400)
    subprocess.run(
        [
            "/usr/bin/openssl",
            "pkey",
            "-in",
            str(trusted_private),
            "-pubout",
            "-out",
            str(trusted_public),
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )
    trusted_public.chmod(0o400)
    fingerprint = tmp_path / "trusted.sha256"
    fingerprint.write_text(
        hashlib.sha256(trusted_public.read_bytes()).hexdigest() + "\n",
        encoding="ascii",
    )
    fingerprint.chmod(0o400)
    module = _load_abort_module()
    monkeypatch.setattr(
        module,
        "TRUSTED_EVIDENCE_PUBLIC_KEY",
        trusted_public,
    )
    monkeypatch.setattr(
        module,
        "TRUSTED_EVIDENCE_PUBLIC_KEY_SHA256",
        fingerprint,
    )
    monkeypatch.setattr(module, "TRUSTED_EVIDENCE_SIGNING_KEY", attacker_private)
    monkeypatch.setattr(
        module,
        "_protected_trust_file",
        lambda path, **_kwargs: path.read_bytes(),
    )

    with pytest.raises(
        module.AbortError,
        match="does not match the independently trusted public key",
    ):
        module._validate_evidence_trust_root(module.Runner(), contract="b" * 64)

    monkeypatch.setattr(module, "TRUSTED_EVIDENCE_SIGNING_KEY", trusted_private)
    assert (
        module._validate_evidence_trust_root(module.Runner(), contract="b" * 64)
        == hashlib.sha256(trusted_public.read_bytes()).hexdigest()
    )
    assert set(tmp_path.iterdir()) == {
        trusted_private,
        trusted_public,
        attacker_private,
        fingerprint,
    }


def test_trust_validator_accepts_a_pre_materialization_challenge_context(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_abort_module()
    context = "b" * 64
    observed: list[str] = []

    monkeypatch.setattr(module, "_require_root_linux", lambda: None)
    monkeypatch.setattr(
        module,
        "_self_bound_contract",
        lambda: pytest.fail("explicit pre-materialization context must not require a release path"),
    )
    monkeypatch.setattr(
        module,
        "_validate_evidence_trust_root",
        lambda _runner, *, contract: observed.append(contract) or ("c" * 64),
    )

    assert (
        module.main(
            [
                "validate-evidence-trust-root",
                "--challenge-context-sha256",
                context,
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert observed == [context]
    assert result == {
        "challenge_context_sha256": context,
        "public_key_sha256": "c" * 64,
        "schema_version": 1,
        "status": "verified",
    }


def test_abort_intent_command_is_exact_and_never_reuses_committed_clear() -> None:
    state = _source("offline-recovery-state.py")

    assert 'add_parser("abort-install-intent")' in state
    assert "def abort_install_intent(" in state
    block = state.split("def abort_install_intent(", 1)[1].split("\ndef ", 1)[0]
    assert 'intent["operation"] != "install"' in block
    assert "ACTIVE_PATH" in block
    assert "os.replace" in block
    assert "clear_intent(" not in block


def test_abort_install_intent_archives_exact_state_and_is_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_state_module()
    state_root = tmp_path / "state"
    contract_root = tmp_path / "contracts"
    state_root.mkdir(mode=0o700)
    contract_root.mkdir(mode=0o700)
    monkeypatch.setattr(module, "STATE_ROOT", state_root)
    monkeypatch.setattr(module, "CONTRACT_ROOT", contract_root)
    monkeypatch.setattr(module, "INTENT_PATH", state_root / "cutover-intent.json")
    monkeypatch.setattr(module, "ACTIVE_PATH", state_root / "active-release.json")
    monkeypatch.setattr(module, "_require_root", lambda: None)
    # Windows does not expose POSIX directory modes faithfully; production
    # mode validation is covered by Linux shell acceptance tests.
    monkeypatch.setattr(module, "_validate_directory", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(module, "_regular_root_file", lambda path, _mode: path.read_bytes())
    monkeypatch.setattr(module, "_fsync_directory", lambda _path: None)

    contract = "a" * 64
    transaction = "b" * 32
    adoption_transaction = "c" * 32
    journal_sha256 = "d" * 64
    archive = (
        state_root
        / "legacy-adoption"
        / "transactions"
        / adoption_transaction
        / ".target-pre-migration-abort.pending"
        / "archived"
        / "cutover-intent.json"
    )
    archive.parent.mkdir(parents=True, mode=0o700)
    transaction_root = state_root / "legacy-adoption" / "transactions" / adoption_transaction
    transaction_root.chmod(0o700)
    intent = {
        "schema_version": 1,
        "kind": "offline-cutover-intent",
        "project_name": module.PROJECT_NAME,
        "operation": "install",
        "transaction_id": transaction,
        "contract_sha256": contract,
        "runtime_sha256": "1" * 64,
        "release_sha256": "2" * 64,
        "manifest_sha256": "3" * 64,
        "compose_profile": "strict-offline",
        "compose_config_sha256": "4" * 64,
        "status": "prepared",
    }
    module.INTENT_PATH.write_text(
        json.dumps(intent, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    module.INTENT_PATH.chmod(0o400)
    monkeypatch.setattr(module, "_validate_intent", lambda document: document)

    first = module.abort_install_intent(
        contract,
        transaction,
        adoption_transaction,
        journal_sha256,
        archive,
    )
    second = module.abort_install_intent(
        contract,
        transaction,
        adoption_transaction,
        journal_sha256,
        archive,
    )

    assert first == second
    assert not module.INTENT_PATH.exists()
    assert archive.is_file()
    assert first["sha256"] == hashlib.sha256(archive.read_bytes()).hexdigest()
    assert first["adoption_transaction_id"] == adoption_transaction
    assert first["journal_sha256"] == journal_sha256


def test_abort_intent_refuses_any_active_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_state_module()
    state_root = tmp_path / "state"
    state_root.mkdir(mode=0o700)
    monkeypatch.setattr(module, "STATE_ROOT", state_root)
    monkeypatch.setattr(module, "INTENT_PATH", state_root / "cutover-intent.json")
    monkeypatch.setattr(module, "ACTIVE_PATH", state_root / "active-release.json")
    monkeypatch.setattr(module, "_require_root", lambda: None)
    module.ACTIVE_PATH.write_text("{}\n", encoding="utf-8")

    with pytest.raises(module.StateError, match="active release"):
        module.abort_install_intent(
            "a" * 64,
            "b" * 32,
            "c" * 32,
            "d" * 64,
            state_root
            / "legacy-adoption"
            / "transactions"
            / ("c" * 32)
            / ".target-pre-migration-abort.pending"
            / "archived"
            / "cutover-intent.json",
        )


def _journal_payload(module: ModuleType, transaction: str, contract: str) -> dict[str, object]:
    absent = {
        "load_state": "not-found",
        "active_state": "inactive",
        "unit_file_state": "not-found",
    }
    return {
        "schema_version": 1,
        "kind": "heyi-offline-adoption-transaction",
        "status": "legacy_retired_target_not_started",
        "project": module.PROJECT,
        "created_at": datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z"),
        "adoption_transaction_id": transaction,
        "plan_sha256": "1" * 64,
        "target_contract_sha256": contract,
        "target_manifest_sha256": "2" * 64,
        "target_schema_head": "20260715_0021",
        "legacy_source_schema_head": "20260714_0020",
        "backup_evidence_sha256": "3" * 64,
        "retirement_receipt_sha256": "4" * 64,
        "retirement_signature_sha256": "5" * 64,
        "legacy_receipt_archive_manifest_sha256": "6" * 64,
        "host_isolation_baseline_sha256": "7" * 64,
        "host_isolation_after_retire_sha256": "8" * 64,
        "reconcile_baseline": {
            module.RECONCILE_SERVICE: absent,
            module.RECONCILE_TIMER: absent,
        },
        "restore_boundary": module.RESTORE_BOUNDARY,
    }


def test_abort_journal_hmac_rejects_any_payload_tamper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_abort_module()
    transaction = "a" * 32
    contract = "b" * 64
    transaction_root = tmp_path / "transactions" / transaction
    transaction_root.mkdir(parents=True)
    journal_path = transaction_root / "journal.json"
    key_path = tmp_path / "binding.key"
    key = b"enterprise-adoption-binding-key-32"
    key_path.write_bytes(base64.urlsafe_b64encode(key).rstrip(b"="))
    payload = _journal_payload(module, transaction, contract)
    signature = hmac.new(
        key,
        module.JOURNAL_HMAC_DOMAIN + module._canonical_json(payload),
        hashlib.sha256,
    ).hexdigest()
    journal_path.write_bytes(
        module._canonical_json({"payload": payload, "opaque_hmac_sha256": signature})
    )
    monkeypatch.setattr(module, "TRANSACTION_ROOT", tmp_path / "transactions")
    monkeypatch.setattr(module, "_protected_file", lambda path, **_kwargs: path.read_bytes())
    monkeypatch.setattr(module, "_protected_directory", lambda *_args, **_kwargs: None)

    verified = module.validate_journal(
        journal_path,
        key_path,
        expected_transaction=transaction,
        expected_contract=contract,
    )
    assert verified.payload["legacy_source_schema_head"] == "20260714_0020"
    assert verified.payload["target_schema_head"] == "20260715_0021"

    tampered = json.loads(journal_path.read_text(encoding="utf-8"))
    tampered["payload"]["plan_sha256"] = "9" * 64
    journal_path.write_bytes(module._canonical_json(tampered))
    with pytest.raises(module.AbortError, match="HMAC differs"):
        module.validate_journal(
            journal_path,
            key_path,
            expected_transaction=transaction,
            expected_contract=contract,
        )


def test_durable_journal_resume_survives_host_clock_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_abort_module()
    transaction = "a" * 32
    contract = "b" * 64
    transaction_root = tmp_path / "transactions" / transaction
    transaction_root.mkdir(parents=True)
    journal_path = transaction_root / "journal.json"
    key_path = tmp_path / "binding.key"
    key = b"enterprise-adoption-binding-key-32"
    key_path.write_bytes(base64.urlsafe_b64encode(key).rstrip(b"="))
    payload = _journal_payload(module, transaction, contract)
    # This represents a journal created while the host clock was ahead, then
    # validated after an RTC rollback.  Its signed timestamp remains structural
    # evidence and must not become an availability kill switch.
    payload["created_at"] = "2099-01-01T00:00:00Z"
    signature = hmac.new(
        key,
        module.JOURNAL_HMAC_DOMAIN + module._canonical_json(payload),
        hashlib.sha256,
    ).hexdigest()
    journal_path.write_bytes(
        module._canonical_json({"payload": payload, "opaque_hmac_sha256": signature})
    )
    monkeypatch.setattr(module, "TRANSACTION_ROOT", tmp_path / "transactions")
    monkeypatch.setattr(module, "_protected_file", lambda path, **_kwargs: path.read_bytes())
    monkeypatch.setattr(module, "_protected_directory", lambda *_args, **_kwargs: None)

    verified = module.validate_journal(
        journal_path,
        key_path,
        expected_transaction=transaction,
        expected_contract=contract,
    )
    assert verified.payload["created_at"] == "2099-01-01T00:00:00Z"


def test_pending_journal_recovery_accepts_only_the_fixed_pending_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_abort_module()
    transaction = "a" * 32
    contract = "b" * 64
    transaction_root = tmp_path / "transactions" / transaction
    transaction_root.mkdir(parents=True)
    journal_path = transaction_root / ".journal.pending"
    key_path = tmp_path / "binding.key"
    key = b"enterprise-adoption-binding-key-32"
    key_path.write_bytes(base64.urlsafe_b64encode(key).rstrip(b"="))
    payload = _journal_payload(module, transaction, contract)
    signature = hmac.new(
        key,
        module.JOURNAL_HMAC_DOMAIN + module._canonical_json(payload),
        hashlib.sha256,
    ).hexdigest()
    journal_path.write_bytes(
        module._canonical_json({"payload": payload, "opaque_hmac_sha256": signature})
    )
    monkeypatch.setattr(module, "TRANSACTION_ROOT", tmp_path / "transactions")
    monkeypatch.setattr(module, "_protected_file", lambda path, **_kwargs: path.read_bytes())
    monkeypatch.setattr(module, "_protected_directory", lambda *_args, **_kwargs: None)

    with pytest.raises(module.AbortError, match="fixed transaction path"):
        module.validate_journal(
            journal_path,
            key_path,
            expected_transaction=transaction,
            expected_contract=contract,
        )
    verified = module.validate_journal(
        journal_path,
        key_path,
        expected_transaction=transaction,
        expected_contract=contract,
        allow_pending_journal=True,
    )
    assert verified.path == journal_path


def test_abort_state_closes_before_migration_command_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_abort_module()
    transaction = "a" * 32
    contract = "b" * 64
    payload = _journal_payload(module, transaction, contract)
    journal = module.Journal(tmp_path / "journal.json", "c" * 64, payload)
    state_path = tmp_path / "install-in-progress.json"
    pending = tmp_path / ".target-pre-migration-abort.pending"
    pending.mkdir()
    state = {
        "schema_version": 2,
        "contract_sha256": contract,
        "runtime_sha256": "d" * 64,
        "release_sha256": "e" * 64,
        "manifest_sha256": payload["target_manifest_sha256"],
        "phase": "prepared",
        "migration_command_invoked": False,
        "operation_mode": "adoption",
        "adoption_transaction_id": transaction,
        "adoption_journal_sha256": journal.sha256,
        "adoption_plan_sha256": payload["plan_sha256"],
        "retirement_receipt_sha256": payload["retirement_receipt_sha256"],
        "target_schema_head": payload["target_schema_head"],
        "legacy_source_schema_head": payload["legacy_source_schema_head"],
    }
    state_path.write_text(json.dumps(state), encoding="utf-8")
    monkeypatch.setattr(module, "INSTALL_STATE", state_path)
    monkeypatch.setattr(module, "_protected_file", lambda path, **_kwargs: path.read_bytes())
    observed, _ = module._read_install_state(journal, pending)
    assert observed is not None and observed["phase"] == "prepared"

    state["phase"] = "migration_invoked"
    state["migration_command_invoked"] = True
    state_path.write_text(json.dumps(state), encoding="utf-8")
    with pytest.raises(module.BoundaryClosed, match="closed the rollback boundary"):
        module._read_install_state(journal, pending)


def _api_preflight_mounts(module: ModuleType) -> list[dict[str, object]]:
    return [
        {
            "Type": "bind",
            "RW": False,
            "Source": str(module.DATA_ROOT / "capacity-probe"),
            "Destination": "/var/lib/kb-capacity",
        },
    ]


def _api_preflight_container(
    module: ModuleType,
    *,
    contract: str,
    transaction: str,
    release_root: Path,
    container_id: str,
) -> dict[str, Any]:
    return {
        "Id": container_id,
        "Image": "sha256:" + "d" * 64,
        "Config": {
            "Image": "127.0.0.1:5000/heyi/api@sha256:" + "e" * 64,
            "Labels": {
                "com.docker.compose.project": module.PROJECT,
                "com.docker.compose.service": "api-preflight",
                "com.docker.compose.oneoff": "True",
                "com.docker.compose.project.config_files": str(
                    release_root / "deploy/tencent/compose.offline.yml"
                ),
                "io.heyi.knowledgebases.owner": module.OWNER,
                "io.heyi.knowledgebases.stack": module.STACK,
                "io.heyi.knowledgebases.contract-sha256": contract,
                "io.heyi.knowledgebases.adoption-transaction": transaction,
            },
        },
        "HostConfig": {"NetworkMode": "none"},
        "State": {"Running": False},
        "Mounts": _api_preflight_mounts(module),
    }


def test_abort_api_preflight_mount_contract_accepts_exact_read_only_capacity_probe() -> None:
    module = _load_abort_module()

    assert module._container_mounts_match_contract(
        "api-preflight",
        _api_preflight_mounts(module),
        Path("/srv/heyi-knowledgebases-offline/releases") / ("b" * 64),
    )


@pytest.mark.parametrize(
    ("mount_index", "field", "value"),
    [
        (0, "Source", "/srv/heyi-knowledgebases-offline/data/capacity-probe-drift"),
        (0, "Destination", "/var/lib/kb-capacity-drift"),
        (0, "RW", True),
    ],
    ids=[
        "capacity-source-drift",
        "capacity-destination-drift",
        "capacity-must-be-read-only",
    ],
)
def test_abort_api_preflight_mount_contract_rejects_drift_or_wrong_access_mode(
    mount_index: int,
    field: str,
    value: object,
) -> None:
    module = _load_abort_module()
    mounts = _api_preflight_mounts(module)
    mounts[mount_index][field] = value

    assert not module._container_mounts_match_contract(
        "api-preflight",
        mounts,
        Path("/srv/heyi-knowledgebases-offline/releases") / ("b" * 64),
    )


def test_abort_docker_inventory_denies_unknown_or_unbound_containers() -> None:
    module = _load_abort_module()
    contract = "b" * 64
    transaction = "a" * 32
    release_root = Path("/srv/heyi-knowledgebases-offline/releases") / contract
    container_id = "c" * 64
    document = _api_preflight_container(
        module,
        contract=contract,
        transaction=transaction,
        release_root=release_root,
        container_id=container_id,
    )

    class FakeRunner:
        def run(self, _argv: tuple[str, ...]) -> str:
            return container_id

        def docker_json(self, _argv: tuple[str, ...]) -> object:
            return [document]

    assert (
        len(
            module._validated_preflight_containers(
                FakeRunner(),
                contract_sha256=contract,
                adoption_transaction=transaction,
                release_root=release_root,
            )
        )
        == 1
    )
    document["Config"]["Labels"]["com.docker.compose.service"] = "migrate"
    with pytest.raises(module.BoundaryClosed, match="unknown target container"):
        module._validated_preflight_containers(
            FakeRunner(),
            contract_sha256=contract,
            adoption_transaction=transaction,
            release_root=release_root,
        )


def test_abort_owner_marker_requires_the_exact_adoption_binding() -> None:
    module = _load_abort_module()
    contract = "b" * 64
    transaction = "a" * 32
    labels = {
        "io.heyi.knowledgebases.owner": module.OWNER,
        "io.heyi.knowledgebases.compose-project": module.PROJECT,
        "io.heyi.knowledgebases.contract-sha256": contract,
        "io.heyi.knowledgebases.adoption-transaction": transaction,
    }

    class FakeRunner:
        marker_present = True

        def run(self, argv: tuple[str, ...], **_kwargs: object) -> str:
            if argv[1:4] == ("volume", "ls", "-q"):
                return module.OWNER_MARKER if self.marker_present else ""
            if argv[1:3] == ("volume", "inspect"):
                return json.dumps([{"Labels": labels}])
            if argv[1:3] == ("ps", "-aq"):
                return ""
            raise AssertionError(argv)

    runner = FakeRunner()
    assert module._remove_owner_marker(
        runner,
        contract_sha256=contract,
        adoption_transaction=transaction,
        execute=False,
    )
    runner.marker_present = False
    assert not module._remove_owner_marker(
        runner,
        contract_sha256=contract,
        adoption_transaction=transaction,
        execute=False,
    )
    runner.marker_present = True
    labels["io.heyi.knowledgebases.adoption-transaction"] = "none"
    with pytest.raises(module.BoundaryClosed, match="owner marker binding differs"):
        module._remove_owner_marker(
            FakeRunner(),
            contract_sha256=contract,
            adoption_transaction=transaction,
            execute=False,
        )


def test_abort_never_crosses_a_target_network_or_project_volume(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_abort_module()
    monkeypatch.setattr(
        module,
        "_project_resource_counts",
        lambda _runner: {
            "containers": 0,
            "networks": 1,
            "project_volumes": 0,
            "owner_marker": 1,
        },
    )

    with pytest.raises(module.BoundaryClosed, match="network or volume"):
        module._assert_no_network_or_project_volume(object())


def test_abort_dry_run_accepts_exact_partial_systemd_archive_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_abort_module()
    release_root = tmp_path / "release"
    source_root = release_root / "deploy" / "tencent"
    systemd_root = tmp_path / "systemd"
    pending = tmp_path / "pending"
    source_root.mkdir(parents=True)
    systemd_root.mkdir()
    archive = pending / "archived" / "systemd"
    archive.mkdir(parents=True)
    for unit in (module.RECONCILE_SERVICE, module.RECONCILE_TIMER):
        (source_root / unit).write_text(unit, encoding="utf-8")
    (systemd_root / module.RECONCILE_SERVICE).write_text(module.RECONCILE_SERVICE, encoding="utf-8")
    (archive / module.RECONCILE_TIMER).write_text(module.RECONCILE_TIMER, encoding="utf-8")
    monkeypatch.setattr(module, "SYSTEMD_ROOT", systemd_root)
    monkeypatch.setattr(module, "_protected_file", lambda path, **_kwargs: path.read_bytes())

    result = module._restore_reconcile_baseline(
        object(), release_root=release_root, pending=pending, execute=False
    )
    assert result == {
        module.RECONCILE_SERVICE: {
            "load_state": "not-found",
            "active_state": "inactive",
            "unit_file_state": "not-found",
        },
        module.RECONCILE_TIMER: {
            "load_state": "not-found",
            "active_state": "inactive",
            "unit_file_state": "not-found",
        },
    }


def test_abort_retry_daemon_reloads_after_both_units_were_already_archived(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_abort_module()
    release_root = tmp_path / "release"
    source_root = release_root / "deploy" / "tencent"
    systemd_root = tmp_path / "systemd"
    pending = tmp_path / "pending"
    archive = pending / "archived" / "systemd"
    source_root.mkdir(parents=True)
    systemd_root.mkdir()
    archive.mkdir(parents=True)
    for unit in (module.RECONCILE_SERVICE, module.RECONCILE_TIMER):
        (source_root / unit).write_text(unit, encoding="utf-8")
        (archive / unit).write_text(unit, encoding="utf-8")
    monkeypatch.setattr(module, "SYSTEMD_ROOT", systemd_root)
    monkeypatch.setattr(module, "_protected_file", lambda path, **_kwargs: path.read_bytes())
    monkeypatch.setattr(module, "_fsync_directory", lambda _path: None)

    class FakeRunner:
        reloaded = False

        def run(self, argv: tuple[str, ...], **_kwargs: object) -> str:
            if argv[1] in {"disable", "stop"}:
                return ""
            if argv[1] == "daemon-reload":
                self.reloaded = True
                return ""
            if argv[1] == "show":
                assert self.reloaded
                if "--property=LoadState" in argv:
                    return "not-found"
                if "--property=ActiveState" in argv:
                    return "inactive"
                if "--property=UnitFileState" in argv:
                    return "not-found"
            raise AssertionError(argv)

    runner = FakeRunner()
    module._restore_reconcile_baseline(
        runner, release_root=release_root, pending=pending, execute=True
    )
    assert runner.reloaded


def test_abort_host_evidence_is_sealed_read_only_before_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_abort_module()
    transaction = "a" * 32
    contract = "b" * 64
    baseline = tmp_path / "baseline.json"
    baseline.write_text("baseline", encoding="utf-8")
    payload = _journal_payload(module, transaction, contract)
    payload["host_isolation_baseline_sha256"] = hashlib.sha256(baseline.read_bytes()).hexdigest()
    journal = module.Journal(tmp_path / "journal.json", "c" * 64, payload)
    pending = tmp_path / "pending"
    pending.mkdir()
    observed_modes: list[frozenset[int]] = []

    class FakeRunner:
        def run(self, argv: tuple[str, ...], **_kwargs: object) -> str:
            output = Path(argv[argv.index("--output") + 1])
            output.write_text(
                json.dumps({"status": "PASS", "change_count": 0}),
                encoding="utf-8",
            )
            return ""

    def protected(path: Path, *, modes: frozenset[int], **_kwargs: object) -> bytes:
        observed_modes.append(modes)
        return path.read_bytes()

    monkeypatch.setattr(module, "_protected_file", protected)
    monkeypatch.setattr(module, "_fsync_directory", lambda _path: None)
    result = module._host_isolation_verification(
        FakeRunner(),
        journal,
        pending,
        release_root=tmp_path / "release",
        baseline=baseline,
        hmac_key=tmp_path / "host.key",
    )

    assert observed_modes == [frozenset({0o600}), frozenset({0o400})]
    assert result["status"] == "PASS"
    assert (
        result["sha256"]
        == hashlib.sha256((pending / "host-isolation-after-abort.json").read_bytes()).hexdigest()
    )


def test_abort_host_evidence_retry_atomically_replaces_partial_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_abort_module()
    transaction = "a" * 32
    contract = "b" * 64
    baseline = tmp_path / "baseline.json"
    baseline.write_text("baseline", encoding="utf-8")
    payload = _journal_payload(module, transaction, contract)
    payload["host_isolation_baseline_sha256"] = hashlib.sha256(baseline.read_bytes()).hexdigest()
    journal = module.Journal(tmp_path / "journal.json", "c" * 64, payload)
    pending = tmp_path / "pending"
    pending.mkdir()
    report = pending / "host-isolation-after-abort.json"
    partial = pending / ".host-isolation-after-abort.pending"
    report.write_text(json.dumps({"status": "STALE", "change_count": 1}), encoding="utf-8")
    partial.write_text("partial", encoding="utf-8")

    class FakeRunner:
        def run(self, argv: tuple[str, ...], **_kwargs: object) -> str:
            output = Path(argv[argv.index("--output") + 1])
            assert output == partial
            assert not output.exists()
            output.write_text(
                json.dumps({"status": "PASS", "change_count": 0}),
                encoding="utf-8",
            )
            return ""

    monkeypatch.setattr(module, "_protected_file", lambda path, **_kwargs: path.read_bytes())
    monkeypatch.setattr(module, "_fsync_directory", lambda _path: None)
    result = module._host_isolation_verification(
        FakeRunner(),
        journal,
        pending,
        release_root=tmp_path / "release",
        baseline=baseline,
        hmac_key=tmp_path / "host.key",
    )

    assert result["status"] == "PASS"
    assert not partial.exists()
    assert json.loads(report.read_text(encoding="utf-8")) == {
        "status": "PASS",
        "change_count": 0,
    }


def test_abort_retains_only_contract_bound_inert_recovery_helpers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_abort_module()
    release_root = tmp_path / "release"
    source_root = release_root / "deploy" / "tencent"
    recovery_root = tmp_path / "recovery"
    source_root.mkdir(parents=True)
    recovery_root.mkdir()
    for name in ("offline-recovery-dispatcher.sh", "offline-recovery-state.py"):
        (source_root / name).write_text(f"trusted-{name}", encoding="utf-8")
        (recovery_root / name).write_text(f"trusted-{name}", encoding="utf-8")
    monkeypatch.setattr(module, "RECOVERY_ROOT", recovery_root)
    monkeypatch.setattr(module, "_protected_directory", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(module, "_protected_file", lambda path, **_kwargs: path.read_bytes())

    module._validate_inert_recovery_assets(release_root)
    (recovery_root / "offline-recovery-state.py").write_text("tampered", encoding="utf-8")
    with pytest.raises(module.BoundaryClosed, match="differs from the target release"):
        module._validate_inert_recovery_assets(release_root)


def test_abort_retry_revalidates_final_receipt_then_preserves_dry_run_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_abort_module()
    transaction = "a" * 32
    contract = "b" * 64
    transaction_root = tmp_path / "transactions" / transaction
    final = transaction_root / "target-pre-migration-abort"
    final.mkdir(parents=True)
    release_root = tmp_path / "releases"
    (release_root / contract).mkdir(parents=True)
    journal_path = transaction_root / "journal.json"
    journal = module.Journal(
        journal_path,
        "c" * 64,
        _journal_payload(module, transaction, contract),
    )
    monkeypatch.setattr(module, "RELEASE_ROOT", release_root)
    monkeypatch.setattr(module, "_require_root_linux", lambda: None)
    monkeypatch.setattr(module, "_self_bound_contract", lambda: contract)
    monkeypatch.setattr(
        module,
        "_validate_evidence_trust_root",
        lambda *_args, **_kwargs: "d" * 64,
    )
    monkeypatch.setattr(module, "validate_journal", lambda *_args, **_kwargs: journal)
    monkeypatch.setattr(module, "_protected_file", lambda path, **_kwargs: path.read_bytes())
    monkeypatch.setattr(
        module,
        "_validate_published_receipt",
        lambda *_args, **_kwargs: {"last_install_phase": "preflight_passed"},
    )
    arguments = module.AbortArguments(
        journal=journal_path,
        binding_key=tmp_path / "binding.key",
        host_baseline=tmp_path / "baseline.json",
        host_hmac_key=tmp_path / "host.key",
        execute=False,
        project=module.PROJECT,
        contract=contract,
        adoption_transaction=transaction,
        plan="1" * 64,
        retirement_receipt="4" * 64,
        restore_boundary=module.RESTORE_BOUNDARY,
    )

    result = module.abort_pre_migration(arguments, runner=object())
    assert result == {
        "schema_version": 1,
        "status": "dry-run",
        "project": module.PROJECT,
        "adoption_transaction_id": transaction,
        "contract_sha256": contract,
        "last_install_phase": "preflight_passed",
        "preflight_container_ids": [],
        "owner_marker_present": False,
        "migration_command_invoked": False,
        "restore_boundary": module.RESTORE_BOUNDARY,
    }


def test_published_abort_receipt_rejects_resource_or_evidence_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_abort_module()
    transaction = "a" * 32
    contract = "b" * 64
    journal = module.Journal(
        tmp_path / "journal.json",
        "c" * 64,
        _journal_payload(module, transaction, contract),
    )
    final = tmp_path / "target-pre-migration-abort"
    final.mkdir()
    receipt_path = final / "receipt.json"
    signature_path = final / "receipt.sig"
    signature_path.write_bytes(b"signature")
    receipt = {
        "schema_version": 1,
        "kind": "heyi-target-pre-migration-abort-receipt",
        "status": "aborted_pre_migration",
        "project": module.PROJECT,
        "issued_at": datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z"),
        "adoption_transaction_id": transaction,
        "journal_sha256": journal.sha256,
        "plan_sha256": journal.payload["plan_sha256"],
        "retirement_receipt_sha256": journal.payload["retirement_receipt_sha256"],
        "target_contract_sha256": contract,
        "target_manifest_sha256": journal.payload["target_manifest_sha256"],
        "target_schema_head": journal.payload["target_schema_head"],
        "legacy_source_schema_head": journal.payload["legacy_source_schema_head"],
        "last_install_phase": "not_started",
        "migration_command_invoked": False,
        "active_release_present": False,
        "installed_receipt_present": False,
        "removed_preflight_container_ids": [],
        "removed_owner_marker_volume": False,
        "archived_install_state": None,
        "archived_cutover_intent": None,
        "reconcile_baseline": journal.payload["reconcile_baseline"],
        "reconcile_result": journal.payload["reconcile_baseline"],
        "target_resource_counts_after": {
            "containers": 0,
            "networks": 0,
            "project_volumes": 0,
            "owner_marker": 0,
        },
        "host_isolation_verification": {
            "path": str(final / "host-isolation-after-abort.json"),
            "sha256": "d" * 64,
            "status": "PASS",
        },
        "preserved_bind_root": str(module.DATA_ROOT),
        "bind_data_deleted": False,
        "named_volumes_deleted": False,
        "global_actions": [],
        "restore_boundary": module.RESTORE_BOUNDARY,
    }
    receipt_path.write_bytes(module._canonical_json(receipt))
    monkeypatch.setattr(module, "_protected_file", lambda path, **_kwargs: path.read_bytes())
    monkeypatch.setattr(module, "_verify_signature", lambda *_args, **_kwargs: None)

    assert module._validate_published_receipt(object(), final, journal, tmp_path / "pub") == receipt
    receipt["target_resource_counts_after"]["networks"] = 1
    receipt_path.write_bytes(module._canonical_json(receipt))
    with pytest.raises(module.AbortError, match="target resources remain"):
        module._validate_published_receipt(object(), final, journal, tmp_path / "pub")


def _installed_v1(contract: str) -> dict[str, object]:
    return {
        "schema_version": 1,
        "contract_sha256": contract,
        "runtime_sha256": "1" * 64,
        "release_sha256": "2" * 64,
        "manifest_sha256": "3" * 64,
        "phase": "completed",
    }


def _installed_v2_adoption(contract: str) -> dict[str, object]:
    return {
        **_installed_v1(contract),
        "schema_version": 2,
        "migration_command_invoked": True,
        "operation_mode": "adoption",
        "adoption_transaction_id": "4" * 32,
        "adoption_journal_sha256": "5" * 64,
        "adoption_plan_sha256": "6" * 64,
        "retirement_receipt_sha256": "7" * 64,
        "target_schema_head": "20260715_0021",
        "legacy_source_schema_head": "20260714_0020",
    }


def _prepare_installed_validator(
    module: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, document: object
) -> Path:
    contract = "a" * 64
    state_root = tmp_path / "state"
    state_root.mkdir()
    path = state_root / f"installed-{contract}.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.setattr(module, "STATE_ROOT", state_root)
    monkeypatch.setattr(module, "_require_root", lambda: None)
    monkeypatch.setattr(module, "_regular_root_file", lambda target, _mode: target.read_bytes())
    return path


def test_installed_receipt_accepts_historical_v1_read_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_state_module()
    contract = "a" * 64
    receipt = _installed_v1(contract)
    path = _prepare_installed_validator(module, tmp_path, monkeypatch, receipt)

    assert module.validate_installed_receipt(path, "20260715_0021") == receipt


def test_installed_receipt_accepts_fully_bound_v2_adoption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_state_module()
    contract = "a" * 64
    receipt = _installed_v2_adoption(contract)
    path = _prepare_installed_validator(module, tmp_path, monkeypatch, receipt)

    assert module.validate_installed_receipt(path, "20260715_0021") == receipt


def test_installed_receipt_accepts_v2_standalone_without_adoption_mix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_state_module()
    contract = "a" * 64
    receipt = _installed_v2_adoption(contract)
    receipt.update(
        {
            "operation_mode": "standalone",
            "adoption_transaction_id": "none",
            "adoption_journal_sha256": "none",
            "adoption_plan_sha256": "none",
            "retirement_receipt_sha256": "none",
            "legacy_source_schema_head": "none",
        }
    )
    path = _prepare_installed_validator(module, tmp_path, monkeypatch, receipt)

    assert module.validate_installed_receipt(path, "20260715_0021") == receipt


@pytest.mark.parametrize("mutation", ["tampered", "mixed", "unknown"])
def test_installed_receipt_rejects_tampered_mixed_or_unknown_v2(
    mutation: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_state_module()
    contract = "a" * 64
    receipt = _installed_v2_adoption(contract)
    if mutation == "tampered":
        receipt["adoption_journal_sha256"] = "none"
    elif mutation == "mixed":
        receipt["schema_version"] = 1
    else:
        receipt["unexpected"] = True
    path = _prepare_installed_validator(module, tmp_path, monkeypatch, receipt)

    with pytest.raises(module.StateError):
        module.validate_installed_receipt(path, "20260715_0021")
