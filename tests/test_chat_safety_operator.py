from __future__ import annotations

import errno
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPOSITORY = Path(__file__).resolve().parents[1]
DEPLOY = REPOSITORY / "deploy/tencent"
SENTINEL_HELPER = DEPLOY / "chat-safety-sentinel.py"
CLEAR_SCRIPT = DEPLOY / "clear-chat-safety-poison.sh"
RECONCILER = DEPLOY / "reconcile-offline.sh"
DISPATCHER = DEPLOY / "offline-recovery-dispatcher.sh"
OPERATION_COMMON = DEPLOY / "offline-operation-common.sh"
PREFLIGHT = DEPLOY / "preflight-offline.sh"
INSTALL = DEPLOY / "install-offline.sh"
DEPLOY_SCRIPT = DEPLOY / "deploy-offline.sh"


def _sentinel_helper_module() -> ModuleType:
    name = "chat_safety_sentinel_under_test"
    spec = importlib.util.spec_from_file_location(name, SENTINEL_HELPER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _posix_id(name: str) -> int:
    getter = getattr(os, name, None)
    if not callable(getter):
        raise RuntimeError(f"{name} is unavailable")
    return int(getter())


def test_status_reports_only_enoent_as_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _sentinel_helper_module()
    sentinel = Path("/protected/chat-safety/poison.json")
    monkeypatch.setattr(
        module,
        "_validate_parent",
        lambda *_args, **_kwargs: sentinel.parent,
    )

    def missing(_path: Path) -> os.stat_result:
        raise FileNotFoundError(errno.ENOENT, "missing", str(sentinel))

    monkeypatch.setattr(Path, "lstat", missing)

    assert module.status(sentinel, expected_uid=10001, expected_gid=10001) is None


@pytest.mark.parametrize(
    ("error_number", "error_type"),
    [
        pytest.param(errno.EACCES, PermissionError, id="eacces"),
        pytest.param(errno.EIO, OSError, id="eio"),
    ],
)
def test_status_never_misclassifies_unreadable_state_as_absent(
    monkeypatch: pytest.MonkeyPatch,
    error_number: int,
    error_type: type[OSError],
) -> None:
    module = _sentinel_helper_module()
    sentinel = Path("/protected/chat-safety/poison.json")
    monkeypatch.setattr(
        module,
        "_validate_parent",
        lambda *_args, **_kwargs: sentinel.parent,
    )

    def unreadable(_path: Path) -> os.stat_result:
        raise error_type(error_number, "injected status failure", str(sentinel))

    monkeypatch.setattr(Path, "lstat", unreadable)

    with pytest.raises(error_type) as raised:
        module.status(sentinel, expected_uid=10001, expected_gid=10001)
    assert raised.value.errno == error_number


def test_status_never_misclassifies_invalid_existing_state_as_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _sentinel_helper_module()
    sentinel = Path("/protected/chat-safety/poison.json")
    sentinel_error = module.SentinelError("injected invalid sentinel")
    monkeypatch.setattr(
        module,
        "_validate_parent",
        lambda *_args, **_kwargs: sentinel.parent,
    )
    monkeypatch.setattr(Path, "lstat", lambda _path: object())

    def reject_invalid(*_args: object, **_kwargs: object) -> None:
        raise sentinel_error

    monkeypatch.setattr(module, "verify", reject_invalid)

    with pytest.raises(module.SentinelError, match="invalid sentinel"):
        module.status(sentinel, expected_uid=10001, expected_gid=10001)


@pytest.mark.parametrize("fault_target", ["final", "temporary"])
@pytest.mark.parametrize(
    ("error_number", "error_type"),
    [
        pytest.param(errno.EACCES, PermissionError, id="eacces"),
        pytest.param(errno.EIO, OSError, id="eio"),
    ],
)
def test_materialize_never_treats_metadata_fault_as_absence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault_target: str,
    error_number: int,
    error_type: type[OSError],
) -> None:
    module = _sentinel_helper_module()
    sentinel = tmp_path / "chat-safety" / "poison.json"
    temporary = sentinel.parent / ".poison.json.materialize"
    real_lstat = Path.lstat
    monkeypatch.setattr(
        module,
        "_validate_parent",
        lambda *_args, **_kwargs: sentinel.parent,
    )

    def faulted_lstat(path: Path) -> os.stat_result:
        selected = sentinel if fault_target == "final" else temporary
        if path == selected:
            raise error_type(error_number, "injected metadata fault", str(path))
        if path == sentinel:
            raise FileNotFoundError(errno.ENOENT, "missing", str(path))
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", faulted_lstat)

    with pytest.raises(error_type) as raised:
        module.materialize(
            sentinel,
            expected_uid=10001,
            expected_gid=10001,
            reason="chat_safety_persistence_failed",
            error_class="WorkerExit78",
        )
    assert raised.value.errno == error_number


@pytest.mark.skipif(os.name != "posix", reason="strict uid/mode checks are Linux-only")
def test_sentinel_helper_verifies_digest_and_clears_exact_inode(tmp_path: Path) -> None:
    directory = tmp_path / "chat-safety"
    directory.mkdir(mode=0o700)
    sentinel = directory / "poison.json"
    payload = json.dumps(
        {
            "schema_version": 1,
            "created_at": "2026-07-16T00:00:00+00:00",
            "pid": 123,
            "reason": "test",
            "error_class": None,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    sentinel.write_bytes(payload)
    sentinel.chmod(0o600)
    digest = hashlib.sha256(payload).hexdigest()
    uid = _posix_id("geteuid")
    gid = _posix_id("getegid")

    verified = subprocess.run(
        [
            sys.executable,
            "-I",
            str(SENTINEL_HELPER),
            "verify",
            str(sentinel),
            "--expected-uid",
            str(uid),
            "--expected-gid",
            str(gid),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert verified.stdout.strip() == digest

    cleared = subprocess.run(
        [
            sys.executable,
            "-I",
            str(SENTINEL_HELPER),
            "clear",
            str(sentinel),
            "--expected-uid",
            str(uid),
            "--expected-gid",
            str(gid),
            "--expected-sha256",
            digest,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert cleared.stdout.strip() == digest
    assert sentinel.exists() is False


@pytest.mark.skipif(os.name != "posix", reason="strict hard-link checks are Linux-only")
def test_sentinel_helper_rejects_hard_links(tmp_path: Path) -> None:
    directory = tmp_path / "chat-safety"
    directory.mkdir(mode=0o700)
    sentinel = directory / "poison.json"
    sentinel.write_text(
        '{"created_at":"x","error_class":null,"pid":1,"reason":"test","schema_version":1}',
        encoding="utf-8",
    )
    sentinel.chmod(0o600)
    os.link(sentinel, directory / "linked.json")

    rejected = subprocess.run(
        [
            sys.executable,
            "-I",
            str(SENTINEL_HELPER),
            "verify",
            str(sentinel),
            "--expected-uid",
            str(_posix_id("geteuid")),
            "--expected-gid",
            str(_posix_id("getegid")),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert rejected.returncode == 65
    assert "metadata is invalid" in rejected.stderr


@pytest.mark.skipif(os.name != "posix", reason="strict ownership checks are Linux-only")
def test_sentinel_helper_materializes_root_observed_worker_exit(tmp_path: Path) -> None:
    directory = tmp_path / "chat-safety"
    directory.mkdir(mode=0o700)
    sentinel = directory / "poison.json"
    uid = _posix_id("geteuid")
    gid = _posix_id("getegid")

    materialized = subprocess.run(
        [
            sys.executable,
            "-I",
            str(SENTINEL_HELPER),
            "materialize",
            str(sentinel),
            "--expected-uid",
            str(uid),
            "--expected-gid",
            str(gid),
            "--reason",
            "chat_safety_persistence_failed",
            "--error-class",
            "WorkerExit78",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    digest = materialized.stdout.strip()
    payload = json.loads(sentinel.read_text(encoding="utf-8"))

    assert len(digest) == 64
    assert payload["pid"] == 0
    assert payload["reason"] == "chat_safety_persistence_failed"
    assert payload["error_class"] == "WorkerExit78"
    assert stat.S_IMODE(sentinel.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name != "posix", reason="strict ownership checks are Linux-only")
def test_operator_marks_run_state_clean_before_clearing_exact_poison(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "chat-safety"
    directory.mkdir(mode=0o700)
    sentinel = directory / "poison.json"
    uid = _posix_id("geteuid")
    gid = _posix_id("getegid")
    materialized = subprocess.run(
        [
            sys.executable,
            "-I",
            str(SENTINEL_HELPER),
            "materialize",
            str(sentinel),
            "--expected-uid",
            str(uid),
            "--expected-gid",
            str(gid),
            "--reason",
            "chat_safety_persistence_failed",
            "--error-class",
            "WorkerExit78",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    poison_digest = materialized.stdout.strip()

    marked = subprocess.run(
        [
            sys.executable,
            "-I",
            str(SENTINEL_HELPER),
            "mark-run-clean",
            str(sentinel),
            "--expected-uid",
            str(uid),
            "--expected-gid",
            str(gid),
            "--expected-sha256",
            poison_digest,
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    run_state = directory / "run-state.json"
    payload = json.loads(run_state.read_text(encoding="utf-8"))
    assert len(marked.stdout.strip()) == 64
    assert payload["schema_version"] == 1
    assert payload["phase"] == "clean"
    assert payload["pid"] == 0
    assert stat.S_IMODE(run_state.stat().st_mode) == 0o600
    assert hashlib.sha256(sentinel.read_bytes()).hexdigest() == poison_digest


@pytest.mark.skipif(os.name != "posix", reason="hard-link crash recovery is POSIX-only")
def test_materialize_recovers_from_crash_after_no_clobber_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _sentinel_helper_module()
    directory = tmp_path / "chat-safety"
    directory.mkdir(mode=0o700)
    sentinel = directory / "poison.json"
    temporary = directory / ".poison.json.materialize"
    uid = _posix_id("geteuid")
    gid = _posix_id("getegid")
    real_link = os.link

    class SimulatedPowerLoss(BaseException):
        pass

    def publish_then_crash(
        source: os.PathLike[str] | str,
        target: os.PathLike[str] | str,
        *,
        follow_symlinks: bool = True,
    ) -> None:
        real_link(source, target, follow_symlinks=follow_symlinks)
        raise SimulatedPowerLoss

    monkeypatch.setattr(module.os, "link", publish_then_crash)

    with pytest.raises(SimulatedPowerLoss):
        module.materialize(
            sentinel,
            expected_uid=uid,
            expected_gid=gid,
            reason="chat_safety_persistence_failed",
            error_class="WorkerExit78",
        )

    assert sentinel.is_file()
    assert temporary.is_file()
    published = sentinel.stat()
    staged = temporary.stat()
    assert (published.st_dev, published.st_ino, published.st_nlink) == (
        staged.st_dev,
        staged.st_ino,
        2,
    )

    monkeypatch.setattr(module.os, "link", real_link)
    recovered = module.materialize(
        sentinel,
        expected_uid=uid,
        expected_gid=gid,
        reason="chat_safety_persistence_failed",
        error_class="WorkerExit78",
    )

    assert len(recovered.digest) == 64
    assert sentinel.stat().st_nlink == 1
    assert temporary.exists() is False


def test_operator_clear_is_locked_digest_bound_and_audited() -> None:
    source = CLEAR_SCRIPT.read_text(encoding="utf-8")

    assert "offline_acquire_lock chat-safety-clear" in source
    assert 'selection not in {"intent","active"}' in source
    assert '"state_selection","state_operation","contract_sha256","transaction_id"' in source
    assert "--expected-sha256" in source
    assert "chat-safety-reconciliation.json" in source
    assert "processing_claims_reconciled" in source
    assert "provider_usage_reconciled" in source
    assert "audit_log_reviewed" in source
    assert "WHERE status = '\\''PROCESSING'\\''" in source
    assert '"phase":sys.argv[2]' in source
    assert "authorized" in source
    assert "cleared" in source
    assert "reconciliation-$evidence_digest.json" in source
    assert "worker-exit-$api_witness_exit_code-$api_witness_id.json" in source
    assert 'docker rm "$api_witness_id"' in source


def test_clear_pending_transaction_is_durable_and_recovery_fenced() -> None:
    clear = CLEAR_SCRIPT.read_text(encoding="utf-8")
    reconciler = RECONCILER.read_text(encoding="utf-8")
    pending_invocations = [
        match.start() for match in re.finditer(r'python3 -I - "\$clear_pending"', clear)
    ]

    assert len(pending_invocations) == 3
    pending_status, pending_prepare, pending_commit = pending_invocations
    authorized_audit = clear.index('"$audit_file" authorized')
    witness_enumeration = clear.index("api_witness_ids=")
    witness_consumption = clear.index('docker rm "$api_witness_id"', witness_enumeration)
    clean_handoff = clear.index(
        "create --pull never --no-build --no-deps api",
        witness_consumption,
    )
    clean_handoff_verified = clear.index(
        '[ "$clean_api_running" = false ] && [ "$clean_api_exit_code" = 0 ]',
        clean_handoff,
    )
    run_state_commit = clear.index(
        "mark-run-clean",
        clean_handoff_verified,
    )
    sentinel_commit = clear.index(
        '"$script_dir/chat-safety-sentinel.py" clear',
        run_state_commit,
    )
    cleared_audit = clear.index('"$audit_file" cleared')
    completion = clear.index('echo "chat-safety-clear:', pending_commit)

    assert (
        pending_status
        < authorized_audit
        < pending_prepare
        < witness_enumeration
        < witness_consumption
        < clean_handoff
        < clean_handoff_verified
        < run_state_commit
        < sentinel_commit
        < cleared_audit
        < pending_commit
        < completion
    )
    prepare = clear[pending_prepare:witness_enumeration]
    assert '"sentinel_sha256"' in prepare
    assert '"evidence_sha256"' in prepare
    assert '"contract_sha256"' in prepare
    assert '"transaction_id"' in prepare
    assert "os.O_EXCL" in prepare
    assert "os.fsync(fd)" in prepare
    assert "os.fsync(directory_fd)" in prepare
    assert 'temporary=path.with_name(f".{path.name}.{os.getpid()}.tmp")' in prepare
    assert "os.rename(temporary,path)" in prepare
    assert (
        prepare.index("os.fsync(fd)")
        < prepare.index("os.rename(temporary,path)")
        < prepare.index("os.fsync(directory_fd)")
    )
    handoff = clear[clean_handoff:sentinel_commit]
    assert "clean API handoff ownership changed" in handoff
    assert "clean API image reference is not pinned" in handoff
    assert "clean API handoff image changed" in handoff

    commit = clear[pending_commit:completion]
    assert "os.unlink(path)" in commit
    assert commit.index("os.unlink(path)") < commit.index("os.fsync(directory_fd)")

    hold_start = reconciler.index("enter_chat_safety_hold_if_present() {")
    hold = reconciler[hold_start : reconciler.index("\nhandle_exit() {", hold_start)]
    assert "chat-safety-clear-pending.json" in reconciler
    assert "chat_safety_clear_pending" in hold
    assert hold.index("chat_safety_clear_pending") < hold.index("absent)")
    assert "stop_sensitive_services" in hold
    assert "maintenance-page" in hold


def test_resumed_clear_reuses_durable_authorization_without_expiring_at_24_hours() -> None:
    source = CLEAR_SCRIPT.read_text(encoding="utf-8")
    evidence_start = source.index("evidence_fields=$(python3")
    authorization_start = source.index('if [ "$resume_pending" != true ]; then')
    pending_prepare = source.index('python3 -I - "$clear_pending" "$sentinel_present"')
    evidence = source[evidence_start:authorization_start]
    authorization = source[authorization_start:pending_prepare]

    assert 'resume=sys.argv[7] == "true"' in evidence
    assert "(not resume and now - captured > dt.timedelta(hours=24))" in evidence
    assert "(resume and digest != pending_evidence)" in evidence
    assert '"$audit_file" authorized' in authorization
    assert authorization.count('"$audit_file" authorized') == 1
    assert authorization.rstrip().endswith("fi")


def test_pending_parsers_use_three_state_lstat_without_suppressed_metadata_errors() -> None:
    clear = CLEAR_SCRIPT.read_text(encoding="utf-8")
    reconciler = RECONCILER.read_text(encoding="utf-8")
    clear_status_start = clear.index('pending_status=$(python3 -I - "$clear_pending"')
    clear_status_end = clear.index(
        ") || offline_fail chat-safety-clear",
        clear_status_start,
    )
    clear_status = clear[clear_status_start:clear_status_end]
    reconcile_status_start = reconciler.index(
        'clear_pending_status=$(python3 -I - "$chat_safety_clear_pending"'
    )
    reconcile_status_end = reconciler.index(
        ") || offline_fail recovery",
        reconcile_status_start,
    )
    reconcile_status = reconciler[reconcile_status_start:reconcile_status_end]

    for parser in (clear_status, reconcile_status):
        assert "except FileNotFoundError:" in parser
        assert "except OSError:" in parser
        assert ".exists(" not in parser
        assert ".is_symlink(" not in parser


def test_dispatcher_fail_closes_after_any_recovery_worker_failure() -> None:
    source = DISPATCHER.read_text(encoding="utf-8")
    worker_call = source.index('if sh "$worker"')
    capture_status = source.index("worker_status=$?", worker_call)
    failure_notice = source.index(
        "selected recovery worker failed; isolating the business boundary",
        capture_status,
    )
    fail_closed = source.index("fail_closed_project || exit 71", failure_notice)
    propagate_status = source.index('exit "$worker_status"', fail_closed)

    assert worker_call < capture_status < failure_notice < fail_closed < propagate_status
    assert 'exec sh "$worker"' not in source


@pytest.mark.parametrize("exit_code", [1, 78, 137, 255])
@pytest.mark.skipif(os.name != "posix", reason="strict ownership checks are Linux-only")
def test_nonzero_api_exit_matrix_is_never_treated_as_clean(
    tmp_path: Path,
    exit_code: int,
) -> None:
    reconciler = RECONCILER.read_text(encoding="utf-8")
    clear = CLEAR_SCRIPT.read_text(encoding="utf-8")
    witness = reconciler.split("materialize_api_persistence_witness() {", 1)[1].split(
        "\n}",
        1,
    )[0]

    assert '[ "$api_running" = false ] && [ "$api_exit_code" -ne 0 ]' in witness
    assert '[ "$api_exit_code" -eq 78 ] && witness_reason=chat_safety_persistence_failed' in witness
    assert "witness_reason=api_worker_abnormal_exit" in witness
    assert '"WorkerExit$api_exit_code"' in witness
    assert '1 <= document["exit_code"] <= 255' in clear

    directory = tmp_path / f"chat-safety-{exit_code}"
    directory.mkdir(mode=0o700)
    sentinel = directory / "poison.json"
    reason = "chat_safety_persistence_failed" if exit_code == 78 else "api_worker_abnormal_exit"
    materialized = subprocess.run(
        [
            sys.executable,
            "-I",
            str(SENTINEL_HELPER),
            "materialize",
            str(sentinel),
            "--expected-uid",
            str(_posix_id("geteuid")),
            "--expected-gid",
            str(_posix_id("getegid")),
            "--reason",
            reason,
            "--error-class",
            f"WorkerExit{exit_code}",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert len(materialized.stdout.strip()) == 64
    payload = json.loads(sentinel.read_text(encoding="utf-8"))
    assert payload["reason"] == reason
    assert payload["error_class"] == f"WorkerExit{exit_code}"


def test_pending_clear_marker_blocks_every_mutating_entry_point() -> None:
    common = OPERATION_COMMON.read_text(encoding="utf-8")
    gate = common.split("offline_require_no_chat_safety_poison() {", 1)[1].split(
        "\n}",
        1,
    )[0]

    assert "chat-safety-clear-pending.json" in gate
    assert "chat safety clear transaction is pending; mutation remains blocked" in gate
    for script in (PREFLIGHT, INSTALL, DEPLOY_SCRIPT):
        source = script.read_text(encoding="utf-8")
        assert "offline_require_no_chat_safety_poison" in source


def test_missing_api_recovery_is_selection_aware_and_safety_gated() -> None:
    source = RECONCILER.read_text(encoding="utf-8")
    witness = source.split("materialize_api_persistence_witness() {", 1)[1].split(
        "\n}",
        1,
    )[0]
    missing_branch = witness.index('if [ "$#" -eq 0 ]; then')
    active_missing = witness.index('if [ "$selection" = active ]; then', missing_branch)
    missing_poison = witness.index("--reason api_worker_missing", active_missing)
    missing_return = witness.index("return 0", missing_poison)
    intent_start = source.index('if [ "$selection" = intent ]; then')
    committed_start = source.index("# A committed active receipt", intent_start)
    intent_branch = source[intent_start:committed_start]

    assert missing_branch < active_missing < missing_poison < missing_return
    assert "--error-class WorkerMissing" in witness[missing_poison:missing_return]
    assert "maintenance-page" in intent_branch
    assert "exit 0" in intent_branch
    assert " api " not in intent_branch
    assert " proxy " not in intent_branch
    assert '[ "$api_running" = false ] && [ "$api_exit_code" -ne 0 ]' in witness
    assert '[ "$api_exit_code" -eq 0 ]' not in witness

    active_api_start = source.index(
        "postgres redis minio minio-init minio-multipart-gc clamd api maintenance web",
        committed_start,
    )
    active_gate = source.rindex(
        "enter_chat_safety_hold_if_present",
        committed_start,
        active_api_start,
    )
    assert committed_start < active_gate < active_api_start


def test_reconciler_holds_maintenance_before_any_automatic_repair() -> None:
    source = RECONCILER.read_text(encoding="utf-8")
    sentinel_branch = source.index(
        "chat_safety_sentinel=$OFFLINE_PERSISTENT_ROOT/data/chat-safety/poison.json"
    )
    repair_branch = source.index("# A committed active receipt")
    automatic_up = source.index(
        'offline_compose recovery "$contract_dir" \\\n'
        "    up -d --pull never --no-build --wait --wait-timeout 300"
    )

    assert sentinel_branch < repair_branch < automatic_up
    fenced = source[sentinel_branch:repair_branch]
    assert "chat-safety-sentinel.py" in fenced
    assert "stop_sensitive_services" in fenced
    assert "maintenance-page" in fenced
    assert "chat_safety_persistence_failed" in fenced
    assert '"WorkerExit$api_exit_code"' in fenced
    assert 'offline_compose recovery "$contract_dir" \\\n    up -d' not in fenced
    assert "$KB_DATA_ROOT/chat-safety" not in source
    quiesce = source.index(
        "stop_sensitive_services || \\\n"
        '  offline_fail recovery "cannot isolate the active release before repair"'
    )
    second_witness = source.index("materialize_api_persistence_witness", quiesce)
    assert quiesce < second_witness < automatic_up
