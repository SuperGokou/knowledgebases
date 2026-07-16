from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

import app.services.chat_safety as chat_safety
from app.services.chat_safety import (
    _reset_chat_safety_poison_for_testing,
    chat_safety_poison_reasons,
    chat_safety_poisoned,
    complete_chat_safety_shutdown,
    configure_chat_safety_state,
    poison_chat_safety,
)

REPOSITORY = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("failure_kind", ["OSError", "KeyboardInterrupt", "SystemExit"])
def test_real_child_process_uses_exit_78_for_every_persistence_base_exception(
    tmp_path: Path,
    failure_kind: str,
) -> None:
    state_directory = tmp_path / f"child-{failure_kind}"
    state_directory.mkdir()
    if os.name == "posix":
        state_directory.chmod(0o700)
    sentinel = state_directory / "poison.json"
    child = """
import pathlib
import sys

import app.services.chat_safety as chat_safety

sentinel = pathlib.Path(sys.argv[1])
failure_kind = sys.argv[2]
failures = {
    "OSError": OSError("simulated ENOSPC"),
    "KeyboardInterrupt": KeyboardInterrupt(),
    "SystemExit": SystemExit(99),
}

def fail_persistence(*_args, **_kwargs):
    raise failures[failure_kind]

chat_safety.configure_chat_safety_state(sentinel)
chat_safety._persist_poison_and_clean_run_state = fail_persistence
chat_safety.poison_chat_safety(reason="subprocess_persistence_failure")
raise SystemExit(100)
"""

    completed = subprocess.run(
        [sys.executable, "-c", child, str(sentinel), failure_kind],
        cwd=REPOSITORY,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 78, completed.stderr
    assert sentinel.exists() is False


@pytest.mark.parametrize(
    "persistence_error",
    [
        pytest.param(OSError("simulated ENOSPC"), id="os-error"),
        pytest.param(KeyboardInterrupt(), id="keyboard-interrupt"),
        pytest.param(SystemExit(99), id="system-exit"),
    ],
)
def test_every_persistence_base_exception_immediately_terminates_with_exit_78_witness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    persistence_error: BaseException,
) -> None:
    state_directory = tmp_path / "chat-safety"
    state_directory.mkdir()
    if os.name == "posix":
        state_directory.chmod(0o700)
    sentinel = state_directory / "poison.json"
    configure_chat_safety_state(sentinel)
    observed_error: BaseException | None = None
    logger_calls = 0

    class WorkerTerminated(RuntimeError):
        pass

    def fail_persistence(*_args: object, **_kwargs: object) -> None:
        raise persistence_error

    def terminate(error: BaseException) -> None:
        nonlocal observed_error
        observed_error = error
        raise WorkerTerminated("exit 78")

    def forbidden_logger(*_args: object, **_kwargs: object) -> None:
        nonlocal logger_calls
        logger_calls += 1
        raise AssertionError("logging must not precede fail-stop")

    monkeypatch.setattr(
        chat_safety,
        "_persist_poison_and_clean_run_state",
        fail_persistence,
    )
    monkeypatch.setattr(chat_safety, "_terminate_after_persistence_failure", terminate)
    monkeypatch.setattr(chat_safety._LOGGER, "critical", forbidden_logger)

    with pytest.raises(WorkerTerminated, match="exit 78"):
        poison_chat_safety(reason="persistence_failure_test")

    assert observed_error is persistence_error
    assert logger_calls == 0
    assert "chat_safety_persistence_failed" in chat_safety_poison_reasons()
    assert sentinel.exists() is False


def test_poison_sentinel_survives_process_local_state_reset(tmp_path: Path) -> None:
    state_directory = tmp_path / "chat-safety"
    state_directory.mkdir()
    if os.name == "posix":
        state_directory.chmod(0o700)
    sentinel = state_directory / "poison.json"

    configure_chat_safety_state(sentinel)
    poison_chat_safety(reason="terminal_state_uncertain", error_class="OSError")

    payload = json.loads(sentinel.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 1
    assert payload["reason"] == "terminal_state_uncertain"
    assert payload["error_class"] == "OSError"
    assert chat_safety_poisoned() is True

    _reset_chat_safety_poison_for_testing()
    assert chat_safety_poisoned() is False

    configure_chat_safety_state(sentinel)
    assert chat_safety_poisoned() is True
    assert "persistent_chat_safety_sentinel" in chat_safety_poison_reasons()


def test_existing_hard_linked_sentinel_is_rejected(tmp_path: Path) -> None:
    state_directory = tmp_path / "chat-safety"
    state_directory.mkdir()
    if os.name == "posix":
        state_directory.chmod(0o700)
    sentinel = state_directory / "poison.json"

    configure_chat_safety_state(sentinel)
    poison_chat_safety(reason="unsafe")
    os.link(sentinel, state_directory / "second-link.json")

    _reset_chat_safety_poison_for_testing()
    with pytest.raises(RuntimeError, match="hard linked"):
        configure_chat_safety_state(sentinel)


def _make_state_directory(tmp_path: Path, name: str = "chat-safety") -> Path:
    directory = tmp_path / name
    directory.mkdir()
    if os.name == "posix":
        directory.chmod(0o700)
    return directory


def _run_phase(directory: Path) -> str:
    return json.loads((directory / "run-state.json").read_text(encoding="utf-8"))["phase"]


def test_clean_shutdown_allows_a_normal_restart_without_poison(tmp_path: Path) -> None:
    directory = _make_state_directory(tmp_path)
    sentinel = directory / "poison.json"

    configure_chat_safety_state(sentinel)
    assert _run_phase(directory) == "running"

    complete_chat_safety_shutdown()
    assert _run_phase(directory) == "clean"
    assert sentinel.exists() is False

    _reset_chat_safety_poison_for_testing()
    configure_chat_safety_state(sentinel)

    assert _run_phase(directory) == "running"
    assert chat_safety_poisoned() is False


def test_sigkill_then_restart_promotes_stale_running_state_to_poison(
    tmp_path: Path,
) -> None:
    directory = _make_state_directory(tmp_path)
    sentinel = directory / "poison.json"
    ready = directory / "child-ready"
    child_source = """
import pathlib
import sys
import time

from app.services.chat_safety import configure_chat_safety_state

configure_chat_safety_state(pathlib.Path(sys.argv[1]))
pathlib.Path(sys.argv[2]).write_text("ready", encoding="utf-8")
time.sleep(60)
"""
    child = subprocess.Popen(
        [sys.executable, "-c", child_source, str(sentinel), str(ready)],
        cwd=REPOSITORY,
    )
    try:
        deadline = time.monotonic() + 10
        while not ready.exists() and child.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        assert ready.exists(), f"child exited early with {child.poll()}"
        assert _run_phase(directory) == "running"
        child.kill()
        child.wait(timeout=10)
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=10)

    restart_source = """
import pathlib
import sys

from app.services.chat_safety import (
    chat_safety_poison_reasons,
    chat_safety_poisoned,
    configure_chat_safety_state,
)

configure_chat_safety_state(pathlib.Path(sys.argv[1]))
print(chat_safety_poisoned())
print(",".join(chat_safety_poison_reasons()))
"""
    restarted = subprocess.run(
        [sys.executable, "-c", restart_source, str(sentinel)],
        cwd=REPOSITORY,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert restarted.returncode == 0, restarted.stderr
    assert restarted.stdout.splitlines()[0] == "True"
    assert "unclean_worker_exit" in restarted.stdout
    assert json.loads(sentinel.read_text(encoding="utf-8"))["reason"] == ("unclean_worker_exit")
    assert _run_phase(directory) == "clean"


@pytest.mark.parametrize(
    "failure_kind",
    [
        "open",
        "write",
        "file_fsync",
        "dir_fsync",
        "KeyboardInterrupt",
        "SystemExit",
    ],
)
def test_real_fault_injection_cannot_bypass_exit_78(
    tmp_path: Path,
    failure_kind: str,
) -> None:
    directory = _make_state_directory(tmp_path, f"fault-{failure_kind}")
    sentinel = directory / "poison.json"
    source = """
import os
import pathlib
import stat
import sys

import app.services.chat_safety as chat_safety

sentinel = pathlib.Path(sys.argv[1])
failure_kind = sys.argv[2]
chat_safety.configure_chat_safety_state(sentinel)
if failure_kind == "open":
    original = os.open
    def fail_open(path, *args, **kwargs):
        if os.fspath(path) == os.fspath(sentinel):
            raise OSError("simulated open failure")
        return original(path, *args, **kwargs)
    os.open = fail_open
elif failure_kind == "write":
    def fail_write(*_args, **_kwargs):
        raise OSError("simulated write failure")
    os.write = fail_write
elif failure_kind == "file_fsync":
    original = os.fsync
    def fail_file_fsync(descriptor):
        if stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError("simulated file fsync failure")
        return original(descriptor)
    os.fsync = fail_file_fsync
elif failure_kind == "dir_fsync":
    def fail_directory_fsync(*_args, **_kwargs):
        raise OSError("simulated directory fsync failure")
    chat_safety._fsync_directory = fail_directory_fsync
elif failure_kind == "KeyboardInterrupt":
    def fail_persistence(*_args, **_kwargs):
        raise KeyboardInterrupt()
    chat_safety._persist_poison_and_clean_run_state = fail_persistence
else:
    def fail_persistence(*_args, **_kwargs):
        raise SystemExit(99)
    chat_safety._persist_poison_and_clean_run_state = fail_persistence
chat_safety.poison_chat_safety(reason="fault_injection")
raise SystemExit(100)
"""
    completed = subprocess.run(
        [sys.executable, "-c", source, str(sentinel), failure_kind],
        cwd=REPOSITORY,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 78, completed.stderr


def test_fail_stop_does_not_wait_for_the_process_local_poison_lock(
    tmp_path: Path,
) -> None:
    directory = _make_state_directory(tmp_path)
    sentinel = directory / "poison.json"
    source = """
import pathlib
import sys

import app.services.chat_safety as chat_safety

chat_safety.configure_chat_safety_state(pathlib.Path(sys.argv[1]))
chat_safety._POISON_LOCK.acquire()
chat_safety._fail_stop_after_persistence_failure(OSError("simulated ENOSPC"))
raise SystemExit(100)
"""
    completed = subprocess.run(
        [sys.executable, "-c", source, str(sentinel)],
        cwd=REPOSITORY,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 78, completed.stderr


@pytest.mark.parametrize("failure_kind", ["OSError", "KeyboardInterrupt", "SystemExit"])
def test_clean_state_commit_failure_always_exits_78(
    tmp_path: Path,
    failure_kind: str,
) -> None:
    directory = _make_state_directory(tmp_path, f"clean-{failure_kind}")
    sentinel = directory / "poison.json"
    source = """
import pathlib
import sys

import app.services.chat_safety as chat_safety

sentinel = pathlib.Path(sys.argv[1])
failure_kind = sys.argv[2]
failures = {
    "OSError": OSError("simulated ENOSPC"),
    "KeyboardInterrupt": KeyboardInterrupt(),
    "SystemExit": SystemExit(99),
}
chat_safety.configure_chat_safety_state(sentinel)
def fail_clean(*_args, **_kwargs):
    raise failures[failure_kind]
chat_safety._write_run_state_locked = fail_clean
chat_safety.complete_chat_safety_shutdown()
raise SystemExit(100)
"""
    completed = subprocess.run(
        [sys.executable, "-c", source, str(sentinel), failure_kind],
        cwd=REPOSITORY,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 78, completed.stderr
    assert _run_phase(directory) == "running"


@pytest.mark.parametrize("failure_kind", ["OSError", "KeyboardInterrupt", "SystemExit"])
def test_existing_poison_clean_state_failure_always_exits_78(
    tmp_path: Path,
    failure_kind: str,
) -> None:
    directory = _make_state_directory(tmp_path, f"existing-clean-{failure_kind}")
    sentinel = directory / "poison.json"
    source = """
import pathlib
import sys

import app.services.chat_safety as chat_safety

sentinel = pathlib.Path(sys.argv[1])
failure_kind = sys.argv[2]
failures = {
    "OSError": OSError("simulated ENOSPC"),
    "KeyboardInterrupt": KeyboardInterrupt(),
    "SystemExit": SystemExit(99),
}
chat_safety.configure_chat_safety_state(sentinel)
chat_safety.poison_chat_safety(reason="existing_poison")
chat_safety._reset_chat_safety_poison_for_testing()
def fail_clean(*_args, **_kwargs):
    raise failures[failure_kind]
chat_safety._write_run_state_locked = fail_clean
chat_safety.configure_chat_safety_state(sentinel)
raise SystemExit(100)
"""
    completed = subprocess.run(
        [sys.executable, "-c", source, str(sentinel), failure_kind],
        cwd=REPOSITORY,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 78, completed.stderr


def test_failed_write_fsyncs_parent_both_before_and_during_finalization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = _make_state_directory(tmp_path)
    sentinel = directory / "poison.json"
    syncs: list[Path] = []

    monkeypatch.setattr(
        chat_safety,
        "_fsync_directory",
        lambda path: syncs.append(path),
    )
    monkeypatch.setattr(
        chat_safety.os,
        "write",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("write failed")),
    )

    with pytest.raises(OSError, match="write failed"):
        chat_safety._persist_sentinel(
            sentinel,
            reason="test",
            error_class="OSError",
        )

    assert syncs == [directory, directory]


def test_close_failure_does_not_skip_parent_directory_fsync(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = _make_state_directory(tmp_path)
    sentinel = directory / "poison.json"
    original_open = chat_safety.os.open
    original_close = chat_safety.os.close
    sentinel_descriptor: int | None = None
    syncs: list[Path] = []

    def track_open(path: os.PathLike[str] | str, *args: object) -> int:
        nonlocal sentinel_descriptor
        descriptor = original_open(path, *args)
        if os.fspath(path) == os.fspath(sentinel):
            sentinel_descriptor = descriptor
        return descriptor

    def fail_sentinel_close(descriptor: int) -> None:
        if descriptor == sentinel_descriptor:
            raise OSError("simulated close failure")
        original_close(descriptor)

    monkeypatch.setattr(chat_safety.os, "open", track_open)
    monkeypatch.setattr(chat_safety.os, "close", fail_sentinel_close)
    monkeypatch.setattr(
        chat_safety,
        "_fsync_directory",
        lambda path: syncs.append(path),
    )

    try:
        with pytest.raises(OSError, match="close failure"):
            chat_safety._persist_sentinel(
                sentinel,
                reason="test",
                error_class="OSError",
            )
    finally:
        if sentinel_descriptor is not None:
            original_close(sentinel_descriptor)

    assert syncs == [directory, directory]


def test_existing_invalid_sentinel_still_fsyncs_its_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = _make_state_directory(tmp_path)
    sentinel = directory / "poison.json"
    sentinel.write_text("{}", encoding="utf-8")
    if os.name == "posix":
        sentinel.chmod(0o600)
    syncs: list[Path] = []
    monkeypatch.setattr(
        chat_safety,
        "_fsync_directory",
        lambda path: syncs.append(path),
    )

    with pytest.raises(RuntimeError, match="schema"):
        chat_safety._persist_sentinel(
            sentinel,
            reason="test",
            error_class=None,
        )

    assert syncs == [directory]


@pytest.mark.skipif(os.name != "posix", reason="flock is a POSIX deployment contract")
def test_clean_shutdown_keeps_the_process_lifetime_lock_until_exit(
    tmp_path: Path,
) -> None:
    directory = _make_state_directory(tmp_path)
    sentinel = directory / "poison.json"
    ready = directory / "lock-ready"
    holder_source = """
import pathlib
import sys
import time
from app.services.chat_safety import (
    complete_chat_safety_shutdown,
    configure_chat_safety_state,
)
configure_chat_safety_state(pathlib.Path(sys.argv[1]))
complete_chat_safety_shutdown()
pathlib.Path(sys.argv[2]).write_text("ready", encoding="utf-8")
time.sleep(60)
"""
    holder = subprocess.Popen(
        [sys.executable, "-c", holder_source, str(sentinel), str(ready)],
        cwd=REPOSITORY,
    )
    try:
        deadline = time.monotonic() + 10
        while not ready.exists() and holder.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        assert ready.exists()
        contender = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import pathlib,sys;"
                    "from app.services.chat_safety import configure_chat_safety_state;"
                    "configure_chat_safety_state(pathlib.Path(sys.argv[1]))"
                ),
                str(sentinel),
            ],
            cwd=REPOSITORY,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert contender.returncode != 0
        assert "exactly one API worker" in contender.stderr
    finally:
        if holder.poll() is None:
            holder.kill()
            holder.wait(timeout=10)
