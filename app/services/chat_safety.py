from __future__ import annotations

import json
import logging
import os
import secrets
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from contextvars import ContextVar
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import Any, Final, Literal, NoReturn, cast

_LOGGER = logging.getLogger(__name__)
CHAT_TERMINALIZATION_RESERVE_SECONDS = 2.0
_SENTINEL_SCHEMA_VERSION: Final[int] = 1
_RUN_STATE_SCHEMA_VERSION: Final[int] = 1
_RUN_STATE_FILENAME: Final[str] = "run-state.json"
_MAX_SENTINEL_BYTES: Final[int] = 4096
_MAX_RUN_STATE_BYTES: Final[int] = 1024
_PERSISTENCE_FAILURE_EXIT_CODE: Final[int] = 78
_RUN_STATE_PHASES: Final[frozenset[str]] = frozenset({"clean", "running"})
RunStatePhase = Literal["clean", "running"]
_CHAT_CLEANUP_DEADLINE: ContextVar[float | None] = ContextVar(
    "chat_cleanup_deadline",
    default=None,
)
_POISON_LOCK = Lock()
_PERSISTENCE_LOCK = Lock()
_POISON_REASONS: set[str] = set()
_POISON_LISTENERS: set[Callable[[], None]] = set()
_PERSISTENT_STATE_PATH: Path | None = None
_PERSISTENT_RUN_STATE_PATH: Path | None = None
_WORKER_DIRECTORY_LOCK_DESCRIPTOR: int | None = None
_RUN_STATE_OWNED = False


@contextmanager
def bind_chat_cleanup_deadline(deadline: float) -> Iterator[None]:
    """Bind one absolute cleanup fence to every child task in a chat operation."""

    token = _CHAT_CLEANUP_DEADLINE.set(deadline)
    try:
        yield
    finally:
        _CHAT_CLEANUP_DEADLINE.reset(token)


def current_chat_cleanup_deadline() -> float | None:
    return _CHAT_CLEANUP_DEADLINE.get()


def register_chat_poison_listener(listener: Callable[[], None]) -> None:
    """Register a process-local fail-closed action such as cancelling active chats."""

    with _POISON_LOCK:
        _POISON_LISTENERS.add(listener)
        poisoned = bool(_POISON_REASONS)
    if poisoned:
        listener()


def configure_chat_safety_state(path: Path | None) -> None:
    """Bind the poison sentinel and durably arm the single-worker run latch.

    Isolated production supplies a host-backed directory owned by the API uid.
    The application never creates that directory and refuses symlinks, hard
    links, unsafe ownership, or unsafe modes. ``run-state.json`` remains present
    across clean restarts: startup changes ``clean`` to ``running`` before
    readiness can open, while only a fully completed lifespan shutdown may
    change it back to ``clean``. A stale ``running`` state is first promoted to
    the canonical poison sentinel, closing the crash/restart fail-open window.

    The host-backed state directory is also held under a non-blocking exclusive
    ``flock`` for the process lifetime. Isolated deployment supports exactly one
    API worker; a second worker fails startup instead of sharing an unsafe latch.
    """

    global _PERSISTENT_RUN_STATE_PATH
    global _PERSISTENT_STATE_PATH
    global _RUN_STATE_OWNED
    global _WORKER_DIRECTORY_LOCK_DESCRIPTOR
    if path is None:
        with _PERSISTENCE_LOCK:
            _release_worker_directory_lock_locked()
            with _POISON_LOCK:
                _PERSISTENT_STATE_PATH = None
                _PERSISTENT_RUN_STATE_PATH = None
                _RUN_STATE_OWNED = False
        return
    if not path.is_absolute():
        raise RuntimeError("chat safety state path must be absolute")
    parent = path.parent
    run_state_path = parent / _RUN_STATE_FILENAME
    _validate_directory(parent)
    with _PERSISTENCE_LOCK:
        with _POISON_LOCK:
            if (
                path == _PERSISTENT_STATE_PATH
                and run_state_path == _PERSISTENT_RUN_STATE_PATH
                and _RUN_STATE_OWNED
            ):
                return
            if _PERSISTENT_STATE_PATH is not None or _PERSISTENT_RUN_STATE_PATH is not None:
                raise RuntimeError("chat safety state is already bound to another path")

        directory_lock = _acquire_worker_directory_lock(parent)
        _WORKER_DIRECTORY_LOCK_DESCRIPTOR = directory_lock
        poisoned_reason: str | None = None
        try:
            if _sentinel_present(path):
                try:
                    _validate_sentinel(path)
                finally:
                    _fsync_directory(parent)
                try:
                    _write_run_state_locked(run_state_path, phase="clean")
                except BaseException as error:
                    _fail_stop_after_persistence_failure(error)
                poisoned_reason = "persistent_chat_safety_sentinel"
            else:
                _probe_durable_directory(parent)
                prior_phase = _read_run_state_optional(run_state_path)
                if prior_phase == "running":
                    try:
                        _persist_sentinel_locked(
                            path,
                            reason="unclean_worker_exit",
                            error_class="StaleRunState",
                        )
                        _write_run_state_locked(run_state_path, phase="clean")
                    except BaseException as error:
                        _fail_stop_after_persistence_failure(error)
                    poisoned_reason = "unclean_worker_exit"
                else:
                    try:
                        _write_run_state_locked(run_state_path, phase="running")
                    except BaseException as error:
                        _fail_stop_after_persistence_failure(error)
        except BaseException:
            _release_worker_directory_lock_locked()
            raise

        with _POISON_LOCK:
            _PERSISTENT_STATE_PATH = path
            _PERSISTENT_RUN_STATE_PATH = run_state_path
            _RUN_STATE_OWNED = True
            if poisoned_reason is not None:
                _POISON_REASONS.add(poisoned_reason)
                _POISON_REASONS.add("persistent_chat_safety_sentinel")


def poison_chat_safety(*, reason: str, error_class: str | None = None) -> None:
    """Permanently fail this worker and its shared isolated deployment closed.

    Recovery is deliberately outside the HTTP process. Operators must reconcile
    the idempotency ledger and provider-side usage, then use the audited
    digest-bound clearing command and restart the API.
    """

    with _POISON_LOCK:
        already_poisoned = bool(_POISON_REASONS)
        _POISON_REASONS.add(reason)
        state_path = _PERSISTENT_STATE_PATH
        run_state_path = _PERSISTENT_RUN_STATE_PATH
        listeners = tuple(_POISON_LISTENERS)
    if state_path is not None:
        try:
            _persist_poison_and_clean_run_state(
                state_path,
                run_state_path=run_state_path,
                reason=reason,
                error_class=error_class,
            )
        except BaseException as error:
            _fail_stop_after_persistence_failure(error)
    _LOGGER.critical(
        "Chat safety fence is poisoned; new chat work is blocked",
        extra={
            "reason": reason,
            "error_class": error_class,
            "already_poisoned": already_poisoned,
            "persistent": state_path is not None,
            "persistence_error_class": None,
        },
    )
    if not already_poisoned:
        for listener in listeners:
            try:
                listener()
            except BaseException as error:
                if isinstance(error, (KeyboardInterrupt, SystemExit)):
                    raise
                _LOGGER.critical(
                    "Chat safety poison listener failed",
                    extra={"error_class": type(error).__name__},
                )


def chat_safety_poisoned() -> bool:
    with _POISON_LOCK:
        state_path = _PERSISTENT_STATE_PATH
        run_state_path = _PERSISTENT_RUN_STATE_PATH
        run_state_owned = _RUN_STATE_OWNED
        poisoned = bool(_POISON_REASONS)
    if state_path is not None:
        try:
            present = _sentinel_present(state_path)
        except RuntimeError:
            with _POISON_LOCK:
                _POISON_REASONS.add("persistent_chat_safety_sentinel_invalid")
            return True
        if not present:
            if poisoned:
                return True
            if run_state_path is None or not run_state_owned:
                with _POISON_LOCK:
                    _POISON_REASONS.add("persistent_chat_safety_run_state_invalid")
                return True
            try:
                run_phase = _read_run_state_optional(run_state_path)
            except RuntimeError:
                with _POISON_LOCK:
                    _POISON_REASONS.add("persistent_chat_safety_run_state_invalid")
                return True
            if run_phase != "running":
                with _POISON_LOCK:
                    _POISON_REASONS.add("persistent_chat_safety_run_state_invalid")
                return True
            return False
        try:
            _validate_sentinel(state_path)
        except RuntimeError:
            with _POISON_LOCK:
                _POISON_REASONS.add("persistent_chat_safety_sentinel_invalid")
        else:
            with _POISON_LOCK:
                _POISON_REASONS.add("persistent_chat_safety_sentinel")
        return True
    return poisoned


def chat_safety_poison_reasons() -> tuple[str, ...]:
    chat_safety_poisoned()
    with _POISON_LOCK:
        return tuple(sorted(_POISON_REASONS))


def complete_chat_safety_shutdown() -> None:
    """Persist a clean handoff only after all lifespan cleanup has succeeded.

    Any failure to commit the clean state uses the dedicated exit-78 witness.
    The previous ``running`` state therefore remains authoritative across a
    crash, ``SIGKILL``, host restart, or incomplete application shutdown.
    """

    with _PERSISTENCE_LOCK:
        with _POISON_LOCK:
            run_state_path = _PERSISTENT_RUN_STATE_PATH
            state_path = _PERSISTENT_STATE_PATH
            owned = _RUN_STATE_OWNED
            poisoned = bool(_POISON_REASONS)
        if not owned or run_state_path is None:
            return
        try:
            sentinel_present = state_path is not None and _sentinel_present(state_path)
            if sentinel_present and state_path is not None:
                try:
                    _validate_sentinel(state_path)
                finally:
                    _fsync_directory(state_path.parent)
            elif poisoned:
                raise RuntimeError("chat safety poison lacks a durable sentinel during shutdown")
            _write_run_state_locked(run_state_path, phase="clean")
        except BaseException as error:
            _fail_stop_after_persistence_failure(error)


def _persist_sentinel(
    path: Path,
    *,
    reason: str,
    error_class: str | None,
) -> None:
    with _PERSISTENCE_LOCK:
        _persist_sentinel_locked(path, reason=reason, error_class=error_class)


def _persist_poison_and_clean_run_state(
    path: Path,
    *,
    run_state_path: Path | None,
    reason: str,
    error_class: str | None,
) -> None:
    with _PERSISTENCE_LOCK:
        _persist_sentinel_locked(path, reason=reason, error_class=error_class)
        if run_state_path is not None:
            _write_run_state_locked(run_state_path, phase="clean")


def _persist_sentinel_locked(
    path: Path,
    *,
    reason: str,
    error_class: str | None,
) -> None:
    if _sentinel_present(path):
        try:
            _validate_sentinel(path)
        finally:
            _fsync_directory(path.parent)
        return
    payload = json.dumps(
        {
            "schema_version": _SENTINEL_SCHEMA_VERSION,
            "created_at": datetime.now(UTC).isoformat(),
            "pid": os.getpid(),
            "reason": reason,
            "error_class": error_class,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(payload) > _MAX_SENTINEL_BYTES:
        raise RuntimeError("chat safety sentinel exceeds its size boundary")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        try:
            _validate_sentinel(path)
        finally:
            _fsync_directory(path.parent)
        return
    persistence_error: BaseException | None = None
    try:
        # Persist the directory entry before writing. If any later operation
        # fails or the host crashes, an empty/partial marker remains an
        # intentionally invalid fail-closed state instead of disappearing.
        _fsync_directory(path.parent)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("chat safety sentinel write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    except BaseException as error:
        persistence_error = error
        raise
    finally:
        cleanup_error: BaseException | None = None
        try:
            os.close(descriptor)
        except BaseException as error:
            cleanup_error = error
        try:
            _fsync_directory(path.parent)
        except BaseException as error:
            if cleanup_error is None:
                cleanup_error = error
        if persistence_error is None and cleanup_error is not None:
            raise cleanup_error
    _validate_sentinel(path)
    _fsync_directory(path.parent)


def _read_run_state_optional(path: Path) -> RunStatePhase | None:
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise RuntimeError("chat safety run state cannot be determined") from error
    return _validate_run_state(path)


def _validate_run_state(path: Path) -> RunStatePhase:
    try:
        before = path.lstat()
    except FileNotFoundError as error:
        raise RuntimeError("chat safety run state disappeared") from error
    except OSError as error:
        raise RuntimeError("chat safety run state cannot be determined") from error
    if stat.S_ISLNK(before.st_mode):
        raise RuntimeError("chat safety run state must not be symbolic")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RuntimeError("chat safety run state cannot be opened safely") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            metadata.st_dev != before.st_dev
            or metadata.st_ino != before.st_ino
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size <= 0
            or metadata.st_size > _MAX_RUN_STATE_BYTES
        ):
            raise RuntimeError("chat safety run state metadata is invalid")
        if os.name == "posix":
            if metadata.st_uid != _effective_uid() or metadata.st_gid != _effective_gid():
                raise RuntimeError("chat safety run state has unexpected ownership")
            if stat.S_IMODE(metadata.st_mode) != 0o600:
                raise RuntimeError("chat safety run state mode must be 0600")
        raw = bytearray()
        while len(raw) <= _MAX_RUN_STATE_BYTES:
            chunk = os.read(descriptor, min(512, _MAX_RUN_STATE_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        if (
            after.st_dev != metadata.st_dev
            or after.st_ino != metadata.st_ino
            or after.st_size != metadata.st_size
            or len(raw) != metadata.st_size
            or not raw
            or len(raw) > _MAX_RUN_STATE_BYTES
        ):
            raise RuntimeError("chat safety run state changed during validation")
    except OSError as error:
        raise RuntimeError("chat safety run state cannot be read safely") from error
    finally:
        os.close(descriptor)
    try:
        payload = json.loads(
            raw,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise RuntimeError("chat safety run state is not valid JSON") from error
    phase = payload.get("phase") if isinstance(payload, dict) else None
    if (
        not isinstance(payload, dict)
        or set(payload) != {"schema_version", "updated_at", "pid", "phase"}
        or payload.get("schema_version") != _RUN_STATE_SCHEMA_VERSION
        or type(payload.get("schema_version")) is not int
        or not isinstance(payload.get("updated_at"), str)
        or type(payload.get("pid")) is not int
        or cast(int, payload.get("pid")) < 0
        or not isinstance(phase, str)
        or phase not in _RUN_STATE_PHASES
    ):
        raise RuntimeError("chat safety run state schema is invalid")
    return cast(RunStatePhase, phase)


def _write_run_state_locked(path: Path, *, phase: RunStatePhase) -> None:
    if phase not in _RUN_STATE_PHASES:
        raise ValueError("chat safety run state phase is invalid")
    _read_run_state_optional(path)
    payload = json.dumps(
        {
            "schema_version": _RUN_STATE_SCHEMA_VERSION,
            "updated_at": datetime.now(UTC).isoformat(),
            "pid": os.getpid(),
            "phase": phase,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(payload) > _MAX_RUN_STATE_BYTES:
        raise RuntimeError("chat safety run state exceeds its size boundary")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    temporary_created = False
    operation_error: BaseException | None = None
    try:
        descriptor = os.open(temporary, flags, 0o600)
        temporary_created = True
        _fsync_directory(path.parent)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("chat safety run state write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        if _validate_run_state(temporary) != phase:
            raise RuntimeError("chat safety run state phase changed before publish")
        os.replace(temporary, path)
        temporary_created = False
        _fsync_directory(path.parent)
    except BaseException as error:
        operation_error = error
        raise
    finally:
        cleanup_error: BaseException | None = None
        if descriptor is not None:
            try:
                os.close(descriptor)
            except BaseException as error:
                cleanup_error = error
        if temporary_created:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            except BaseException as error:
                if cleanup_error is None:
                    cleanup_error = error
            try:
                _fsync_directory(path.parent)
            except BaseException as error:
                if cleanup_error is None:
                    cleanup_error = error
        if operation_error is None and cleanup_error is not None:
            raise cleanup_error


def _validate_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise RuntimeError("chat safety state directory must be provisioned") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError("chat safety state directory must be a real directory")
    if os.name == "posix":
        expected_uid = _effective_uid()
        expected_gid = _effective_gid()
        if metadata.st_uid != expected_uid or metadata.st_gid != expected_gid:
            raise RuntimeError("chat safety state directory has unexpected ownership")
        if stat.S_IMODE(metadata.st_mode) != 0o700:
            raise RuntimeError("chat safety state directory mode must be 0700")


def _sentinel_present(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError as error:
        raise RuntimeError("chat safety sentinel state cannot be determined") from error
    return True


def _validate_sentinel(path: Path) -> None:
    try:
        path_metadata = path.lstat()
    except FileNotFoundError as error:
        raise RuntimeError("chat safety sentinel disappeared") from error
    except OSError as error:
        raise RuntimeError("chat safety sentinel state cannot be determined") from error
    if stat.S_ISLNK(path_metadata.st_mode):
        raise RuntimeError("chat safety sentinel must not be symbolic")
    try:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
    except FileNotFoundError as error:
        raise RuntimeError("chat safety sentinel disappeared") from error
    except OSError as error:
        raise RuntimeError("chat safety sentinel cannot be opened safely") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("chat safety sentinel must be a regular file")
        if metadata.st_nlink != 1:
            raise RuntimeError("chat safety sentinel must not be hard linked")
        if metadata.st_size <= 0 or metadata.st_size > _MAX_SENTINEL_BYTES:
            raise RuntimeError("chat safety sentinel size is invalid")
        if os.name == "posix":
            if metadata.st_uid != _effective_uid() or metadata.st_gid != _effective_gid():
                raise RuntimeError("chat safety sentinel has unexpected ownership")
            if stat.S_IMODE(metadata.st_mode) != 0o600:
                raise RuntimeError("chat safety sentinel mode must be 0600")
        raw = bytearray()
        while len(raw) <= _MAX_SENTINEL_BYTES:
            chunk = os.read(descriptor, min(1024, _MAX_SENTINEL_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        if not raw or len(raw) > _MAX_SENTINEL_BYTES:
            raise RuntimeError("chat safety sentinel content size is invalid")
    except OSError as error:
        raise RuntimeError("chat safety sentinel cannot be read safely") from error
    finally:
        os.close(descriptor)
    try:
        payload = json.loads(
            raw,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise RuntimeError("chat safety sentinel is not valid JSON") from error
    if (
        not isinstance(payload, dict)
        or set(payload) != {"schema_version", "created_at", "pid", "reason", "error_class"}
        or payload.get("schema_version") != _SENTINEL_SCHEMA_VERSION
        or type(payload.get("schema_version")) is not int
        or not isinstance(payload.get("created_at"), str)
        or type(payload.get("pid")) is not int
        or cast(int, payload.get("pid")) < 0
        or not isinstance(payload.get("reason"), str)
        or not payload.get("reason")
        or (
            payload.get("error_class") is not None
            and not isinstance(payload.get("error_class"), str)
        )
    ):
        raise RuntimeError("chat safety sentinel schema is invalid")


def _probe_durable_directory(parent: Path) -> None:
    probe = parent / f".write-probe-{os.getpid()}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(probe, flags, 0o600)
        try:
            os.write(descriptor, b"ok")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        metadata = probe.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise RuntimeError("chat safety state write probe is unsafe")
    except OSError as error:
        raise RuntimeError("chat safety state directory is not durably writable") from error
    finally:
        with suppress(FileNotFoundError):
            probe.unlink()
    _fsync_directory(parent)


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _acquire_worker_directory_lock(path: Path) -> int | None:
    """Hold one process-lifetime lock for the single supported API worker."""

    if os.name != "posix":
        return None
    import fcntl

    fcntl_api = cast(Any, fcntl)
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = path.lstat()
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_dev != before.st_dev
            or metadata.st_ino != before.st_ino
            or metadata.st_uid != _effective_uid()
            or metadata.st_gid != _effective_gid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise RuntimeError("chat safety state directory lock target is invalid")
        try:
            fcntl_api.flock(descriptor, fcntl_api.LOCK_EX | fcntl_api.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("chat safety state supports exactly one API worker") from error
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _release_worker_directory_lock_locked() -> None:
    global _WORKER_DIRECTORY_LOCK_DESCRIPTOR

    descriptor = _WORKER_DIRECTORY_LOCK_DESCRIPTOR
    _WORKER_DIRECTORY_LOCK_DESCRIPTOR = None
    if descriptor is None:
        return
    if os.name == "posix":
        import fcntl

        fcntl_api = cast(Any, fcntl)
        with suppress(OSError):
            fcntl_api.flock(descriptor, fcntl_api.LOCK_UN)
    with suppress(OSError):
        os.close(descriptor)


def _effective_uid() -> int:
    get_effective_uid = getattr(os, "geteuid", None)
    if not callable(get_effective_uid):  # pragma: no cover - POSIX-only call site.
        raise RuntimeError("effective uid is unavailable")
    return int(get_effective_uid())


def _effective_gid() -> int:
    get_effective_gid = getattr(os, "getegid", None)
    if not callable(get_effective_gid):  # pragma: no cover - POSIX-only call site.
        raise RuntimeError("effective gid is unavailable")
    return int(get_effective_gid())


def _terminate_after_persistence_failure(error: BaseException) -> NoReturn:
    """Leave a durable Docker exit-code witness when the sentinel cannot persist."""

    del error
    # No logger, listener, await, cleanup, or other fallible work may precede
    # this process boundary. Docker persists the dedicated exit status and the
    # root reconciler turns it into a canonical sentinel.
    os._exit(_PERSISTENCE_FAILURE_EXIT_CODE)


def _fail_stop_after_persistence_failure(error: BaseException) -> NoReturn:
    """Record a local reason when possible, but make exit 78 unconditional."""

    try:
        acquired = _POISON_LOCK.acquire(blocking=False)
        if acquired:
            try:
                _POISON_REASONS.add("chat_safety_persistence_failed")
            finally:
                _POISON_LOCK.release()
    finally:
        _terminate_after_persistence_failure(error)


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON constant is forbidden: {value}")


def _reset_chat_safety_poison_for_testing() -> None:
    """Test-only reset; production recovery requires audited operator action."""

    global _PERSISTENT_RUN_STATE_PATH
    global _PERSISTENT_STATE_PATH
    global _RUN_STATE_OWNED
    with _PERSISTENCE_LOCK:
        _release_worker_directory_lock_locked()
        with _POISON_LOCK:
            _POISON_REASONS.clear()
            _PERSISTENT_STATE_PATH = None
            _PERSISTENT_RUN_STATE_PATH = None
            _RUN_STATE_OWNED = False
