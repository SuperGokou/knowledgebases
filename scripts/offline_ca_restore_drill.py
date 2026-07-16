#!/usr/bin/env python3
"""Perform the signed Caddy CA restore challenge on a physically isolated Linux host.

The command is intentionally narrow: it verifies a signed legacy-adoption challenge,
decrypts the CMS archive into process memory, validates the deterministic tar stream,
uses the recovered CA to issue and verify one ephemeral certificate, and writes the
strict attestation consumed by ``legacy_offline_adoption.py finalize``.

CA plaintext is never written to a filesystem.  OpenSSL receives recovered material
only through sealed Linux memfd descriptors.  Inputs are read-only and outputs are
created exactly once in one root-owned directory.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import importlib
import io
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tarfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any, Final, Never, Protocol, cast

OPENSSL: Final = Path("/usr/bin/openssl")
PROJECT: Final = "heyi-kb-offline"
CHALLENGE_KIND: Final = "heyi-caddy-ca-restore-challenge"
ATTESTATION_KIND: Final = "heyi-caddy-ca-restore-drill"
HMAC_DOMAIN: Final = b"heyi-caddy-ca-v1\0"
DRILL_HOSTNAME: Final = "heyi-ca-restore-drill.invalid"
MAX_CONTROL_BYTES: Final = 8 * 1024 * 1024
MAX_KEY_BYTES: Final = 65_536
MAX_CMS_BYTES: Final = 128 * 1024 * 1024
MAX_CA_PLAINTEXT_BYTES: Final = 64 * 1024 * 1024
MAX_CA_FILE_BYTES: Final = 64 * 1024
MAX_CA_FILES: Final = 128
MAX_OPENSSL_OUTPUT_BYTES: Final = 2 * 1024 * 1024
MIN_ATTESTATION_RSA_BITS: Final = 3072
MIN_RECIPIENT_RSA_BITS: Final = 3072
MIN_CA_RSA_BITS: Final = 3072
MIN_CA_EC_BITS: Final = 256
PR_GET_DUMPABLE: Final = 3
PR_SET_DUMPABLE: Final = 4
OUTPUT_LOCK_NAME: Final = ".offline-ca-restore-drill.lock"
SUPPORTED_OPENSSL_MAJOR: Final = 3
_SHA256: Final = re.compile(r"^[0-9a-f]{64}$")
_SAFE_NAME: Final = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_BASE64URL: Final = re.compile(rb"^[A-Za-z0-9_-]+={0,2}$")
_RFC3339_UTC: Final = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z$"
)
_PEM_BODY: Final = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_OPENSSL_VERSION: Final = re.compile(
    r"^OpenSSL ([0-9]+)\.([0-9]+)\.([0-9]+)(?:[A-Za-z0-9.-]*)?(?:\s|$)"
)
_OPENSSL_ISO_DATE: Final = re.compile(
    r"^(notBefore|notAfter)=([0-9]{4}-[0-9]{2}-[0-9]{2} "
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}Z)$",
    re.MULTILINE,
)
_PUBLIC_KEY_BITS: Final = re.compile(r"^Public-Key: \(([0-9]+) bit\)$", re.MULTILINE)
_PRIVATE_KEY_BITS: Final = re.compile(
    r"^Private-Key: \(([0-9]+) bit(?:, [0-9]+ primes)?\)$",
    re.MULTILINE,
)
_APPROVED_EC_CURVES: Final = frozenset({"prime256v1", "secp384r1", "secp521r1"})
_CA_FILENAMES: Final = frozenset({"root.crt", "root.key", "intermediate.crt", "intermediate.key"})
_CHALLENGE_KEYS: Final = frozenset(
    {
        "schema_version",
        "kind",
        "project",
        "run_id",
        "plan_sha256",
        "release_authorization_sha256",
        "nonce",
        "issued_at",
        "expires_at",
        "encrypted_archive_sha256",
        "encrypted_archive_size_bytes",
        "plaintext_opaque_hmac_sha256",
        "file_count",
        "recipient_certificate_sha256",
        "ca_attestation_public_key_sha256",
        "cos_transfer_allowed",
    }
)
_ATTESTATION_KEYS: Final = frozenset(
    {
        "schema_version",
        "kind",
        "project",
        "challenge_sha256",
        "encrypted_archive_sha256",
        "plaintext_opaque_hmac_sha256",
        "file_count",
        "recipient_certificate_sha256",
        "status",
        "tested_at",
        "private_key_location",
        "server_private_key_present",
        "cos_used",
    }
)


class DrillError(RuntimeError):
    """A fixed, non-sensitive fail-closed status."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        del message
        raise DrillError("arguments_invalid")


@dataclass(frozen=True, slots=True)
class SecurityContext:
    """Production defaults plus an explicit non-CLI test injection seam."""

    expected_uid: int = 0
    trusted_root: Path = Path("/")
    require_linux_root: bool = True
    validate_openssl_binary: bool = True
    enforce_process_hardening: bool = True


@dataclass(frozen=True, slots=True)
class DrillConfig:
    challenge: Path
    challenge_signature: Path
    challenge_public_key: Path
    expected_challenge_public_key_sha256: str
    cms_archive: Path
    recipient_certificate: Path
    recipient_private_key: Path
    binding_key: Path
    attestation_signing_key: Path
    attestation_public_key: Path
    output_attestation: Path
    output_signature: Path


class OpenSSLProtocol(Protocol):
    def run(
        self,
        arguments: Sequence[str],
        *,
        input_bytes: bytes | None = None,
        pass_fds: Sequence[int] = (),
        timeout: int = 30,
        max_output: int = MAX_OPENSSL_OUTPUT_BYTES,
    ) -> bytes: ...

    def run_expect_failure(
        self,
        arguments: Sequence[str],
        *,
        input_bytes: bytes | None = None,
        pass_fds: Sequence[int] = (),
        timeout: int = 30,
    ) -> None: ...


class OpenSSLRunner:
    """Fixed-path, argv-only OpenSSL adapter with redacted failures."""

    _environment: Final = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LC_ALL": "C",
        "LANG": "C",
        "HOME": "/root",
    }

    def run(
        self,
        arguments: Sequence[str],
        *,
        input_bytes: bytes | None = None,
        pass_fds: Sequence[int] = (),
        timeout: int = 30,
        max_output: int = MAX_OPENSSL_OUTPUT_BYTES,
    ) -> bytes:
        if (
            not arguments
            or max_output <= 0
            or any(
                not isinstance(value, str)
                or not value
                or any(character in value for character in ("\x00", "\r", "\n"))
                or len(value) > 16_384
                for value in arguments
            )
            or any(type(descriptor) is not int or descriptor < 0 for descriptor in pass_fds)
        ):
            raise DrillError("openssl_arguments_invalid")
        try:
            completed = subprocess.run(  # nosec B603
                (str(OPENSSL), *arguments),
                input=input_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=dict(self._environment),
                cwd="/",
                check=False,
                shell=False,
                timeout=timeout,
                pass_fds=tuple(pass_fds),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise DrillError("openssl_execution_failed") from exc
        if completed.returncode != 0:
            raise DrillError("openssl_verification_failed")
        if len(completed.stdout) > max_output:
            raise DrillError("openssl_output_exceeded_limit")
        return completed.stdout

    def run_expect_failure(
        self,
        arguments: Sequence[str],
        *,
        input_bytes: bytes | None = None,
        pass_fds: Sequence[int] = (),
        timeout: int = 30,
    ) -> None:
        if (
            not arguments
            or any(
                not isinstance(value, str)
                or not value
                or any(character in value for character in ("\x00", "\r", "\n"))
                or len(value) > 16_384
                for value in arguments
            )
            or any(type(descriptor) is not int or descriptor < 0 for descriptor in pass_fds)
        ):
            raise DrillError("openssl_arguments_invalid")
        try:
            completed = subprocess.run(  # nosec B603
                (str(OPENSSL), *arguments),
                input=input_bytes,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=dict(self._environment),
                cwd="/",
                check=False,
                shell=False,
                timeout=timeout,
                pass_fds=tuple(pass_fds),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise DrillError("openssl_execution_failed") from exc
        if completed.returncode == 0:
            raise DrillError("openssl_negative_control_unexpectedly_passed")


def _canonical_json(document: object) -> bytes:
    return (
        json.dumps(document, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _disable_process_dumps(
    resource_module: Any | None = None,
    ctypes_module: Any | None = None,
) -> None:
    """Disable filesystem core dumps and Linux ptrace-style dumpability."""

    try:
        resource_api = resource_module or importlib.import_module("resource")
        core_limit = resource_api.RLIMIT_CORE
        resource_api.setrlimit(core_limit, (0, 0))
        if tuple(resource_api.getrlimit(core_limit)) != (0, 0):
            raise DrillError("process_core_dump_limit_not_disabled")

        ctypes_api = ctypes_module or importlib.import_module("ctypes")
        libc = ctypes_api.CDLL(None, use_errno=True)
        prctl = libc.prctl
        if prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
            raise DrillError("process_dumpability_not_disabled")
        if prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0:
            raise DrillError("process_dumpability_not_disabled")
    except DrillError:
        raise
    except (AttributeError, ImportError, OSError, TypeError, ValueError) as exc:
        raise DrillError("process_dump_hardening_failed") from exc


def _require_runtime(context: SecurityContext) -> None:
    if not context.require_linux_root:
        return
    if sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise DrillError("linux_root_required")
    if not hasattr(os, "memfd_create"):
        raise DrillError("linux_memfd_required")
    if context.enforce_process_hardening:
        _disable_process_dumps()


def _under_root(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _validate_ancestors(path: Path, context: SecurityContext) -> None:
    trusted = context.trusted_root
    if (
        not trusted.is_absolute()
        or trusted.is_symlink()
        or trusted.resolve(strict=True) != trusted
        or not _under_root(path, trusted)
    ):
        raise DrillError("protected_path_root_invalid")
    current = path
    while True:
        info = current.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != context.expected_uid
            or bool(stat.S_IMODE(info.st_mode) & 0o022)
        ):
            raise DrillError("protected_path_ancestor_unsafe")
        if current == trusted:
            return
        current = current.parent


def _protected_file(
    path: Path,
    *,
    modes: frozenset[int],
    max_bytes: int,
    context: SecurityContext,
) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise DrillError("protected_file_path_unsafe")
    canonical = path.resolve(strict=True)
    if canonical != path:
        raise DrillError("protected_file_path_noncanonical")
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != context.expected_uid
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) not in modes
        or not 0 < info.st_size <= max_bytes
    ):
        raise DrillError("protected_file_metadata_unsafe")
    _validate_ancestors(path.parent, context)
    return canonical


def _protected_directory(
    path: Path,
    *,
    modes: frozenset[int],
    context: SecurityContext,
) -> Path:
    if not path.is_absolute() or path.is_symlink():
        raise DrillError("protected_directory_path_unsafe")
    canonical = path.resolve(strict=True)
    if canonical != path:
        raise DrillError("protected_directory_path_noncanonical")
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != context.expected_uid
        or stat.S_IMODE(info.st_mode) not in modes
    ):
        raise DrillError("protected_directory_metadata_unsafe")
    _validate_ancestors(path, context)
    return canonical


def _validate_openssl(context: SecurityContext) -> None:
    if not context.validate_openssl_binary:
        return
    if not OPENSSL.is_absolute() or OPENSSL.is_symlink() or OPENSSL.resolve(strict=True) != OPENSSL:
        raise DrillError("openssl_binary_path_unsafe")
    info = OPENSSL.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or bool(stat.S_IMODE(info.st_mode) & 0o022)
        or not bool(stat.S_IMODE(info.st_mode) & 0o111)
    ):
        raise DrillError("openssl_binary_metadata_unsafe")
    production_context = SecurityContext(expected_uid=0, trusted_root=Path("/"))
    _validate_ancestors(OPENSSL.parent, production_context)


def _open_protected_bytes(
    path: Path,
    *,
    modes: frozenset[int],
    max_bytes: int,
    context: SecurityContext,
) -> bytes:
    protected = _protected_file(path, modes=modes, max_bytes=max_bytes, context=context)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(protected, flags)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != context.expected_uid
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) not in modes
        ):
            raise DrillError("protected_file_changed_during_open")
        payload = os.read(descriptor, max_bytes + 1)
        if not payload or len(payload) > max_bytes or len(payload) != info.st_size:
            raise DrillError("protected_file_changed_during_read")
        return payload
    finally:
        os.close(descriptor)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b""):
                digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _pairs_without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if not isinstance(key, str) or key in result:
            raise DrillError("json_duplicate_or_invalid_key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Never:
    del value
    raise DrillError("challenge_json_nonfinite_number")


def _read_canonical_json(
    path: Path,
    *,
    context: SecurityContext,
) -> tuple[dict[str, object], bytes]:
    raw = _open_protected_bytes(
        path,
        modes=frozenset({0o400, 0o440, 0o444, 0o600}),
        max_bytes=MAX_CONTROL_BYTES,
        context=context,
    )
    try:
        document = json.loads(
            raw,
            object_pairs_hook=_pairs_without_duplicates,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise DrillError("challenge_json_invalid") from exc
    if not isinstance(document, dict) or _canonical_json(document) != raw:
        raise DrillError("challenge_json_not_canonical")
    return document, raw


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str) or _RFC3339_UTC.fullmatch(value) is None:
        raise DrillError("challenge_timestamp_invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise DrillError("challenge_timestamp_invalid") from exc
    if parsed.tzinfo != UTC:
        raise DrillError("challenge_timestamp_invalid")
    return parsed


def _validate_challenge(
    document: Mapping[str, object],
    *,
    now: datetime,
) -> tuple[datetime, datetime]:
    if set(document) != _CHALLENGE_KEYS:
        raise DrillError("challenge_schema_invalid")
    file_count = document.get("file_count")
    cms_size = document.get("encrypted_archive_size_bytes")
    if (
        document.get("schema_version") != 2
        or document.get("kind") != CHALLENGE_KIND
        or document.get("project") != PROJECT
        or not isinstance(document.get("run_id"), str)
        or _SAFE_NAME.fullmatch(str(document.get("run_id"))) is None
        or not isinstance(document.get("plan_sha256"), str)
        or _SHA256.fullmatch(str(document.get("plan_sha256"))) is None
        or not isinstance(document.get("release_authorization_sha256"), str)
        or _SHA256.fullmatch(str(document.get("release_authorization_sha256"))) is None
        or not isinstance(document.get("nonce"), str)
        or _SHA256.fullmatch(str(document.get("nonce"))) is None
        or not isinstance(document.get("encrypted_archive_sha256"), str)
        or _SHA256.fullmatch(str(document.get("encrypted_archive_sha256"))) is None
        or not isinstance(document.get("plaintext_opaque_hmac_sha256"), str)
        or _SHA256.fullmatch(str(document.get("plaintext_opaque_hmac_sha256"))) is None
        or not isinstance(document.get("recipient_certificate_sha256"), str)
        or _SHA256.fullmatch(str(document.get("recipient_certificate_sha256"))) is None
        or not isinstance(document.get("ca_attestation_public_key_sha256"), str)
        or _SHA256.fullmatch(str(document.get("ca_attestation_public_key_sha256"))) is None
        or type(cms_size) is not int
        or not 0 < cms_size <= MAX_CMS_BYTES
        or type(file_count) is not int
        or file_count != len(_CA_FILENAMES)
        or document.get("cos_transfer_allowed") is not False
    ):
        raise DrillError("challenge_contract_invalid")
    issued = _parse_timestamp(document.get("issued_at"))
    expires = _parse_timestamp(document.get("expires_at"))
    if (
        now.tzinfo != UTC
        or expires - issued != timedelta(days=7)
        or not issued - timedelta(minutes=5) <= now <= expires
    ):
        raise DrillError("challenge_expired_or_not_current")
    return issued, expires


def _read_binding_key(path: Path, context: SecurityContext) -> bytes:
    raw = _open_protected_bytes(
        path,
        modes=frozenset({0o400, 0o600}),
        max_bytes=4096,
        context=context,
    )
    encoded = raw[:-1] if raw.endswith(b"\n") else raw
    if (
        not encoded
        or raw not in {encoded, encoded + b"\n"}
        or _BASE64URL.fullmatch(encoded) is None
        or b"=" in encoded[:-2]
    ):
        raise DrillError("binding_key_encoding_invalid")
    try:
        decoded = base64.b64decode(
            encoded + b"=" * (-len(encoded) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error) as exc:
        raise DrillError("binding_key_encoding_invalid") from exc
    if len(decoded) < 32 or not hmac.compare_digest(
        base64.urlsafe_b64encode(decoded).rstrip(b"="),
        encoded.rstrip(b"="),
    ):
        raise DrillError("binding_key_strength_or_canonicality_invalid")
    return decoded


def _validate_new_outputs(config: DrillConfig, context: SecurityContext) -> Path:
    attestation = config.output_attestation
    signature = config.output_signature
    if (
        not attestation.is_absolute()
        or not signature.is_absolute()
        or attestation == signature
        or attestation.parent != signature.parent
        or _SAFE_NAME.fullmatch(attestation.name) is None
        or _SAFE_NAME.fullmatch(signature.name) is None
        or attestation.name == OUTPUT_LOCK_NAME
        or signature.name == OUTPUT_LOCK_NAME
        or attestation.exists()
        or attestation.is_symlink()
        or signature.exists()
        or signature.is_symlink()
    ):
        raise DrillError("output_contract_invalid")
    return _protected_directory(
        attestation.parent,
        modes=frozenset({0o700}),
        context=context,
    )


def _verify_file_signature(
    runner: OpenSSLProtocol,
    *,
    payload: Path,
    signature: Path,
    public_key: Path,
) -> None:
    runner.run(
        (
            "dgst",
            "-sha256",
            "-verify",
            str(public_key),
            "-signature",
            str(signature),
            str(payload),
        )
    )


def _validate_pem(payload: bytes, allowed_labels: frozenset[str]) -> None:
    try:
        text = payload.decode("ascii")
    except UnicodeError as exc:
        raise DrillError("ca_pem_invalid") from exc
    lines = text.splitlines()
    if len(lines) < 3 or text not in {"\n".join(lines), "\n".join(lines) + "\n"}:
        raise DrillError("ca_pem_invalid")
    first = lines[0]
    last = lines[-1]
    if (
        not first.startswith("-----BEGIN ")
        or not first.endswith("-----")
        or not last.startswith("-----END ")
        or not last.endswith("-----")
    ):
        raise DrillError("ca_pem_invalid")
    label = first.removeprefix("-----BEGIN ").removesuffix("-----")
    if label not in allowed_labels or last != f"-----END {label}-----":
        raise DrillError("ca_pem_invalid")
    if any(_PEM_BODY.fullmatch(line) is None for line in lines[1:-1]):
        raise DrillError("ca_pem_invalid")
    try:
        base64.b64decode("".join(lines[1:-1]), validate=True)
    except binascii.Error as exc:
        raise DrillError("ca_pem_invalid") from exc


def _canonical_ca_tar(materials: Mapping[str, bytes]) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name in sorted(materials):
            data = materials[name]
            member = tarfile.TarInfo(name)
            member.size = len(data)
            member.mode = 0o600
            member.uid = 0
            member.gid = 0
            member.uname = "root"
            member.gname = "root"
            member.mtime = 0
            archive.addfile(member, io.BytesIO(data))
    return stream.getvalue()


def _read_ca_archive(payload: bytes, *, expected_file_count: int) -> dict[str, bytes]:
    if (
        not payload
        or len(payload) > MAX_CA_PLAINTEXT_BYTES
        or len(payload) % tarfile.RECORDSIZE != 0
    ):
        raise DrillError("ca_tar_size_or_blocking_invalid")
    selected: dict[str, bytes] = {}
    names: set[str] = set()
    folded_names: set[str] = set()
    count = 0
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
            for member in archive:
                count += 1
                if count > MAX_CA_FILES:
                    raise DrillError("ca_tar_file_count_exceeded")
                pure = PurePosixPath(member.name)
                folded = member.name.casefold()
                if (
                    not member.name
                    or len(member.name.encode("utf-8")) > 1024
                    or pure.is_absolute()
                    or pure.as_posix() != member.name
                    or "." in pure.parts
                    or ".." in pure.parts
                    or "\\" in member.name
                    or member.name not in _CA_FILENAMES
                    or member.name in names
                    or folded in folded_names
                    or not member.isfile()
                    or member.linkname
                    or member.pax_headers
                    or member.sparse is not None
                    or member.mode != 0o600
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname != "root"
                    or member.gname != "root"
                    or member.mtime != 0
                    or not 0 < member.size <= MAX_CA_FILE_BYTES
                ):
                    raise DrillError("ca_tar_member_unsafe")
                names.add(member.name)
                folded_names.add(folded)
                total += member.size
                if total > MAX_CA_PLAINTEXT_BYTES:
                    raise DrillError("ca_tar_content_limit_exceeded")
                stream = archive.extractfile(member)
                if stream is None:
                    raise DrillError("ca_tar_member_unreadable")
                data = stream.read(member.size + 1)
                if len(data) != member.size:
                    raise DrillError("ca_tar_member_size_mismatch")
                selected[member.name] = data
            end_offset = archive.offset
    except (tarfile.TarError, UnicodeError, OSError) as exc:
        raise DrillError("ca_tar_invalid") from exc
    if (
        count != expected_file_count
        or end_offset + tarfile.BLOCKSIZE * 2 > len(payload)
        or any(payload[end_offset:])
    ):
        raise DrillError("ca_tar_count_or_trailer_invalid")
    if names != _CA_FILENAMES or selected.keys() != _CA_FILENAMES:
        raise DrillError("ca_material_set_invalid")
    _validate_pem(selected["root.crt"], frozenset({"CERTIFICATE"}))
    _validate_pem(
        selected["root.key"],
        frozenset({"PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY"}),
    )
    _validate_pem(selected["intermediate.crt"], frozenset({"CERTIFICATE"}))
    _validate_pem(
        selected["intermediate.key"],
        frozenset({"PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY"}),
    )
    if not hmac.compare_digest(payload, _canonical_ca_tar(selected)):
        raise DrillError("ca_tar_not_canonical_producer_format")
    return selected


@contextmanager
def _sealed_memfd(payload: bytes, *, name: str) -> Iterator[tuple[str, int]]:
    if not hasattr(os, "memfd_create"):
        raise DrillError("linux_memfd_required")
    allow_sealing = getattr(os, "MFD_ALLOW_SEALING", 0x0002)
    close_on_exec = getattr(os, "MFD_CLOEXEC", 0x0001)
    descriptor = os.memfd_create(name, allow_sealing | close_on_exec)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise DrillError("memfd_write_failed")
            view = view[written:]
        fchmod = getattr(os, "fchmod", None)
        if fchmod is None:
            raise DrillError("posix_fchmod_unavailable")
        fchmod(descriptor, 0o400)
        os.lseek(descriptor, 0, os.SEEK_SET)
        try:
            fcntl_module = importlib.import_module("fcntl")
            operation = fcntl_module.fcntl
            add_seals = getattr(fcntl_module, "F_ADD_SEALS", 1033)
            seals = (
                getattr(fcntl_module, "F_SEAL_SEAL", 0x0001)
                | getattr(fcntl_module, "F_SEAL_SHRINK", 0x0002)
                | getattr(fcntl_module, "F_SEAL_GROW", 0x0004)
                | getattr(fcntl_module, "F_SEAL_WRITE", 0x0008)
            )
            operation(descriptor, add_seals, seals)
        except (ImportError, AttributeError, OSError) as exc:
            raise DrillError("memfd_sealing_failed") from exc
        yield f"/proc/self/fd/{descriptor}", descriptor
    finally:
        os.close(descriptor)


def _certificate_public_key(
    runner: OpenSSLProtocol,
    certificate: str,
    pass_fds: Sequence[int],
) -> bytes:
    pem = runner.run(
        ("x509", "-in", certificate, "-pubkey", "-noout"),
        pass_fds=pass_fds,
    )
    return runner.run(
        ("pkey", "-pubin", "-outform", "DER"),
        input_bytes=pem,
        pass_fds=pass_fds,
    )


def _private_public_key(
    runner: OpenSSLProtocol,
    private_key: str,
    pass_fds: Sequence[int],
) -> bytes:
    return runner.run(
        ("pkey", "-in", private_key, "-pubout", "-outform", "DER"),
        pass_fds=pass_fds,
    )


def _verify_key_pair(
    runner: OpenSSLProtocol,
    *,
    certificate: str,
    private_key: str,
    pass_fds: Sequence[int],
) -> None:
    runner.run(("pkey", "-in", private_key, "-check", "-noout"), pass_fds=pass_fds)
    certificate_public = _certificate_public_key(runner, certificate, pass_fds)
    private_public = _private_public_key(runner, private_key, pass_fds)
    if not hmac.compare_digest(
        hashlib.sha256(certificate_public).digest(),
        hashlib.sha256(private_public).digest(),
    ):
        raise DrillError("ca_certificate_private_key_mismatch")


def _openssl_text(payload: bytes, code: str) -> str:
    try:
        text = payload.decode("utf-8")
    except UnicodeError as exc:
        raise DrillError(code) from exc
    if not text or "\x00" in text:
        raise DrillError(code)
    return text


def _validate_openssl_version(runner: OpenSSLProtocol) -> None:
    text = _openssl_text(
        runner.run(("version",), max_output=4096),
        "openssl_version_unsupported",
    )
    match = _OPENSSL_VERSION.match(text)
    if match is None or int(match.group(1)) != SUPPORTED_OPENSSL_MAJOR:
        raise DrillError("openssl_version_unsupported")


def _certificate_window(text: str) -> tuple[datetime, datetime]:
    observed: dict[str, datetime] = {}
    for label, value in _OPENSSL_ISO_DATE.findall(text):
        if label in observed:
            raise DrillError("recipient_certificate_validity_invalid")
        try:
            observed[label] = datetime.strptime(value, "%Y-%m-%d %H:%M:%SZ").replace(tzinfo=UTC)
        except ValueError as exc:
            raise DrillError("recipient_certificate_validity_invalid") from exc
    if set(observed) != {"notBefore", "notAfter"}:
        raise DrillError("recipient_certificate_validity_invalid")
    return observed["notBefore"], observed["notAfter"]


def _validate_certificate_signature_algorithms(text: str) -> None:
    algorithms = re.findall(r"^\s*Signature Algorithm:\s*([^\r\n]+)\s*$", text, re.MULTILINE)
    if not algorithms or any(
        "sha1" in algorithm.casefold() or "md5" in algorithm.casefold() for algorithm in algorithms
    ):
        raise DrillError("ca_certificate_signature_algorithm_weak")


def _validate_rsa_public_key_description(text: str, *, minimum_bits: int) -> None:
    match = _PUBLIC_KEY_BITS.search(text)
    if (
        match is None
        or int(match.group(1)) < minimum_bits
        or re.search(r"^Modulus:\s*$", text, re.MULTILINE) is None
        or re.search(r"^Exponent:\s*[0-9]+", text, re.MULTILINE) is None
    ):
        raise DrillError("recipient_rsa_key_strength_invalid")


def _validate_ca_private_key_description(text: str) -> None:
    match = _PRIVATE_KEY_BITS.search(text)
    if match is None:
        raise DrillError("ca_private_key_strength_invalid")
    bits = int(match.group(1))
    if (
        re.search(r"^modulus:\s*$", text, re.MULTILINE) is not None
        and re.search(r"^publicExponent:\s*[0-9]+", text, re.MULTILINE) is not None
    ):
        if bits < MIN_CA_RSA_BITS:
            raise DrillError("ca_private_key_strength_invalid")
        return
    curve = re.search(r"^ASN1 OID:\s*([A-Za-z0-9.-]+)\s*$", text, re.MULTILINE)
    if bits < MIN_CA_EC_BITS or curve is None or curve.group(1) not in _APPROVED_EC_CURVES:
        raise DrillError("ca_private_key_strength_invalid")


def _validate_recipient_contract(
    runner: OpenSSLProtocol,
    *,
    certificate: str,
    private_key: str,
    pass_fds: Sequence[int],
    now: datetime,
) -> None:
    if now.tzinfo != UTC:
        raise DrillError("recipient_certificate_validity_invalid")
    _verify_key_pair(
        runner,
        certificate=certificate,
        private_key=private_key,
        pass_fds=pass_fds,
    )
    certificate_text = _openssl_text(
        runner.run(
            (
                "x509",
                "-in",
                certificate,
                "-noout",
                "-dateopt",
                "iso_8601",
                "-startdate",
                "-enddate",
                "-text",
            ),
            pass_fds=pass_fds,
        ),
        "recipient_certificate_contract_invalid",
    )
    not_before, not_after = _certificate_window(certificate_text)
    key_usage = re.search(
        r"X509v3 Key Usage:[^\r\n]*\r?\n\s*([^\r\n]+)",
        certificate_text,
    )
    if (
        not not_before <= now <= not_after
        or key_usage is None
        or "Key Encipherment" not in {value.strip() for value in key_usage.group(1).split(",")}
    ):
        raise DrillError("recipient_certificate_contract_invalid")
    public_key = runner.run(
        ("x509", "-in", certificate, "-pubkey", "-noout"),
        pass_fds=pass_fds,
        max_output=MAX_KEY_BYTES,
    )
    public_description = _openssl_text(
        runner.run(
            ("pkey", "-pubin", "-text_pub", "-noout"),
            input_bytes=public_key,
            pass_fds=pass_fds,
            max_output=MAX_KEY_BYTES,
        ),
        "recipient_rsa_key_strength_invalid",
    )
    _validate_rsa_public_key_description(
        public_description,
        minimum_bits=MIN_RECIPIENT_RSA_BITS,
    )


def _validate_ca_contract(
    runner: OpenSSLProtocol,
    *,
    certificate: str,
    private_key: str,
    pass_fds: Sequence[int],
) -> None:
    certificate_text = _openssl_text(
        runner.run(
            ("x509", "-in", certificate, "-noout", "-text"),
            pass_fds=pass_fds,
        ),
        "ca_certificate_contract_invalid",
    )
    _validate_certificate_signature_algorithms(certificate_text)
    private_description = _openssl_text(
        runner.run(
            ("pkey", "-in", private_key, "-text", "-noout"),
            pass_fds=pass_fds,
            max_output=MAX_KEY_BYTES,
        ),
        "ca_private_key_strength_invalid",
    )
    _validate_ca_private_key_description(private_description)


def _validate_cms_print_contract(text: str) -> None:
    key_algorithm = re.search(
        r"keyEncryptionAlgorithm:\s*\r?\n(?P<body>.*?)^\s*encryptedKey:",
        text,
        re.MULTILINE | re.DOTALL,
    )
    content_algorithm = re.search(
        r"contentEncryptionAlgorithm:\s*\r?\n(?P<body>.*?)^\s*encryptedContent:",
        text,
        re.MULTILINE | re.DOTALL,
    )
    key_body = key_algorithm.group("body") if key_algorithm is not None else ""
    content_body = content_algorithm.group("body") if content_algorithm is not None else ""
    sha256_parameters = re.findall(r"OBJECT\s*:sha256\s*$", key_body, re.MULTILINE)
    mgf1_parameters = re.findall(r"OBJECT\s*:mgf1\s*$", key_body, re.MULTILINE)
    if (
        "contentType: pkcs7-envelopedData (1.2.840.113549.1.7.3)" not in text
        or "contentType: pkcs7-data (1.2.840.113549.1.7.1)" not in text
        or text.count("d.ktri:") != 1
        or any(value in text for value in ("d.kari:", "d.kekri:", "d.pwri:", "d.ori:"))
        or "algorithm: rsaesOaep (1.2.840.113549.1.1.7)" not in key_body
        or len(sha256_parameters) != 2
        or len(mgf1_parameters) != 1
        or "algorithm: aes-256-cbc (2.16.840.1.101.3.4.1.42)" not in content_body
    ):
        raise DrillError("cms_algorithm_contract_invalid")


def _validate_cms_contract(
    runner: OpenSSLProtocol,
    cms: Path,
) -> None:
    printed = _openssl_text(
        runner.run(
            ("cms", "-cmsout", "-print", "-inform", "DER", "-in", str(cms)),
            timeout=60,
        ),
        "cms_algorithm_contract_invalid",
    )
    _validate_cms_print_contract(printed)


def _exercise_ca(materials: Mapping[str, bytes], runner: OpenSSLProtocol) -> None:
    with ExitStack() as stack:
        handles: dict[str, tuple[str, int]] = {
            name: stack.enter_context(_sealed_memfd(payload, name=f"heyi-{name}"))
            for name, payload in materials.items()
        }
        pass_fds = tuple(descriptor for _, descriptor in handles.values())
        root_cert = handles["root.crt"][0]
        root_key = handles["root.key"][0]
        intermediate_cert = handles["intermediate.crt"][0]
        intermediate_key = handles["intermediate.key"][0]
        runner.run(
            ("x509", "-in", root_cert, "-noout", "-checkend", "2592000"),
            pass_fds=pass_fds,
        )
        identity = runner.run(
            ("x509", "-in", root_cert, "-noout", "-subject", "-issuer", "-nameopt", "RFC2253"),
            pass_fds=pass_fds,
        ).decode("ascii", errors="strict")
        identity_lines = identity.splitlines()
        if (
            len(identity_lines) != 2
            or not identity_lines[0].startswith("subject=")
            or not identity_lines[1].startswith("issuer=")
            or not hmac.compare_digest(
                identity_lines[0].removeprefix("subject="),
                identity_lines[1].removeprefix("issuer="),
            )
        ):
            raise DrillError("ca_root_not_self_issued")
        _verify_key_pair(
            runner,
            certificate=root_cert,
            private_key=root_key,
            pass_fds=pass_fds,
        )
        _validate_ca_contract(
            runner,
            certificate=root_cert,
            private_key=root_key,
            pass_fds=pass_fds,
        )
        runner.run(
            ("verify", "-x509_strict", "-check_ss_sig", "-CAfile", root_cert, root_cert),
            pass_fds=pass_fds,
        )
        runner.run(
            ("x509", "-in", intermediate_cert, "-noout", "-checkend", "86400"),
            pass_fds=pass_fds,
        )
        intermediate_identity = runner.run(
            (
                "x509",
                "-in",
                intermediate_cert,
                "-noout",
                "-subject",
                "-issuer",
                "-nameopt",
                "RFC2253",
            ),
            pass_fds=pass_fds,
        ).decode("ascii", errors="strict")
        intermediate_lines = intermediate_identity.splitlines()
        if (
            len(intermediate_lines) != 2
            or not intermediate_lines[0].startswith("subject=")
            or not intermediate_lines[1].startswith("issuer=")
            or hmac.compare_digest(
                intermediate_lines[0].removeprefix("subject="),
                intermediate_lines[1].removeprefix("issuer="),
            )
        ):
            raise DrillError("ca_intermediate_identity_invalid")
        _verify_key_pair(
            runner,
            certificate=intermediate_cert,
            private_key=intermediate_key,
            pass_fds=pass_fds,
        )
        _validate_ca_contract(
            runner,
            certificate=intermediate_cert,
            private_key=intermediate_key,
            pass_fds=pass_fds,
        )
        runner.run(
            ("verify", "-x509_strict", "-CAfile", root_cert, intermediate_cert),
            pass_fds=pass_fds,
        )

        subordinate_key = runner.run(
            ("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"),
            pass_fds=pass_fds,
            timeout=60,
            max_output=MAX_KEY_BYTES,
        )
        subordinate_key_handle = stack.enter_context(
            _sealed_memfd(subordinate_key, name="heyi-root-signing-drill-key")
        )
        pass_fds = (*pass_fds, subordinate_key_handle[1])
        subordinate_request = runner.run(
            (
                "req",
                "-new",
                "-key",
                subordinate_key_handle[0],
                "-subj",
                "/CN=heyi-root-signing-drill.invalid",
            ),
            pass_fds=pass_fds,
            max_output=MAX_KEY_BYTES,
        )
        subordinate_request_handle = stack.enter_context(
            _sealed_memfd(subordinate_request, name="heyi-root-signing-drill-csr")
        )
        pass_fds = (*pass_fds, subordinate_request_handle[1])
        subordinate_extensions = (
            b"basicConstraints=critical,CA:TRUE,pathlen:0\n"
            b"keyUsage=critical,keyCertSign,cRLSign\n"
            b"subjectKeyIdentifier=hash\n"
            b"authorityKeyIdentifier=keyid,issuer\n"
        )
        subordinate_extensions_handle = stack.enter_context(
            _sealed_memfd(
                subordinate_extensions,
                name="heyi-root-signing-drill-extensions",
            )
        )
        pass_fds = (*pass_fds, subordinate_extensions_handle[1])
        subordinate_certificate = runner.run(
            (
                "x509",
                "-req",
                "-in",
                subordinate_request_handle[0],
                "-CA",
                root_cert,
                "-CAkey",
                root_key,
                "-set_serial",
                f"0x{secrets.token_hex(16)}",
                "-days",
                "1",
                "-sha256",
                "-extfile",
                subordinate_extensions_handle[0],
            ),
            pass_fds=pass_fds,
            max_output=MAX_KEY_BYTES,
        )
        subordinate_handle = stack.enter_context(
            _sealed_memfd(subordinate_certificate, name="heyi-root-signing-drill-certificate")
        )
        pass_fds = (*pass_fds, subordinate_handle[1])
        runner.run(
            ("verify", "-x509_strict", "-CAfile", root_cert, subordinate_handle[0]),
            pass_fds=pass_fds,
        )

        leaf_key = runner.run(
            ("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"),
            pass_fds=pass_fds,
            timeout=60,
            max_output=MAX_KEY_BYTES,
        )
        leaf_key_handle = stack.enter_context(_sealed_memfd(leaf_key, name="heyi-leaf-key"))
        pass_fds = (*pass_fds, leaf_key_handle[1])
        leaf_request = runner.run(
            (
                "req",
                "-new",
                "-key",
                leaf_key_handle[0],
                "-subj",
                f"/CN={DRILL_HOSTNAME}",
            ),
            pass_fds=pass_fds,
            max_output=MAX_KEY_BYTES,
        )
        request_handle = stack.enter_context(_sealed_memfd(leaf_request, name="heyi-leaf-csr"))
        pass_fds = (*pass_fds, request_handle[1])
        leaf_extensions = (
            b"basicConstraints=critical,CA:FALSE\n"
            b"keyUsage=critical,digitalSignature\n"
            b"extendedKeyUsage=serverAuth\n"
            + f"subjectAltName=DNS:{DRILL_HOSTNAME}\n".encode("ascii")
            + b"subjectKeyIdentifier=hash\n"
            + b"authorityKeyIdentifier=keyid,issuer\n"
        )
        leaf_extensions_handle = stack.enter_context(
            _sealed_memfd(leaf_extensions, name="heyi-leaf-extensions")
        )
        pass_fds = (*pass_fds, leaf_extensions_handle[1])
        leaf_certificate = runner.run(
            (
                "x509",
                "-req",
                "-in",
                request_handle[0],
                "-CA",
                intermediate_cert,
                "-CAkey",
                intermediate_key,
                "-set_serial",
                f"0x{secrets.token_hex(16)}",
                "-days",
                "1",
                "-sha256",
                "-extfile",
                leaf_extensions_handle[0],
            ),
            pass_fds=pass_fds,
            max_output=MAX_KEY_BYTES,
        )
        leaf_handle = stack.enter_context(
            _sealed_memfd(leaf_certificate, name="heyi-leaf-certificate")
        )
        pass_fds = (*pass_fds, leaf_handle[1])
        _verify_key_pair(
            runner,
            certificate=leaf_handle[0],
            private_key=leaf_key_handle[0],
            pass_fds=pass_fds,
        )
        verify_arguments = [
            "verify",
            "-x509_strict",
            "-purpose",
            "sslserver",
            "-verify_hostname",
            DRILL_HOSTNAME,
            "-CAfile",
            root_cert,
            "-untrusted",
            intermediate_cert,
        ]
        verify_arguments.append(leaf_handle[0])
        runner.run(tuple(verify_arguments), pass_fds=pass_fds)
        wrong_hostname_arguments = list(verify_arguments)
        hostname_index = wrong_hostname_arguments.index(DRILL_HOSTNAME)
        wrong_hostname_arguments[hostname_index] = "wrong-heyi-ca-restore-drill.invalid"
        runner.run_expect_failure(
            tuple(wrong_hostname_arguments),
            pass_fds=pass_fds,
        )
        untrusted_index = verify_arguments.index("-untrusted")
        missing_intermediate_arguments = tuple(
            verify_arguments[:untrusted_index] + verify_arguments[untrusted_index + 2 :]
        )
        runner.run_expect_failure(
            missing_intermediate_arguments,
            pass_fds=pass_fds,
        )


def _rsa_modulus_bits(payload: bytes) -> int:
    try:
        line = payload.decode("ascii").strip()
    except UnicodeError as exc:
        raise DrillError("attestation_rsa_key_invalid") from exc
    prefix = "Modulus="
    value = line.removeprefix(prefix)
    if (
        not line.startswith(prefix)
        or not value
        or len(value) % 2 != 0
        or any(character not in "0123456789ABCDEFabcdef" for character in value)
    ):
        raise DrillError("attestation_rsa_key_invalid")
    return len(value) * 4


def _validate_attestation_signer(
    runner: OpenSSLProtocol,
    private_key: Path,
    public_key: Path,
) -> None:
    runner.run(("pkey", "-in", str(private_key), "-check", "-noout"))
    private_modulus = runner.run(("rsa", "-in", str(private_key), "-noout", "-modulus"))
    public_modulus = runner.run(("rsa", "-pubin", "-in", str(public_key), "-noout", "-modulus"))
    if _rsa_modulus_bits(private_modulus) < MIN_ATTESTATION_RSA_BITS or not hmac.compare_digest(
        private_modulus.strip(), public_modulus.strip()
    ):
        raise DrillError("attestation_rsa_key_invalid")


def _sign_and_self_verify(
    runner: OpenSSLProtocol,
    payload: bytes,
    *,
    private_key: Path,
    public_key: Path,
) -> bytes:
    _validate_attestation_signer(runner, private_key, public_key)
    signature = runner.run(
        ("dgst", "-sha256", "-sign", str(private_key)),
        input_bytes=payload,
        max_output=MAX_KEY_BYTES,
    )
    if not signature or len(signature) > MAX_KEY_BYTES:
        raise DrillError("attestation_signature_invalid")
    with _sealed_memfd(signature, name="heyi-attestation-signature") as signature_handle:
        runner.run(
            (
                "dgst",
                "-sha256",
                "-verify",
                str(public_key),
                "-signature",
                signature_handle[0],
            ),
            input_bytes=payload,
            pass_fds=(signature_handle[1],),
        )
    return signature


def _write_file(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise DrillError("output_write_failed")
        view = view[written:]
    fchmod = getattr(os, "fchmod", None)
    if fchmod is None:
        raise DrillError("posix_fchmod_unavailable")
    fchmod(descriptor, 0o400)
    os.fsync(descriptor)


def _file_identity(path: Path) -> tuple[int, int] | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode):
        return None
    return info.st_dev, info.st_ino


def _unlink_same_file(path: Path, identity: tuple[int, int] | None) -> None:
    if identity is not None and _file_identity(path) == identity:
        path.unlink()


def _fsync_directory(directory: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(directory, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode):
            raise DrillError("output_directory_changed")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish_without_overwrite(source: Path, destination: Path) -> None:
    source_identity = _file_identity(source)
    if source_identity is None:
        raise DrillError("output_temporary_file_changed")
    try:
        os.link(source, destination, follow_symlinks=False)
    except FileExistsError as exc:
        raise DrillError("output_raced_or_already_exists") from exc
    except OSError as exc:
        raise DrillError("output_atomic_publish_failed") from exc
    if _file_identity(destination) != source_identity:
        raise DrillError("output_atomic_publish_identity_mismatch")


def _write_output_pair(
    directory: Path,
    *,
    attestation_path: Path,
    attestation: bytes,
    signature_path: Path,
    signature: bytes,
) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    lock_path = directory / OUTPUT_LOCK_NAME
    attestation_temporary = directory / f".{attestation_path.name}.{secrets.token_hex(16)}.tmp"
    signature_temporary = directory / f".{signature_path.name}.{secrets.token_hex(16)}.tmp"
    lock_identity: tuple[int, int] | None = None
    attestation_identity: tuple[int, int] | None = None
    signature_identity: tuple[int, int] | None = None
    try:
        try:
            lock_descriptor = os.open(lock_path, flags, 0o600)
        except FileExistsError as exc:
            raise DrillError("output_operation_in_progress") from exc
        try:
            lock_info = os.fstat(lock_descriptor)
            lock_identity = (lock_info.st_dev, lock_info.st_ino)
            _write_file(lock_descriptor, b"heyi-offline-ca-restore-drill-output-lock-v1\n")
        finally:
            os.close(lock_descriptor)

        attestation_descriptor = os.open(attestation_temporary, flags, 0o600)
        try:
            attestation_info = os.fstat(attestation_descriptor)
            attestation_identity = (attestation_info.st_dev, attestation_info.st_ino)
            _write_file(attestation_descriptor, attestation)
        finally:
            os.close(attestation_descriptor)
        signature_descriptor = os.open(signature_temporary, flags, 0o600)
        try:
            signature_info = os.fstat(signature_descriptor)
            signature_identity = (signature_info.st_dev, signature_info.st_ino)
            _write_file(signature_descriptor, signature)
        finally:
            os.close(signature_descriptor)

        _publish_without_overwrite(signature_temporary, signature_path)
        _publish_without_overwrite(attestation_temporary, attestation_path)
        _unlink_same_file(signature_temporary, signature_identity)
        _unlink_same_file(attestation_temporary, attestation_identity)
        _fsync_directory(directory)
    except BaseException as original:
        try:
            _unlink_same_file(attestation_path, attestation_identity)
            _unlink_same_file(signature_path, signature_identity)
            _unlink_same_file(attestation_temporary, attestation_identity)
            _unlink_same_file(signature_temporary, signature_identity)
            _fsync_directory(directory)
        except BaseException as cleanup_error:
            original.add_note("output rollback is incomplete; operation lock retained")
            raise original from cleanup_error
        try:
            _unlink_same_file(lock_path, lock_identity)
            _fsync_directory(directory)
        except BaseException as cleanup_error:
            original.add_note("output rollback completed but lock release is incomplete")
            raise original from cleanup_error
        raise
    try:
        _unlink_same_file(lock_path, lock_identity)
        _fsync_directory(directory)
    except BaseException as release_error:
        release_error.add_note(
            "output pair committed; operation lock release durability is uncertain"
        )
        raise


def run_drill(
    config: DrillConfig,
    *,
    runner: OpenSSLProtocol | None = None,
    security: SecurityContext | None = None,
    now_provider: Callable[[], datetime] = _utc_now,
) -> dict[str, str]:
    context = security or SecurityContext()
    openssl = runner or OpenSSLRunner()
    _require_runtime(context)
    _validate_openssl(context)
    _validate_openssl_version(openssl)
    output_directory = _validate_new_outputs(config, context)

    challenge = _protected_file(
        config.challenge,
        modes=frozenset({0o400, 0o440, 0o444}),
        max_bytes=MAX_CONTROL_BYTES,
        context=context,
    )
    challenge_signature = _protected_file(
        config.challenge_signature,
        modes=frozenset({0o400, 0o440, 0o444}),
        max_bytes=MAX_KEY_BYTES,
        context=context,
    )
    challenge_public = _protected_file(
        config.challenge_public_key,
        modes=frozenset({0o400, 0o440, 0o444}),
        max_bytes=MAX_KEY_BYTES,
        context=context,
    )
    if _SHA256.fullmatch(
        config.expected_challenge_public_key_sha256
    ) is None or not hmac.compare_digest(
        _sha256_file(challenge_public),
        config.expected_challenge_public_key_sha256,
    ):
        raise DrillError("challenge_signer_pin_mismatch")
    _verify_file_signature(
        openssl,
        payload=challenge,
        signature=challenge_signature,
        public_key=challenge_public,
    )
    challenge_document, challenge_raw = _read_canonical_json(challenge, context=context)
    validation_now = now_provider()
    issued, expires = _validate_challenge(challenge_document, now=validation_now)

    cms = _protected_file(
        config.cms_archive,
        modes=frozenset({0o400, 0o600}),
        max_bytes=MAX_CMS_BYTES,
        context=context,
    )
    recipient_certificate = _protected_file(
        config.recipient_certificate,
        modes=frozenset({0o400, 0o440, 0o444}),
        max_bytes=MAX_KEY_BYTES,
        context=context,
    )
    recipient_key = _protected_file(
        config.recipient_private_key,
        modes=frozenset({0o400, 0o600}),
        max_bytes=MAX_KEY_BYTES,
        context=context,
    )
    attestation_key = _protected_file(
        config.attestation_signing_key,
        modes=frozenset({0o400, 0o600}),
        max_bytes=MAX_KEY_BYTES,
        context=context,
    )
    attestation_public = _protected_file(
        config.attestation_public_key,
        modes=frozenset({0o400, 0o440, 0o444}),
        max_bytes=MAX_KEY_BYTES,
        context=context,
    )
    if not hmac.compare_digest(
        _sha256_file(attestation_public),
        str(challenge_document["ca_attestation_public_key_sha256"]),
    ):
        raise DrillError("attestation_public_key_binding_mismatch")
    cms_size = cms.stat().st_size
    if (
        cms_size != challenge_document["encrypted_archive_size_bytes"]
        or not hmac.compare_digest(
            _sha256_file(cms),
            str(challenge_document["encrypted_archive_sha256"]),
        )
        or not hmac.compare_digest(
            _sha256_file(recipient_certificate),
            str(challenge_document["recipient_certificate_sha256"]),
        )
    ):
        raise DrillError("cms_or_recipient_binding_mismatch")

    _validate_recipient_contract(
        openssl,
        certificate=str(recipient_certificate),
        private_key=str(recipient_key),
        pass_fds=(),
        now=validation_now,
    )
    _validate_cms_contract(openssl, cms)
    binding_key = _read_binding_key(config.binding_key, context)
    plaintext = openssl.run(
        (
            "cms",
            "-decrypt",
            "-binary",
            "-inform",
            "DER",
            "-in",
            str(cms),
            "-recip",
            str(recipient_certificate),
            "-inkey",
            str(recipient_key),
        ),
        timeout=120,
        max_output=MAX_CA_PLAINTEXT_BYTES,
    )
    expected_hmac = str(challenge_document["plaintext_opaque_hmac_sha256"])
    observed_hmac = hmac.new(binding_key, HMAC_DOMAIN + plaintext, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(observed_hmac, expected_hmac):
        raise DrillError("ca_plaintext_hmac_mismatch")
    materials = _read_ca_archive(
        plaintext,
        expected_file_count=cast(int, challenge_document["file_count"]),
    )
    try:
        _exercise_ca(materials, openssl)
    finally:
        materials.clear()
        plaintext = b""
        binding_key = b""

    tested_at = now_provider()
    if tested_at.tzinfo != UTC or not issued <= tested_at <= expires:
        raise DrillError("attestation_time_outside_challenge")
    attestation_document: dict[str, object] = {
        "schema_version": 1,
        "kind": ATTESTATION_KIND,
        "project": PROJECT,
        "challenge_sha256": _sha256_bytes(challenge_raw),
        "encrypted_archive_sha256": challenge_document["encrypted_archive_sha256"],
        "plaintext_opaque_hmac_sha256": challenge_document["plaintext_opaque_hmac_sha256"],
        "file_count": challenge_document["file_count"],
        "recipient_certificate_sha256": challenge_document["recipient_certificate_sha256"],
        "status": "passed",
        "tested_at": tested_at.isoformat().replace("+00:00", "Z"),
        "private_key_location": "offline-only",
        "server_private_key_present": False,
        "cos_used": False,
    }
    if set(attestation_document) != _ATTESTATION_KEYS:
        raise DrillError("attestation_internal_schema_invalid")
    attestation_bytes = _canonical_json(attestation_document)
    signature_bytes = _sign_and_self_verify(
        openssl,
        attestation_bytes,
        private_key=attestation_key,
        public_key=attestation_public,
    )
    _write_output_pair(
        output_directory,
        attestation_path=config.output_attestation,
        attestation=attestation_bytes,
        signature_path=config.output_signature,
        signature=signature_bytes,
    )
    return {
        "status": "passed",
        "attestation": str(config.output_attestation),
        "attestation_sha256": _sha256_file(config.output_attestation),
        "signature": str(config.output_signature),
        "signature_sha256": _sha256_file(config.output_signature),
    }


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(
        description=(
            "Verify and execute the signed heyi-kb-offline Caddy CA restore challenge "
            "on a physically isolated Linux host."
        )
    )
    parser.add_argument("--challenge", type=Path, required=True)
    parser.add_argument("--challenge-signature", type=Path, required=True)
    parser.add_argument("--challenge-public-key", type=Path, required=True)
    parser.add_argument("--expected-challenge-public-key-sha256", required=True)
    parser.add_argument("--cms-archive", type=Path, required=True)
    parser.add_argument("--recipient-certificate", type=Path, required=True)
    parser.add_argument("--recipient-private-key", type=Path, required=True)
    parser.add_argument("--binding-key", type=Path, required=True)
    parser.add_argument("--attestation-signing-key", type=Path, required=True)
    parser.add_argument("--attestation-public-key", type=Path, required=True)
    parser.add_argument("--output-attestation", type=Path, required=True)
    parser.add_argument("--output-signature", type=Path, required=True)
    return parser


def _config(arguments: argparse.Namespace) -> DrillConfig:
    return DrillConfig(
        challenge=arguments.challenge,
        challenge_signature=arguments.challenge_signature,
        challenge_public_key=arguments.challenge_public_key,
        expected_challenge_public_key_sha256=arguments.expected_challenge_public_key_sha256,
        cms_archive=arguments.cms_archive,
        recipient_certificate=arguments.recipient_certificate,
        recipient_private_key=arguments.recipient_private_key,
        binding_key=arguments.binding_key,
        attestation_signing_key=arguments.attestation_signing_key,
        attestation_public_key=arguments.attestation_public_key,
        output_attestation=arguments.output_attestation,
        output_signature=arguments.output_signature,
    )


def main(argv: Sequence[str] | None = None) -> int:
    try:
        result = run_drill(_config(_parser().parse_args(argv)))
    except DrillError as exc:
        print(f"offline-ca-restore-drill: blocked:{exc.code}", file=sys.stderr)
        return 65
    except (OSError, UnicodeError, tarfile.TarError, ValueError):
        print("offline-ca-restore-drill: blocked:unexpected_safe_failure", file=sys.stderr)
        return 65
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
