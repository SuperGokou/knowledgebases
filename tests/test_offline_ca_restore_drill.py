from __future__ import annotations

import base64
import hashlib
import hmac
import importlib.util
import io
import json
import os
import signal
import subprocess
import sys
import tarfile
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPOSITORY = Path(__file__).resolve().parents[1]
SCRIPT = REPOSITORY / "scripts" / "offline_ca_restore_drill.py"


def _module() -> ModuleType:
    name = "offline_ca_restore_drill_under_test"
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _now() -> datetime:
    return datetime(2026, 7, 16, 12, 0, tzinfo=UTC)


def _challenge(
    module: ModuleType,
    *,
    now: datetime | None = None,
    cms: bytes = b"CMS",
    recipient_certificate: bytes = b"RECIPIENT",
    attestation_public_key: bytes = b"ATTESTATION-PUBLIC",
    plaintext: bytes = b"TAR",
    file_count: int = 4,
) -> dict[str, object]:
    current = now or _now()
    return {
        "schema_version": 2,
        "kind": module.CHALLENGE_KIND,
        "project": module.PROJECT,
        "run_id": "20260716-CHG-001",
        "plan_sha256": "a" * 64,
        "release_authorization_sha256": "c" * 64,
        "nonce": "b" * 64,
        "issued_at": current.isoformat().replace("+00:00", "Z"),
        "expires_at": (current + timedelta(days=7)).isoformat().replace("+00:00", "Z"),
        "encrypted_archive_sha256": hashlib.sha256(cms).hexdigest(),
        "encrypted_archive_size_bytes": len(cms),
        "plaintext_opaque_hmac_sha256": hmac.new(
            b"k" * 32,
            module.HMAC_DOMAIN + plaintext,
            hashlib.sha256,
        ).hexdigest(),
        "file_count": file_count,
        "recipient_certificate_sha256": hashlib.sha256(recipient_certificate).hexdigest(),
        "ca_attestation_public_key_sha256": hashlib.sha256(attestation_public_key).hexdigest(),
        "cos_transfer_allowed": False,
    }


def _pem(label: str, payload: bytes) -> bytes:
    encoded = base64.b64encode(payload).decode("ascii")
    return (f"-----BEGIN {label}-----\n{encoded}\n-----END {label}-----\n").encode("ascii")


def _ca_materials() -> dict[str, bytes]:
    return {
        "root.crt": _pem("CERTIFICATE", b"root-certificate"),
        "root.key": _pem("PRIVATE KEY", b"root-private-key"),
        "intermediate.crt": _pem("CERTIFICATE", b"intermediate-certificate"),
        "intermediate.key": _pem("PRIVATE KEY", b"intermediate-private-key"),
    }


def test_process_dump_hardening_sets_irreversible_core_limit_and_prctl() -> None:
    module = _module()

    class FakeResource:
        RLIMIT_CORE = 4

        def __init__(self) -> None:
            self.limit = (1024, 1024)

        def setrlimit(self, resource: int, value: tuple[int, int]) -> None:
            assert resource == self.RLIMIT_CORE
            self.limit = value

        def getrlimit(self, resource: int) -> tuple[int, int]:
            assert resource == self.RLIMIT_CORE
            return self.limit

    class FakeLibC:
        def __init__(self) -> None:
            self.dumpable = 1
            self.calls: list[int] = []

        def prctl(self, option: int, value: int, *unused: int) -> int:
            del unused
            self.calls.append(option)
            if option == module.PR_SET_DUMPABLE:
                self.dumpable = value
                return 0
            if option == module.PR_GET_DUMPABLE:
                return self.dumpable
            return -1

    class FakeCtypes:
        def __init__(self, libc: FakeLibC) -> None:
            self.libc = libc

        def CDLL(self, name: object, *, use_errno: bool) -> FakeLibC:
            assert name is None
            assert use_errno is True
            return self.libc

    resource = FakeResource()
    libc = FakeLibC()
    module._disable_process_dumps(resource, FakeCtypes(libc))
    assert resource.limit == (0, 0)
    assert libc.dumpable == 0
    assert libc.calls == [module.PR_SET_DUMPABLE, module.PR_GET_DUMPABLE]


def test_runtime_hardening_is_fail_closed_with_explicit_test_seam(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    monkeypatch.setattr(module.sys, "platform", "linux")
    monkeypatch.setattr(module.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(module.os, "memfd_create", lambda *args: 1, raising=False)
    calls: list[str] = []
    monkeypatch.setattr(module, "_disable_process_dumps", lambda: calls.append("hardened"))

    module._require_runtime(module.SecurityContext())
    assert calls == ["hardened"]

    calls.clear()
    module._require_runtime(module.SecurityContext(enforce_process_hardening=False))
    assert calls == []

    def failed() -> None:
        raise module.DrillError("process_dump_hardening_failed")

    monkeypatch.setattr(module, "_disable_process_dumps", failed)
    with pytest.raises(module.DrillError, match="process_dump_hardening_failed"):
        module._require_runtime(module.SecurityContext())


def _custom_tar(
    entries: list[tuple[str, bytes, bytes]],
    *,
    mode: int = 0o600,
) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, payload, type_flag in entries:
            member = tarfile.TarInfo(name)
            member.size = 0 if type_flag != tarfile.REGTYPE else len(payload)
            member.type = type_flag
            member.mode = mode
            member.uid = 0
            member.gid = 0
            member.uname = "root"
            member.gname = "root"
            member.mtime = 0
            archive.addfile(member, io.BytesIO(payload) if member.size else None)
    return stream.getvalue()


def test_challenge_v2_is_exact_current_and_cos_forbidden() -> None:
    module = _module()
    document = _challenge(module)
    issued, expires = module._validate_challenge(document, now=_now())
    assert expires - issued == timedelta(days=7)

    document["extra"] = True
    with pytest.raises(module.DrillError, match="challenge_schema_invalid"):
        module._validate_challenge(document, now=_now())
    document.pop("extra")

    document["cos_transfer_allowed"] = True
    with pytest.raises(module.DrillError, match="challenge_contract_invalid"):
        module._validate_challenge(document, now=_now())
    document["cos_transfer_allowed"] = False

    document["schema_version"] = 1
    with pytest.raises(module.DrillError, match="challenge_contract_invalid"):
        module._validate_challenge(document, now=_now())


def test_challenge_rejects_bool_counts_and_non_exact_or_expired_window() -> None:
    module = _module()
    document = _challenge(module)
    document["file_count"] = True
    with pytest.raises(module.DrillError, match="challenge_contract_invalid"):
        module._validate_challenge(document, now=_now())

    document = _challenge(module)
    document["expires_at"] = (_now() + timedelta(days=6)).isoformat().replace("+00:00", "Z")
    with pytest.raises(module.DrillError, match="challenge_expired"):
        module._validate_challenge(document, now=_now())

    document = _challenge(module, now=_now() - timedelta(days=8))
    with pytest.raises(module.DrillError, match="challenge_expired"):
        module._validate_challenge(document, now=_now())


def test_canonical_json_rejects_duplicates_nonfinite_and_noncanonical(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    path = tmp_path / "challenge.json"
    monkeypatch.setattr(module, "_open_protected_bytes", lambda *args, **kwargs: path.read_bytes())

    path.write_bytes(b'{"a":1,"a":2}\n')
    with pytest.raises(module.DrillError, match="duplicate"):
        module._read_canonical_json(path, context=module.SecurityContext())

    path.write_bytes(b'{"a":NaN}\n')
    with pytest.raises(module.DrillError, match="nonfinite"):
        module._read_canonical_json(path, context=module.SecurityContext())

    path.write_bytes(b'{ "a": 1 }\n')
    with pytest.raises(module.DrillError, match="not_canonical"):
        module._read_canonical_json(path, context=module.SecurityContext())


def test_binding_key_requires_canonical_base64url_and_32_decoded_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    path = tmp_path / "binding.key"
    monkeypatch.setattr(module, "_open_protected_bytes", lambda *args, **kwargs: path.read_bytes())

    key = b"k" * 32
    path.write_bytes(base64.urlsafe_b64encode(key).rstrip(b"=") + b"\n")
    assert module._read_binding_key(path, module.SecurityContext()) == key

    path.write_bytes(base64.urlsafe_b64encode(b"short").rstrip(b"="))
    with pytest.raises(module.DrillError, match="strength"):
        module._read_binding_key(path, module.SecurityContext())

    path.write_bytes(b"not base64url!")
    with pytest.raises(module.DrillError, match="encoding"):
        module._read_binding_key(path, module.SecurityContext())


def _recipient_certificate_text(
    *,
    not_before: str = "2026-07-15 00:00:00Z",
    not_after: str = "2026-08-15 00:00:00Z",
    key_usage: str = "Key Encipherment, Data Encipherment",
) -> bytes:
    return (
        "Certificate:\n"
        "    Data:\n"
        "        X509v3 extensions:\n"
        "            X509v3 Key Usage: critical\n"
        f"                {key_usage}\n"
        "    Signature Algorithm: sha256WithRSAEncryption\n"
        f"notBefore={not_before}\n"
        f"notAfter={not_after}\n"
    ).encode("ascii")


def _recipient_public_key_text(bits: int = 3072) -> bytes:
    return (f"Public-Key: ({bits} bit)\nModulus:\n    00:aa\nExponent: 65537 (0x10001)\n").encode(
        "ascii"
    )


def test_recipient_requires_current_rsa3072_key_encipherment_certificate() -> None:
    module = _module()

    class RecipientRunner:
        def __init__(self, certificate_text: bytes, public_text: bytes) -> None:
            self.certificate_text = certificate_text
            self.public_text = public_text

        def run(self, arguments: Any, **kwargs: Any) -> bytes:
            del kwargs
            values = tuple(arguments)
            if values[:2] == ("pkey", "-in") and "-check" in values:
                return b""
            if values[:2] == ("x509", "-in") and "-pubkey" in values:
                return b"-----BEGIN PUBLIC KEY-----\nQQ==\n-----END PUBLIC KEY-----\n"
            if values[:2] == ("pkey", "-pubin") and "-outform" in values:
                return b"MATCHED-DER"
            if values[:2] == ("pkey", "-in") and "-pubout" in values:
                return b"MATCHED-DER"
            if values[:2] == ("x509", "-in") and "-dateopt" in values:
                return self.certificate_text
            if values[:2] == ("pkey", "-pubin") and "-text_pub" in values:
                return self.public_text
            raise AssertionError(values)

    module._validate_recipient_contract(
        RecipientRunner(_recipient_certificate_text(), _recipient_public_key_text()),
        certificate="/protected/recipient.pem",
        private_key="/protected/recipient.key",
        pass_fds=(),
        now=_now(),
    )

    invalid_contracts = (
        (_recipient_certificate_text(key_usage="Digital Signature"), _recipient_public_key_text()),
        (
            _recipient_certificate_text(not_after="2026-07-15 23:59:59Z"),
            _recipient_public_key_text(),
        ),
        (_recipient_certificate_text(), _recipient_public_key_text(2048)),
    )
    for certificate_text, public_text in invalid_contracts:
        with pytest.raises(
            module.DrillError,
            match="recipient_certificate_contract_invalid|recipient_rsa_key_strength_invalid",
        ):
            module._validate_recipient_contract(
                RecipientRunner(certificate_text, public_text),
                certificate="/protected/recipient.pem",
                private_key="/protected/recipient.key",
                pass_fds=(),
                now=_now(),
            )


def test_ca_key_and_certificate_strength_contract() -> None:
    module = _module()
    module._validate_ca_private_key_description(
        "Private-Key: (3072 bit, 2 primes)\nmodulus:\npublicExponent: 65537 (0x10001)\n"
    )
    module._validate_ca_private_key_description(
        "Private-Key: (256 bit)\npriv:\npub:\nASN1 OID: prime256v1\nNIST CURVE: P-256\n"
    )
    module._validate_certificate_signature_algorithms(
        "    Signature Algorithm: ecdsa-with-SHA256\n"
    )

    weak_keys = (
        "Private-Key: (2048 bit, 2 primes)\nmodulus:\npublicExponent: 65537\n",
        "Private-Key: (224 bit)\npriv:\npub:\nASN1 OID: secp224r1\n",
        "Private-Key: (256 bit)\npriv:\npub:\nASN1 OID: sect233k1\n",
    )
    for description in weak_keys:
        with pytest.raises(module.DrillError, match="ca_private_key_strength_invalid"):
            module._validate_ca_private_key_description(description)
    with pytest.raises(module.DrillError, match="signature_algorithm_weak"):
        module._validate_certificate_signature_algorithms(
            "    Signature Algorithm: sha1WithRSAEncryption\n"
        )


def _cms_print_contract() -> str:
    return """
CMS_ContentInfo:
  contentType: pkcs7-envelopedData (1.2.840.113549.1.7.3)
  d.envelopedData:
    recipientInfos:
      d.ktri:
        keyEncryptionAlgorithm:
          algorithm: rsaesOaep (1.2.840.113549.1.1.7)
          parameter: SEQUENCE:
    6:d=3  hl=2 l=9 prim: OBJECT :sha256
   21:d=3  hl=2 l=9 prim: OBJECT :mgf1
   34:d=4  hl=2 l=9 prim: OBJECT :sha256
        encryptedKey:
          0000 - 00
    encryptedContentInfo:
      contentType: pkcs7-data (1.2.840.113549.1.7.1)
      contentEncryptionAlgorithm:
        algorithm: aes-256-cbc (2.16.840.1.101.3.4.1.42)
        parameter: OCTET STRING:
      encryptedContent:
        0000 - 00
"""


def test_cms_contract_requires_openssl3_oaep_sha256_mgf1_and_aes256() -> None:
    module = _module()
    module._validate_cms_print_contract(_cms_print_contract())

    invalid_documents = (
        _cms_print_contract().replace("rsaesOaep", "rsaEncryption"),
        _cms_print_contract().replace("OBJECT :sha256", "OBJECT :sha1", 1),
        _cms_print_contract().replace("OBJECT :mgf1", "OBJECT :pSpecified"),
        _cms_print_contract().replace("aes-256-cbc", "aes-128-cbc"),
        _cms_print_contract().replace("      d.ktri:", "      d.ktri:\n      d.ktri:"),
    )
    for document in invalid_documents:
        with pytest.raises(module.DrillError, match="cms_algorithm_contract_invalid"):
            module._validate_cms_print_contract(document)

    class VersionRunner:
        def __init__(self, version: bytes) -> None:
            self.version = version

        def run(self, arguments: Any, **kwargs: Any) -> bytes:
            del kwargs
            assert tuple(arguments) == ("version",)
            return self.version

    module._validate_openssl_version(VersionRunner(b"OpenSSL 3.0.13 30 Jan 2024\n"))
    with pytest.raises(module.DrillError, match="openssl_version_unsupported"):
        module._validate_openssl_version(VersionRunner(b"OpenSSL 1.1.1w 11 Sep 2023\n"))


def test_ca_tar_accepts_only_exact_canonical_four_file_archive() -> None:
    module = _module()
    materials = _ca_materials()
    payload = module._canonical_ca_tar(materials)
    assert module._read_ca_archive(payload, expected_file_count=4) == materials

    with pytest.raises(module.DrillError, match="count"):
        module._read_ca_archive(payload, expected_file_count=3)

    altered = bytearray(payload)
    altered[-1] = 1
    with pytest.raises(module.DrillError, match="trailer"):
        module._read_ca_archive(bytes(altered), expected_file_count=4)


@pytest.mark.parametrize(
    ("name", "type_flag"),
    [
        ("../root.crt", tarfile.REGTYPE),
        ("/root.crt", tarfile.REGTYPE),
        ("nested/root.crt", tarfile.REGTYPE),
        ("root.crt", tarfile.SYMTYPE),
        ("root.crt", tarfile.LNKTYPE),
        ("root.crt", tarfile.CHRTYPE),
        ("root.crt", tarfile.FIFOTYPE),
    ],
)
def test_ca_tar_rejects_paths_links_devices_and_missing_fixed_set(
    name: str,
    type_flag: bytes,
) -> None:
    module = _module()
    materials = _ca_materials()
    entries = [(filename, payload, tarfile.REGTYPE) for filename, payload in materials.items()]
    entries[0] = (name, entries[0][1], type_flag)
    payload = _custom_tar(entries)
    with pytest.raises(module.DrillError, match="member_unsafe|material_set"):
        module._read_ca_archive(payload, expected_file_count=4)


def test_ca_tar_rejects_duplicate_case_collision_and_wrong_metadata() -> None:
    module = _module()
    materials = _ca_materials()
    duplicate = [
        ("root.crt", materials["root.crt"], tarfile.REGTYPE),
        ("ROOT.CRT", materials["root.crt"], tarfile.REGTYPE),
        ("root.key", materials["root.key"], tarfile.REGTYPE),
        ("intermediate.crt", materials["intermediate.crt"], tarfile.REGTYPE),
    ]
    with pytest.raises(module.DrillError, match="member_unsafe"):
        module._read_ca_archive(_custom_tar(duplicate), expected_file_count=4)

    entries = [(name, value, tarfile.REGTYPE) for name, value in materials.items()]
    with pytest.raises(module.DrillError, match="member_unsafe"):
        module._read_ca_archive(_custom_tar(entries, mode=0o644), expected_file_count=4)


def test_hmac_mismatch_blocks_before_tar_parsing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    cms = b"CMS"
    recipient = b"RECIPIENT"
    attestation_public = b"ATTESTATION-PUBLIC"
    plaintext = module._canonical_ca_tar(_ca_materials())
    document = _challenge(
        module,
        cms=cms,
        recipient_certificate=recipient,
        attestation_public_key=attestation_public,
        plaintext=b"different",
    )
    files = {
        "challenge": module._canonical_json(document),
        "challenge.sig": b"signature",
        "challenge.pub": b"challenge-public",
        "archive.p7m": cms,
        "recipient.crt": recipient,
        "recipient.key": b"recipient-key",
        "binding.key": b"binding",
        "attestation.key": b"attestation-key",
        "attestation.pub": attestation_public,
    }
    paths: dict[str, Path] = {}
    for name, value in files.items():
        path = tmp_path / name
        path.write_bytes(value)
        paths[name] = path

    class FakeRunner:
        def run(self, arguments: Any, **kwargs: Any) -> bytes:
            if "-decrypt" in arguments:
                return plaintext
            return b""

    monkeypatch.setattr(module, "_require_runtime", lambda context: None)
    monkeypatch.setattr(module, "_validate_openssl", lambda context: None)
    monkeypatch.setattr(module, "_validate_openssl_version", lambda runner: None)
    monkeypatch.setattr(module, "_validate_new_outputs", lambda config, context: tmp_path)
    monkeypatch.setattr(module, "_protected_file", lambda path, **kwargs: path)
    monkeypatch.setattr(
        module,
        "_read_canonical_json",
        lambda path, **kwargs: (document, module._canonical_json(document)),
    )
    monkeypatch.setattr(module, "_verify_file_signature", lambda *args, **kwargs: None)
    monkeypatch.setattr(module, "_validate_recipient_contract", lambda *args, **kwargs: None)
    monkeypatch.setattr(module, "_validate_cms_contract", lambda *args, **kwargs: None)
    monkeypatch.setattr(module, "_read_binding_key", lambda *args, **kwargs: b"k" * 32)

    def forbidden(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("tar parser must not run after an HMAC mismatch")

    monkeypatch.setattr(module, "_read_ca_archive", forbidden)
    config = module.DrillConfig(
        challenge=paths["challenge"],
        challenge_signature=paths["challenge.sig"],
        challenge_public_key=paths["challenge.pub"],
        expected_challenge_public_key_sha256=hashlib.sha256(files["challenge.pub"]).hexdigest(),
        cms_archive=paths["archive.p7m"],
        recipient_certificate=paths["recipient.crt"],
        recipient_private_key=paths["recipient.key"],
        binding_key=paths["binding.key"],
        attestation_signing_key=paths["attestation.key"],
        attestation_public_key=paths["attestation.pub"],
        output_attestation=tmp_path / "result.json",
        output_signature=tmp_path / "result.sig",
    )
    with pytest.raises(module.DrillError, match="hmac_mismatch"):
        module.run_drill(config, runner=FakeRunner(), now_provider=_now)


def test_successful_flow_emits_finalize_compatible_attestation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    materials = _ca_materials()
    plaintext = module._canonical_ca_tar(materials)
    cms = b"CMS"
    recipient = b"RECIPIENT"
    attestation_public = b"ATTESTATION-PUBLIC"
    challenge_public = b"CHALLENGE-PUBLIC"
    document = _challenge(
        module,
        cms=cms,
        recipient_certificate=recipient,
        attestation_public_key=attestation_public,
        plaintext=plaintext,
    )
    file_values = {
        "challenge": module._canonical_json(document),
        "challenge.sig": b"challenge-signature",
        "challenge.pub": challenge_public,
        "archive.p7m": cms,
        "recipient.crt": recipient,
        "recipient.key": b"recipient-key",
        "binding.key": b"binding",
        "attestation.key": b"attestation-key",
        "attestation.pub": attestation_public,
    }
    paths: dict[str, Path] = {}
    for name, value in file_values.items():
        path = tmp_path / name
        path.write_bytes(value)
        paths[name] = path

    class FakeRunner:
        def run(self, arguments: Any, **kwargs: Any) -> bytes:
            if "-decrypt" in arguments:
                return plaintext
            return b""

    monkeypatch.setattr(module, "_require_runtime", lambda context: None)
    monkeypatch.setattr(module, "_validate_openssl", lambda context: None)
    monkeypatch.setattr(module, "_validate_openssl_version", lambda runner: None)
    monkeypatch.setattr(module, "_validate_new_outputs", lambda config, context: tmp_path)
    monkeypatch.setattr(module, "_protected_file", lambda path, **kwargs: path)
    monkeypatch.setattr(
        module,
        "_read_canonical_json",
        lambda path, **kwargs: (document, module._canonical_json(document)),
    )
    monkeypatch.setattr(module, "_verify_file_signature", lambda *args, **kwargs: None)
    monkeypatch.setattr(module, "_validate_recipient_contract", lambda *args, **kwargs: None)
    monkeypatch.setattr(module, "_validate_cms_contract", lambda *args, **kwargs: None)
    monkeypatch.setattr(module, "_read_binding_key", lambda *args, **kwargs: b"k" * 32)
    exercised: list[dict[str, bytes]] = []
    monkeypatch.setattr(
        module,
        "_exercise_ca",
        lambda restored, runner: exercised.append(dict(restored)),
    )
    monkeypatch.setattr(module, "_sign_and_self_verify", lambda *args, **kwargs: b"SIGNATURE")

    def write_outputs(
        directory: Path,
        *,
        attestation_path: Path,
        attestation: bytes,
        signature_path: Path,
        signature: bytes,
    ) -> None:
        del directory
        attestation_path.write_bytes(attestation)
        signature_path.write_bytes(signature)

    monkeypatch.setattr(module, "_write_output_pair", write_outputs)
    config = module.DrillConfig(
        challenge=paths["challenge"],
        challenge_signature=paths["challenge.sig"],
        challenge_public_key=paths["challenge.pub"],
        expected_challenge_public_key_sha256=hashlib.sha256(challenge_public).hexdigest(),
        cms_archive=paths["archive.p7m"],
        recipient_certificate=paths["recipient.crt"],
        recipient_private_key=paths["recipient.key"],
        binding_key=paths["binding.key"],
        attestation_signing_key=paths["attestation.key"],
        attestation_public_key=paths["attestation.pub"],
        output_attestation=tmp_path / "result.json",
        output_signature=tmp_path / "result.sig",
    )
    result = module.run_drill(config, runner=FakeRunner(), now_provider=_now)
    attestation = json.loads(config.output_attestation.read_text(encoding="utf-8"))
    assert exercised == [materials]
    assert set(attestation) == module._ATTESTATION_KEYS
    assert attestation["schema_version"] == 1
    assert attestation["status"] == "passed"
    assert attestation["private_key_location"] == "offline-only"
    assert attestation["server_private_key_present"] is False
    assert attestation["cos_used"] is False
    assert attestation["tested_at"] == "2026-07-16T12:00:00Z"
    assert result["status"] == "passed"


def test_source_contract_uses_fixed_openssl_memfd_and_never_extracts() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert 'OPENSSL: Final = Path("/usr/bin/openssl")' in source
    assert "shell=False" in source
    assert "memfd_create" in source
    assert "F_ADD_SEALS" in source
    assert ".extract(" not in source
    assert ".extractall(" not in source
    assert "r:*" not in source
    assert "-CAcreateserial" not in source
    assert '"enc"' not in source
    assert "HMAC_DOMAIN + plaintext" in source
    assert "ca_attestation_public_key_sha256" in source
    assert "wrong-heyi-ca-restore-drill.invalid" in source
    assert source.count("run_expect_failure(") >= 3
    assert "RLIMIT_CORE" in source
    assert "PR_SET_DUMPABLE" in source
    assert "PR_GET_DUMPABLE" in source
    assert "os.replace(" not in source
    assert "_validate_cms_contract(openssl, cms)" in source
    assert source.index("_validate_cms_contract(openssl, cms)") < source.index('"-decrypt"')


def test_openssl_negative_control_must_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    invocations: list[tuple[object, dict[str, object]]] = []

    def expected_failure(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        invocations.append((args, kwargs))
        return subprocess.CompletedProcess(args[0], 1, stdout=b"", stderr=b"")

    monkeypatch.setattr(module.subprocess, "run", expected_failure)
    module.OpenSSLRunner().run_expect_failure(("verify", "leaf.pem"))
    assert invocations
    assert invocations[0][1]["shell"] is False
    assert invocations[0][1]["check"] is False

    def unexpected_success(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        del kwargs
        return subprocess.CompletedProcess(args[0], 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(module.subprocess, "run", unexpected_success)
    with pytest.raises(
        module.DrillError,
        match="openssl_negative_control_unexpectedly_passed",
    ):
        module.OpenSSLRunner().run_expect_failure(("verify", "leaf.pem"))


def test_output_pair_refuses_overwrite_and_cleans_temporaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    attestation = tmp_path / "attestation.json"
    signature = tmp_path / "attestation.sig"
    attestation.write_bytes(b"pre-existing")

    def write_without_platform_fchmod(descriptor: int, payload: bytes) -> None:
        assert os.write(descriptor, payload) == len(payload)

    monkeypatch.setattr(module, "_write_file", write_without_platform_fchmod)
    monkeypatch.setattr(module, "_fsync_directory", lambda directory: None)
    with pytest.raises(module.DrillError, match="output_raced_or_already_exists"):
        module._write_output_pair(
            tmp_path,
            attestation_path=attestation,
            attestation=b"replacement",
            signature_path=signature,
            signature=b"signature",
        )

    assert attestation.read_bytes() == b"pre-existing"
    assert not signature.exists()
    assert not list(tmp_path.glob(".*.tmp"))
    assert not (tmp_path / module.OUTPUT_LOCK_NAME).exists()


@pytest.mark.skipif(os.name != "posix", reason="inode-bound rollback is a Linux contract")
def test_output_pair_rolls_back_keyboard_interrupt_during_attestation_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    attestation = tmp_path / "attestation.json"
    signature = tmp_path / "attestation.sig"
    sentinel = tmp_path / "keep.me"
    sentinel.write_bytes(b"keep")
    original_write = module._write_file
    interruption = KeyboardInterrupt()

    def interrupted_write(descriptor: int, payload: bytes) -> None:
        original_write(descriptor, payload)
        if payload == b"attestation":
            raise interruption

    monkeypatch.setattr(module, "_write_file", interrupted_write)
    with pytest.raises(KeyboardInterrupt) as caught:
        module._write_output_pair(
            tmp_path,
            attestation_path=attestation,
            attestation=b"attestation",
            signature_path=signature,
            signature=b"signature",
        )

    assert caught.value is interruption
    assert sentinel.read_bytes() == b"keep"
    assert not attestation.exists()
    assert not signature.exists()
    assert not list(tmp_path.glob(".*.tmp"))
    assert not (tmp_path / module.OUTPUT_LOCK_NAME).exists()


@pytest.mark.skipif(os.name != "posix", reason="hard-link rollback is a Linux contract")
def test_output_pair_rolls_back_keyboard_interrupt_after_signature_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    attestation = tmp_path / "attestation.json"
    signature = tmp_path / "attestation.sig"
    sentinel = tmp_path / "keep.me"
    sentinel.write_bytes(b"keep")
    original_publish = module._publish_without_overwrite
    interruption = KeyboardInterrupt()

    def interrupted_publish(source: Path, destination: Path) -> None:
        original_publish(source, destination)
        if destination == signature:
            raise interruption

    monkeypatch.setattr(module, "_publish_without_overwrite", interrupted_publish)
    with pytest.raises(KeyboardInterrupt) as caught:
        module._write_output_pair(
            tmp_path,
            attestation_path=attestation,
            attestation=b"attestation",
            signature_path=signature,
            signature=b"signature",
        )

    assert caught.value is interruption
    assert sentinel.read_bytes() == b"keep"
    assert not attestation.exists()
    assert not signature.exists()
    assert not list(tmp_path.glob(".*.tmp"))
    assert not (tmp_path / module.OUTPUT_LOCK_NAME).exists()


@pytest.mark.skipif(os.name != "posix", reason="directory fsync rollback is a POSIX contract")
def test_output_pair_retains_lock_when_interrupt_rollback_fsync_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    attestation = tmp_path / "attestation.json"
    signature = tmp_path / "attestation.sig"
    sentinel = tmp_path / "keep.me"
    sentinel.write_bytes(b"keep")
    original_publish = module._publish_without_overwrite
    interruption = KeyboardInterrupt("operator-cancelled")
    cleanup_error = OSError("synthetic-directory-fsync-failure")
    fsync_calls = 0

    def interrupted_publish(source: Path, destination: Path) -> None:
        original_publish(source, destination)
        if destination == signature:
            raise interruption

    def failed_cleanup_fsync(directory: Path) -> None:
        nonlocal fsync_calls
        assert directory == tmp_path
        fsync_calls += 1
        raise cleanup_error

    monkeypatch.setattr(module, "_publish_without_overwrite", interrupted_publish)
    monkeypatch.setattr(module, "_fsync_directory", failed_cleanup_fsync)
    with pytest.raises(KeyboardInterrupt) as caught:
        module._write_output_pair(
            tmp_path,
            attestation_path=attestation,
            attestation=b"attestation",
            signature_path=signature,
            signature=b"signature",
        )

    assert caught.value is interruption
    assert caught.value.args == ("operator-cancelled",)
    assert caught.value.__cause__ is cleanup_error
    assert getattr(caught.value, "__notes__", []) == [
        "output rollback is incomplete; operation lock retained"
    ]
    assert fsync_calls == 1
    assert sentinel.read_bytes() == b"keep"
    assert not attestation.exists()
    assert not signature.exists()
    assert not list(tmp_path.glob(".*.tmp"))
    assert (tmp_path / module.OUTPUT_LOCK_NAME).read_bytes() == (
        b"heyi-offline-ca-restore-drill-output-lock-v1\n"
    )


def test_output_pair_preserves_committed_outputs_when_lock_release_fsync_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    attestation = tmp_path / "attestation.json"
    signature = tmp_path / "attestation.sig"
    sentinel = tmp_path / "keep.me"
    sentinel.write_bytes(b"keep")
    release_error = OSError("synthetic-lock-release-fsync-failure")
    fsync_calls = 0

    def write_without_platform_fchmod(descriptor: int, payload: bytes) -> None:
        assert os.write(descriptor, payload) == len(payload)

    def fail_lock_release_fsync(directory: Path) -> None:
        nonlocal fsync_calls
        assert directory == tmp_path
        fsync_calls += 1
        if fsync_calls == 2:
            raise release_error

    monkeypatch.setattr(module, "_write_file", write_without_platform_fchmod)
    monkeypatch.setattr(module, "_fsync_directory", fail_lock_release_fsync)
    with pytest.raises(OSError) as caught:
        module._write_output_pair(
            tmp_path,
            attestation_path=attestation,
            attestation=b"attestation",
            signature_path=signature,
            signature=b"signature",
        )

    assert caught.value is release_error
    assert caught.value.__cause__ is None
    assert getattr(caught.value, "__notes__", []) == [
        "output pair committed; operation lock release durability is uncertain"
    ]
    assert fsync_calls == 2
    assert sentinel.read_bytes() == b"keep"
    assert attestation.read_bytes() == b"attestation"
    assert signature.read_bytes() == b"signature"
    assert not list(tmp_path.glob(".*.tmp"))
    assert not (tmp_path / module.OUTPUT_LOCK_NAME).exists()

    with pytest.raises(module.DrillError, match="output_raced_or_already_exists"):
        module._write_output_pair(
            tmp_path,
            attestation_path=attestation,
            attestation=b"replacement-attestation",
            signature_path=signature,
            signature=b"replacement-signature",
        )
    assert attestation.read_bytes() == b"attestation"
    assert signature.read_bytes() == b"signature"
    assert not list(tmp_path.glob(".*.tmp"))
    assert not (tmp_path / module.OUTPUT_LOCK_NAME).exists()


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="fresh-process SIGKILL durability semantics require Linux or WSL",
)
def test_output_pair_sigkill_after_durable_lock_retains_recovery_boundary(
    tmp_path: Path,
) -> None:
    kill_process_group = getattr(os, "killpg", None)
    sigkill = getattr(signal, "SIGKILL", None)
    if not callable(kill_process_group) or sigkill is None:
        pytest.skip("process-group SIGKILL is unavailable")

    attestation = tmp_path / "attestation.json"
    signature = tmp_path / "attestation.sig"
    sentinel = tmp_path / "keep.me"
    marker = tmp_path / "lock-durable"
    sentinel.write_bytes(b"keep")
    child = """
import importlib.util
import pathlib
import sys
import time

script = pathlib.Path(sys.argv[1])
directory = pathlib.Path(sys.argv[2])
marker = pathlib.Path(sys.argv[3])
spec = importlib.util.spec_from_file_location("offline_ca_restore_sigkill_worker", script)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
original_write = module._write_file

def block_after_durable_lock(descriptor, payload):
    original_write(descriptor, payload)
    if payload.startswith(b"heyi-offline-ca-restore-drill-output-lock"):
        marker.write_bytes(b"ready")
        while True:
            time.sleep(60)

module._write_file = block_after_durable_lock
module._write_output_pair(
    directory,
    attestation_path=directory / "attestation.json",
    attestation=b"attestation",
    signature_path=directory / "attestation.sig",
    signature=b"signature",
)
"""
    process = subprocess.Popen(
        [sys.executable, "-c", child, str(SCRIPT), str(tmp_path), str(marker)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    stdout = ""
    stderr = ""
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not marker.exists():
            if process.poll() is not None:
                break
            time.sleep(0.02)
    finally:
        if process.poll() is None:
            kill_process_group(process.pid, sigkill)
        stdout, stderr = process.communicate(timeout=10)

    if not marker.exists() or process.returncode != -int(sigkill):
        pytest.fail(
            "CA output worker did not reach the durable-lock SIGKILL barrier; "
            f"returncode={process.returncode}, stdout={stdout!r}, stderr={stderr!r}"
        )
    assert sentinel.read_bytes() == b"keep"
    assert not attestation.exists()
    assert not signature.exists()
    assert not list(tmp_path.glob(".*.tmp"))
    assert (tmp_path / ".offline-ca-restore-drill.lock").read_bytes() == (
        b"heyi-offline-ca-restore-drill-output-lock-v1\n"
    )


@pytest.mark.skipif(os.name != "posix", reason="atomic hard-link publish is a Linux contract")
def test_output_pair_serializes_concurrent_publishers_without_overwrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    attestation = tmp_path / "attestation.json"
    signature = tmp_path / "attestation.sig"
    original_write = module._write_file
    lock_written = threading.Event()
    release_first = threading.Event()
    first_lock = True
    state_lock = threading.Lock()
    failures: list[BaseException] = []

    def blocking_write(descriptor: int, payload: bytes) -> None:
        nonlocal first_lock
        original_write(descriptor, payload)
        if not payload.startswith(b"heyi-offline-ca-restore-drill-output-lock"):
            return
        with state_lock:
            should_block = first_lock
            first_lock = False
        if should_block:
            lock_written.set()
            assert release_first.wait(timeout=10)

    monkeypatch.setattr(module, "_write_file", blocking_write)

    def first_publisher() -> None:
        try:
            module._write_output_pair(
                tmp_path,
                attestation_path=attestation,
                attestation=b"first-attestation",
                signature_path=signature,
                signature=b"first-signature",
            )
        except BaseException as exc:
            failures.append(exc)

    thread = threading.Thread(target=first_publisher)
    thread.start()
    assert lock_written.wait(timeout=10)
    with pytest.raises(module.DrillError, match="output_operation_in_progress"):
        module._write_output_pair(
            tmp_path,
            attestation_path=attestation,
            attestation=b"second-attestation",
            signature_path=signature,
            signature=b"second-signature",
        )
    release_first.set()
    thread.join(timeout=10)

    assert not thread.is_alive()
    assert failures == []
    assert attestation.read_bytes() == b"first-attestation"
    assert signature.read_bytes() == b"first-signature"
    assert not (tmp_path / module.OUTPUT_LOCK_NAME).exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership and mode contract")
def test_output_directory_requires_exact_root_only_0700(tmp_path: Path) -> None:
    module = _module()
    output_attestation = tmp_path / "attestation.json"
    output_signature = tmp_path / "attestation.sig"
    config = module.DrillConfig(
        challenge=tmp_path / "challenge.json",
        challenge_signature=tmp_path / "challenge.sig",
        challenge_public_key=tmp_path / "challenge.pub",
        expected_challenge_public_key_sha256="a" * 64,
        cms_archive=tmp_path / "archive.p7m",
        recipient_certificate=tmp_path / "recipient.crt",
        recipient_private_key=tmp_path / "recipient.key",
        binding_key=tmp_path / "binding.key",
        attestation_signing_key=tmp_path / "attestation.key",
        attestation_public_key=tmp_path / "attestation.pub",
        output_attestation=output_attestation,
        output_signature=output_signature,
    )
    context = module.SecurityContext(
        expected_uid=tmp_path.stat().st_uid,
        trusted_root=tmp_path,
        require_linux_root=False,
        validate_openssl_binary=False,
    )

    os.chmod(tmp_path, 0o700)
    assert module._validate_new_outputs(config, context) == tmp_path

    os.chmod(tmp_path, 0o750)
    with pytest.raises(module.DrillError, match="protected_directory_metadata_unsafe"):
        module._validate_new_outputs(config, context)


@pytest.mark.skipif(
    sys.platform != "linux" or not Path("/usr/bin/openssl").is_file(),
    reason="real sealed-memfd CA drill requires Linux /usr/bin/openssl",
)
def test_real_openssl_exercises_recovered_root_and_intermediate(tmp_path: Path) -> None:
    module = _module()
    root_key = tmp_path / "root.key"
    root_cert = tmp_path / "root.crt"
    intermediate_key = tmp_path / "intermediate.key"
    intermediate_request = tmp_path / "intermediate.csr"
    intermediate_cert = tmp_path / "intermediate.crt"
    extensions = tmp_path / "intermediate.ext"
    extensions.write_text(
        "\n".join(
            (
                "basicConstraints=critical,CA:TRUE,pathlen:0",
                "keyUsage=critical,keyCertSign,cRLSign",
                "subjectKeyIdentifier=hash",
                "authorityKeyIdentifier=keyid,issuer",
            )
        )
        + "\n",
        encoding="ascii",
    )

    def openssl(*arguments: str) -> None:
        subprocess.run(
            ("/usr/bin/openssl", *arguments),
            cwd=tmp_path,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=30,
        )

    openssl(
        "genpkey",
        "-algorithm",
        "EC",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-out",
        str(root_key),
    )
    openssl(
        "req",
        "-x509",
        "-new",
        "-key",
        str(root_key),
        "-sha256",
        "-days",
        "3650",
        "-subj",
        "/CN=Heyi Test Root",
        "-addext",
        "basicConstraints=critical,CA:TRUE,pathlen:1",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-addext",
        "subjectKeyIdentifier=hash",
        "-out",
        str(root_cert),
    )
    openssl(
        "genpkey",
        "-algorithm",
        "EC",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-out",
        str(intermediate_key),
    )
    openssl(
        "req",
        "-new",
        "-key",
        str(intermediate_key),
        "-subj",
        "/CN=Heyi Test Intermediate",
        "-out",
        str(intermediate_request),
    )
    openssl(
        "x509",
        "-req",
        "-in",
        str(intermediate_request),
        "-CA",
        str(root_cert),
        "-CAkey",
        str(root_key),
        "-set_serial",
        "0x02",
        "-days",
        "365",
        "-sha256",
        "-extfile",
        str(extensions),
        "-out",
        str(intermediate_cert),
    )
    module._exercise_ca(
        {
            "root.crt": root_cert.read_bytes(),
            "root.key": root_key.read_bytes(),
            "intermediate.crt": intermediate_cert.read_bytes(),
            "intermediate.key": intermediate_key.read_bytes(),
        },
        module.OpenSSLRunner(),
    )
