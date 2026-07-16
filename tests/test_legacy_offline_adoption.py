from __future__ import annotations

import argparse
import hashlib
import importlib.util
import inspect
import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPOSITORY = Path(__file__).resolve().parents[1]
SCRIPT = REPOSITORY / "scripts" / "legacy_offline_adoption.py"
RESTORE_SCRIPT = REPOSITORY / "scripts" / "offline_ca_restore_drill.py"
UPGRADE_VERIFIER = REPOSITORY / "deploy" / "tencent" / "verify-upgrade-backup.py"


def _module_from_script(script: Path, *, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _module() -> ModuleType:
    return _module_from_script(SCRIPT, name="legacy_offline_adoption_under_test")


def _container_document(
    module: ModuleType,
    *,
    service: str = "api",
    container_id: str = "1" * 64,
    image: str = "a" * 64,
    host_port: str | None = None,
    mount_source: str = "/var/lib/docker/volumes/example/_data",
    mount_type: str = "volume",
    running: bool = True,
    oneoff: bool = False,
    config_files: str = "/srv/legacy/compose.yml",
) -> dict[str, Any]:
    ports: dict[str, Any] = {}
    if host_port is not None:
        ports = {"443/tcp": [{"HostIp": "0.0.0.0", "HostPort": host_port}]}
    return {
        "Id": container_id,
        "Image": f"sha256:{image}",
        "RestartCount": 0,
        "Config": {
            "Image": f"registry.invalid/{service}@sha256:{image}",
            "Labels": {
                "com.docker.compose.project": module.PROJECT,
                "com.docker.compose.service": service,
                "com.docker.compose.oneoff": str(oneoff),
                "com.docker.compose.config-hash": "b" * 64,
                "com.docker.compose.project.config_files": config_files,
                "io.heyi.knowledgebases.owner": module.OWNER,
                "io.heyi.knowledgebases.stack": module.STACK,
            },
        },
        "State": {"Running": running},
        "Mounts": [
            {
                "Type": mount_type,
                "Source": mount_source,
                "Destination": "/data",
                "RW": True,
            }
        ],
        "NetworkSettings": {
            "Networks": {"heyi-kb-offline_internal": {}},
            "Ports": ports,
        },
    }


def _inventory(module: ModuleType) -> Any:
    container = module.ContainerRecord(
        service="api",
        container_id="1" * 64,
        image_id="sha256:" + "a" * 64,
        config_image="registry.invalid/api@sha256:" + "a" * 64,
        config_hash="b" * 64,
        config_files=("/srv/legacy/compose.yml",),
        oneoff=False,
        running=True,
        restart_count=0,
        mounts=(("volume", "/data", True, "volume"),),
        networks=("heyi-kb-offline_internal",),
        published_ports=(),
    )
    return module.LegacyInventory((container,), (), ())


def _write_ca_source(ca_root: Path) -> dict[str, bytes]:
    materials = {
        "root.crt": (
            b"-----BEGIN CERTIFICATE-----\ncm9vdC1jZXJ0aWZpY2F0ZQ==\n-----END CERTIFICATE-----\n"
        ),
        "root.key": (
            b"-----BEGIN PRIVATE KEY-----\n"  # gitleaks:allow
            b"cm9vdC1wcml2YXRlLWtleQ==\n"
            b"-----END PRIVATE KEY-----\n"
        ),
        "intermediate.crt": (
            b"-----BEGIN CERTIFICATE-----\n"
            b"aW50ZXJtZWRpYXRlLWNlcnRpZmljYXRl\n"
            b"-----END CERTIFICATE-----\n"
        ),
        "intermediate.key": (
            b"-----BEGIN PRIVATE KEY-----\n"  # gitleaks:allow
            b"aW50ZXJtZWRpYXRlLXByaXZhdGUta2V5\n"
            b"-----END PRIVATE KEY-----\n"
        ),
    }
    ca_root.mkdir()
    os.chmod(ca_root, 0o700)
    for name, payload in materials.items():
        path = ca_root / name
        path.write_bytes(payload)
        os.chmod(path, 0o600 if name.endswith(".key") else 0o644)
    return materials


def _write_real_adoption_signer_material(
    tmp_path: Path,
) -> tuple[Path, Path, Path, Path]:
    trusted_private = tmp_path / "trusted.key"
    trusted_public = tmp_path / "trusted.pub"
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
    trusted_public.chmod(0o444)
    fingerprint = tmp_path / "trusted.sha256"
    fingerprint.write_text(
        hashlib.sha256(trusted_public.read_bytes()).hexdigest() + "\n",
        encoding="ascii",
    )
    fingerprint.chmod(0o444)
    return trusted_private, trusted_public, attacker_private, fingerprint


def _release_authorization(
    target_manifest: Path,
    *,
    git_sha: str = "a" * 40,
    manifest_sha256: str = "d" * 64,
    size_bytes: int = 1,
) -> dict[str, Any]:
    descriptor = {
        "path": str(target_manifest),
        "sha256": manifest_sha256,
        "size_bytes": size_bytes,
    }
    return {
        "schema_version": 1,
        "release_sequence": 202607160001,
        "release_id": "2026.07.16.1",
        "release_git_sha": git_sha,
        "release_schema_head": "20260715_0021",
        "release_sha256": "1" * 64,
        "release_assets_sha256": "2" * 64,
        "checksum_set_sha256": "3" * 64,
        "signature_sha256": "4" * 64,
        "target_manifest": descriptor,
        "registry_import_receipt": {
            "path": "/srv/heyi-knowledgebases-offline/state/registry-import-" + "d" * 64 + ".json",
            "sha256": "5" * 64,
            "size_bytes": 1,
        },
        "highest_release": {
            "path": "/srv/heyi-knowledgebases-offline/state/highest-release.json",
            "sha256": "6" * 64,
            "size_bytes": 1,
        },
        "trusted_release_public_key": {
            "path": "/etc/heyi-release/trusted-release-public.pem",
            "sha256": "7" * 64,
            "size_bytes": 1,
        },
    }


def test_runner_rejects_untrusted_executable_and_arguments_before_spawn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    called = False

    def forbidden(*args: object, **kwargs: object) -> None:
        nonlocal called
        called = True

    monkeypatch.setattr(module.subprocess, "run", forbidden)
    runner = module.Runner()
    with pytest.raises(module.CommandError, match="allowlist"):
        runner.run(("/tmp/docker", "ps"))
    with pytest.raises(module.CommandError, match="unsafe argument"):
        runner.run(("/usr/bin/docker", "ps\n--all"))
    assert called is False


def test_runner_rebuilds_path_and_rejects_environment_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    observed: dict[str, str] = {}

    def completed(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        observed.update(kwargs["env"])  # type: ignore[arg-type]
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=b"ok", stderr=b"")

    monkeypatch.setattr(module.subprocess, "run", completed)
    runner = module.Runner()
    assert runner.run(("/usr/bin/docker", "version")) == b"ok"
    assert observed["PATH"] == "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    with pytest.raises(module.CommandError, match="unapproved key"):
        runner.run(("/usr/bin/docker", "version"), extra_env={"PATH": "/tmp"})


def test_runtime_parser_preserves_optional_empty_values_and_binds_raw_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    required = "\n".join(
        f"{key}=required-{index}"
        for index, key in enumerate(sorted(module.REQUIRED_RUNTIME_KEYS), 1)
    )
    with_empty = (
        required
        + "\nKB_LLM_EGRESS_GATEWAY_URL=\n"
        + "KB_LLM_EGRESS_APPROVED_PROVIDERS=''\n"
        + "KB_UPGRADE_BACKUP_EVIDENCE_PATH=\n"
        + "KB_UPGRADE_BACKUP_SIGNATURE_PATH=\n"
        + "KB_UPGRADE_BACKUP_PUBLIC_KEY_PATH=\n"
        + 'KB_BOOTSTRAP_ADMIN_PASSWORD=""\n'
    ).encode()
    without_empty = (required + "\n").encode()
    payloads = {
        Path("/runtime-with-empty.env"): with_empty,
        Path("/runtime-without-empty.env"): without_empty,
    }
    monkeypatch.setattr(module, "_open_protected_bytes", lambda path: payloads[path])

    values, digest = module.parse_runtime_environment(
        Path("/runtime-with-empty.env"),
        b"k" * 32,
    )
    _, digest_without_empty = module.parse_runtime_environment(
        Path("/runtime-without-empty.env"),
        b"k" * 32,
    )

    for key in (
        "KB_LLM_EGRESS_GATEWAY_URL",
        "KB_LLM_EGRESS_APPROVED_PROVIDERS",
        "KB_UPGRADE_BACKUP_EVIDENCE_PATH",
        "KB_UPGRADE_BACKUP_SIGNATURE_PATH",
        "KB_UPGRADE_BACKUP_PUBLIC_KEY_PATH",
        "KB_BOOTSTRAP_ADMIN_PASSWORD",
    ):
        assert key in values
        assert values[key] == ""
    assert digest == module._hmac_binding(
        with_empty,
        b"k" * 32,
        domain="heyi-runtime-env-v1",
    )
    assert digest != digest_without_empty


def test_runtime_parser_accepts_the_standard_strict_offline_example(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    payload = (REPOSITORY / "deploy" / "tencent" / "offline.env.example").read_bytes()
    monkeypatch.setattr(module, "_open_protected_bytes", lambda path: payload)

    values, digest = module.parse_runtime_environment(Path("/runtime.env"), b"k" * 32)

    assert values["KB_LLM_EGRESS_MODE"] == "strict_offline"
    assert values["KB_LLM_EGRESS_GATEWAY_URL"] == ""
    assert values["KB_LLM_EGRESS_APPROVED_PROVIDERS"] == ""
    assert values["KB_UPGRADE_BACKUP_EVIDENCE_PATH"] == ""
    assert digest == module._hmac_binding(
        payload,
        b"k" * 32,
        domain="heyi-runtime-env-v1",
    )


def test_runtime_parser_rejects_empty_required_unknown_and_duplicate_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    required_values = {
        key: f"required-{index}"
        for index, key in enumerate(sorted(module.REQUIRED_RUNTIME_KEYS), 1)
    }

    def payload(overrides: dict[str, str], *extra_lines: str) -> bytes:
        values = {**required_values, **overrides}
        lines = [f"{key}={value}" for key, value in sorted(values.items())]
        return ("\n".join([*lines, *extra_lines]) + "\n").encode()

    documents = {
        Path("/empty-required.env"): payload({"POSTGRES_DB": ""}),
        Path("/unknown.env"): payload({}, "UNEXPECTED_RUNTIME_KEY=value"),
        Path("/release-image.env"): payload(
            {},
            "KB_API_IMAGE=registry.invalid/api@sha256:" + "a" * 64,
        ),
        Path("/duplicate.env"): payload({}, "POSTGRES_DB=duplicate"),
    }
    monkeypatch.setattr(module, "_open_protected_bytes", lambda path: documents[path])

    with pytest.raises(module.AdoptionError, match="required protected values"):
        module.parse_runtime_environment(Path("/empty-required.env"), b"k" * 32)
    with pytest.raises(module.AdoptionError, match="unknown"):
        module.parse_runtime_environment(Path("/unknown.env"), b"k" * 32)
    with pytest.raises(module.AdoptionError, match="unknown"):
        module.parse_runtime_environment(Path("/release-image.env"), b"k" * 32)
    with pytest.raises(module.AdoptionError, match="duplicate"):
        module.parse_runtime_environment(Path("/duplicate.env"), b"k" * 32)


def test_runtime_parser_allowlist_matches_offline_environment_validator() -> None:
    module = _module()
    validator = _module_from_script(
        REPOSITORY / "deploy" / "tencent" / "validate-offline-environment.py",
        name="offline_environment_validator_under_test",
    )
    assert module.ALLOWED_RUNTIME_KEYS == validator._RUNTIME_KEYS


def test_container_contract_rejects_protected_port_and_external_writable_bind(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    data_root = tmp_path / "data"
    data_root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.setattr(module, "DATA_ROOT", data_root)
    protected_port = _container_document(module, service="proxy", host_port="10050")
    with pytest.raises(module.AdoptionError, match="protected port 10050"):
        module._container_record(protected_port)
    external_bind = _container_document(
        module,
        mount_source=str(outside),
        mount_type="bind",
    )
    with pytest.raises(module.AdoptionError, match="outside the fixed data root"):
        module._container_record(external_bind)


def test_container_contract_accepts_only_fixed_edge_ports() -> None:
    module = _module()
    record = module._container_record(
        _container_document(module, service="proxy", host_port="19443")
    )
    assert record.published_ports == ("19443/443/tcp",)
    with pytest.raises(module.AdoptionError, match="unapproved host port"):
        module._container_record(_container_document(module, service="proxy", host_port="18080"))


def test_topology_binding_ignores_recreated_ids_but_not_images() -> None:
    module = _module()
    inventory = _inventory(module)
    original = inventory.containers[0]
    recreated = module.LegacyInventory(
        (replace(original, container_id="2" * 64, restart_count=99),), (), ()
    )
    changed_image = module.LegacyInventory(
        (replace(original, image_id="sha256:" + "c" * 64),), (), ()
    )
    assert module.topology_sha256(inventory) == module.topology_sha256(recreated)
    assert module.topology_sha256(inventory) != module.topology_sha256(changed_image)


def test_plan_contains_opaque_environment_bindings_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    inventory = _inventory(module)
    compose = Path("/srv/legacy/compose.yml")
    runtime = Path("/srv/legacy/runtime.env")
    legacy_env = Path("/srv/legacy/release.env")
    target = Path("/srv/target/release.env.images")
    monkeypatch.setattr(module, "protected_file", lambda path, **kwargs: path)
    monkeypatch.setattr(module, "_sha256_file", lambda path: "d" * 64)
    monkeypatch.setattr(
        module,
        "_verify_descriptor",
        lambda value, **kwargs: Path(value["path"]),
    )
    inventory = module.LegacyInventory(
        (replace(inventory.containers[0], config_files=(str(compose),)),), (), ()
    )
    document = module.build_plan(
        inventory=inventory,
        runtime_env=runtime,
        runtime_binding="e" * 64,
        compose_files=(compose,),
        legacy_env_files=(legacy_env,),
        legacy_env_bindings={str(legacy_env): "f" * 64},
        release_authorization=_release_authorization(target),
    )
    serialized = json.dumps(document)
    assert document["runtime_env"]["opaque_hmac_sha256"] == "e" * 64
    assert document["legacy_compose"]["env_files"][0]["opaque_hmac_sha256"] == "f" * 64
    assert document["schema_version"] == 4
    assert document["git_sha"] == "a" * 40
    assert document["release_authorization_sha256"] == module._release_authorization_sha256(
        document["release_authorization"]
    )
    assert document["host_isolation_guard"] == {
        "relative_path": "scripts/host_isolation_guard.py",
        "sha256": "d" * 64,
    }
    assert "bound-at-execution" not in serialized
    assert "POSTGRES_PASSWORD" not in serialized


def test_release_authorization_is_derived_only_from_fixed_state_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    state = tmp_path / "state"
    artifacts = tmp_path / "artifacts"
    trust_key = tmp_path / "trusted-release-public.pem"
    highest_path = state / "highest-release.json"
    manifest = artifacts / "2026.07.16.1" / "offline-registry-bundle" / "release.env.images"
    receipt_path = state / f"registry-import-{'2' * 64}.json"
    highest = {
        "schema_version": 2,
        "release_sequence": 202607160001,
        "release_id": "2026.07.16.1",
        "release_git_sha": "a" * 40,
        "release_schema_head": "20260715_0021",
        "manifest_sha256": "2" * 64,
        "release_assets_sha256": "3" * 64,
        "trusted_key_sha256": "7" * 64,
    }
    receipt = {
        "schema_version": 2,
        "kind": "offline-registry-import",
        "status": "verified",
        **{
            key: highest[key]
            for key in (
                "release_sequence",
                "release_id",
                "release_git_sha",
                "release_schema_head",
                "manifest_sha256",
                "release_assets_sha256",
                "trusted_key_sha256",
            )
        },
        "release_sha256": "1" * 64,
        "checksum_set_sha256": "4" * 64,
        "signature_sha256": "5" * 64,
    }
    descriptors = {
        highest_path: {"path": str(highest_path), "sha256": "6" * 64, "size_bytes": 1},
        receipt_path: {"path": str(receipt_path), "sha256": "8" * 64, "size_bytes": 1},
        manifest: {"path": str(manifest), "sha256": "2" * 64, "size_bytes": 1},
        trust_key: {"path": str(trust_key), "sha256": "7" * 64, "size_bytes": 1},
    }
    monkeypatch.setattr(module, "STATE_ROOT", state)
    monkeypatch.setattr(module, "ARTIFACT_ROOT", artifacts)
    monkeypatch.setattr(module, "HIGHEST_RELEASE_STATE", highest_path)
    monkeypatch.setattr(module, "TRUSTED_RELEASE_PUBLIC_KEY", trust_key)
    monkeypatch.setattr(
        module,
        "_stable_json_document",
        lambda path, **kwargs: (
            highest if path == highest_path else receipt,
            descriptors[path],
        ),
    )
    monkeypatch.setattr(module, "protected_file", lambda path, **kwargs: path)
    monkeypatch.setattr(module, "_descriptor", lambda path: descriptors[path])

    authorization = module._current_release_authorization()

    assert authorization["release_git_sha"] == "a" * 40
    assert authorization["target_manifest"] == descriptors[manifest]
    assert authorization["registry_import_receipt"] == descriptors[receipt_path]
    assert authorization["trusted_release_public_key"] == descriptors[trust_key]


@pytest.mark.parametrize(
    "payload",
    [
        b'{"schema_version":2,"schema_version":2}\n',
        b'{"schema_version":NaN}\n',
        b'{"schema_version":Infinity}\n',
    ],
)
def test_protected_json_rejects_duplicate_keys_and_nonfinite_numbers(
    payload: bytes,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    monkeypatch.setattr(module, "_open_protected_bytes", lambda *args, **kwargs: payload)
    with pytest.raises(module.AdoptionError, match="malformed"):
        module._read_json_file(Path("/protected/state.json"))


def test_release_authorization_is_revalidated_after_plan_creation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    authorization = _release_authorization(Path("/srv/release.env.images"))
    plan = {
        "release_authorization": authorization,
        "release_authorization_sha256": module._release_authorization_sha256(authorization),
    }
    current = {"authorization": authorization}
    monkeypatch.setattr(
        module,
        "_current_release_authorization",
        lambda: current["authorization"],
    )
    assert module._validate_release_authorization(plan) == authorization
    current["authorization"] = {**authorization, "release_sequence": 202607160002}
    with pytest.raises(module.AdoptionError, match="changed after planning"):
        module._validate_release_authorization(plan)


def test_confirmations_are_fail_closed() -> None:
    module = _module()
    digest = "a" * 64
    dry_run = argparse.Namespace(
        execute=False,
        confirm_project="wrong",
        confirm_plan_sha256="wrong",
    )
    assert module._confirm(dry_run, digest) is False
    incomplete = argparse.Namespace(
        execute=True,
        confirm_project=module.PROJECT,
        confirm_plan_sha256="wrong",
    )
    with pytest.raises(module.AdoptionError, match="exact project"):
        module._confirm(incomplete, digest)
    complete = argparse.Namespace(
        execute=True,
        confirm_project=module.PROJECT,
        confirm_plan_sha256=digest,
    )
    assert module._confirm(complete, digest) is True


def test_database_count_query_quotes_adversarial_identifiers_as_identifiers() -> None:
    module = _module()
    statement = module._count_statement('public"; DROP SCHEMA public; --', "table name")
    assert statement == ('SELECT count(*) FROM "public""; DROP SCHEMA public; --"."table name";')
    assert "SELECT count(*) FROM" in statement
    with pytest.raises(module.AdoptionError, match="NUL"):
        module._count_statement("public\x00", "table")


def test_object_manifest_is_streamed_and_strict(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    objects = tmp_path / "objects"
    objects.mkdir()
    (objects / "a.txt").write_bytes(b"alpha")
    nested = objects / "nested"
    nested.mkdir()
    (nested / "b.txt").write_bytes(b"beta")
    manifest = tmp_path / "manifest.ndjson"
    monkeypatch.setattr(module, "protected_directory", lambda path, **kwargs: path)
    monkeypatch.setattr(module, "protected_file", lambda path, **kwargs: path)
    real_open = os.open
    anchor = tmp_path / "directory-fsync.anchor"

    def portable_open(path: object, flags: int, mode: int = 0o777) -> int:
        if Path(path) == tmp_path:
            return real_open(anchor, os.O_CREAT | os.O_RDWR, 0o600)
        return real_open(path, flags, mode)  # type: ignore[arg-type]

    monkeypatch.setattr(module.os, "open", portable_open)
    summary = module._object_manifest(objects, manifest)
    rows = list(module._iter_object_manifest(manifest))
    assert summary["object_count"] == 2
    assert summary["total_bytes"] == 9
    assert [(row[0], row[1]) for row in rows] == [
        ("a.txt", 5),
        ("nested/b.txt", 4),
    ]


def test_source_has_no_global_or_volume_destructive_commands() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    forbidden = (
        '"rm", "-f"',
        '"volume", "rm"',
        '"down"',
        '"prune"',
        '"systemctl"',
        '"--remove-orphans"',
        "shell=True",
    )
    for value in forbidden:
        assert value not in source
    assert (
        '_ALLOWED_EXECUTABLES: Final = frozenset({"/usr/bin/docker", "/usr/bin/openssl"})' in source
    )
    assert "shell=False" in source


def _recipient_certificate_pem() -> bytes:
    return b"-----BEGIN CERTIFICATE-----\nUkVDSVBJRU5ULUNFUlRJRklDQVRF\n-----END CERTIFICATE-----\n"


def _recipient_certificate_contract(
    *,
    not_before: str = "2026-07-15 00:00:00Z",
    not_after: str = "2026-08-15 00:00:00Z",
    key_usage: str = "Key Encipherment, Data Encipherment",
    public_key_algorithm: str = "rsaEncryption",
) -> bytes:
    return (
        "Certificate:\n"
        "    Data:\n"
        f"            Public Key Algorithm: {public_key_algorithm}\n"
        "        X509v3 extensions:\n"
        "            X509v3 Basic Constraints: critical\n"
        "                CA:FALSE\n"
        "            X509v3 Key Usage: critical\n"
        f"                {key_usage}\n"
        "    Signature Algorithm: sha256WithRSAEncryption\n"
        f"notBefore={not_before}\n"
        f"notAfter={not_after}\n"
    ).encode("ascii")


def _recipient_rsa_public_description(bits: int = 3072) -> bytes:
    return (f"Public-Key: ({bits} bit)\nModulus:\n    00:aa\nExponent: 65537 (0x10001)\n").encode(
        "ascii"
    )


def test_ca_escrow_is_ciphertext_with_only_an_opaque_plaintext_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    ca_root = tmp_path / "ca"
    materials = _write_ca_source(ca_root)
    secret = materials["root.key"]
    certificate = tmp_path / "recipient.pem"
    certificate.write_bytes(_recipient_certificate_pem())
    os.chmod(certificate, 0o444)
    output = tmp_path / "escrow.p7m"
    events: list[str] = []
    monkeypatch.setattr(module, "protected_directory", lambda path, **kwargs: path)
    monkeypatch.setattr(module, "protected_file", lambda path, **kwargs: path)
    monkeypatch.setattr(
        module,
        "_recipient_certificate_identity_is_stable",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        module,
        "_read_ca_source_file",
        lambda path, **kwargs: materials[path.name],
    )
    original_ca_tar_payload = module._ca_tar_payload

    def tracked_ca_tar_payload(path: Path) -> tuple[bytes, int]:
        events.append("ca-private-material-read")
        return original_ca_tar_payload(path)

    monkeypatch.setattr(module, "_ca_tar_payload", tracked_ca_tar_payload)
    monkeypatch.setattr(
        module,
        "_utc_now",
        lambda: module.datetime(2026, 7, 16, 12, 0, tzinfo=module.UTC),
    )
    real_open = os.open
    anchor = tmp_path / "ca-directory-fsync.anchor"

    def portable_open(path: object, flags: int, mode: int = 0o777) -> int:
        if Path(path) == tmp_path:
            return real_open(anchor, os.O_CREAT | os.O_RDWR, 0o600)
        return real_open(path, flags, mode)  # type: ignore[arg-type]

    monkeypatch.setattr(module.os, "open", portable_open)

    class FakeRunner:
        def run(
            self,
            argv: tuple[str, ...],
            *,
            input_bytes: bytes | None = None,
            stdout_file: Any = None,
            timeout: int = 0,
            pass_fds: tuple[int, ...] = (),
        ) -> bytes:
            del timeout
            values = tuple(argv)
            if values[1:3] == ("x509", "-in") and "-text" in values:
                events.append("recipient-contract")
                assert len(pass_fds) == 1
                return _recipient_certificate_contract()
            if values[1:3] == ("x509", "-in") and "-pubkey" in values:
                events.append("recipient-public-key")
                assert len(pass_fds) == 1
                return (
                    b"-----BEGIN PUBLIC KEY-----\n"
                    b"UkVDSVBJRU5ULVBVQkxJQw==\n"
                    b"-----END PUBLIC KEY-----\n"
                )
            if values[1:3] == ("pkey", "-pubin"):
                events.append("recipient-rsa-policy")
                assert input_bytes is not None
                return _recipient_rsa_public_description()
            if "-encrypt" in argv:
                events.append("cms-encrypt")
                assert "-aes256" in argv
                assert argv[-6:] == (
                    "-keyopt",
                    "rsa_padding_mode:oaep",
                    "-keyopt",
                    "rsa_oaep_md:sha256",
                    "-keyopt",
                    "rsa_mgf1_md:sha256",
                )
                assert input_bytes is not None and secret in input_bytes
                assert stdout_file is not None
                assert len(pass_fds) == 1
                stdout_file.write(b"CMS-CIPHERTEXT")
            else:
                events.append("cms-parse")
                assert "-cmsout" in argv
            return b""

    metadata = module._encrypt_ca_escrow(
        FakeRunner(),
        ca_root=ca_root,
        recipient_certificate=certificate,
        binding_key=b"k" * 32,
        destination=output,
    )
    assert output.read_bytes() == b"CMS-CIPHERTEXT"
    assert secret not in output.read_bytes()
    assert metadata["plaintext_opaque_hmac_sha256"]
    assert "plaintext_sha256" not in metadata
    assert metadata["private_key_bytes_in_evidence"] is False
    assert metadata["cos_transfer_allowed"] is False
    assert metadata["file_count"] == 4
    assert metadata["recipient_certificate_sha256"] == module._sha256_bytes(
        _recipient_certificate_pem()
    )
    assert events == [
        "recipient-contract",
        "recipient-public-key",
        "recipient-rsa-policy",
        "ca-private-material-read",
        "cms-encrypt",
        "cms-parse",
    ]


@pytest.mark.parametrize(
    ("case", "contract", "public_description", "certificate_payload"),
    [
        (
            "rsa-2048",
            _recipient_certificate_contract(),
            _recipient_rsa_public_description(2048),
            _recipient_certificate_pem(),
        ),
        (
            "expired",
            _recipient_certificate_contract(not_after="2026-07-15 23:59:59Z"),
            _recipient_rsa_public_description(),
            _recipient_certificate_pem(),
        ),
        (
            "not-yet-valid",
            _recipient_certificate_contract(not_before="2026-07-17 00:00:00Z"),
            _recipient_rsa_public_description(),
            _recipient_certificate_pem(),
        ),
        (
            "missing-key-encipherment",
            _recipient_certificate_contract(key_usage="Digital Signature"),
            _recipient_rsa_public_description(),
            _recipient_certificate_pem(),
        ),
        (
            "wrong-public-key-algorithm",
            _recipient_certificate_contract(public_key_algorithm="id-ecPublicKey"),
            b"Public-Key: (256 bit)\nASN1 OID: prime256v1\n",
            _recipient_certificate_pem(),
        ),
        (
            "certificate-chain",
            _recipient_certificate_contract(),
            _recipient_rsa_public_description(),
            _recipient_certificate_pem() + _recipient_certificate_pem(),
        ),
    ],
)
def test_ca_recipient_policy_blocks_before_any_private_ca_read_or_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    contract: bytes,
    public_description: bytes,
    certificate_payload: bytes,
) -> None:
    module = _module()
    certificate = tmp_path / f"{case}.pem"
    certificate.write_bytes(certificate_payload)
    os.chmod(certificate, 0o444)
    output = tmp_path / f"{case}.p7m"
    ca_reads = 0

    def forbidden_ca_read(path: Path) -> tuple[bytes, int]:
        nonlocal ca_reads
        del path
        ca_reads += 1
        raise AssertionError("recipient policy must run before reading CA private material")

    class InvalidRecipientRunner:
        def run(
            self,
            argv: tuple[str, ...],
            *,
            input_bytes: bytes | None = None,
            stdout_file: Any = None,
            timeout: int = 0,
            pass_fds: tuple[int, ...] = (),
        ) -> bytes:
            del stdout_file, timeout
            values = tuple(argv)
            if values[1:3] == ("x509", "-in") and "-text" in values:
                assert len(pass_fds) == 1
                return contract
            if values[1:3] == ("x509", "-in") and "-pubkey" in values:
                assert len(pass_fds) == 1
                return (
                    b"-----BEGIN PUBLIC KEY-----\n"
                    b"UkVDSVBJRU5ULVBVQkxJQw==\n"
                    b"-----END PUBLIC KEY-----\n"
                )
            if values[1:3] == ("pkey", "-pubin"):
                assert input_bytes is not None
                return public_description
            raise AssertionError(f"recipient validation reached an unexpected command: {values}")

    monkeypatch.setattr(module, "protected_file", lambda path, **kwargs: path)
    monkeypatch.setattr(module, "_ca_tar_payload", forbidden_ca_read)
    monkeypatch.setattr(
        module,
        "_utc_now",
        lambda: module.datetime(2026, 7, 16, 12, 0, tzinfo=module.UTC),
    )

    with pytest.raises(module.AdoptionError, match="recipient certificate"):
        module._encrypt_ca_escrow(
            InvalidRecipientRunner(),
            ca_root=tmp_path / "must-not-be-read",
            recipient_certificate=certificate,
            binding_key=b"k" * 32,
            destination=output,
        )

    assert ca_reads == 0
    assert not output.exists()
    assert not list(tmp_path.glob(f".{output.name}.*.tmp"))


@pytest.mark.parametrize("unexpected_kind", ("extra", "nested"))
def test_ca_tar_rejects_extra_or_nested_source_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unexpected_kind: str,
) -> None:
    module = _module()
    ca_root = tmp_path / "ca"
    _write_ca_source(ca_root)
    if unexpected_kind == "extra":
        (ca_root / "notes.txt").write_text("not CA material", encoding="ascii")
    else:
        (ca_root / "archive").mkdir()
        (ca_root / "archive" / "root.key").write_text("stale key", encoding="ascii")
    monkeypatch.setattr(module, "protected_directory", lambda path, **kwargs: path)
    with pytest.raises(module.AdoptionError, match="exactly the four canonical files"):
        module._ca_tar_payload(ca_root)


def test_ca_tar_rejects_directory_drift_during_protected_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    ca_root = tmp_path / "ca"
    materials = _write_ca_source(ca_root)
    calls = 0

    def read_with_namespace_drift(path: Path, **kwargs: object) -> bytes:
        nonlocal calls
        del kwargs
        calls += 1
        if calls == 1:
            (ca_root / "notes.txt").write_text("late extra entry", encoding="ascii")
        return materials[path.name]

    monkeypatch.setattr(module, "protected_directory", lambda path, **kwargs: path)
    monkeypatch.setattr(module, "_read_ca_source_file", read_with_namespace_drift)
    with pytest.raises(module.AdoptionError, match="changed while"):
        module._ca_tar_payload(ca_root)


@pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="real CA ownership and mode checks require root Linux",
)
def test_ca_tar_rejects_group_or_world_readable_private_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    ca_root = tmp_path / "ca"
    _write_ca_source(ca_root)
    os.chmod(ca_root / "root.key", 0o644)
    monkeypatch.setattr(module, "protected_directory", lambda path, **kwargs: path)
    monkeypatch.setattr(module, "protected_file", lambda path, **kwargs: path)
    with pytest.raises(module.AdoptionError, match="protected open"):
        module._ca_tar_payload(ca_root)


@pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="real CA hard-link and ownership checks require root Linux",
)
def test_ca_tar_rejects_hardlinked_private_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    ca_root = tmp_path / "ca"
    _write_ca_source(ca_root)
    try:
        os.link(ca_root / "root.key", tmp_path / "root-key-hardlink")
    except OSError as exc:
        pytest.skip(f"hard links are unavailable: {exc}")
    monkeypatch.setattr(module, "protected_directory", lambda path, **kwargs: path)
    monkeypatch.setattr(module, "protected_file", lambda path, **kwargs: path)
    with pytest.raises(module.AdoptionError, match="protected open"):
        module._ca_tar_payload(ca_root)


@pytest.mark.skipif(
    sys.platform != "linux"
    or not hasattr(os, "geteuid")
    or os.geteuid() != 0
    or not Path("/usr/bin/openssl").is_file(),
    reason="real recipient-certificate policy requires root Linux and OpenSSL 3",
)
def test_real_recipient_policy_rejects_weak_time_usage_and_non_rsa_before_ca_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()

    def issue_certificate(
        name: str,
        *,
        newkey: tuple[str, ...],
        key_usage: str,
    ) -> Path:
        key = tmp_path / f"{name}.key"
        certificate = tmp_path / f"{name}.pem"
        subprocess.run(
            (
                "/usr/bin/openssl",
                "req",
                "-x509",
                "-newkey",
                *newkey,
                "-nodes",
                "-sha256",
                "-days",
                "2",
                "-subj",
                f"/CN={name}",
                "-addext",
                f"keyUsage=critical,{key_usage}",
                "-keyout",
                str(key),
                "-out",
                str(certificate),
            ),
            cwd=tmp_path,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=60,
        )
        return certificate

    compliant = issue_certificate(
        "recipient-rsa-3072",
        newkey=("rsa:3072",),
        key_usage="keyEncipherment",
    )
    weak = issue_certificate(
        "recipient-rsa-2048",
        newkey=("rsa:2048",),
        key_usage="keyEncipherment",
    )
    wrong_usage = issue_certificate(
        "recipient-signing-only",
        newkey=("rsa:3072",),
        key_usage="digitalSignature",
    )
    non_rsa = issue_certificate(
        "recipient-ec-p256",
        newkey=("ec", "-pkeyopt", "ec_paramgen_curve:P-256"),
        key_usage="keyEncipherment",
    )
    monkeypatch.setattr(module, "protected_file", lambda path, **kwargs: path)
    ca_reads = 0

    def forbidden_ca_read(path: Path) -> tuple[bytes, int]:
        nonlocal ca_reads
        del path
        ca_reads += 1
        raise AssertionError("invalid recipient certificate reached CA private material")

    monkeypatch.setattr(module, "_ca_tar_payload", forbidden_ca_read)
    current = module.datetime.now(module.UTC)
    cases = (
        ("weak", weak, current),
        ("expired", compliant, module.datetime(2100, 1, 1, tzinfo=module.UTC)),
        ("not-yet-valid", compliant, module.datetime(2000, 1, 1, tzinfo=module.UTC)),
        ("wrong-usage", wrong_usage, current),
        ("non-rsa", non_rsa, current),
    )
    for name, certificate, validation_time in cases:
        monkeypatch.setattr(module, "_utc_now", lambda value=validation_time: value)
        output = tmp_path / f"{name}.p7m"
        with pytest.raises(module.AdoptionError, match="recipient certificate"):
            module._encrypt_ca_escrow(
                module.Runner(),
                ca_root=tmp_path / "must-not-be-read",
                recipient_certificate=certificate,
                binding_key=b"k" * 32,
                destination=output,
            )
        assert not output.exists()
        assert not list(tmp_path.glob(f".{output.name}.*.tmp"))

    assert ca_reads == 0


@pytest.mark.skipif(
    sys.platform != "linux"
    or not hasattr(os, "geteuid")
    or os.geteuid() != 0
    or not Path("/usr/bin/openssl").is_file(),
    reason="real producer-to-consumer CMS roundtrip requires root Linux and OpenSSL 3",
)
def test_real_ca_escrow_roundtrip_matches_restore_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    producer = _module()
    consumer = _module_from_script(
        RESTORE_SCRIPT,
        name="offline_ca_restore_drill_for_producer_roundtrip",
    )
    ca_root = tmp_path / "ca"
    materials = _write_ca_source(ca_root)
    recipient_key = tmp_path / "recipient.key"
    recipient_certificate = tmp_path / "recipient.pem"
    subprocess.run(
        (
            "/usr/bin/openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:3072",
            "-nodes",
            "-sha256",
            "-days",
            "2",
            "-subj",
            "/CN=Heyi Offline CA Escrow Recipient",
            "-addext",
            "keyUsage=critical,keyEncipherment",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-keyout",
            str(recipient_key),
            "-out",
            str(recipient_certificate),
        ),
        cwd=tmp_path,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
        timeout=60,
    )
    output = tmp_path / "caddy-ca.cms.p7m"
    monkeypatch.setattr(producer, "protected_directory", lambda path, **kwargs: path)
    monkeypatch.setattr(producer, "protected_file", lambda path, **kwargs: path)
    metadata = producer._encrypt_ca_escrow(
        producer.Runner(),
        ca_root=ca_root,
        recipient_certificate=recipient_certificate,
        binding_key=b"k" * 32,
        destination=output,
    )

    openssl = consumer.OpenSSLRunner()
    consumer._validate_cms_contract(openssl, output)
    plaintext = openssl.run(
        (
            "cms",
            "-decrypt",
            "-binary",
            "-inform",
            "DER",
            "-in",
            str(output),
            "-recip",
            str(recipient_certificate),
            "-inkey",
            str(recipient_key),
        ),
        timeout=120,
        max_output=consumer.MAX_CA_PLAINTEXT_BYTES,
    )
    assert (
        consumer._read_ca_archive(
            plaintext,
            expected_file_count=metadata["file_count"],
        )
        == materials
    )


def test_ca_restore_attestation_fails_closed_on_cos_or_server_private_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    now = module._utc_now()
    challenge_path = Path("/protected/challenge.json")
    attestation_path = Path("/protected/attestation.json")
    signature_path = Path("/protected/attestation.sig")
    public_key = Path("/protected/offline-public.pem")
    issued_at = now - module.timedelta(hours=1)
    challenge = {
        "schema_version": 2,
        "kind": "heyi-caddy-ca-restore-challenge",
        "project": module.PROJECT,
        "run_id": "restore-drill-001",
        "plan_sha256": "e" * 64,
        "release_authorization_sha256": "8" * 64,
        "nonce": "f" * 64,
        "issued_at": issued_at.isoformat().replace("+00:00", "Z"),
        "expires_at": (issued_at + module.timedelta(days=7)).isoformat().replace("+00:00", "Z"),
        "encrypted_archive_sha256": "b" * 64,
        "encrypted_archive_size_bytes": 4096,
        "plaintext_opaque_hmac_sha256": "c" * 64,
        "file_count": 4,
        "recipient_certificate_sha256": "d" * 64,
        "ca_attestation_public_key_sha256": "a" * 64,
        "cos_transfer_allowed": False,
    }
    attestation = {
        "schema_version": 1,
        "kind": "heyi-caddy-ca-restore-drill",
        "project": module.PROJECT,
        "challenge_sha256": "a" * 64,
        "encrypted_archive_sha256": "b" * 64,
        "plaintext_opaque_hmac_sha256": "c" * 64,
        "file_count": 4,
        "recipient_certificate_sha256": "d" * 64,
        "status": "passed",
        "tested_at": now.isoformat().replace("+00:00", "Z"),
        "private_key_location": "offline-only",
        "server_private_key_present": False,
        "cos_used": False,
    }
    monkeypatch.setattr(module, "_verify_signature", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        module,
        "_read_json_file",
        lambda path: challenge if path == challenge_path else attestation,
    )
    monkeypatch.setattr(module, "_sha256_file", lambda path: "a" * 64)
    monkeypatch.setattr(module, "_descriptor", lambda path: {"path": str(path)})
    monkeypatch.setattr(module, "protected_file", lambda path, **kwargs: path)
    result = module._verify_ca_attestation(
        object(),
        challenge=challenge_path,
        attestation=attestation_path,
        signature=signature_path,
        public_key=public_key,
    )
    assert result["status"] == "passed"
    attestation["cos_used"] = True
    with pytest.raises(module.AdoptionError, match="does not match"):
        module._verify_ca_attestation(
            object(),
            challenge=challenge_path,
            attestation=attestation_path,
            signature=signature_path,
            public_key=public_key,
        )
    attestation["cos_used"] = False
    challenge["ca_attestation_public_key_sha256"] = "9" * 64
    with pytest.raises(module.AdoptionError, match="challenge contract differs"):
        module._verify_ca_attestation(
            object(),
            challenge=challenge_path,
            attestation=attestation_path,
            signature=signature_path,
            public_key=public_key,
        )


def test_ca_challenge_v2_binds_preapproved_attestation_public_key() -> None:
    module = _module()
    document = module._ca_challenge(
        run_id="restore-drill-001",
        plan_digest="a" * 64,
        release_authorization_sha256="f" * 64,
        ca_escrow={
            "ciphertext_sha256": "b" * 64,
            "ciphertext_size_bytes": 4096,
            "plaintext_opaque_hmac_sha256": "c" * 64,
            "file_count": 4,
            "recipient_certificate_sha256": "d" * 64,
        },
        ca_attestation_public_key_sha256="e" * 64,
    )
    assert document["schema_version"] == 2
    assert document["release_authorization_sha256"] == "f" * 64
    assert document["ca_attestation_public_key_sha256"] == "e" * 64
    assert set(document) == module.CA_RESTORE_CHALLENGE_KEYS


def test_retirement_intent_is_forward_only_after_publication() -> None:
    module = _module()
    source = inspect.getsource(module._retire)
    assert "_resume_or_recreate_legacy(" not in source
    assert "allow_missing=True" in source
    assert source.index("_publish_retirement_intent(") < source.index("_retire_exact_resources(")
    assert '"rm", record.container_id' in inspect.getsource(module._retire_exact_resources)


def test_stopped_known_oneoff_is_recorded_but_running_or_unknown_oneoff_is_rejected() -> None:
    module = _module()
    accepted = module._container_record(
        _container_document(
            module,
            service="migrate",
            running=False,
            oneoff=True,
        )
    )
    assert accepted.oneoff is True
    assert accepted.service == "migrate"
    with pytest.raises(module.AdoptionError, match="must be stopped"):
        module._container_record(
            _container_document(module, service="migrate", running=True, oneoff=True)
        )
    with pytest.raises(module.AdoptionError, match="unknown one-off"):
        module._container_record(
            _container_document(module, service="unknown-job", running=False, oneoff=True)
        )


def test_oneoff_rejects_external_writable_bind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    data_root = tmp_path / "data"
    data_root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.setattr(module, "DATA_ROOT", data_root)
    with pytest.raises(module.AdoptionError, match="outside the fixed data root"):
        module._container_record(
            _container_document(
                module,
                service="bootstrap",
                running=False,
                oneoff=True,
                mount_type="bind",
                mount_source=str(outside),
            )
        )


def test_plan_binds_mixed_compose_paths_per_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    first = Path("/srv/releases/one/compose.yml")
    second = Path("/srv/releases/two/compose.yml")
    inventory = _inventory(module)
    api = replace(inventory.containers[0], config_files=(str(first),))
    web = replace(
        inventory.containers[0],
        service="web",
        container_id="2" * 64,
        config_files=(str(second),),
    )
    inventory = module.LegacyInventory((api, web), (), ())
    monkeypatch.setattr(module, "protected_file", lambda path, **kwargs: path)
    monkeypatch.setattr(module, "_sha256_file", lambda path: "d" * 64)
    monkeypatch.setattr(
        module,
        "_verify_descriptor",
        lambda value, **kwargs: Path(value["path"]),
    )
    document = module.build_plan(
        inventory=inventory,
        runtime_env=Path("/srv/runtime.env"),
        runtime_binding="e" * 64,
        compose_files=(first, second),
        legacy_env_files=(),
        legacy_env_bindings={},
        release_authorization=_release_authorization(Path("/srv/release.env.images")),
    )
    assert document["schema_version"] == 4
    assert document["legacy_compose"]["service_bindings"] == {
        "api": [str(first)],
        "web": [str(second)],
    }
    assert [entry["path"] for entry in document["legacy_compose"]["files"]] == [
        str(first),
        str(second),
    ]


def test_host_isolation_guard_binding_survives_release_materialization_path_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle_root = tmp_path / "bundle-source"
    materialized_root = tmp_path / "materialized-release"
    guard_payload = b"def marker():\n    return 'same-release-control'\n"
    for root in (bundle_root, materialized_root):
        scripts = root / "scripts"
        scripts.mkdir(parents=True)
        (scripts / "legacy_offline_adoption.py").write_bytes(SCRIPT.read_bytes())
        (scripts / "host_isolation_guard.py").write_bytes(guard_payload)

    compose = tmp_path / "compose.yml"
    runtime = tmp_path / "runtime.env"
    target = tmp_path / "release.env.images"
    compose.write_text("services: {}\n", encoding="utf-8")
    runtime.write_text("KEY=value\n", encoding="utf-8")
    target.write_text("IMAGE=example.invalid/app@sha256:" + "a" * 64 + "\n", encoding="utf-8")

    build_module = _module_from_script(
        bundle_root / "scripts" / "legacy_offline_adoption.py",
        name="legacy_offline_adoption_bundle_source",
    )
    build_inventory = _inventory(build_module)
    build_inventory = build_module.LegacyInventory(
        (
            replace(
                build_inventory.containers[0],
                config_files=(str(compose.resolve()),),
            ),
        ),
        (),
        (),
    )
    monkeypatch.setattr(
        build_module,
        "protected_file",
        lambda path, **kwargs: path.resolve(strict=True),
    )
    plan = build_module.build_plan(
        inventory=build_inventory,
        runtime_env=runtime.resolve(),
        runtime_binding="e" * 64,
        compose_files=(compose.resolve(),),
        legacy_env_files=(),
        legacy_env_bindings={},
        release_authorization=_release_authorization(
            target.resolve(),
            manifest_sha256=build_module._sha256_file(target.resolve()),
            size_bytes=target.stat().st_size,
        ),
    )

    materialized_module = _module_from_script(
        materialized_root / "scripts" / "legacy_offline_adoption.py",
        name="legacy_offline_adoption_materialized_release",
    )
    monkeypatch.setattr(
        materialized_module,
        "protected_file",
        lambda path, **kwargs: path.resolve(strict=True),
    )
    resolved = materialized_module._protected_host_isolation_guard(plan["host_isolation_guard"])

    assert plan["host_isolation_guard"] == {
        "relative_path": materialized_module.HOST_ISOLATION_GUARD_RELATIVE_PATH,
        "sha256": materialized_module._sha256_bytes(guard_payload),
    }
    assert (
        bundle_root / build_module.HOST_ISOLATION_GUARD_RELATIVE_PATH
        != materialized_root / materialized_module.HOST_ISOLATION_GUARD_RELATIVE_PATH
    )
    assert (
        resolved
        == (materialized_root / materialized_module.HOST_ISOLATION_GUARD_RELATIVE_PATH).resolve()
    )


@pytest.mark.parametrize(
    "relative_path",
    [
        "../scripts/host_isolation_guard.py",
        "scripts/../scripts/host_isolation_guard.py",
        "/scripts/host_isolation_guard.py",
        "host_isolation_guard.py",
        "scripts\\host_isolation_guard.py",
    ],
)
def test_host_isolation_guard_binding_rejects_traversal_or_noncanonical_relative_path(
    relative_path: str,
) -> None:
    module = _module()
    with pytest.raises(module.AdoptionError, match="relative path differs"):
        module._protected_host_isolation_guard(
            {
                "relative_path": relative_path,
                "sha256": "a" * 64,
            }
        )


def test_host_isolation_guard_binding_rejects_legacy_or_extended_schema() -> None:
    module = _module()
    with pytest.raises(module.AdoptionError, match="schema differs"):
        module._protected_host_isolation_guard(
            {
                "path": "/bundle/scripts/host_isolation_guard.py",
                "sha256": "a" * 64,
            }
        )
    with pytest.raises(module.AdoptionError, match="schema differs"):
        module._protected_host_isolation_guard(
            {
                "relative_path": module.HOST_ISOLATION_GUARD_RELATIVE_PATH,
                "sha256": "a" * 64,
                "path": "/bundle/scripts/host_isolation_guard.py",
            }
        )


def test_plan_parser_accepts_repeatable_compose_files() -> None:
    module = _module()
    arguments = module._parser().parse_args(
        [
            "plan",
            "--binding-key",
            "/srv/key",
            "--runtime-env",
            "/srv/runtime.env",
            "--compose-file",
            "/srv/one.yml",
            "--compose-file",
            "/srv/two.yml",
        ]
    )
    assert arguments.compose_file == [Path("/srv/one.yml"), Path("/srv/two.yml")]
    with pytest.raises(module.AdoptionError, match="unrecognized arguments"):
        module._parser().parse_args(
            [
                "plan",
                "--binding-key",
                "/srv/key",
                "--runtime-env",
                "/srv/runtime.env",
                "--compose-file",
                "/srv/one.yml",
                "--target-manifest",
                "/srv/release.env.images",
            ]
        )


def test_prepare_parser_requires_preapproved_ca_attestation_public_key() -> None:
    module = _module()
    base = [
        "prepare",
        "--plan",
        "/srv/plan.json",
        "--binding-key",
        "/srv/binding.key",
        "--run-id",
        "restore-drill-001",
        "--ca-root",
        "/srv/ca",
        "--ca-recipient-certificate",
        "/srv/recipient.pem",
        "--evidence-signing-key",
        "/srv/evidence.key",
        "--evidence-public-key",
        "/srv/evidence.pub",
    ]
    with pytest.raises(module.AdoptionError, match="required"):
        module._parser().parse_args(base)
    arguments = module._parser().parse_args(
        [
            *base,
            "--ca-attestation-public-key",
            "/srv/ca-attestation.pub",
        ]
    )
    assert arguments.ca_attestation_public_key == Path("/srv/ca-attestation.pub")


def test_production_cli_rejects_operator_selected_evidence_and_ca_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    trust_checks: list[bool] = []
    monkeypatch.setattr(
        module,
        "_validate_trusted_adoption_evidence_public_key",
        lambda: trust_checks.append(True),
    )
    accepted = argparse.Namespace(
        operation="prepare",
        evidence_public_key=module.TRUSTED_ADOPTION_EVIDENCE_PUBLIC_KEY,
        evidence_signing_key=module.EPHEMERAL_ADOPTION_EVIDENCE_SIGNING_KEY,
        ca_attestation_public_key=module.TRUSTED_CA_RESTORE_ATTESTATION_PUBLIC_KEY,
    )
    module._validate_production_evidence_key_arguments(accepted)
    assert trust_checks == [True]

    for field, attacker_path in (
        ("evidence_public_key", Path("/root/attacker-evidence.pub")),
        ("evidence_signing_key", Path("/root/attacker-evidence.key")),
        ("ca_attestation_public_key", Path("/root/attacker-ca.pub")),
    ):
        forged = argparse.Namespace(**vars(accepted))
        setattr(forged, field, attacker_path)
        with pytest.raises(module.AdoptionError, match="fixed"):
            module._validate_production_evidence_key_arguments(forged)
    assert trust_checks == [True]


def test_plan_does_not_require_the_adoption_signer_trust_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    monkeypatch.setattr(
        module,
        "_validate_trusted_adoption_evidence_public_key",
        lambda: (_ for _ in ()).throw(AssertionError("plan must not load adoption signer state")),
    )
    module._validate_production_evidence_key_arguments(argparse.Namespace(operation="plan"))


def test_reactivate_parser_requires_host_guard_and_pre_migration_contract() -> None:
    module = _module()
    arguments = module._parser().parse_args(
        [
            "reactivate",
            "--plan",
            "/srv/plan.json",
            "--binding-key",
            "/srv/key",
            "--retirement-receipt",
            "/srv/receipt.json",
            "--retirement-signature",
            "/srv/receipt.sig",
            "--target-abort-receipt",
            "/srv/target-abort/receipt.json",
            "--target-abort-signature",
            "/srv/target-abort/receipt.sig",
            "--adoption-transaction",
            "1" * 32,
            "--evidence-public-key",
            "/srv/public.pem",
            "--host-isolation-baseline",
            "/srv/host-before.json",
            "--host-isolation-hmac-key",
            "/srv/host.key",
            "--execute",
            "--confirm-project",
            module.PROJECT,
            "--confirm-plan-sha256",
            "a" * 64,
            "--confirm-restore-boundary",
            module.REACTIVATION_BOUNDARY,
        ]
    )
    assert arguments.operation == "reactivate"
    assert arguments.confirm_restore_boundary == "PRE_MIGRATION_ONLY"


def test_reactivation_order_omits_oneoffs_and_starts_proxy_last() -> None:
    module = _module()
    base = _inventory(module).containers[0]
    containers = (
        replace(base, service="proxy", container_id="2" * 64),
        replace(base, service="postgres", container_id="3" * 64),
        replace(
            base,
            service="migrate",
            container_id="4" * 64,
            oneoff=True,
            running=False,
        ),
        replace(base, service="web", container_id="5" * 64),
    )
    inventory = module.LegacyInventory(containers, (), ())
    assert module._ordered_primary_services(inventory) == ("postgres", "web", "proxy")


def test_retirement_uses_140_second_stop_and_receipt_never_restores_oneoffs() -> None:
    module = _module()
    retire_source = inspect.getsource(module._retire_exact_resources)
    receipt_source = inspect.getsource(module._retire)
    reactivate_source = inspect.getsource(module._reactivate)
    assert "LEGACY_STOP_GRACE_SECONDS" in retire_source
    assert module.LEGACY_STOP_GRACE_SECONDS >= 140
    assert '"stopped_oneoff_container_ids_not_restored"' in receipt_source
    assert "any(item.oneoff" in reactivate_source
    assert '"down"' not in reactivate_source
    assert '"prune"' not in reactivate_source


def test_reactivation_rejects_active_reconcile_timer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()

    class FakeGuard:
        @staticmethod
        def load_hmac_key(path: Path) -> bytes:
            del path
            return b"k" * 32

        @staticmethod
        def load_json_evidence(path: Path) -> dict[str, object]:
            del path
            return {"signed": True}

        @staticmethod
        def verify_against_baseline(
            baseline: dict[str, object], *, integrity_key: bytes
        ) -> dict[str, str]:
            del baseline, integrity_key
            return {"status": "PASS"}

        @staticmethod
        def _systemctl_show(unit: str) -> dict[str, str]:
            return {
                "LoadState": "loaded",
                "ActiveState": "active" if unit.endswith(".timer") else "inactive",
                "UnitFileState": "enabled" if unit.endswith(".timer") else "static",
            }

    monkeypatch.setattr(module, "_load_host_isolation_guard", lambda plan: FakeGuard)
    with pytest.raises(module.AdoptionError, match="inactive and disabled"):
        module._verify_host_isolation({}, Path("/baseline"), Path("/key"))


def test_retirement_data_gate_requires_exact_postgres_and_minio_bind_paths() -> None:
    module = _module()
    base = _inventory(module).containers[0]
    postgres = replace(
        base,
        service="postgres",
        container_id="2" * 64,
        mounts=((str(module.DATA_ROOT / "postgres"), "/var/lib/postgresql/data", True, "bind"),),
    )
    minio = replace(
        base,
        service="minio",
        container_id="3" * 64,
        mounts=((str(module.DATA_ROOT / "minio"), "/data", True, "bind"),),
    )
    inventory = module.LegacyInventory((postgres, minio), (), ())
    module._verify_data_bindings(inventory)
    drifted = module.LegacyInventory(
        (postgres, replace(minio, mounts=(("/srv/wrong", "/data", True, "bind"),))),
        (),
        (),
    )
    with pytest.raises(module.AdoptionError, match="minio data bind path differs"):
        module._verify_data_bindings(drifted)


def test_prepare_ca_root_is_derived_from_exact_live_edge_data_binds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    data_root = tmp_path / "data"
    caddy_data = data_root / "caddy-data"
    expected_ca = caddy_data / "caddy" / "pki" / "authorities" / "local"
    base = _inventory(module).containers[0]
    proxy = replace(
        base,
        service="proxy",
        mounts=((str(caddy_data), "/data", True, "bind"),),
    )
    maintenance = replace(
        base,
        service="maintenance-page",
        container_id="2" * 64,
        mounts=((str(caddy_data), "/data", True, "bind"),),
    )
    inventory = module.LegacyInventory((proxy, maintenance), (), ())
    monkeypatch.setattr(module, "DATA_ROOT", data_root)
    monkeypatch.setattr(module, "protected_directory", lambda path, **kwargs: path)

    assert module._validated_legacy_ca_root(inventory, expected_ca) == expected_ca


@pytest.mark.parametrize(
    ("proxy_mount", "requested_suffix", "error"),
    [
        (("caddy-data", "/data", True, "volume"), "caddy-data", "proxy Caddy data bind"),
        (("caddy-data", "/data", False, "bind"), "caddy-data", "proxy Caddy data bind"),
        (("decoy-caddy", "/data", True, "bind"), "decoy-caddy", "proxy Caddy data bind"),
        (("caddy-data", "/wrong", True, "bind"), "caddy-data", "proxy Caddy data bind"),
        (("caddy-data", "/data", True, "bind"), "fake-ca", "must equal the derived"),
    ],
)
def test_prepare_ca_root_rejects_nonexact_bind_or_other_data_root_subdirectory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    proxy_mount: tuple[str, str, bool, str],
    requested_suffix: str,
    error: str,
) -> None:
    module = _module()
    data_root = tmp_path / "data"
    source_name, destination, writable, kind = proxy_mount
    source = data_root / source_name
    requested = data_root / requested_suffix / "caddy" / "pki" / "authorities" / "local"
    proxy = replace(
        _inventory(module).containers[0],
        service="proxy",
        mounts=((str(source), destination, writable, kind),),
    )
    inventory = module.LegacyInventory((proxy,), (), ())
    monkeypatch.setattr(module, "DATA_ROOT", data_root)
    monkeypatch.setattr(module, "protected_directory", lambda path, **kwargs: path)

    with pytest.raises(module.AdoptionError, match=error):
        module._validated_legacy_ca_root(inventory, requested)


def test_prepare_ca_root_rejects_mismatched_maintenance_page_data_bind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    data_root = tmp_path / "data"
    caddy_data = data_root / "caddy-data"
    expected_ca = caddy_data / "caddy" / "pki" / "authorities" / "local"
    base = _inventory(module).containers[0]
    proxy = replace(
        base,
        service="proxy",
        mounts=((str(caddy_data), "/data", True, "bind"),),
    )
    maintenance = replace(
        base,
        service="maintenance-page",
        container_id="2" * 64,
        mounts=((str(data_root / "decoy"), "/data", True, "bind"),),
    )
    inventory = module.LegacyInventory((proxy, maintenance), (), ())
    monkeypatch.setattr(module, "DATA_ROOT", data_root)
    monkeypatch.setattr(module, "protected_directory", lambda path, **kwargs: path)

    with pytest.raises(module.AdoptionError, match="maintenance-page Caddy data bind"):
        module._validated_legacy_ca_root(inventory, expected_ca)


def test_prepare_command_applies_live_inventory_ca_root_gate_before_backup_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    data_root = tmp_path / "data"
    caddy_data = data_root / "caddy-data"
    proxy = replace(
        _inventory(module).containers[0],
        service="proxy",
        mounts=((str(caddy_data), "/data", True, "bind"),),
    )
    inventory = module.LegacyInventory((proxy,), (), ())
    plan = {
        "inventory_sha256": module.inventory_sha256(inventory),
        "runtime_env": {"path": "/runtime.env"},
    }
    arguments = argparse.Namespace(
        binding_key=tmp_path / "binding.key",
        plan=tmp_path / "plan.json",
        ca_root=data_root / "fake-ca" / "caddy" / "pki" / "authorities" / "local",
        evidence_signing_key=tmp_path / "evidence-signing.key",
        evidence_public_key=tmp_path / "evidence-public.pem",
    )
    monkeypatch.setattr(
        module,
        "_validate_adoption_evidence_key_pair",
        lambda *args, **kwargs: (
            arguments.evidence_signing_key,
            arguments.evidence_public_key,
        ),
    )
    monkeypatch.setattr(module, "DATA_ROOT", data_root)
    monkeypatch.setattr(module, "_read_binding_key", lambda path: b"k" * 32)
    monkeypatch.setattr(
        module,
        "_validate_plan",
        lambda path, key: (plan, "d" * 64, {}, (), ()),
    )
    monkeypatch.setattr(module, "collect_inventory", lambda runner: inventory)
    monkeypatch.setattr(module, "protected_directory", lambda path, **kwargs: path)

    with pytest.raises(module.AdoptionError, match="must equal the derived"):
        module._prepare(arguments, object())


def test_prepare_validates_signer_before_any_downstream_or_mutating_operation() -> None:
    module = _module()
    source = inspect.getsource(module._prepare)

    entry_challenge = source.index('phase="prepare-entry"')
    binding_read = source.index("_read_binding_key")
    run_directory = source.index("_create_run_directory")
    quiesce = source.index("_quiesce_legacy")
    signature_challenge = source.index('phase="prepare-ca-challenge-signature"')
    challenge_persistence = source.index("_atomic_write(challenge_path")

    assert entry_challenge < binding_read < run_directory < quiesce
    assert signature_challenge < challenge_persistence
    assert source.count("_validate_adoption_evidence_key_pair(") == 2


@pytest.mark.skipif(
    sys.platform != "linux"
    or not Path("/usr/bin/openssl").is_file()
    or getattr(os, "memfd_create", None) is None,
    reason="real adoption signer challenge requires Linux, memfd, and OpenSSL",
)
def test_prepare_rejects_mismatched_fixed_signer_with_zero_downstream_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    trusted_private, trusted_public, attacker_private, fingerprint = (
        _write_real_adoption_signer_material(tmp_path)
    )

    monkeypatch.setattr(module, "TRUSTED_ADOPTION_EVIDENCE_PUBLIC_KEY", trusted_public)
    monkeypatch.setattr(
        module,
        "TRUSTED_ADOPTION_EVIDENCE_PUBLIC_KEY_SHA256",
        fingerprint,
    )
    monkeypatch.setattr(
        module,
        "EPHEMERAL_ADOPTION_EVIDENCE_SIGNING_KEY",
        trusted_private,
    )
    monkeypatch.setattr(module, "protected_file", lambda path, **kwargs: path)

    runner = module.Runner()
    assert module._validate_adoption_evidence_key_pair(
        runner,
        signing_key=trusted_private,
        public_key=trusted_public,
        phase="prepare-entry",
    ) == (trusted_private, trusted_public)

    monkeypatch.setattr(
        module,
        "EPHEMERAL_ADOPTION_EVIDENCE_SIGNING_KEY",
        attacker_private,
    )
    downstream_calls: list[str] = []

    def forbidden(name: str) -> Any:
        def call(*args: object, **kwargs: object) -> None:
            del args, kwargs
            downstream_calls.append(name)
            raise AssertionError(f"{name} ran before signer validation")

        return call

    for function_name in (
        "_read_binding_key",
        "_validate_plan",
        "collect_inventory",
        "_create_run_directory",
        "_new_private_directory",
        "_atomic_write",
        "_quiesce_legacy",
        "_database_backup",
        "_run_mc_backup",
        "_encrypt_ca_escrow",
    ):
        monkeypatch.setattr(module, function_name, forbidden(function_name))

    arguments = argparse.Namespace(
        evidence_signing_key=attacker_private,
        evidence_public_key=trusted_public,
    )
    with pytest.raises(
        module.AdoptionError,
        match="does not match the independently trusted public key",
    ):
        module._prepare(arguments, runner)
    assert downstream_calls == []


def test_finalize_and_retire_validate_signer_before_sensitive_work() -> None:
    module = _module()
    finalize_source = inspect.getsource(module._finalize)
    retire_source = inspect.getsource(module._retire)

    assert (
        finalize_source.index('phase="finalize-entry"')
        < finalize_source.index("_read_binding_key")
        < finalize_source.index("collect_inventory")
        < finalize_source.index("_run_restore_drill")
    )
    assert finalize_source.index('phase="finalize-evidence-signature"') < finalize_source.index(
        "_atomic_write(detailed_path"
    )
    assert finalize_source.count("_validate_adoption_evidence_key_pair(") == 2

    assert (
        retire_source.index('phase="retire-entry"')
        < retire_source.index("_read_binding_key")
        < retire_source.index("collect_inventory")
        < retire_source.index("_publish_retirement_intent")
        < retire_source.index("_retire_exact_resources")
    )
    assert retire_source.index('phase="retire-intent-signature"') < retire_source.index(
        "_publish_retirement_intent"
    )
    assert retire_source.count("_validate_adoption_evidence_key_pair(") == 2


@pytest.mark.skipif(
    sys.platform != "linux"
    or not Path("/usr/bin/openssl").is_file()
    or getattr(os, "memfd_create", None) is None,
    reason="real adoption signer challenge requires Linux, memfd, and OpenSSL",
)
@pytest.mark.parametrize(
    ("operation", "downstream_functions"),
    [
        (
            "finalize",
            (
                "_read_binding_key",
                "_validate_plan",
                "_validate_prepared_state",
                "_validate_backup_artifacts",
                "collect_inventory",
                "_ensure_scratch_root",
                "_run_restore_drill",
                "_atomic_write",
                "_signature",
            ),
        ),
        (
            "retire",
            (
                "_read_binding_key",
                "_locate_upgrade_evidence_run",
                "_validate_plan",
                "_planned_inventory",
                "_verify_upgrade_evidence",
                "collect_inventory",
                "_publish_retirement_intent",
                "_retire_exact_resources",
                "_atomic_publish_receipt_directory",
            ),
        ),
    ],
)
def test_finalize_and_retire_reject_mismatched_signer_with_zero_downstream_calls(
    operation: str,
    downstream_functions: tuple[str, ...],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    trusted_private, trusted_public, attacker_private, fingerprint = (
        _write_real_adoption_signer_material(tmp_path)
    )
    monkeypatch.setattr(module, "TRUSTED_ADOPTION_EVIDENCE_PUBLIC_KEY", trusted_public)
    monkeypatch.setattr(
        module,
        "TRUSTED_ADOPTION_EVIDENCE_PUBLIC_KEY_SHA256",
        fingerprint,
    )
    monkeypatch.setattr(
        module,
        "EPHEMERAL_ADOPTION_EVIDENCE_SIGNING_KEY",
        trusted_private,
    )
    monkeypatch.setattr(module, "protected_file", lambda path, **kwargs: path)
    entrypoint = module._finalize if operation == "finalize" else module._retire
    trusted_downstream_calls: list[str] = []

    def stop_after_trusted_challenge(*args: object, **kwargs: object) -> None:
        del args, kwargs
        trusted_downstream_calls.append("_read_binding_key")
        raise module.AdoptionError("trusted signer reached downstream")

    monkeypatch.setattr(module, "_read_binding_key", stop_after_trusted_challenge)
    trusted_arguments = argparse.Namespace(
        evidence_signing_key=trusted_private,
        evidence_public_key=trusted_public,
        binding_key=tmp_path / "binding.key",
    )
    with pytest.raises(module.AdoptionError, match="trusted signer reached downstream"):
        entrypoint(trusted_arguments, module.Runner())
    assert trusted_downstream_calls == ["_read_binding_key"]

    monkeypatch.setattr(
        module,
        "EPHEMERAL_ADOPTION_EVIDENCE_SIGNING_KEY",
        attacker_private,
    )
    downstream_calls: list[str] = []

    def forbidden(name: str) -> Any:
        def call(*args: object, **kwargs: object) -> None:
            del args, kwargs
            downstream_calls.append(name)
            raise AssertionError(f"{name} ran before signer validation")

        return call

    for function_name in downstream_functions:
        monkeypatch.setattr(module, function_name, forbidden(function_name))

    arguments = argparse.Namespace(
        evidence_signing_key=attacker_private,
        evidence_public_key=trusted_public,
        binding_key=tmp_path / "binding.key",
    )
    with pytest.raises(
        module.AdoptionError,
        match="does not match the independently trusted public key",
    ):
        entrypoint(arguments, module.Runner())
    assert downstream_calls == []


def test_retirement_data_gate_requires_postgres_major_17_and_signed_schema() -> None:
    module = _module()
    postgres = replace(
        _inventory(module).containers[0],
        service="postgres",
        running=True,
    )
    inventory = module.LegacyInventory((postgres,), (), ())

    class FakeRunner:
        docker = "/usr/bin/docker"
        version = "170005"

        def run(self, argv: tuple[str, ...], *, timeout: int = 120) -> bytes:
            del timeout
            command = argv[-1]
            if command == "SHOW server_version_num;":
                return f"{self.version}\n".encode()
            if command == "SELECT version_num FROM alembic_version;":
                return b"20260714_0020\n"
            raise AssertionError(f"unexpected command: {command}")

    runner = FakeRunner()
    runtime = {"POSTGRES_USER": "postgres", "POSTGRES_DB": "knowledge"}
    module._verify_postgres_17_and_schema(runner, inventory, runtime, "20260714_0020")
    runner.version = "160009"
    with pytest.raises(module.AdoptionError, match="major version is not 17"):
        module._verify_postgres_17_and_schema(runner, inventory, runtime, "20260714_0020")


@pytest.mark.parametrize("kill_boundary", ["stop", "remove", "network-remove"])
def test_retirement_exact_resources_resumes_forward_after_kill_boundary(
    kill_boundary: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    record = replace(_inventory(module).containers[0], service="api", running=True)
    network = module.NetworkRecord(
        name="heyi-kb-offline_backend",
        network_id="9" * 64,
        internal=True,
        attached_container_ids=(record.container_id,),
    )
    inventory = module.LegacyInventory((record,), (network,), ())
    container_ids = {record.container_id}
    network_ids = {network.network_id}
    running = {record.container_id: True}
    killed = False

    class FakeRunner:
        docker = "/usr/bin/docker"

        def run(self, argv: tuple[str, ...], *, timeout: int = 120) -> bytes:
            nonlocal killed
            del timeout
            action = argv[1]
            if action == "stop":
                running[record.container_id] = False
                if kill_boundary == "stop" and not killed:
                    killed = True
                    raise SystemExit(137)
            elif action == "rm":
                container_ids.discard(record.container_id)
                if kill_boundary == "remove" and not killed:
                    killed = True
                    raise SystemExit(137)
            return b""

    monkeypatch.setattr(module, "_project_container_ids", lambda runner: set(container_ids))
    monkeypatch.setattr(module, "_project_network_ids", lambda runner: set(network_ids))
    monkeypatch.setattr(
        module,
        "_inspect_exact_legacy_container",
        lambda runner, expected: replace(expected, running=running[expected.container_id]),
    )

    def remove_network(runner: object, expected: object) -> None:
        nonlocal killed
        network_ids.discard(network.network_id)
        if kill_boundary == "network-remove" and not killed:
            killed = True
            raise SystemExit(137)

    monkeypatch.setattr(module, "_remove_exact_legacy_network", remove_network)
    with pytest.raises(SystemExit):
        module._retire_exact_resources(FakeRunner(), inventory, allow_missing=True)
    removed_containers, removed_networks = module._retire_exact_resources(
        FakeRunner(), inventory, allow_missing=True
    )
    assert removed_containers == [record.container_id]
    assert removed_networks == [network.network_id]
    assert container_ids == set()
    assert network_ids == set()


def test_retirement_resume_rejects_unknown_project_resource(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    inventory = _inventory(module)
    monkeypatch.setattr(
        module,
        "_project_container_ids",
        lambda runner: {inventory.containers[0].container_id, "f" * 64},
    )
    monkeypatch.setattr(module, "_project_network_ids", lambda runner: set())
    with pytest.raises(module.AdoptionError, match="unknown project container"):
        module._retire_exact_resources(object(), inventory, allow_missing=True)


def test_reactivation_accepts_only_an_exact_legacy_service_subset() -> None:
    module = _module()
    expected = _inventory(module)
    current = module.LegacyInventory(
        (
            replace(
                expected.containers[0],
                container_id="2" * 64,
                running=False,
                restart_count=7,
            ),
        ),
        (),
        expected.volumes,
    )
    module._validate_reactivation_subset(current, expected)
    unknown = module.LegacyInventory(
        (replace(current.containers[0], service="unknown"),), (), expected.volumes
    )
    with pytest.raises(module.AdoptionError, match="unknown service"):
        module._validate_reactivation_subset(unknown, expected)
    drifted = module.LegacyInventory(
        (replace(current.containers[0], image_id="sha256:" + "f" * 64),),
        (),
        expected.volumes,
    )
    with pytest.raises(module.AdoptionError, match="contract differs"):
        module._validate_reactivation_subset(drifted, expected)


def test_reactivation_partial_services_must_be_an_exact_start_order_prefix() -> None:
    module = _module()
    base = _inventory(module).containers[0]
    postgres = replace(base, service="postgres", container_id="2" * 64)
    api = replace(base, service="api", container_id="3" * 64)
    proxy = replace(base, service="proxy", container_id="4" * 64)
    expected = module.LegacyInventory((proxy, api, postgres), (), ())
    module._validate_reactivation_subset(
        module.LegacyInventory((replace(postgres, container_id="5" * 64),), (), ()),
        expected,
    )
    with pytest.raises(module.AdoptionError, match="start-order prefix"):
        module._validate_reactivation_subset(
            module.LegacyInventory((replace(proxy, container_id="6" * 64),), (), ()),
            expected,
        )
    with pytest.raises(module.AdoptionError, match="start-order prefix"):
        module._validate_reactivation_subset(
            module.LegacyInventory(
                (
                    replace(postgres, container_id="7" * 64),
                    replace(proxy, container_id="8" * 64),
                ),
                (),
                (),
            ),
            expected,
        )


def test_reactivation_port_gate_rejects_non_docker_listener() -> None:
    module = _module()
    base = _inventory(module)
    proxy = replace(
        base.containers[0],
        service="proxy",
        container_id="2" * 64,
        published_ports=("19443/443/tcp", "19444/8443/tcp"),
    )
    expected = module.LegacyInventory((base.containers[0], proxy), (), base.volumes)
    partial = module.LegacyInventory((), (), expected.volumes)

    class FakeRunner:
        docker = "/usr/bin/docker"

        def run(self, argv: tuple[str, ...], *, timeout: int = 120) -> bytes:
            del argv, timeout
            return b""

    class FakeGuard:
        @staticmethod
        def _tcp_listeners(port: int) -> list[dict[str, object]]:
            return [{"local_port": port, "state": "LISTEN", "socket_inode": 123}]

    with pytest.raises(module.AdoptionError, match="non-Docker host listener"):
        module._verify_edge_ports_available(FakeRunner(), partial, expected, FakeGuard)


def test_reactivation_port_gate_rejects_extra_listener_beside_exact_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    proxy_document = _container_document(module, service="proxy", host_port="19443")
    proxy_document["NetworkSettings"]["Networks"]["heyi-kb-offline_internal"] = {
        "IPAddress": "172.30.0.8",
        "GlobalIPv6Address": "",
    }
    proxy_document["NetworkSettings"]["Ports"]["8443/tcp"] = [
        {"HostIp": "0.0.0.0", "HostPort": "19444"}
    ]
    proxy = module._container_record(proxy_document)
    inventory = module.LegacyInventory((proxy,), (), ())

    class FakeRunner:
        docker = "/usr/bin/docker"

        def run(self, argv: tuple[str, ...], *, timeout: int = 120) -> bytes:
            del timeout
            if argv[1:3] == ("ps", "-q"):
                return f"{proxy.container_id}\n".encode()
            raise AssertionError(f"unexpected command: {argv}")

        def docker_json(self, argv: tuple[str, ...]) -> object:
            assert argv == ("inspect", proxy.container_id)
            return [proxy_document]

    class FakeGuard:
        @staticmethod
        def _tcp_listeners(port: int) -> list[dict[str, object]]:
            if port != 19443:
                return []
            return [
                {
                    "family": "ipv4",
                    "local_address": "0.0.0.0",
                    "local_port": port,
                    "state": "LISTEN",
                    "socket_inode": 123,
                },
                {
                    "family": "ipv4",
                    "local_address": "127.0.0.1",
                    "local_port": port,
                    "state": "LISTEN",
                    "socket_inode": 456,
                },
            ]

    monkeypatch.setattr(module, "_verify_listener_owned_by_proxy", lambda *args: None)
    with pytest.raises(module.AdoptionError, match="extra non-Docker listener"):
        module._verify_edge_ports_available(FakeRunner(), inventory, inventory, FakeGuard)


def test_reactivation_port_gate_checks_owner_even_for_same_configured_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    proxy_document = _container_document(module, service="proxy", host_port="19443")
    proxy_document["NetworkSettings"]["Networks"]["heyi-kb-offline_internal"] = {
        "IPAddress": "172.30.0.8",
        "GlobalIPv6Address": "",
    }
    proxy_document["NetworkSettings"]["Ports"]["8443/tcp"] = [
        {"HostIp": "0.0.0.0", "HostPort": "19444"}
    ]
    proxy = module._container_record(proxy_document)
    inventory = module.LegacyInventory((proxy,), (), ())

    class FakeRunner:
        docker = "/usr/bin/docker"

        def run(self, argv: tuple[str, ...], *, timeout: int = 120) -> bytes:
            del timeout
            if argv[1:3] == ("ps", "-q"):
                return f"{proxy.container_id}\n".encode()
            raise AssertionError(f"unexpected command: {argv}")

        def docker_json(self, argv: tuple[str, ...]) -> object:
            assert argv == ("inspect", proxy.container_id)
            return [proxy_document]

    class FakeGuard:
        @staticmethod
        def _tcp_listeners(port: int) -> list[dict[str, object]]:
            if port != 19443:
                return []
            return [
                {
                    "family": "ipv4",
                    "local_address": "0.0.0.0",
                    "local_port": port,
                    "state": "LISTEN",
                    "socket_inode": 123,
                }
            ]

    monkeypatch.setattr(
        module,
        "_verify_listener_owned_by_proxy",
        lambda *args: (_ for _ in ()).throw(
            module.AdoptionError("host TCP listener is owned by a non-Docker process")
        ),
    )
    with pytest.raises(module.AdoptionError, match="non-Docker process"):
        module._verify_edge_ports_available(FakeRunner(), inventory, inventory, FakeGuard)


def test_retirement_uses_one_fixed_signed_intent_before_resource_removal() -> None:
    module = _module()
    source = inspect.getsource(module._retire)
    assert module.RETIREMENT_INTENT_DIRECTORY == ".retirement-in-progress"
    assert source.index("_publish_retirement_intent(") < source.index("_retire_exact_resources(")
    assert "_verify_retirement_receipt(" in source


def test_schema_v3_legacy_evidence_passes_shared_and_deep_validators(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    verifier = _module_from_script(
        UPGRADE_VERIFIER,
        name="legacy_upgrade_backup_verifier_under_test",
    )
    now = module._utc_now().replace(microsecond=0)
    run = tmp_path / "backups" / "run-1"
    evidence_directory = run / "evidence"
    evidence_directory.mkdir(parents=True)
    evidence_path = evidence_directory / "upgrade-backup-evidence.json"
    detailed_path = evidence_directory / "restore-evidence.json"
    artifact = {
        "path": str(run / "artifact"),
        "sha256": "c" * 64,
        "size_bytes": 1,
    }
    top_evidence = {
        "schema_version": 3,
        "kind": "offline-upgrade-backup",
        "project": module.PROJECT,
        "operation_scope": "legacy_adoption",
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + module.timedelta(hours=24)).isoformat().replace("+00:00", "Z"),
        "release_authorization_sha256": "a" * 64,
        "target_manifest_sha256": "b" * 64,
        "database_backup": artifact,
        "object_manifest": artifact,
        "restore_evidence": {
            "path": str(detailed_path),
            "sha256": "d" * 64,
            "size_bytes": 1,
        },
        "restore_drill": {
            "status": "passed",
            "tested_at": now.isoformat().replace("+00:00", "Z"),
            "source_schema_head": "20260715_0021",
        },
    }
    detailed = {
        "schema_version": 2,
        "kind": "heyi-legacy-adoption-restore-evidence",
        "project": module.PROJECT,
        "plan_sha256": "e" * 64,
        "release_authorization_sha256": "a" * 64,
        "git_sha": "f" * 40,
        "target_manifest_sha256": "b" * 64,
        "isolated_restore_drill": {"status": "passed"},
        "ca_restore_attestation": {"status": "passed"},
        "secret_policy": {
            "runtime_secret_values_recorded": False,
            "low_entropy_secret_sha256_recorded": False,
            "ca_private_key_plaintext_on_server": False,
            "ca_recipient_private_key_on_server": False,
            "private_artifacts_on_cos": False,
        },
    }
    plan = {
        "target_manifest": {"sha256": "b" * 64},
        "release_authorization_sha256": "a" * 64,
        "git_sha": "f" * 40,
    }

    monkeypatch.setattr(
        verifier,
        "_artifact",
        lambda _document, _field: (run / "artifact", "c" * 64, 1),
    )
    verifier.validate_evidence_document(
        top_evidence,
        expected_manifest_sha256="b" * 64,
        expected_release_authorization_sha256="a" * 64,
        expected_operation_scope="legacy_adoption",
        require_current=True,
    )

    monkeypatch.setattr(module, "BACKUP_ROOT", tmp_path / "backups")
    monkeypatch.setattr(module, "_verify_signature", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        module,
        "_read_json_file",
        lambda path, **_kwargs: top_evidence if path == evidence_path else detailed,
    )
    monkeypatch.setattr(module, "protected_directory", lambda path, **kwargs: path)
    monkeypatch.setattr(
        module,
        "_verify_descriptor",
        lambda value, **_kwargs: Path(value["path"]),
    )
    monkeypatch.setattr(module, "_load_upgrade_backup_verifier", lambda: verifier)

    verified, verified_detailed, verified_run = module._verify_upgrade_evidence(
        object(),
        evidence_path=evidence_path,
        signature_path=evidence_directory / "upgrade-backup-evidence.sig",
        public_key=evidence_directory / "evidence.pub",
        plan=plan,
        plan_digest="e" * 64,
    )
    assert verified == top_evidence
    assert verified_detailed == detailed
    assert verified_run == run


def test_fresh_retire_process_resumes_signed_partial_intent_without_live_recollection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    inventory = _inventory(module)
    run = tmp_path / "backups" / "run-1"
    evidence_directory = run / "evidence"
    intent = evidence_directory / module.RETIREMENT_INTENT_DIRECTORY
    intent.mkdir(parents=True)
    plan_digest = "d" * 64
    plan = {
        "git_sha": "a" * 40,
        "topology_sha256": module.topology_sha256(inventory),
        "target_manifest": {"sha256": "b" * 64},
    }
    release_binding = {"schema_version": 1, "control_files": []}
    receipt = {
        "release_state_binding": release_binding,
        "upgrade_evidence_sha256": "e" * 64,
        "removed_container_ids": [item.container_id for item in inventory.containers],
        "removed_network_ids": [item.network_id for item in inventory.networks],
    }
    arguments = argparse.Namespace(
        binding_key=tmp_path / "binding.key",
        plan=tmp_path / "plan.json",
        evidence=tmp_path / "evidence.json",
        evidence_signature=tmp_path / "evidence.sig",
        evidence_public_key=tmp_path / "public.pem",
        evidence_signing_key=tmp_path / "private.pem",
        execute=True,
        confirm_project=module.PROJECT,
        confirm_plan_sha256=plan_digest,
        confirm_preserve_data="PRESERVE_BIND_DATA_AND_NAMED_VOLUMES",
    )
    monkeypatch.setattr(
        module,
        "_validate_adoption_evidence_key_pair",
        lambda runner, **kwargs: (kwargs["signing_key"], kwargs["public_key"]),
    )
    monkeypatch.setattr(module, "_read_binding_key", lambda path: b"k" * 32)
    monkeypatch.setattr(
        module,
        "_locate_upgrade_evidence_run",
        lambda path: (path, run),
    )
    monkeypatch.setattr(module, "_sha256_file", lambda path: "e" * 64)
    plan_validations: list[bool] = []

    def validate_plan(*args: object, **kwargs: object) -> object:
        plan_validations.append(kwargs["enforce_freshness"] is False)
        return plan, plan_digest, {}, (), ()

    monkeypatch.setattr(
        module,
        "_validate_plan",
        validate_plan,
    )
    monkeypatch.setattr(
        module,
        "_verify_upgrade_evidence",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("signed intent resume must not reapply freshness gates")
        ),
    )
    monkeypatch.setattr(module, "_planned_inventory", lambda document: inventory)
    monkeypatch.setattr(module, "_confirm", lambda arguments, digest: True)
    monkeypatch.setattr(module, "protected_directory", lambda path, **kwargs: path)
    monkeypatch.setattr(module, "_verify_retirement_receipt", lambda *args, **kwargs: receipt)
    monkeypatch.setattr(module, "_release_state_binding", lambda: release_binding)
    monkeypatch.setattr(module, "_verify_named_volumes", lambda *args, **kwargs: None)
    monkeypatch.setattr(module, "_assert_legacy_resources_absent", lambda runner: None)
    monkeypatch.setattr(
        module,
        "collect_inventory",
        lambda runner: (_ for _ in ()).throw(AssertionError("must not recollect")),
    )
    retired: list[bool] = []

    def retire_exact(
        runner: object, expected: object, *, allow_missing: bool
    ) -> tuple[list[str], list[str]]:
        del runner
        assert expected == inventory
        retired.append(allow_missing)
        return receipt["removed_container_ids"], receipt["removed_network_ids"]

    promoted: list[tuple[Path, Path]] = []
    monkeypatch.setattr(module, "_retire_exact_resources", retire_exact)
    monkeypatch.setattr(
        module,
        "_atomic_publish_receipt_directory",
        lambda parent, pending, final: promoted.append((pending, final)),
    )
    monkeypatch.setattr(module, "_print_retirement_result", lambda **kwargs: None)
    module._retire(arguments, object())
    assert retired == [True]
    assert promoted == [(intent, evidence_directory / "retirement")]
    assert plan_validations == [True]


def test_tampered_retirement_intent_blocks_before_any_resource_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    inventory = _inventory(module)
    run = tmp_path / "backups" / "run-1"
    (run / "evidence" / module.RETIREMENT_INTENT_DIRECTORY).mkdir(parents=True)
    plan = {"topology_sha256": module.topology_sha256(inventory)}
    arguments = argparse.Namespace(
        binding_key=tmp_path / "binding.key",
        plan=tmp_path / "plan.json",
        evidence=tmp_path / "evidence.json",
        evidence_signature=tmp_path / "evidence.sig",
        evidence_public_key=tmp_path / "public.pem",
        evidence_signing_key=tmp_path / "private.pem",
        execute=True,
        confirm_preserve_data="PRESERVE_BIND_DATA_AND_NAMED_VOLUMES",
    )
    monkeypatch.setattr(
        module,
        "_validate_adoption_evidence_key_pair",
        lambda runner, **kwargs: (kwargs["signing_key"], kwargs["public_key"]),
    )
    monkeypatch.setattr(module, "_read_binding_key", lambda path: b"k" * 32)
    monkeypatch.setattr(
        module,
        "_locate_upgrade_evidence_run",
        lambda path: (path, run),
    )
    monkeypatch.setattr(module, "_sha256_file", lambda path: "e" * 64)
    monkeypatch.setattr(
        module,
        "_validate_plan",
        lambda *args, **kwargs: (plan, "d" * 64, {}, (), ()),
    )
    monkeypatch.setattr(
        module,
        "_verify_upgrade_evidence",
        lambda *args, **kwargs: (
            {},
            {
                "source_images": module._source_images(inventory),
                "database": {"schema_head": "20260714_0020"},
            },
            run,
        ),
    )
    monkeypatch.setattr(module, "_planned_inventory", lambda document: inventory)
    monkeypatch.setattr(module, "_confirm", lambda *args: True)
    monkeypatch.setattr(module, "protected_directory", lambda path, **kwargs: path)
    monkeypatch.setattr(
        module,
        "_verify_retirement_receipt",
        lambda *args, **kwargs: (_ for _ in ()).throw(module.AdoptionError("bad signature")),
    )
    mutated: list[bool] = []
    monkeypatch.setattr(
        module,
        "_retire_exact_resources",
        lambda *args, **kwargs: mutated.append(True),
    )
    with pytest.raises(module.AdoptionError, match="bad signature"):
        module._retire(arguments, object())
    assert mutated == []


def test_fresh_retire_process_accepts_committed_final_without_stale_evidence_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    inventory = _inventory(module)
    run = tmp_path / "backups" / "run-1"
    final = run / "evidence" / "retirement"
    final.mkdir(parents=True)
    plan_digest = "d" * 64
    plan = {"topology_sha256": module.topology_sha256(inventory)}
    release_binding = {"schema_version": 1, "control_files": []}
    receipt = {
        "release_state_binding": release_binding,
        "upgrade_evidence_sha256": "e" * 64,
    }
    arguments = argparse.Namespace(
        binding_key=tmp_path / "binding.key",
        plan=tmp_path / "plan.json",
        evidence=tmp_path / "upgrade-backup-evidence.json",
        evidence_signature=tmp_path / "evidence.sig",
        evidence_public_key=tmp_path / "public.pem",
        evidence_signing_key=tmp_path / "private.pem",
        execute=True,
        confirm_preserve_data="PRESERVE_BIND_DATA_AND_NAMED_VOLUMES",
    )
    monkeypatch.setattr(
        module,
        "_validate_adoption_evidence_key_pair",
        lambda runner, **kwargs: (kwargs["signing_key"], kwargs["public_key"]),
    )
    monkeypatch.setattr(module, "_read_binding_key", lambda path: b"k" * 32)
    monkeypatch.setattr(
        module,
        "_validate_plan",
        lambda *args, **kwargs: (plan, plan_digest, {}, (), ()),
    )
    monkeypatch.setattr(module, "_planned_inventory", lambda document: inventory)
    monkeypatch.setattr(module, "_locate_upgrade_evidence_run", lambda path: (path, run))
    monkeypatch.setattr(module, "_sha256_file", lambda path: "e" * 64)
    monkeypatch.setattr(module, "_confirm", lambda *args: True)
    monkeypatch.setattr(module, "protected_directory", lambda path, **kwargs: path)
    monkeypatch.setattr(module, "_verify_retirement_receipt", lambda *args, **kwargs: receipt)
    monkeypatch.setattr(module, "_release_state_binding", lambda: release_binding)
    monkeypatch.setattr(module, "_verify_named_volumes", lambda *args: None)
    monkeypatch.setattr(module, "_assert_legacy_resources_absent", lambda runner: None)
    monkeypatch.setattr(
        module,
        "_verify_upgrade_evidence",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("committed final must not reapply evidence freshness")
        ),
    )
    results: list[bool] = []
    monkeypatch.setattr(
        module,
        "_print_retirement_result",
        lambda **kwargs: results.append(kwargs["already_retired"]),
    )
    module._retire(arguments, object())
    assert results == [True]


def test_signed_retirement_receipts_support_explicit_long_outage_recovery_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    inventory = _inventory(module)
    backup_root = tmp_path / "backups"
    evidence = backup_root / "run-1" / "evidence"
    intent = evidence / module.RETIREMENT_INTENT_DIRECTORY
    final = evidence / "retirement"
    intent.mkdir(parents=True)
    final.mkdir()
    plan_digest = "d" * 64
    plan = {
        "git_sha": "a" * 40,
        "topology_sha256": "b" * 64,
        "target_manifest": {"sha256": "c" * 64},
    }
    document = {
        "schema_version": 2,
        "kind": "heyi-legacy-retirement-receipt",
        "status": "retired",
        "project": module.PROJECT,
        "issued_at": "2026-05-01T00:00:00Z",
        "git_sha": plan["git_sha"],
        "plan_sha256": plan_digest,
        "upgrade_evidence_sha256": "e" * 64,
        "target_manifest_sha256": "c" * 64,
        "source_schema_head": "20260714_0020",
        "source_postgres_major": 17,
        "source_topology_sha256": "b" * 64,
        "restorable_topology_sha256": module.restorable_topology_sha256(inventory),
        "release_state_binding": {},
        "removed_container_ids": [item.container_id for item in inventory.containers],
        "stopped_oneoff_container_ids_not_restored": [],
        "removed_network_ids": [],
        "preserved_named_volumes": [],
        "preserved_bind_root": str(module.DATA_ROOT),
        "named_volumes_deleted": False,
        "bind_data_deleted": False,
        "global_prune_used": False,
        "docker_daemon_restarted": False,
        "restore_boundary": module.REACTIVATION_BOUNDARY,
        "post_migration_rollback_policy": "forward-only",
    }
    monkeypatch.setattr(module, "BACKUP_ROOT", backup_root)
    monkeypatch.setattr(module, "protected_file", lambda path, **kwargs: path)
    monkeypatch.setattr(module, "protected_directory", lambda path, **kwargs: path)
    monkeypatch.setattr(module, "_verify_signature", lambda *args, **kwargs: None)
    monkeypatch.setattr(module, "_read_json_file", lambda *args, **kwargs: document)
    monkeypatch.setattr(
        module,
        "_utc_now",
        lambda: module.datetime(2026, 7, 15, tzinfo=module.UTC),
    )
    verified = module._verify_retirement_receipt(
        object(),
        receipt_path=intent / "receipt.json",
        signature_path=intent / "receipt.sig",
        public_key=tmp_path / "public.pem",
        plan=plan,
        plan_digest=plan_digest,
        inventory=inventory,
        expected_directory_name=module.RETIREMENT_INTENT_DIRECTORY,
    )
    assert verified == document
    with pytest.raises(module.AdoptionError, match="identity differs"):
        module._verify_retirement_receipt(
            object(),
            receipt_path=final / "receipt.json",
            signature_path=final / "receipt.sig",
            public_key=tmp_path / "public.pem",
            plan=plan,
            plan_digest=plan_digest,
            inventory=inventory,
        )
    recovered = module._verify_retirement_receipt(
        object(),
        receipt_path=final / "receipt.json",
        signature_path=final / "receipt.sig",
        public_key=tmp_path / "public.pem",
        plan=plan,
        plan_digest=plan_digest,
        inventory=inventory,
        enforce_freshness=False,
    )
    assert recovered == document


def test_plan_identity_supports_explicit_31_day_recovery_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    inventory = {"containers": [], "networks": [], "volumes": []}
    release_authorization = _release_authorization(Path("/srv/release.env.images"))
    plan = {
        "schema_version": 4,
        "kind": "heyi-legacy-adoption-plan",
        "project": module.PROJECT,
        "created_at": "2026-06-01T00:00:00Z",
        "git_sha": "a" * 40,
        "data_root": str(module.DATA_ROOT),
        "runtime_env": {},
        "legacy_compose": {},
        "host_isolation_guard": {},
        "target_manifest": release_authorization["target_manifest"],
        "release_authorization": release_authorization,
        "release_authorization_sha256": module._release_authorization_sha256(release_authorization),
        "inventory_sha256": module._sha256_bytes(module._canonical_json(inventory)),
        "topology_sha256": "b" * 64,
        "inventory": inventory,
        "safety": {
            "protected_other_port": 10050,
            "delete_containers": True,
            "delete_project_networks": True,
            "delete_named_volumes": False,
            "delete_bind_data": False,
            "global_prune": False,
            "restart_docker_daemon": False,
        },
    }
    active_plan = {"document": plan}
    monkeypatch.setattr(module, "_read_json_file", lambda path: active_plan["document"])
    monkeypatch.setattr(
        module,
        "_utc_now",
        lambda: module.datetime(2026, 7, 15, tzinfo=module.UTC),
    )
    active_plan["document"] = {**plan, "schema_version": 3}
    with pytest.raises(module.AdoptionError, match="identity differs"):
        module._load_plan_identity(tmp_path / "plan.json", enforce_freshness=False)
    active_plan["document"] = plan
    with pytest.raises(module.AdoptionError, match="stale or future-dated"):
        module._load_plan_identity(tmp_path / "plan.json")
    loaded, digest = module._load_plan_identity(
        tmp_path / "plan.json",
        enforce_freshness=False,
    )
    assert loaded == plan
    assert digest == module._plan_digest(plan)


def test_reactivation_fresh_retry_accepts_exact_started_prefix_and_finishes_proxy_last(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    base = _inventory(module).containers[0]
    postgres = replace(base, service="postgres", container_id="2" * 64)
    api = replace(base, service="api", container_id="3" * 64)
    proxy = replace(base, service="proxy", container_id="4" * 64)
    expected = module.LegacyInventory((proxy, api, postgres), (), ())
    plan_digest = "d" * 64
    plan = {"runtime_env": {"path": str(tmp_path / "runtime.env")}}
    receipt = {
        "release_state_binding": {"state": "same"},
        "source_schema_head": "20260714_0020",
        "restorable_topology_sha256": "restorable",
    }
    arguments = argparse.Namespace(
        binding_key=tmp_path / "binding.key",
        plan=tmp_path / "plan.json",
        retirement_receipt=tmp_path / "receipt.json",
        retirement_signature=tmp_path / "receipt.sig",
        target_abort_receipt=tmp_path / "target-abort-receipt.json",
        target_abort_signature=tmp_path / "target-abort-receipt.sig",
        adoption_transaction="1" * 32,
        evidence_public_key=tmp_path / "public.pem",
        host_isolation_baseline=tmp_path / "host.json",
        host_isolation_hmac_key=tmp_path / "host.key",
        execute=True,
        confirm_restore_boundary=module.REACTIVATION_BOUNDARY,
    )
    monkeypatch.setattr(module, "_read_binding_key", lambda path: b"k" * 32)
    plan_freshness: list[bool] = []
    receipt_freshness: list[bool] = []

    def validate_plan(*args: object, **kwargs: object) -> object:
        del args
        plan_freshness.append(bool(kwargs["enforce_freshness"]))
        return plan, plan_digest, {}, (tmp_path / "compose.yml",), ()

    def verify_receipt(*args: object, **kwargs: object) -> object:
        del args
        receipt_freshness.append(bool(kwargs["enforce_freshness"]))
        return receipt

    monkeypatch.setattr(module, "_validate_plan", validate_plan)
    monkeypatch.setattr(module, "_planned_inventory", lambda document: expected)
    monkeypatch.setattr(module, "_verify_retirement_receipt", verify_receipt)
    monkeypatch.setattr(module, "_verify_target_abort_authorization", lambda *args, **kwargs: {})
    monkeypatch.setattr(module, "_verify_data_bindings", lambda inventory: None)
    monkeypatch.setattr(module, "_release_state_binding", lambda: {"state": "same"})
    monkeypatch.setattr(module, "_verify_host_isolation", lambda *args: object())
    monkeypatch.setattr(module, "_confirm", lambda *args: True)
    monkeypatch.setattr(module, "_verify_postgres_17_and_schema", lambda *args: None)
    monkeypatch.setattr(module, "_verify_named_volumes", lambda *args: None)
    monkeypatch.setattr(module, "_verify_edge_ports_available", lambda *args: None)
    monkeypatch.setattr(module, "_verify_legacy_edge_readiness", lambda *args: None)
    monkeypatch.setattr(module, "_wait_reactivated_service_ready", lambda *args, **kwargs: None)
    monkeypatch.setattr(module, "restorable_topology_sha256", lambda inventory: "restorable")
    expected_by_service = {item.service: item for item in expected.containers}
    recreated_ids = {"postgres": "5" * 64, "api": "6" * 64, "proxy": "7" * 64}
    current: dict[str, object] = {}
    killed = False
    calls: list[str] = []

    def current_inventory() -> object:
        return module.LegacyInventory(tuple(current.values()), (), ())

    def assert_surface(runner: object, signed: object, guard: object) -> object:
        del runner, guard
        partial = current_inventory()
        module._validate_reactivation_subset(partial, signed)
        return partial

    def run_service(runner: object, *, service: str, **kwargs: object) -> None:
        nonlocal killed
        del runner, kwargs
        calls.append(service)
        current[service] = replace(
            expected_by_service[service], container_id=recreated_ids[service]
        )
        if service == "api" and not killed:
            killed = True
            raise SystemExit(137)

    monkeypatch.setattr(module, "_assert_reactivation_surface", assert_surface)
    monkeypatch.setattr(module, "_run_exact_compose_service", run_service)
    monkeypatch.setattr(
        module,
        "_collect_exact_primary_service",
        lambda runner, service: current[service],
    )
    monkeypatch.setattr(module, "collect_inventory", lambda runner: current_inventory())
    with pytest.raises(SystemExit):
        module._reactivate(arguments, object())
    assert set(current) == {"postgres", "api"}
    module._reactivate(arguments, object())
    assert set(current) == {"postgres", "api", "proxy"}
    assert calls[-1] == "proxy"
    assert plan_freshness == [False, False]
    assert receipt_freshness == [False, False]


def test_reactivate_execute_cannot_parse_without_target_abort_capability() -> None:
    module = _module()
    with pytest.raises(module.AdoptionError, match="required"):
        module._parser().parse_args(
            [
                "reactivate",
                "--plan",
                "/srv/plan.json",
                "--binding-key",
                "/srv/key",
                "--retirement-receipt",
                "/srv/receipt.json",
                "--retirement-signature",
                "/srv/receipt.sig",
                "--evidence-public-key",
                "/srv/public.pem",
                "--host-isolation-baseline",
                "/srv/host.json",
                "--host-isolation-hmac-key",
                "/srv/host.key",
                "--execute",
            ]
        )


def test_target_abort_capability_is_fixed_signed_and_migration_false(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    state_root = tmp_path / "state"
    transaction = "1" * 32
    transaction_root = state_root / "legacy-adoption" / "transactions" / transaction
    abort_directory = transaction_root / "target-pre-migration-abort"
    abort_directory.mkdir(parents=True)
    journal = transaction_root / "journal.json"
    retirement = tmp_path / "retirement.json"
    host_report = abort_directory / "host-isolation-after-abort.json"
    for path, payload in (
        (journal, b"journal"),
        (retirement, b"retirement"),
        (host_report, b"host-report"),
    ):
        path.write_bytes(payload)
    reconcile = {
        unit: {
            "load_state": "not-found",
            "active_state": "inactive",
            "unit_file_state": "not-found",
        }
        for unit in module.RECONCILE_UNITS
    }
    document = {
        "schema_version": 1,
        "kind": "heyi-target-pre-migration-abort-receipt",
        "status": "aborted_pre_migration",
        "project": module.PROJECT,
        "issued_at": "2026-07-15T00:00:00Z",
        "adoption_transaction_id": transaction,
        "journal_sha256": module._sha256_file(journal),
        "plan_sha256": "a" * 64,
        "retirement_receipt_sha256": module._sha256_file(retirement),
        "target_contract_sha256": "b" * 64,
        "target_manifest_sha256": "c" * 64,
        "target_schema_head": "20260714_0020",
        "legacy_source_schema_head": "20260714_0020",
        "last_install_phase": "preflight_passed",
        "migration_command_invoked": False,
        "active_release_present": False,
        "installed_receipt_present": False,
        "removed_preflight_container_ids": ["2" * 64],
        "removed_owner_marker_volume": True,
        "archived_install_state": None,
        "archived_cutover_intent": None,
        "reconcile_baseline": reconcile,
        "reconcile_result": reconcile,
        "target_resource_counts_after": {
            "containers": 0,
            "networks": 0,
            "project_volumes": 0,
            "owner_marker": 0,
        },
        "host_isolation_verification": {
            "path": str(host_report),
            "sha256": module._sha256_file(host_report),
            "status": "PASS",
        },
        "preserved_bind_root": str(module.DATA_ROOT),
        "bind_data_deleted": False,
        "named_volumes_deleted": False,
        "global_actions": [],
        "restore_boundary": module.REACTIVATION_BOUNDARY,
    }
    receipt = abort_directory / "receipt.json"
    signature = abort_directory / "receipt.sig"
    receipt.write_text(json.dumps(document), encoding="utf-8")
    signature.write_bytes(b"signature")
    monkeypatch.setattr(module, "STATE_ROOT", state_root)
    monkeypatch.setattr(module, "protected_file", lambda path, **kwargs: path)
    monkeypatch.setattr(module, "protected_directory", lambda path, **kwargs: path)
    monkeypatch.setattr(module, "_verify_signature", lambda *args, **kwargs: None)
    verified = module._verify_target_abort_authorization(
        object(),
        receipt_path=receipt,
        signature_path=signature,
        public_key=tmp_path / "public.pem",
        adoption_transaction=transaction,
        plan_digest="a" * 64,
        retirement_receipt_path=retirement,
        retirement_receipt={"source_schema_head": "20260714_0020"},
    )
    assert verified["migration_command_invoked"] is False
    document["migration_command_invoked"] = True
    receipt.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(module.AdoptionError, match="identity differs"):
        module._verify_target_abort_authorization(
            object(),
            receipt_path=receipt,
            signature_path=signature,
            public_key=tmp_path / "public.pem",
            adoption_transaction=transaction,
            plan_digest="a" * 64,
            retirement_receipt_path=retirement,
            retirement_receipt={"source_schema_head": "20260714_0020"},
        )


def test_reactivated_defined_healthcheck_must_not_be_unhealthy() -> None:
    module = _module()
    document = _container_document(module, service="api")
    document["Config"]["Healthcheck"] = {"Test": ["CMD", "healthcheck"]}
    document["State"]["Health"] = {"Status": "unhealthy"}
    current = module._container_record(document)

    class FakeRunner:
        def docker_json(self, argv: tuple[str, ...]) -> object:
            assert argv == ("inspect", current.container_id)
            return [document]

    with pytest.raises(module.AdoptionError, match="is unhealthy"):
        module._wait_reactivated_service_ready(FakeRunner(), current=current, expected=current)


def test_listener_named_docker_proxy_outside_trusted_installation_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    listener = {
        "family": "ipv4",
        "local_address": "0.0.0.0",
        "local_port": 19443,
        "state": "LISTEN",
        "socket_inode": 123,
    }

    class FakeGuard:
        @staticmethod
        def _process_identity(pid: int) -> dict[str, object]:
            return {
                "pid": pid,
                "executable": {
                    "resolved_path": "/tmp/docker-proxy",
                    "sha256": "a" * 64,
                },
            }

    monkeypatch.setattr(module, "_listener_owner_pids", lambda guard, inode: (456,))
    with pytest.raises(module.AdoptionError, match="trusted installation"):
        module._verify_listener_owned_by_proxy(
            FakeGuard,
            listener,
            {("ipv4", "0.0.0.0"): frozenset({("172.30.0.8", 443)})},
        )


def test_legacy_edge_readiness_uses_internal_ca_and_business_endpoints(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    base = _inventory(module).containers[0]
    proxy = replace(
        base,
        service="proxy",
        mounts=((str(tmp_path / "caddy-data"), "/data", True, "bind"),),
    )
    inventory = module.LegacyInventory((proxy,), (), ())
    calls: list[tuple[tuple[str, ...], bytes]] = []

    class FakeRunner:
        def run(
            self,
            argv: tuple[str, ...],
            *,
            timeout: int = 120,
            input_bytes: bytes | None = None,
        ) -> bytes:
            del timeout
            assert input_bytes is not None
            calls.append((argv, input_bytes))
            return b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

    monkeypatch.setattr(module, "protected_file", lambda path, **kwargs: path)
    module._verify_legacy_edge_readiness(
        FakeRunner(),
        inventory,
        {"KB_PUBLIC_HOST": "10.0.14.55", "KB_BIND_ADDRESS": "0.0.0.0"},
    )
    assert len(calls) == 3
    assert all("-CAfile" in argv and "-verify_ip" in argv for argv, _ in calls)
    requests = [payload.decode("ascii") for _, payload in calls]
    assert any("GET /health/ready HTTP/1.1" in value for value in requests)
    assert any("GET / HTTP/1.1" in value for value in requests)
    assert any("GET /minio/health/ready HTTP/1.1" in value for value in requests)


def test_listening_proxy_without_successful_tls_business_probe_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    proxy = replace(
        _inventory(module).containers[0],
        service="proxy",
        mounts=((str(tmp_path / "caddy-data"), "/data", True, "bind"),),
    )
    inventory = module.LegacyInventory((proxy,), (), ())

    class FakeRunner:
        def run(self, *args: object, **kwargs: object) -> bytes:
            return b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n"

    monkeypatch.setattr(module, "protected_file", lambda path, **kwargs: path)
    monkeypatch.setattr(module, "REACTIVATION_EDGE_TIMEOUT_SECONDS", 0)
    with pytest.raises(module.AdoptionError, match="business readiness timed out"):
        module._verify_legacy_edge_readiness(
            FakeRunner(),
            inventory,
            {"KB_PUBLIC_HOST": "kb.internal", "KB_BIND_ADDRESS": "127.0.0.1"},
        )


def test_legacy_edge_readiness_retries_a_transient_503_as_one_probe_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    proxy = replace(
        _inventory(module).containers[0],
        service="proxy",
        mounts=((str(tmp_path / "caddy-data"), "/data", True, "bind"),),
    )
    inventory = module.LegacyInventory((proxy,), (), ())
    calls = 0
    sleeps: list[float] = []

    class FakeRunner:
        def run(self, *args: object, **kwargs: object) -> bytes:
            nonlocal calls
            calls += 1
            status = 503 if calls == 1 else 200
            return f"HTTP/1.1 {status} status\r\nContent-Length: 0\r\n\r\n".encode("ascii")

    monkeypatch.setattr(module, "protected_file", lambda path, **kwargs: path)
    monkeypatch.setattr(module.time, "sleep", sleeps.append)
    module._verify_legacy_edge_readiness(
        FakeRunner(),
        inventory,
        {"KB_PUBLIC_HOST": "kb.internal", "KB_BIND_ADDRESS": "127.0.0.1"},
    )
    assert calls == 4
    assert sleeps == [module.REACTIVATION_EDGE_POLL_SECONDS]
