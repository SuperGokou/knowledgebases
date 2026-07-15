from __future__ import annotations

import argparse
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


def _module() -> ModuleType:
    name = "legacy_offline_adoption_under_test"
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _container_document(
    module: ModuleType,
    *,
    service: str = "api",
    container_id: str = "1" * 64,
    image: str = "a" * 64,
    host_port: str | None = None,
    mount_source: str = "/var/lib/docker/volumes/example/_data",
    mount_type: str = "volume",
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
                "com.docker.compose.config-hash": "b" * 64,
                "com.docker.compose.project.config_files": "/srv/legacy/compose.yml",
                "io.heyi.knowledgebases.owner": module.OWNER,
                "io.heyi.knowledgebases.stack": module.STACK,
            },
        },
        "State": {"Running": True},
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
        config_files="/srv/legacy/compose.yml",
        running=True,
        restart_count=0,
        mounts=(("volume", "/data", True, "volume"),),
        networks=("heyi-kb-offline_internal",),
        published_ports=(),
    )
    return module.LegacyInventory((container,), (), ())


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
    inventory = module.LegacyInventory(
        (replace(inventory.containers[0], config_files=str(compose)),), (), ()
    )
    document = module.build_plan(
        inventory=inventory,
        runtime_env=runtime,
        runtime_binding="e" * 64,
        compose_file=compose,
        legacy_env_files=(legacy_env,),
        legacy_env_bindings={str(legacy_env): "f" * 64},
        target_manifest=target,
        git_sha="a" * 40,
    )
    serialized = json.dumps(document)
    assert document["runtime_env"]["opaque_hmac_sha256"] == "e" * 64
    assert document["legacy_compose"]["env_files"][0]["opaque_hmac_sha256"] == "f" * 64
    assert "bound-at-execution" not in serialized
    assert "POSTGRES_PASSWORD" not in serialized


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


def test_ca_escrow_is_ciphertext_with_only_an_opaque_plaintext_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    ca_root = tmp_path / "ca"
    ca_root.mkdir()
    secret = b"low-entropy-ca-private-key"
    (ca_root / "root.key").write_bytes(secret)
    certificate = tmp_path / "recipient.pem"
    certificate.write_text("offline recipient certificate", encoding="ascii")
    output = tmp_path / "escrow.p7m"
    monkeypatch.setattr(module, "protected_directory", lambda path, **kwargs: path)
    monkeypatch.setattr(module, "protected_file", lambda path, **kwargs: path)
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
        ) -> bytes:
            del timeout
            if "-encrypt" in argv:
                assert "-aes256" in argv
                assert input_bytes is not None and secret in input_bytes
                assert stdout_file is not None
                stdout_file.write(b"CMS-CIPHERTEXT")
            else:
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


def test_ca_restore_attestation_fails_closed_on_cos_or_server_private_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    now = module._utc_now()
    challenge_path = Path("/protected/challenge.json")
    attestation_path = Path("/protected/attestation.json")
    signature_path = Path("/protected/attestation.sig")
    public_key = Path("/protected/offline-public.pem")
    challenge = {
        "issued_at": (now - module.timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        "expires_at": (now + module.timedelta(days=6)).isoformat().replace("+00:00", "Z"),
        "encrypted_archive_sha256": "b" * 64,
        "plaintext_opaque_hmac_sha256": "c" * 64,
        "file_count": 2,
        "recipient_certificate_sha256": "d" * 64,
    }
    attestation = {
        "schema_version": 1,
        "kind": "heyi-caddy-ca-restore-drill",
        "project": module.PROJECT,
        "challenge_sha256": "a" * 64,
        "encrypted_archive_sha256": "b" * 64,
        "plaintext_opaque_hmac_sha256": "c" * 64,
        "file_count": 2,
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


def test_retirement_failure_path_recreates_the_old_stack() -> None:
    module = _module()
    source = inspect.getsource(module._retire)
    assert "finally:" in source
    assert "if not committed:" in source
    assert "_resume_or_recreate_legacy(" in source
    assert '"rm", record.container_id' in inspect.getsource(module._retire_exact_resources)
