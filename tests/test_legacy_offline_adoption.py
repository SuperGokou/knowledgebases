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
        (replace(inventory.containers[0], config_files=(str(compose),)),), (), ()
    )
    document = module.build_plan(
        inventory=inventory,
        runtime_env=runtime,
        runtime_binding="e" * 64,
        compose_files=(compose,),
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
    document = module.build_plan(
        inventory=inventory,
        runtime_env=Path("/srv/runtime.env"),
        runtime_binding="e" * 64,
        compose_files=(first, second),
        legacy_env_files=(),
        legacy_env_bindings={},
        target_manifest=Path("/srv/release.env.images"),
        git_sha="a" * 40,
    )
    assert document["schema_version"] == 2
    assert document["legacy_compose"]["service_bindings"] == {
        "api": [str(first)],
        "web": [str(second)],
    }
    assert [entry["path"] for entry in document["legacy_compose"]["files"]] == [
        str(first),
        str(second),
    ]


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
            "--target-manifest",
            "/srv/release.env.images",
            "--git-sha",
            "a" * 40,
        ]
    )
    assert arguments.compose_file == [Path("/srv/one.yml"), Path("/srv/two.yml")]


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
    monkeypatch.setattr(module, "_read_binding_key", lambda path: b"k" * 32)
    monkeypatch.setattr(
        module,
        "_locate_upgrade_evidence_run",
        lambda path: (path, run),
    )
    monkeypatch.setattr(module, "_sha256_file", lambda path: "e" * 64)
    monkeypatch.setattr(
        module,
        "_load_plan_identity",
        lambda path, enforce_freshness: (plan, plan_digest),
    )
    monkeypatch.setattr(
        module,
        "_validate_plan",
        lambda *args: (_ for _ in ()).throw(
            AssertionError("durable intent must not revalidate mutable plan material")
        ),
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
    monkeypatch.setattr(module, "_read_binding_key", lambda path: b"k" * 32)
    monkeypatch.setattr(
        module,
        "_locate_upgrade_evidence_run",
        lambda path: (path, run),
    )
    monkeypatch.setattr(module, "_sha256_file", lambda path: "e" * 64)
    monkeypatch.setattr(
        module,
        "_load_plan_identity",
        lambda path, enforce_freshness: (plan, "d" * 64),
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
        execute=True,
        confirm_preserve_data="PRESERVE_BIND_DATA_AND_NAMED_VOLUMES",
    )
    monkeypatch.setattr(module, "_read_binding_key", lambda path: b"k" * 32)
    monkeypatch.setattr(
        module,
        "_load_plan_identity",
        lambda path, enforce_freshness: (plan, plan_digest),
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
    plan = {
        "schema_version": 2,
        "kind": "heyi-legacy-adoption-plan",
        "project": module.PROJECT,
        "created_at": "2026-06-01T00:00:00Z",
        "git_sha": "a" * 40,
        "data_root": str(module.DATA_ROOT),
        "runtime_env": {},
        "legacy_compose": {},
        "host_isolation_guard": {},
        "target_manifest": {},
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
    monkeypatch.setattr(module, "_read_json_file", lambda path: plan)
    monkeypatch.setattr(
        module,
        "_utc_now",
        lambda: module.datetime(2026, 7, 15, tzinfo=module.UTC),
    )
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
