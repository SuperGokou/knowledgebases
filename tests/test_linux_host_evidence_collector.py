from __future__ import annotations

import ast
import base64
import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import linux_host_evidence_collector as collector
from scripts.functional_acceptance import _signature_payload
from scripts.host_preflight import HostFacts


def _target() -> dict[str, str]:
    return {
        "git_head": "a" * 40,
        "content_fingerprint": "b" * 64,
        "run_id": "linux-host-run-001",
    }


def _challenge(target: dict[str, str], now: datetime) -> dict[str, object]:
    return {
        "schema_version": 1,
        "challenge_id": "challenge-linux-host-001",
        "evidence_id": collector.EVIDENCE_ID,
        "nonce": "n" * 40,
        "issued_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(minutes=10)).isoformat(),
        "status": "issued",
        "target": target,
    }


def _artifact_records() -> list[dict[str, object]]:
    return [
        {
            "id": artifact_id,
            "path": f"linux-host-artifacts/linux-host-run-001/{artifact_id}.json",
            "sha256": hashlib.sha256(artifact_id.encode()).hexdigest(),
            "bytes": len(artifact_id),
        }
        for artifact_id in (
            "host",
            "offline-images",
            "clamav",
            "readiness",
            "business-smoke",
            "caddy",
        )
    ]


def test_collector_contract_is_frozen_to_exact_twelve_checks() -> None:
    assert collector.COLLECTOR == {"id": "heyi-linux-host", "version": "1.0.0"}
    assert collector.KEY_ID == "linux-host-ed25519"
    assert collector.REQUIRED_CHECKS == (
        "linux_amd64",
        "cpu_8",
        "memory_16g",
        "filesystem_300g",
        "free_space_240g",
        "offline_images",
        "clamav_database",
        "health_readiness",
        "business_smoke",
        "caddy_ca_persistent_storage",
        "caddy_automatic_certificate_management",
        "caddy_renewal_health",
    )


def test_complete_evidence_is_signed_with_canonical_challenge_payload() -> None:
    now = datetime.now(UTC)
    target = _target()
    challenge = _challenge(target, now)
    private_key = Ed25519PrivateKey.generate()

    evidence = collector.build_complete_evidence(
        target,
        _artifact_records(),
        private_key,
        challenge,
        collected_at=now,
    )

    assert tuple(evidence["checks"]) == collector.REQUIRED_CHECKS
    assert evidence["target"] == target
    attestation = evidence["attestation"]
    assert isinstance(attestation, dict)
    private_key.public_key().verify(
        base64.b64decode(str(attestation["signature"]), validate=True),
        _signature_payload(
            evidence,
            key_id=collector.KEY_ID,
            challenge_id=str(challenge["challenge_id"]),
            challenge_nonce=str(challenge["nonce"]),
        ),
    )


def test_complete_evidence_rejects_mismatched_challenge_target() -> None:
    now = datetime.now(UTC)
    target = _target()
    challenge = _challenge({**target, "run_id": "different-run-001"}, now)

    with pytest.raises(collector.CollectorBlocked) as captured:
        collector.build_complete_evidence(
            target,
            _artifact_records(),
            Ed25519PrivateKey.generate(),
            challenge,
            collected_at=now,
        )

    assert captured.value.code == "evidence_challenge_target_mismatch"


def test_complete_evidence_rejects_unsafe_or_empty_artifact() -> None:
    now = datetime.now(UTC)
    target = _target()
    records = _artifact_records()
    records[0] = {**records[0], "path": "../.env", "bytes": 0}

    with pytest.raises(collector.CollectorBlocked) as captured:
        collector.build_complete_evidence(
            target,
            records,
            Ed25519PrivateKey.generate(),
            _challenge(target, now),
            collected_at=now,
        )

    assert captured.value.code == "evidence_artifact_invalid"


def test_signing_material_requires_pkcs8_ed25519_and_exact_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime.now(UTC)
    target = _target()
    key = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    challenge = _challenge(target, now)
    challenge_path = Path(f"/{challenge['challenge_id']}.json")

    monkeypatch.setattr(
        collector,
        "read_protected_file",
        lambda path, _repository, _maximum: (
            key if path.name == "key.pem" else json.dumps(challenge).encode()
        ),
    )
    loaded, parsed, raw = collector.load_signing_material(
        Path("/repository"),
        Path("/key.pem"),
        challenge_path,
        target,
        now=now,
    )

    assert isinstance(loaded, Ed25519PrivateKey)
    assert parsed == challenge
    assert hashlib.sha256(raw).hexdigest()


def test_challenge_claim_is_exclusive_and_directory_fsynced(tmp_path: Path) -> None:
    challenge = _challenge(_target(), datetime.now(UTC))
    challenge_path = tmp_path / f"{challenge['challenge_id']}.json"
    fsync_calls: list[Path] = []

    with patch.object(collector, "_fsync_directory", side_effect=fsync_calls.append):
        claim = collector.claim_challenge(challenge_path, challenge, b"challenge")
        with pytest.raises(collector.CollectorBlocked) as captured:
            collector.claim_challenge(challenge_path, challenge, b"challenge")

    assert claim.name.endswith(".collector-claimed")
    if os.name == "posix":
        assert claim.stat().st_mode & 0o777 in {0o400, 0o600}
    assert fsync_calls == [tmp_path]
    assert captured.value.code == "challenge_already_claimed"


@pytest.mark.parametrize(
    ("facts", "expected_code"),
    [
        (
            HostFacts(
                platform="Linux",
                architecture="x86_64",
                logical_cpus=8,
                memory_bytes=collector.MINIMUM_VISIBLE_MEMORY_BYTES,
                filesystem_total_bytes=collector.MINIMUM_FILESYSTEM_TOTAL_BYTES,
                filesystem_available_bytes=collector.MINIMUM_FILESYSTEM_AVAILABLE_BYTES,
                disk_path=Path("/srv"),
            ),
            None,
        ),
        (
            HostFacts(
                platform="Linux",
                architecture="x86_64",
                logical_cpus=7,
                memory_bytes=collector.MINIMUM_VISIBLE_MEMORY_BYTES,
                filesystem_total_bytes=collector.MINIMUM_FILESYSTEM_TOTAL_BYTES,
                filesystem_available_bytes=collector.MINIMUM_FILESYSTEM_AVAILABLE_BYTES,
                disk_path=Path("/srv"),
            ),
            "host_capacity_below_baseline",
        ),
    ],
)
def test_host_capacity_thresholds_are_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    facts: HostFacts,
    expected_code: str | None,
) -> None:
    monkeypatch.setattr(collector, "collect_host_facts", lambda _path: facts)
    if expected_code is None:
        assert collector._host_artifact(collector.PERSISTENT_ROOT)["checks"]["cpu_8"] is True
    else:
        with pytest.raises(collector.CollectorBlocked) as captured:
            collector._host_artifact(collector.PERSISTENT_ROOT)
        assert captured.value.code == expected_code


def test_host_probe_rejects_operator_selected_unrelated_disk() -> None:
    with pytest.raises(collector.CollectorBlocked) as captured:
        collector._host_artifact(Path("/unrelated-large-disk"))

    assert captured.value.code == "disk_path_must_be_persistent_root"


def test_active_data_mounts_are_fixed_to_persistent_root_and_same_filesystem(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    persistent = tmp_path / "srv/heyi-knowledgebases-offline"
    for name in ("postgres", "minio", "caddy-data"):
        (persistent / "data" / name).mkdir(parents=True)
    monkeypatch.setattr(collector, "PERSISTENT_ROOT", persistent)
    config = {
        "services": {
            "postgres": {
                "volumes": [
                    {
                        "target": "/var/lib/postgresql/data",
                        "source": str(persistent / "data/postgres"),
                    }
                ]
            },
            "minio": {"volumes": [{"target": "/data", "source": str(persistent / "data/minio")}]},
            "proxy": {
                "volumes": [{"target": "/data", "source": str(persistent / "data/caddy-data")}]
            },
        }
    }

    evidence = collector._validate_data_filesystem(config, persistent)
    assert evidence["filesystem_device"] == persistent.stat().st_dev

    config["services"]["minio"]["volumes"][0]["source"] = str(tmp_path / "other")
    with pytest.raises(collector.CollectorBlocked) as captured:
        collector._validate_data_filesystem(config, persistent)
    assert captured.value.code == "active_data_mount_unavailable"


def _caddy_probe_stubs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    records: list[dict[str, object]],
    now: datetime,
) -> None:
    data = tmp_path / "caddy-data"
    ca = data / "caddy/pki/authorities/local/root.crt"
    contract = tmp_path / "contract"
    expected_caddyfile = contract / "release/deploy/tencent/Caddyfile.offline"
    expected_caddyfile.parent.mkdir(parents=True)
    expected_caddyfile.write_text("tls internal\n", encoding="utf-8")
    actual_caddyfile = tmp_path / "Caddyfile"
    actual_caddyfile.write_text("tls internal\n", encoding="utf-8")
    actual_caddyfile.chmod(0o444)
    monkeypatch.setattr(
        collector,
        "_compose_origins",
        lambda _config: ("https://kb.internal:8443", "https://kb.internal:9443", ca),
    )
    monkeypatch.setattr(
        collector,
        "_container_inspect",
        lambda _service, _runner: {
            "_verified_id": "c" * 64,
            "Mounts": [
                {"Destination": "/data", "Type": "bind", "RW": True, "Source": str(data)},
                {
                    "Destination": "/config",
                    "Type": "bind",
                    "RW": True,
                    "Source": str(tmp_path / "caddy-config"),
                },
                {
                    "Destination": "/etc/caddy/Caddyfile",
                    "Type": "bind",
                    "RW": False,
                    "Source": str(actual_caddyfile),
                },
            ],
        },
    )
    monkeypatch.setattr(collector, "_read_public_ca", lambda _path: (b"public-ca", object()))
    monkeypatch.setattr(
        collector,
        "_runtime_caddy_config",
        lambda _identifier, _runner: {"issuer": {"module": "internal"}},
    )
    leaf = {
        "not_after": (now + timedelta(hours=4)).isoformat(),
        "not_before": (now - timedelta(minutes=2)).isoformat(),
        "leaf_sha256": "d" * 64,
    }
    monkeypatch.setattr(collector, "_tls_leaf", lambda *_args, **_kwargs: dict(leaf))
    monkeypatch.setattr(collector, "_caddy_logs", lambda _identifier, _runner: records)
    monkeypatch.setattr(
        collector,
        "_validate_container_binding",
        lambda *_args, **_kwargs: {"bound": True},
    )


def test_caddy_static_config_and_valid_leaf_do_not_fake_renewal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    now = datetime.now(UTC)
    _caddy_probe_stubs(
        monkeypatch,
        tmp_path,
        [
            {
                "level": "info",
                "logger": "http",
                "msg": "enabling automatic TLS certificate management",
                "domains": ["kb.internal"],
                "ts": now.timestamp(),
            }
        ],
        now,
    )

    with pytest.raises(collector.CollectorBlocked) as captured:
        collector._caddy_evidence(
            tmp_path / "contract",
            {"compose_config_sha256": "e" * 64},
            {"services": {"proxy": {"image": "unused"}}},
            {"proxy": "f" * 64},
            object(),  # type: ignore[arg-type]
            now=now,
        )

    assert captured.value.code == "caddy_verified_renewal_event_missing"


def test_caddy_requires_success_reload_cache_replace_and_current_leaf_binding(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    now = datetime.now(UTC)
    success = now - timedelta(minutes=3)
    expiration = int((now + timedelta(hours=4)).timestamp())
    records = [
        {
            "level": "info",
            "logger": "http",
            "msg": "enabling automatic TLS certificate management",
            "domains": ["kb.internal"],
            "ts": (success - timedelta(minutes=1)).timestamp(),
        },
        {
            "level": "info",
            "logger": "tls.renew",
            "msg": "certificate renewed successfully",
            "identifier": "kb.internal",
            "ts": success.timestamp(),
        },
        {
            "level": "info",
            "logger": "tls",
            "msg": "reloading managed certificate",
            "identifiers": ["kb.internal"],
            "ts": (success + timedelta(seconds=1)).timestamp(),
        },
        {
            "level": "info",
            "logger": "tls.cache",
            "msg": "replaced certificate in cache",
            "subjects": ["kb.internal"],
            "new_expiration": expiration,
            "ts": (success + timedelta(seconds=2)).timestamp(),
        },
    ]
    _caddy_probe_stubs(monkeypatch, tmp_path, records, now)

    evidence = collector._caddy_evidence(
        tmp_path / "contract",
        {"compose_config_sha256": "e" * 64},
        {"services": {"proxy": {"image": "unused"}}},
        {"proxy": "f" * 64},
        object(),  # type: ignore[arg-type]
        now=now,
    )

    assert evidence["renewal_success_at"] == success.isoformat()
    assert evidence["renewal_reload_event"] is True
    assert evidence["renewal_cache_replace_event"] is True


def test_command_runner_never_uses_a_shell_or_secret_environment() -> None:
    source = Path(collector.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    popen_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "Popen"
    ]
    assert len(popen_calls) == 1
    assert all(keyword.arg != "shell" for keyword in popen_calls[0].keywords)
    assert ".env" not in collector.BoundedCommandRunner().environment


def test_container_binding_rejects_substitute_image_or_compose_hash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    image = "127.0.0.1:5000/heyi/proxy@sha256:" + "1" * 64
    image_id = "sha256:" + "2" * 64
    image_document = [{"Id": image_id, "Config": {"Entrypoint": ["caddy"], "Cmd": ["run"]}}]

    class Runner:
        def run(self, *_args: object, **_kwargs: object) -> collector.CommandResult:
            return collector.CommandResult(json.dumps(image_document).encode(), b"")

    monkeypatch.setattr(collector, "_tool", lambda _name: "/usr/bin/docker")
    inspected = {
        "Image": image_id,
        "Config": {
            "Image": image,
            "Entrypoint": ["caddy"],
            "Cmd": ["run"],
            "Labels": {"com.docker.compose.config-hash": "3" * 64},
        },
    }
    service = {"image": image}

    bound = collector._validate_container_binding(
        inspected,
        "proxy",
        service,
        "3" * 64,
        Runner(),  # type: ignore[arg-type]
    )
    assert bound["image_id"] == image_id

    substituted = {**inspected, "Image": "sha256:" + "9" * 64}
    with pytest.raises(collector.CollectorBlocked) as captured:
        collector._validate_container_binding(
            substituted,
            "proxy",
            service,
            "3" * 64,
            Runner(),  # type: ignore[arg-type]
        )
    assert captured.value.code == "proxy_container_release_binding_invalid"


def test_blocked_diagnostic_contains_only_enumerated_reason(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    secret = "super-secret-password"
    monkeypatch.setattr(
        collector,
        "collect",
        lambda _arguments: (_ for _ in ()).throw(collector.CollectorBlocked("probe_failed")),
    )
    monkeypatch.setattr(collector, "_FCHMOD", lambda _descriptor, _mode: None)
    monkeypatch.setattr(collector, "_fsync_directory", lambda _path: None)

    result = collector.main(
        [
            "--repository",
            str(tmp_path),
            "--run-id",
            "linux-host-run-001",
            "--signing-key",
            str(tmp_path / secret),
            "--challenge",
            str(tmp_path / f"{secret}.json"),
        ]
    )

    diagnostic = (tmp_path / "artifacts/acceptance/functional/linux-host.blocked.json").read_text(
        encoding="utf-8"
    )
    assert result == 2
    assert "probe_failed" in diagnostic
    assert secret not in diagnostic
    assert secret not in capsys.readouterr().out
