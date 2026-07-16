from __future__ import annotations

import json
import subprocess
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

import scripts.generate_document_acceptance_fixtures as fixture_generator
from scripts.generate_document_acceptance_fixtures import (
    BUILTIN_EXTENSIONS,
    LEGACY_EXTENSIONS,
    REQUIRED_EXTENSIONS,
    FixtureBlocked,
    _atomic_write,
    _require_legacy_toolchain,
    _run_libreoffice,
    build_plan,
    generate_builtin_fixtures,
    generate_legacy_fixtures,
    main,
    verify_fixture_set,
)

OLE_SIGNATURE = bytes.fromhex("D0CF11E0A1B11AE1")


def _legacy_payload(token: str, *, encoding: str = "ascii") -> bytes:
    payload = bytearray(1024)
    payload[:8] = OLE_SIGNATURE
    payload[24:26] = bytes.fromhex("FEFF")
    payload[30:32] = (9).to_bytes(2, "little")
    payload[32:34] = (6).to_bytes(2, "little")
    encoded = token.encode(encoding)
    payload[512 : 512 + len(encoded)] = encoded
    return bytes(payload)


def _create_complete_fixture_set(root: Path) -> None:
    generate_builtin_fixtures(root)
    for item in build_plan(root):
        if item.extension in LEGACY_EXTENSIONS:
            (root / item.relative_path).write_bytes(_legacy_payload(item.token))


def test_plan_declares_all_nine_real_formats_and_unique_grounding_expectations(
    tmp_path: Path,
) -> None:
    plan = build_plan(tmp_path)

    assert [item.extension for item in plan] == list(REQUIRED_EXTENSIONS)
    assert {item.extension for item in plan if item.generator == "stdlib"} == set(
        BUILTIN_EXTENSIONS
    )
    assert {item.extension for item in plan if item.generator == "libreoffice"} == set(
        LEGACY_EXTENSIONS
    )
    assert len({item.token for item in plan}) == 9
    assert {item.extension: item.expected_source_locations for item in plan} == {
        ".txt": ("document",),
        ".csv": ("row:3",),
        ".doc": ("paragraph:2",),
        ".docx": ("paragraph:2",),
        ".xls": ("worksheet:Acceptance!B2",),
        ".xlsx": ("worksheet:Acceptance!B2",),
        ".pdf": ("page:1",),
        ".ppt": ("slide:1",),
        ".pptx": ("slide:1",),
    }
    assert all(item.relative_path.startswith("golden/") for item in plan)


def test_builtin_generation_is_deterministic_original_and_never_writes_outside_root(
    tmp_path: Path,
) -> None:
    root = tmp_path / "acceptance-fixtures"
    first = generate_builtin_fixtures(root)
    first_bytes = {path.name: path.read_bytes() for path in first}
    second = generate_builtin_fixtures(root)

    assert {path.suffix for path in first} == set(BUILTIN_EXTENSIONS)
    assert {path.name: path.read_bytes() for path in second} == first_bytes
    assert all(path.resolve().is_relative_to(root.resolve()) for path in first)
    assert all(b"placeholder" not in payload.lower() for payload in first_bytes.values())
    assert all(
        next(item.token.encode() for item in build_plan(root) if item.extension == path.suffix)
        in path.read_bytes()
        for path in first
    )
    for path in first:
        if path.suffix not in {".docx", ".xlsx", ".pptx"}:
            continue
        with zipfile.ZipFile(path) as archive:
            assert all(info.create_system == 3 for info in archive.infolist())
            assert all(info.date_time == (2026, 1, 1, 0, 0, 0) for info in archive.infolist())


def test_generation_requires_an_absolute_non_symlink_root(tmp_path: Path) -> None:
    with pytest.raises(FixtureBlocked, match="absolute path"):
        generate_builtin_fixtures(Path("relative-fixtures"))

    real_root = tmp_path / "real"
    real_root.mkdir()
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(real_root, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable for this account")
    with pytest.raises(FixtureBlocked, match="non-symlink directory"):
        generate_builtin_fixtures(alias)

    nested_alias = alias / "not-created-yet"
    with pytest.raises(FixtureBlocked, match="symlink path component"):
        generate_builtin_fixtures(nested_alias)
    assert not (real_root / "not-created-yet").exists()


def test_atomic_write_rejects_parent_traversal(tmp_path: Path) -> None:
    root = tmp_path / "fixtures"
    root.mkdir()

    with pytest.raises(FixtureBlocked, match="escapes"):
        _atomic_write(root.resolve(), "../escaped.txt", b"forbidden")

    assert not (tmp_path / "escaped.txt").exists()


def test_verify_blocks_when_legacy_office_outputs_are_missing(tmp_path: Path) -> None:
    root = tmp_path / "acceptance-fixtures"
    generate_builtin_fixtures(root)

    with pytest.raises(FixtureBlocked, match="legacy fixtures are missing"):
        verify_fixture_set(root)


def test_verify_rejects_tampered_hash_and_placeholder_manifest(tmp_path: Path) -> None:
    root = tmp_path / "acceptance-fixtures"
    _create_complete_fixture_set(root)

    manifest_path = verify_fixture_set(root, write_manifest=True)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["schema_version"] == 1
    assert [item["extension"] for item in manifest["fixtures"]] == list(REQUIRED_EXTENSIONS)
    assert all(len(item["sha256"]) == 64 for item in manifest["fixtures"])

    target = root / manifest["fixtures"][0]["relative_path"]
    target.write_bytes(target.read_bytes() + b"tampered")
    with pytest.raises(FixtureBlocked, match="content token is missing|manifest hash mismatch"):
        verify_fixture_set(root, manifest_path=manifest_path)

    target.write_bytes(b"placeholder")
    with pytest.raises(FixtureBlocked, match="placeholder|content token is missing"):
        verify_fixture_set(root, manifest_path=manifest_path)


def test_verify_rejects_missing_legacy_token_and_manifest_location_drift(
    tmp_path: Path,
) -> None:
    root = tmp_path / "acceptance-fixtures"
    _create_complete_fixture_set(root)
    manifest_path = verify_fixture_set(root, write_manifest=True)

    legacy = next(item for item in build_plan(root) if item.extension == ".doc")
    (root / legacy.relative_path).write_bytes(_legacy_payload("no-token"))
    with pytest.raises(FixtureBlocked, match="content token is missing: .doc"):
        verify_fixture_set(root, manifest_path=manifest_path)

    (root / legacy.relative_path).write_bytes(_legacy_payload(legacy.token))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["fixtures"][0]["expected_source_locations"] = ["outside:99"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(FixtureBlocked, match="hash mismatch or contract drift"):
        verify_fixture_set(root, manifest_path=manifest_path)


def test_verify_rejects_manifest_outside_root_and_manifest_symlink(tmp_path: Path) -> None:
    root = tmp_path / "acceptance-fixtures"
    _create_complete_fixture_set(root)

    with pytest.raises(FixtureBlocked, match="beneath the fixture root"):
        verify_fixture_set(root, manifest_path=tmp_path / "outside.json", write_manifest=True)

    real_manifest = root / "real-manifest.json"
    real_manifest.write_text("{}", encoding="utf-8")
    alias = root / "manifest.json"
    try:
        alias.symlink_to(real_manifest)
    except OSError:
        pytest.skip("file symlinks are unavailable for this account")
    with pytest.raises(FixtureBlocked, match="regular non-symlink file"):
        verify_fixture_set(root, manifest_path=alias)


def test_verify_rejects_extension_spoofing_and_utf16_placeholder(tmp_path: Path) -> None:
    root = tmp_path / "acceptance-fixtures"
    _create_complete_fixture_set(root)
    verify_fixture_set(root, write_manifest=True)

    pdf = next(item for item in build_plan(root) if item.extension == ".pdf")
    (root / pdf.relative_path).write_bytes(pdf.token.encode("ascii"))
    with pytest.raises(FixtureBlocked, match="invalid .pdf fixture format"):
        verify_fixture_set(root)

    _create_complete_fixture_set(root)
    legacy = next(item for item in build_plan(root) if item.extension == ".xls")
    payload = bytearray(_legacy_payload(legacy.token, encoding="utf-16le"))
    marker = "placeholder".encode("utf-16le")
    payload[800 : 800 + len(marker)] = marker
    (root / legacy.relative_path).write_bytes(payload)
    with pytest.raises(FixtureBlocked, match="placeholder content is forbidden: .xls"):
        verify_fixture_set(root)


def test_missing_or_untrusted_linux_toolchain_is_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        fixture_generator,
        "_trusted_executable",
        lambda path: path != fixture_generator.BWRAP,
    )

    with pytest.raises(FixtureBlocked, match=r"trusted Linux.*?/usr/bin/bwrap"):
        _require_legacy_toolchain()


def test_generate_cli_preflights_toolchain_before_writing_partial_set(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "acceptance-fixtures"

    def block_toolchain() -> None:
        raise FixtureBlocked("trusted Linux legacy fixture toolchain is unavailable")

    monkeypatch.setattr(fixture_generator, "_require_legacy_toolchain", block_toolchain)

    assert main(["generate", "--root", str(root)]) == 2
    assert not root.exists()


def test_libreoffice_conversion_uses_fixed_sandbox_and_resource_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.docx"
    output = tmp_path / "output"
    profile = tmp_path / "profile"
    source.write_bytes(b"source")
    output.mkdir()
    profile.mkdir()
    invocation: dict[str, object] = {}

    def fake_run(command: list[str], **kwargs: object) -> SimpleNamespace:
        invocation["command"] = command
        invocation.update(kwargs)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    _run_libreoffice(source, output, profile, "doc")

    command = invocation["command"]
    assert isinstance(command, list)
    assert command[0] == "/usr/bin/bwrap"
    assert command.count("--unshare-all") == 1
    assert command.count("--clearenv") == 1
    assert command[command.index("--") + 1] == "/usr/bin/prlimit"
    assert "--cpu=60:60" in command
    assert "--as=1073741824:1073741824" in command
    assert "--fsize=67108864:67108864" in command
    assert "--nofile=128:128" in command
    assert "/usr/bin/libreoffice" in command
    assert command[-5:] == ["--convert-to", "doc", "--outdir", str(output), str(source)]
    assert invocation["shell"] is False
    assert invocation["stdin"] is subprocess.DEVNULL
    assert invocation["timeout"] == 75


def test_libreoffice_launch_failure_is_reported_as_blocked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.docx"
    source.write_bytes(b"source")
    output = tmp_path / "output"
    profile = tmp_path / "profile"
    output.mkdir()
    profile.mkdir()

    def fail_run(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise subprocess.TimeoutExpired("libreoffice", 75)

    monkeypatch.setattr(subprocess, "run", fail_run)
    with pytest.raises(FixtureBlocked, match="conversion failed"):
        _run_libreoffice(source, output, profile, "doc")


def test_three_legacy_formats_are_generated_and_verified_without_placeholders(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "acceptance-fixtures"
    generate_builtin_fixtures(root)
    monkeypatch.setattr(fixture_generator, "_require_legacy_toolchain", lambda: None)
    tokens = {item.extension.removeprefix("."): item.token for item in build_plan(root)}

    def fake_convert(source: Path, output: Path, profile: Path, target: str) -> None:
        del source, profile
        payload = _legacy_payload(tokens[target], encoding="utf-16le")
        (output / f"source.{target}").write_bytes(payload)

    monkeypatch.setattr(fixture_generator, "_run_libreoffice", fake_convert)
    generated = generate_legacy_fixtures(root)

    assert {path.suffix for path in generated} == set(LEGACY_EXTENSIONS)
    manifest_path = verify_fixture_set(root, write_manifest=True)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert len(manifest["fixtures"]) == 9
    assert all(item["token"] for item in manifest["fixtures"])
    assert all(item["expected_source_locations"] for item in manifest["fixtures"])
