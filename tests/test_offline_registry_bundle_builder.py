from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).resolve().parents[1]
BUILDER = REPOSITORY / "scripts/build-offline-registry-bundle.ps1"
COMMON = REPOSITORY / "deploy/tencent/offline-operation-common.sh"
COMPOSE = REPOSITORY / "deploy/tencent/compose.offline.yml"
DOCUMENTATION = REPOSITORY / "docs/OFFLINE_REGISTRY_BUNDLE_BUILD.zh-CN.md"


def builder_text() -> str:
    return BUILDER.read_text(encoding="utf-8")


def canonical_release_assets() -> list[str]:
    match = re.search(
        r"(?ms)^offline_contract_files\(\) \{\r?\n\s*cat <<'EOF'\r?\n"
        r"(?P<body>.*?)\r?\nEOF\r?\n\}",
        COMMON.read_text(encoding="utf-8"),
    )
    assert match is not None
    entries = match.group("body").splitlines()
    assert entries[:3] == ["runtime.env", "release.env", "release.env.images"]
    return [entry for entry in entries if entry.startswith("release/")]


def unpacked_capacity_program() -> str:
    script = builder_text()
    function = re.search(
        r"(?ms)^function Get-DeduplicatedUnpackedCapacity\(.*?^\}\r?\n\r?\n"
        r"function Assert-ImagePlatform",
        script,
    )
    assert function is not None
    program = re.search(r"(?ms)\$program = @'\r?\n(?P<body>.*?)\r?\n'@", function.group())
    assert program is not None
    return program.group("body")


def test_builder_exposes_help_and_a_non_mutating_dry_run() -> None:
    script = builder_text()

    assert "[switch]$Help" in script
    assert "[switch]$DryRun" in script
    assert "DRY-RUN OK" in script
    assert "without pulling, building, pushing, signing or publishing artifacts" in script
    dry_run_block = script.split("if ($DryRun) {", maxsplit=1)[1].split(
        "Write-Output 'offline-bundle-builder: loading", maxsplit=1
    )[0]
    for mutating_operation in (
        "docker pull",
        "buildx",
        "docker push",
        "'image', 'save'",
        "Sign-And-Verify",
        "Directory]::Move($publish",
    ):
        assert mutating_operation not in dry_run_block
    assert "REGISTRY_UNPACKED_BYTES=MEASURED_DURING_FORMAL_BUILD" in dry_run_block
    assert "REGISTRY_UNPACKED_INODES=MEASURED_DURING_FORMAL_BUILD" in dry_run_block


def test_native_tool_wrappers_trust_exit_codes_not_powershell_stderr_records() -> None:
    script = builder_text()

    captured = script.split("function Invoke-Captured(", maxsplit=1)[1].split(
        "function Invoke-Quiet(", maxsplit=1
    )[0]
    quiet = script.split("function Invoke-Quiet(", maxsplit=1)[1].split(
        "function Read-DockerLabels(", maxsplit=1
    )[0]
    for wrapper in (captured, quiet):
        assert "$previousErrorActionPreference = $ErrorActionPreference" in wrapper
        assert "$ErrorActionPreference = 'Continue'" in wrapper
        assert "$exitCode = $LASTEXITCODE" in wrapper
        assert "$ErrorActionPreference = $previousErrorActionPreference" in wrapper
        assert "if ($exitCode -ne 0)" in wrapper
        assert "if ($LASTEXITCODE -ne 0)" not in wrapper


def test_builder_uses_canonical_release_sequence_and_safe_release_id_contracts() -> None:
    script = builder_text()

    assert "[string]$ReleaseSequence" in script
    sequence_match = re.search(r"\$ReleaseSequence -notmatch '([^']+)'", script)
    release_id_match = re.search(r"\$ReleaseId -notmatch '([^']+)'", script)
    assert sequence_match is not None
    assert release_id_match is not None
    sequence_pattern = sequence_match.group(1)
    release_id_pattern = release_id_match.group(1)

    for value in ("1", "202607160001", "999999999999999999"):
        assert re.fullmatch(sequence_pattern, value) is not None
    for value in ("0", "0001", "08", "1000000000000000000"):
        assert re.fullmatch(sequence_pattern, value) is None

    for value in ("a", "2026.07.16", "release_1-test", "a" * 128):
        assert re.fullmatch(release_id_pattern, value) is not None
    for value in (".", "..", ".release", "release.", "release/id", "a" * 129):
        assert re.fullmatch(release_id_pattern, value) is None


@pytest.mark.parametrize(
    ("sequence", "release_id", "expected_message"),
    [
        ("0001", "release-1", "integer with 1-18 digits and no leading zero"),
        ("08", "release-1", "integer with 1-18 digits and no leading zero"),
        ("1", ".", "release ID must be 1-128 characters"),
        ("1", "..", "release ID must be 1-128 characters"),
    ],
)
def test_builder_fails_before_tool_or_path_access_for_noncanonical_identity(
    tmp_path: Path,
    sequence: str,
    release_id: str,
    expected_message: str,
) -> None:
    powershell = shutil.which("powershell.exe") or shutil.which("pwsh")
    if powershell is None:
        pytest.skip("PowerShell is unavailable")
    completed = subprocess.run(
        [
            powershell,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(BUILDER),
            "-OutputDirectory",
            str(tmp_path / "out"),
            "-SigningPrivateKey",
            str(tmp_path / "missing-signing-key.pem"),
            "-ImageSbomScanner",
            str(tmp_path / "missing-sbom-scanner.exe"),
            "-ImageSbomScannerSha256",
            "a" * 64,
            "-ReleaseSequence",
            sequence,
            "-ReleaseId",
            release_id,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode != 0
    assert expected_message in completed.stderr
    assert "required tool is unavailable" not in completed.stderr


def test_builder_rejects_dirty_or_changing_git_state_and_uses_only_head() -> None:
    script = builder_text()

    assert "status', '--porcelain=v1', '--untracked-files=all" in script
    assert script.count("Assert-CleanRepository $git $repository") >= 3
    assert "'archive', '--format=tar'" in script
    assert '"--output=$snapshotTar", $gitHead' in script
    assert "Git HEAD changed while the release was being built" in script
    assert "Git HEAD changed during dry-run validation" in script
    assert "Copy-Item -LiteralPath $repository" not in script


def test_builder_keeps_output_and_private_key_outside_git() -> None:
    script = builder_text()

    assert "output directory must be outside the Git repository" in script
    assert "signing key must be outside the Git repository" in script
    assert "signing key must not be a symbolic link or reparse point" in script
    assert "private key is never copied" in script.lower()
    assert "[IO.File]::Copy($key" not in script
    assert "Copy-Item $key" not in script
    assert "Write-Output $key" not in script
    assert "Write-Host $key" not in script
    assert "Assert-DockerIgnoreSecretBoundary" in script
    assert "bundle contains a forbidden environment or key artifact" in script
    for dockerignore in (REPOSITORY / ".dockerignore", REPOSITORY / "web/.dockerignore"):
        rules = set(dockerignore.read_text(encoding="utf-8").splitlines())
        assert {".env", ".env.*"} <= rules


def test_builder_reads_the_canonical_release_asset_contract_at_runtime() -> None:
    script = builder_text()
    assets = canonical_release_assets()

    assert assets
    assert len(assets) == len(set(assets))
    assert "Get-ReleaseContractAssets $commonScript" in script
    assert "offline_contract_files" in script
    assert "runtime.env" in script
    assert "release.env.images" in script
    for asset in assets:
        source = REPOSITORY / asset.removeprefix("release/")
        assert source.is_file(), asset


def test_builder_enforces_linux_amd64_and_builds_all_three_release_images() -> None:
    script = builder_text()

    assert script.count("'--platform', 'linux/amd64'") >= 4
    assert "'buildx', 'build', '--platform', 'linux/amd64', '--load'" in script
    assert "--provenance=false" in script
    assert "--sbom=false" in script
    assert "SOURCE_DATE_EPOCH=$sourceDateEpoch" in script
    assert "Name = 'api'" in script
    assert "Name = 'migration'" in script
    assert "Name = 'web'" in script
    assert "image is not a single linux/amd64 artifact" in script


def test_builder_generates_exact_image_sboms_before_signing_the_bundle() -> None:
    script = builder_text()

    assert "[string]$ImageSbomScanner" in script
    assert "[string]$ImageSbomScannerSha256" in script
    assert "scanner binary SHA-256 does not match the approved digest" in script
    assert "generate_offline_image_sboms.py" in script
    assert "--release-git-sha', $gitHead" in script
    assert "--image-manifest', (Join-Path $bundleRoot 'release.env.images')" in script
    assert "--output-dir', (Join-Path $bundleRoot 'sbom')" in script
    assert "$sbomReport.image_count -ne 9" in script
    assert script.index("generate_offline_image_sboms.py") < script.index(
        "Write-AsciiFile $checksums $checksumEntries"
    )


def test_builder_fails_closed_if_a_compose_digest_changes() -> None:
    script = builder_text()

    assert "Get-PinnedComposeImages $composeFile" in script
    assert "Compose contains a mutable or non-loopback fixed image" in script
    assert "controlled Registry changed a trusted Compose digest" in script
    assert "temporary Registry did not preserve the exact RepoDigest" in script
    assert "release image manifest differs from docker compose config --images" in script
    assert "refusing to rewrite trust" in script
    assert "Get-ReferenceWithoutDigest $fixedReference" in script
    assert "Get-DigestFromReference $fixedReference" in script
    assert ".Split('@sha256:')" not in script
    assert "fixed Compose reference cannot be reconstructed without losing its tag" in script

    literal_images = {
        match.group(1)
        for match in re.finditer(r"^\s+image:\s+(\S+)\s*$", COMPOSE.read_text(), re.MULTILINE)
        if not match.group(1).startswith("${")
    }
    assert literal_images
    assert all(
        re.fullmatch(r"127\.0\.0\.1:5000/heyi-mirror/.+@sha256:[0-9a-f]{64}", image)
        for image in literal_images
    )


def test_actual_compose_image_contract_preserves_fixed_tags_and_release_shape() -> None:
    environment = os.environ.copy()
    for key in tuple(environment):
        if key.startswith(("KB_", "COMPOSE_", "POSTGRES_", "MINIO_", "REDIS_", "CLAMAV_")):
            environment.pop(key)
    completed = subprocess.run(  # noqa: S603
        [
            "docker",
            "compose",
            "--project-name",
            "heyi-bundle-builder-contract-test",
            "--env-file",
            str(REPOSITORY / "deploy/tencent/offline.env.example"),
            "--env-file",
            str(REPOSITORY / "deploy/tencent/release.env.example"),
            "--file",
            str(COMPOSE),
            "--profile",
            "ops",
            "--profile",
            "maintenance",
            "--profile",
            "controlled-egress",
            "config",
            "--images",
        ],
        cwd=REPOSITORY,
        env=environment,
        capture_output=True,
        check=True,
        shell=False,
        text=True,
        timeout=30,
    )
    rendered = set(completed.stdout.splitlines())
    compose_text = COMPOSE.read_text(encoding="utf-8")
    fixed = {
        match.group(1)
        for match in re.finditer(r"^\s+image:\s+(\S+)\s*$", compose_text, re.MULTILINE)
        if not match.group(1).startswith("${")
    }
    release = {
        line.split("=", maxsplit=1)[1]
        for line in (REPOSITORY / "deploy/tencent/release.env.example")
        .read_text(encoding="utf-8")
        .splitlines()
        if line and not line.startswith("#")
    }

    assert rendered == fixed | release
    assert all(
        ":" in reference.split("@", maxsplit=1)[0].rsplit("/", maxsplit=1)[1] for reference in fixed
    )
    assert all(
        re.fullmatch(
            r"127\.0\.0\.1:5000/heyi-release/(api|migration|web)@sha256:[0-9a-f]{64}",
            reference,
        )
        for reference in release
    )


def test_release_environment_manifest_and_control_have_exact_contracts() -> None:
    script = builder_text()

    release_keys = re.findall(r'"(KB_(?:API|MIGRATION|WEB)_IMAGE)=\$\(', script)
    assert set(release_keys) == {
        "KB_API_IMAGE",
        "KB_MIGRATION_IMAGE",
        "KB_WEB_IMAGE",
    }
    assert '"$($_.Reference)`t$($_.Id)`t$($_.Os)`t$($_.Architecture)"' in script

    control_block = script.split("Write-AsciiFile $control @(", maxsplit=1)[1].split(
        ")", maxsplit=1
    )[0]
    control_keys = re.findall(r'"([A-Z_]+)=', control_block)
    assert control_keys == [
        "REGISTRY_BOOTSTRAP_IMAGE",
        "REGISTRY_BOOTSTRAP_IMAGE_ID",
        "RELEASE_SEQUENCE",
        "RELEASE_ID",
        "RELEASE_GIT_SHA",
        "RELEASE_SCHEMA_HEAD",
        "REGISTRY_UNPACKED_BYTES",
        "REGISTRY_UNPACKED_INODES",
    ]


def test_builder_measures_the_final_deduplicated_unpacked_layer_set() -> None:
    script = builder_text()
    measurement = script.split("function Get-DeduplicatedUnpackedCapacity(", maxsplit=1)[1].split(
        "function Assert-ImagePlatform", maxsplit=1
    )[0]

    assert "$imageRecordArray = $imageRecords.ToArray()" in script
    assert "-ImageRecords $imageRecordArray" in script
    assert "-ImageRecords @($imageRecords)" not in script
    assert "@(sha256:[0-9a-f]{64})$" in measurement
    assert "'image', 'save', '--output'" in measurement
    assert 'archive_member(outer, members, "manifest.json")' in measurement
    assert "layer_diff_ids.setdefault(layer_name, diff_id)" in measurement
    assert 'tarfile.open(fileobj=stream, mode="r|*")' in measurement
    assert 'layer_paths = {"."}' in measurement
    assert "total_bytes += entry.size" in measurement
    assert "$measurementMatch.Groups[1].Value" in measurement
    assert "$matches[1]" not in measurement
    assert "compressed Registry directory by an empirical factor" in measurement
    assert "Get-ChildItem -LiteralPath $registryData" not in measurement
    assert "* 3" not in measurement
    assert script.index("Get-DeduplicatedUnpackedCapacity `") < script.index(
        "Write-AsciiFile $control @("
    )


def test_unpacked_capacity_program_deduplicates_shared_layers(tmp_path: Path) -> None:
    def add_bytes(archive: tarfile.TarFile, name: str, payload: bytes) -> None:
        info = tarfile.TarInfo(name)
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))

    layer_a_stream = io.BytesIO()
    with tarfile.open(fileobj=layer_a_stream, mode="w") as layer:
        directory = tarfile.TarInfo("etc")
        directory.type = tarfile.DIRTYPE
        layer.addfile(directory)
        add_bytes(layer, "etc/a", b"abc")
    layer_a = layer_a_stream.getvalue()

    layer_b_stream = io.BytesIO()
    with tarfile.open(fileobj=layer_b_stream, mode="w") as layer:
        add_bytes(layer, "etc/b", b"hello")
    layer_b = layer_b_stream.getvalue()

    diff_a = "sha256:" + hashlib.sha256(layer_a).hexdigest()
    diff_b = "sha256:" + hashlib.sha256(layer_b).hexdigest()
    config_a_id = "1" * 64
    config_b_id = "2" * 64
    config_a = json.dumps({"rootfs": {"diff_ids": [diff_a]}}).encode()
    config_b = json.dumps({"rootfs": {"diff_ids": [diff_a, diff_b]}}).encode()
    manifest = json.dumps(
        [
            {"Config": f"{config_a_id}.json", "RepoTags": [], "Layers": ["a/layer.tar"]},
            {
                "Config": f"{config_b_id}.json",
                "RepoTags": [],
                "Layers": ["a/layer.tar", "b/layer.tar"],
            },
        ]
    ).encode()

    docker_archive = tmp_path / "images.tar"
    with tarfile.open(docker_archive, mode="w") as archive:
        add_bytes(archive, "manifest.json", manifest)
        add_bytes(archive, f"{config_a_id}.json", config_a)
        add_bytes(archive, f"{config_b_id}.json", config_b)
        add_bytes(archive, "a/layer.tar", layer_a)
        add_bytes(archive, "b/layer.tar", layer_b)

    completed = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-I",
            "-c",
            unpacked_capacity_program(),
            str(docker_archive),
            f"sha256:{config_a_id}",
            f"sha256:{config_b_id}",
        ],
        capture_output=True,
        check=True,
        shell=False,
        text=True,
        timeout=30,
    )

    # Eight logical file bytes and three inodes per unique layer: layer root,
    # implicit/explicit `etc`, and the file. The shared first layer is counted once.
    assert completed.stdout.strip() == "8\t6"


def test_bundle_checksum_inventory_is_complete_and_openssl_signed() -> None:
    script = builder_text()

    assert "@('bundle.control', 'release.env', 'release.env.images')" in script
    assert "foreach ($directory in @('registry', 'release', 'sbom'))" in script
    assert "Get-ChildItem -LiteralPath $base -File -Force -Recurse" in script
    assert "Write-AsciiFile $checksums $checksumEntries" in script
    assert "'dgst', '-sha256', '-sign'" in script
    assert "'dgst', '-sha256', '-verify'" in script
    assert "SHA256SUMS.sig" in script
    assert "SHA256SUMS'" in script


def test_bootstrap_registry_transport_is_separate_and_independently_signed() -> None:
    script = builder_text()

    assert (
        "docker.io/library/registry:2.8.3@sha256:"
        "46faa9a1ae6813194b53921a370f2f4f8c5e1aae228a89bceafef5847a6a3278"
    ) in script
    assert "heyi-bootstrap/registry:2.8.3-amd64-" in script
    assert "registry-bootstrap.tar" in script
    assert "offline-registry-bundle.tar" in script
    assert "Sign-And-Verify $openssl $key $publicKey $bootstrapChecksum" in script
    assert "Sign-And-Verify $openssl $key $publicKey $bundleChecksum" in script


def test_builder_uses_atomic_publish_lock_and_owned_failure_cleanup() -> None:
    script = builder_text()

    assert "[IO.FileShare]::None" in script
    assert "another bundle build holds the output lock" in script
    assert "output directory already exists; refusing a non-atomic overwrite" in script
    assert "[IO.Directory]::Move($publish, $output)" in script
    assert "io.heyi.bundle-builder.run=$runId" in script
    assert "temporary Registry ownership changed" in script
    assert "Remove-OwnedRegistryIfPresent" in script
    assert "Remove-OwnedNetworkIfPresent" in script
    assert "cleanup incomplete" in script
    assert "[IO.Path]::GetPathRoot($output)" in script
    assert 'Join-Path $outputVolumeRoot ".hkb-$runId"' in script
    assert "Join-Path $workspace 'b'" in script
    assert 'Join-Path $outputParent ".$leaf.work.$runId"' not in script
    assert "temporary workspace identity collided with an existing path" in script
    assert "temporary workspace must remain outside the Git repository" in script
    assert "temporary workspace must not be a symbolic link or reparse point" in script
    assert "$primaryFailure = $null" in script
    assert "catch {\n    $primaryFailure = $_\n}\nfinally {" in script
    assert "$($primaryFailure.Exception.Message); cleanup incomplete:" in script
    assert "throw $primaryFailure" in script
    assert "temporary Registry ownership changed; manual cleanup is required" in script
    assert "temporary network ownership changed; manual cleanup is required" in script
    assert "'--publish', '127.0.0.1:0:5000/tcp'" in script
    assert "'com.docker.network.bridge.enable_ip_masquerade=false'" in script
    assert "'com.docker.network.bridge.enable_icc=false'" in script
    assert "'network', 'create', '--internal'" not in script
    assert "Resolve-LoopbackPublishedPort $docker $registryContainerId" in script
    assert "'{{json .NetworkSettings.Ports}}'" in script
    assert "$properties.Count -eq 1" in script
    assert "$bindings[0].HostIp -eq '127.0.0.1'" in script
    assert "'--cap-drop', 'ALL'" in script
    assert "'--security-opt', 'no-new-privileges=true'" in script
    assert "'--network', \"container:$registryContainerId\"" in script
    assert "'--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN'" in script
    assert "'route', 'del', 'default'" in script
    assert "temporary Registry retained a non-local network route" in script
    assert "$registryStartupCommand = (" in script
    assert "$bootstrapId,\n        '-ceu',\n        $registryStartupCommand" in script
    assert ": > /tmp/heyi-network-ready" in script
    assert "temporary Registry routes changed after startup" in script
    assert "'{{json .Config.Labels}}'" in script
    assert "'{{json .Labels}}'" in script
    assert '{{ index .Config.Labels "io.heyi.bundle-builder.run" }}' not in script
    assert '{{ index .Labels "io.heyi.bundle-builder.run" }}' not in script


def test_builder_bounds_fixed_registry_paths_below_legacy_windows_max_path() -> None:
    compose = COMPOSE.read_text(encoding="utf-8")
    fixed_references = re.findall(
        r"(?m)^\s+image:\s+"
        r"(127\.0\.0\.1:5000/heyi-mirror/\S+@sha256:[0-9a-f]{64})\s*$",
        compose,
    )
    assert fixed_references

    workspace = "C:\\.hkb-" + ("a" * 32)
    candidate_lengths: list[int] = []
    for reference in fixed_references:
        repository_and_tag, digest = reference.rsplit("@sha256:", maxsplit=1)
        repository_and_tag = repository_and_tag.removeprefix("127.0.0.1:5000/")
        repository, tag = repository_and_tag.rsplit(":", maxsplit=1)
        manifest_path = "\\".join(
            (
                workspace,
                "b",
                "registry",
                "docker",
                "registry",
                "v2",
                "repositories",
                *repository.split("/"),
                "_manifests",
                "tags",
                tag,
                "index",
                "sha256",
                digest,
            )
        )
        candidate_lengths.append(len(manifest_path))

    assert max(candidate_lengths) < 260
    assert max(candidate_lengths) > 200


def test_builder_creates_a_deterministic_root_owned_posix_tar() -> None:
    script = builder_text()

    assert 'tarfile.open(destination, "x", format=tarfile.PAX_FORMAT)' in script
    assert "info.uid = 0" in script
    assert "info.gid = 0" in script
    assert 'info.uname = "root"' in script
    assert 'info.gname = "root"' in script
    assert "info.mtime = epoch" in script
    assert "info.mode = 0o750 if path.is_dir() else 0o444" in script
    assert 'sorted(source.rglob("*")' in script


def test_bundle_build_documentation_covers_verification_and_import_order() -> None:
    documentation = DOCUMENTATION.read_text(encoding="utf-8")

    for required in (
        "git archive HEAD",
        "linux/amd64",
        "release.env.images",
        "bundle.control",
        "SHA256SUMS",
        "OpenSSL",
        "-DryRun",
        "docker load",
        "import-offline-registry-bundle.sh",
        "RELEASE_SEQUENCE",
        "REGISTRY_UNPACKED_BYTES",
        "REGISTRY_UNPACKED_INODES",
        "MEASURED_DURING_FORMAL_BUILD",
        "root:root",
        "0750",
        "0444",
    ):
        assert required in documentation
    assert documentation.index("docker load") < documentation.index(
        "import-offline-registry-bundle.sh"
    )
    assert "RELEASE_GIT_SHA" in documentation
    assert "/releases/<contract-sha256>" in documentation
    assert "不包含 `runtime.env`、`release.env`、Registry 或 SBOM" in documentation
    assert "`release/`、`registry/`、`sbom/`" in documentation


def test_bundle_build_documentation_binds_the_approved_sbom_scanner_in_both_modes() -> None:
    documentation = DOCUMENTATION.read_text(encoding="utf-8")
    invocations = [
        block
        for block in re.findall(r"```powershell\r?\n(?P<body>.*?)\r?\n```", documentation, re.S)
        if "build-offline-registry-bundle.ps1" in block
    ]

    assert len(invocations) == 2
    assert any("-DryRun" in invocation for invocation in invocations)
    assert any("-DryRun" not in invocation for invocation in invocations)
    for invocation in invocations:
        assert "-ImageSbomScanner D:\\release-tools\\syft.exe" in invocation
        assert "-ImageSbomScannerSha256 <approved-lowercase-sha256>" in invocation
