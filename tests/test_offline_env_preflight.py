from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).resolve().parents[1]
PREFLIGHT = REPOSITORY / "deploy/tencent/preflight-offline.sh"
EXAMPLE_ENV = REPOSITORY / "deploy/tencent/offline.env.example"
PINNED_IMAGE = "example/app@sha256:" + "a" * 64


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8", newline="\n")
    path.chmod(0o755)


def _fake_command_directory(tmp_path: Path) -> Path:
    commands = tmp_path / "commands"
    commands.mkdir()
    _write_executable(
        commands / "id",
        """#!/usr/bin/env sh
if [ "${1:-}" = "-u" ]; then
  printf '%s\\n' "${FAKE_EFFECTIVE_UID:-0}"
else
  exit 64
fi
""",
    )
    _write_executable(
        commands / "stat",
        """#!/usr/bin/env sh
case "$*" in
  *%u*) printf '%s\\n' "${FAKE_FILE_UID:-0}" ;;
  *%a*) printf '%s\\n' "${FAKE_FILE_MODE:-600}" ;;
  *) exit 64 ;;
esac
""",
    )
    _write_executable(
        commands / "getconf",
        """#!/usr/bin/env sh
printf '8\\n'
""",
    )
    _write_executable(
        commands / "awk",
        """#!/usr/bin/env sh
case "$*" in
  *MemTotal*) printf '16000000\\n' ;;
  *) printf '300000000\\n' ;;
esac
""",
    )
    _write_executable(
        commands / "ss",
        """#!/usr/bin/env sh
case "$*" in
  *":${FAKE_PORT_IN_USE:-none}"*) printf 'LISTEN fake\\n' ;;
esac
""",
    )
    _write_executable(
        commands / "python3",
        "#!/usr/bin/env sh\nexit 0\n",
    )
    _write_executable(commands / "install", "#!/usr/bin/env sh\nexit 0\n")
    _write_executable(
        commands / "realpath",
        """#!/usr/bin/env sh
for argument in "$@"; do result=$argument; done
printf '%s\\n' "${FAKE_CANONICAL_DATA_ROOT:-$result}"
""",
    )
    _write_executable(
        commands / "df",
        """#!/usr/bin/env sh
printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n'
printf '/dev/fake 300000000 0 300000000 0%% /srv\\n'
""",
    )
    _write_executable(
        commands / "docker",
        f"""#!/usr/bin/env sh
set -eu
case "$*" in
  *'config --images'*) printf '%s\\n' "${{FAKE_COMPOSE_IMAGE:-{PINNED_IMAGE}}}" ;;
  *'image inspect'*) printf '%s\\n' "${{FAKE_REPO_DIGEST:-{PINNED_IMAGE}}}" ;;
  *'ps -aq'*com.docker.compose.project*)
    [ "${{FAKE_PROJECT_RESOURCE:-0}}" = 1 ] && printf 'unverified-resource\\n' || :
    ;;
  *'network ls -q'*|*'volume ls -q'*) ;;
  *'volume inspect --format'*io.heyi.knowledgebases.owner*)
    printf '%s\\n' "${{FAKE_MARKER_OWNER:-jiangsu-heyi-knowledgebases}}"
    ;;
  *'volume inspect --format'*io.heyi.knowledgebases.compose-project*)
    printf '%s\\n' "${{FAKE_MARKER_PROJECT:-heyi-kb-offline}}"
    ;;
  *'volume inspect heyi-kb-offline-owner-marker'*)
    [ "${{FAKE_MARKER_MISSING:-0}}" = 1 ] && exit 1 || exit 0
    ;;
  *'volume create'*) printf 'heyi-kb-offline-owner-marker\\n' ;;
  *'ps -q'*com.docker.compose.service=proxy*) printf 'proxy123\\n' ;;
  *'ps -q'*publish=*)
    [ "${{FAKE_PROXY_OWNS_PORT:-1}}" = 1 ] && printf 'proxy123\\n' || printf 'other123\\n'
    ;;
  *'inspect --format'*com.docker.compose.project*) printf 'heyi-kb-offline\\n' ;;
  *'inspect --format'*com.docker.compose.service*) printf 'proxy\\n' ;;
  *'port proxy123 8443/tcp'*) printf '0.0.0.0:19443\\n' ;;
  *'port proxy123 9443/tcp'*) printf '0.0.0.0:19444\\n' ;;
  *) exit 0 ;;
esac
""",
    )
    return commands


def _write_env(
    tmp_path: Path,
    *,
    extra: str = "",
    replacements: dict[str, str] | None = None,
) -> Path:
    content = EXAMPLE_ENV.read_text(encoding="utf-8")
    for before, after in (replacements or {}).items():
        content = content.replace(before, after)
    env_file = tmp_path / "offline.env"
    env_file.write_text(content + extra, encoding="utf-8", newline="\n")
    env_file.chmod(0o600)
    (tmp_path / "offline.env.images").write_text(
        PINNED_IMAGE + "\n", encoding="utf-8", newline="\n"
    )
    return env_file


def _run_preflight(
    tmp_path: Path,
    env_file: Path,
    *,
    file_uid: int = 0,
    file_mode: str = "600",
    environment_overrides: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    _fake_command_directory(tmp_path)
    environment = os.environ.copy()
    environment.update(
        {
            "FAKE_EFFECTIVE_UID": "0",
            "FAKE_FILE_UID": str(file_uid),
            "FAKE_FILE_MODE": file_mode,
            "KB_PREFLIGHT_LOCK_HELD": "heyi-kb-offline-preflight-v1",
        }
    )
    environment.update(environment_overrides or {})
    return subprocess.run(  # noqa: S603
        [
            "sh",
            "-c",
            'PATH="$1:$PATH"; export PATH; exec sh "$2" "$3"',
            "preflight-test",
            "commands",
            str(PREFLIGHT),
            str(env_file),
        ],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        check=False,
        shell=False,
        text=True,
        timeout=30,
    )


def test_preflight_rejects_symlinked_environment_file_before_parsing(
    tmp_path: Path,
) -> None:
    marker = tmp_path / "command-was-executed"
    target = _write_env(
        tmp_path,
        replacements={
            "POSTGRES_PASSWORD=REPLACE_WITH_URL_SAFE_RANDOM_VALUE": (
                "POSTGRES_PASSWORD=$(touch command-was-executed)"
            )
        },
    )
    link = tmp_path / "offline-link.env"
    try:
        link.symlink_to(target)
    except OSError as exc:  # pragma: no cover - host capability is a test prerequisite
        pytest.fail(f"test host cannot create the required symlink fixture: {exc}")

    result = _run_preflight(tmp_path, link)

    assert result.returncode != 0
    assert "symbolic link" in result.stderr
    assert not marker.exists()


@pytest.mark.parametrize(
    ("file_uid", "file_mode", "expected"),
    [
        (1000, "600", "owned by root"),
        (0, "640", "permissions must be 0600 or 0400"),
        (0, "700", "permissions must be 0600 or 0400"),
    ],
)
def test_preflight_rejects_unsafe_owner_or_mode_before_parsing(
    tmp_path: Path,
    file_uid: int,
    file_mode: str,
    expected: str,
) -> None:
    env_file = _write_env(tmp_path)

    result = _run_preflight(tmp_path, env_file, file_uid=file_uid, file_mode=file_mode)

    assert result.returncode != 0
    assert expected in result.stderr


def test_preflight_rejects_unknown_environment_keys(tmp_path: Path) -> None:
    env_file = _write_env(tmp_path, extra="UNREVIEWED_ENDPOINT=https://example.com\n")

    result = _run_preflight(tmp_path, env_file)

    assert result.returncode != 0
    assert "unknown environment key: UNREVIEWED_ENDPOINT" in result.stderr


def test_preflight_treats_environment_as_data_and_rejects_command_substitution(
    tmp_path: Path,
) -> None:
    marker = tmp_path / "command-was-executed"
    env_file = _write_env(
        tmp_path,
        replacements={
            "POSTGRES_PASSWORD=REPLACE_WITH_URL_SAFE_RANDOM_VALUE": (
                "POSTGRES_PASSWORD=$(touch command-was-executed)"
            )
        },
    )

    result = _run_preflight(tmp_path, env_file)

    assert result.returncode != 0
    assert "unsafe value for POSTGRES_PASSWORD" in result.stderr
    assert not marker.exists()


@pytest.mark.parametrize(
    ("replacements", "expected"),
    [
        (
            {"KB_PUBLIC_HOST=10.0.0.10": "KB_PUBLIC_HOST=example.com"},
            "KB_PUBLIC_HOST must be an approved private or local address",
        ),
        (
            {
                "KB_PUBLIC_ORIGIN=https://10.0.0.10:19443": (
                    "KB_PUBLIC_ORIGIN=https://example.com:19443"
                )
            },
            "KB_PUBLIC_ORIGIN must exactly match the approved public host and port",
        ),
    ],
)
def test_preflight_rejects_external_host_or_origin(
    tmp_path: Path,
    replacements: dict[str, str],
    expected: str,
) -> None:
    env_file = _write_env(tmp_path, replacements=replacements)

    result = _run_preflight(tmp_path, env_file)

    assert result.returncode != 0
    assert expected in result.stderr


def test_preflight_accepts_strict_root_owned_private_configuration(
    tmp_path: Path,
) -> None:
    env_file = _write_env(tmp_path)

    result = _run_preflight(tmp_path, env_file)

    assert result.returncode == 0, result.stderr
    assert "offline deployment requirements satisfied" in result.stdout


def test_preflight_rejects_trusted_hosts_without_the_internal_api_name(
    tmp_path: Path,
) -> None:
    env_file = _write_env(
        tmp_path,
        replacements={
            'KB_TRUSTED_HOSTS=\'["10.0.0.10","api"]\'': (
                'KB_TRUSTED_HOSTS=\'["10.0.0.10"]\''
            )
        },
    )

    result = _run_preflight(tmp_path, env_file)

    assert result.returncode != 0
    assert "must contain only KB_PUBLIC_HOST and the internal api service" in result.stderr


def test_preflight_rejects_identical_https_ports(tmp_path: Path) -> None:
    env_file = _write_env(
        tmp_path,
        replacements={"KB_OBJECTS_HTTPS_PORT=19444": "KB_OBJECTS_HTTPS_PORT=19443"},
    )

    result = _run_preflight(tmp_path, env_file)

    assert result.returncode != 0
    assert "HTTPS and object HTTPS ports must be different" in result.stderr


@pytest.mark.parametrize("delimiter", ["@", ":", "/", "?", "#", "%"])
def test_preflight_rejects_url_delimiters_in_database_passwords(
    tmp_path: Path,
    delimiter: str,
) -> None:
    env_file = _write_env(
        tmp_path,
        replacements={
            "POSTGRES_APP_PASSWORD=REPLACE_WITH_A_DIFFERENT_URL_SAFE_RANDOM_VALUE": (
                f"POSTGRES_APP_PASSWORD=safe{delimiter}host"
            )
        },
    )

    result = _run_preflight(tmp_path, env_file)

    assert result.returncode != 0
    assert "unsafe URL component for POSTGRES_APP_PASSWORD" in result.stderr


def test_preflight_rejects_symlink_resolved_data_parent(tmp_path: Path) -> None:
    env_file = _write_env(tmp_path)

    result = _run_preflight(
        tmp_path,
        env_file,
        environment_overrides={"FAKE_CANONICAL_DATA_ROOT": "/redirected/data"},
    )

    assert result.returncode != 0
    assert "one of its parents must not be symbolic" in result.stderr


def test_preflight_rejects_unmarked_existing_compose_project(tmp_path: Path) -> None:
    env_file = _write_env(tmp_path)

    result = _run_preflight(
        tmp_path,
        env_file,
        environment_overrides={
            "FAKE_MARKER_MISSING": "1",
            "FAKE_PROJECT_RESOURCE": "1",
        },
    )

    assert result.returncode != 0
    assert "already owned by an unverified deployment" in result.stderr


@pytest.mark.parametrize(
    ("proxy_owns_port", "expected_returncode"),
    [("1", 0), ("0", 69)],
)
def test_preflight_only_allows_verified_project_proxy_during_upgrade(
    tmp_path: Path,
    proxy_owns_port: str,
    expected_returncode: int,
) -> None:
    env_file = _write_env(tmp_path)

    result = _run_preflight(
        tmp_path,
        env_file,
        environment_overrides={
            "FAKE_PORT_IN_USE": "19443",
            "FAKE_PROXY_OWNS_PORT": proxy_owns_port,
        },
    )

    assert result.returncode == expected_returncode, result.stderr
    if expected_returncode:
        assert "occupied by an unverified process" in result.stderr


def test_preflight_serializes_and_forbids_network_pulls_for_run_commands() -> None:
    script = PREFLIGHT.read_text(encoding="utf-8")

    assert 'lock_file=$lock_directory/heyi-kb-offline.preflight.lock' in script
    assert 'exec 9>"$lock_file"' in script
    assert "flock -n 9" in script
    assert script.count("run --pull never --rm --no-deps") == 3


def test_preflight_assigns_postgres_bind_root_to_pinned_image_uid() -> None:
    script = PREFLIGHT.read_text(encoding="utf-8")

    assert (
        'install -d -o 999 -g 999 -m 0700 "$KB_DATA_ROOT/postgres"' in script
    )
