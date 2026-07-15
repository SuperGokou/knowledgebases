from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SHELL_SCRIPT_ROOTS = (
    REPOSITORY_ROOT / "deploy" / "tencent",
    REPOSITORY_ROOT / "scripts",
    REPOSITORY_ROOT / "docker",
)


def _shell_scripts() -> list[Path]:
    scripts = sorted(
        path for root in SHELL_SCRIPT_ROOTS for path in root.rglob("*.sh") if path.is_file()
    )
    assert scripts, "the deployment shell-script inventory must not be empty"
    return scripts


def _run_quality_tool(executable: str, arguments: list[str]) -> None:
    completed = subprocess.run(
        [executable, *arguments],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    output = "\n".join(part for part in (completed.stdout, completed.stderr) if part)
    assert completed.returncode == 0, output


def test_shell_scripts_do_not_use_ambiguous_cdpath_assignment() -> None:
    offenders = [
        path.relative_to(REPOSITORY_ROOT).as_posix()
        for path in _shell_scripts()
        if "CDPATH= cd" in path.read_text(encoding="utf-8")
    ]
    assert offenders == []


def test_shell_scripts_parse_with_posix_sh() -> None:
    shell = shutil.which("sh")
    if shell is None:
        pytest.skip("POSIX sh is not installed in this test environment")

    for script in _shell_scripts():
        _run_quality_tool(shell, ["-n", str(script)])


def test_shellcheck_reports_no_findings() -> None:
    shellcheck = shutil.which("shellcheck")
    if shellcheck is None:
        pytest.skip("ShellCheck is not installed in this test environment")

    _run_quality_tool(shellcheck, [str(path) for path in _shell_scripts()])
