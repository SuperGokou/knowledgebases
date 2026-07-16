from __future__ import annotations

import ast
from pathlib import Path

import pytest

_REPOSITORY = Path(__file__).resolve().parents[1]
_OPTIMIZATION_SENSITIVE_FUNCTIONS = (
    (
        "scripts/functional_acceptance.py",
        ("load_external_trust_context", "_validate_external_provenance"),
    ),
    ("scripts/postgres_acceptance.py", ("run_acceptance",)),
    ("scripts/storage_watermark_preflight.py", ("_raw_artifact_matches",)),
)


@pytest.mark.parametrize(("relative_path", "function_names"), _OPTIMIZATION_SENSITIVE_FUNCTIONS)
def test_acceptance_truth_checks_do_not_depend_on_runtime_assertions(
    relative_path: str,
    function_names: tuple[str, ...],
) -> None:
    path = _REPOSITORY / relative_path
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    definitions = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    for function_name in function_names:
        function = definitions[function_name]
        runtime_assertions = [node for node in ast.walk(function) if isinstance(node, ast.Assert)]
        assert not runtime_assertions, (
            f"{relative_path}:{function_name} must use explicit fail-closed checks; "
            "python -O removes assert statements"
        )

    compile(source, str(path), "exec", optimize=2)
