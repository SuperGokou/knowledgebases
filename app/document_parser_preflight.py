from __future__ import annotations

import argparse
import json
from collections.abc import Sequence

from app.services.document_parser import parser_capabilities


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail-closed document parser capability preflight")
    parser.add_argument(
        "--require-all",
        action="store_true",
        help="require TXT/CSV, OOXML, PDF and legacy Office parser capabilities",
    )
    parser.add_argument(
        "--require",
        nargs="*",
        default=[],
        metavar="EXT",
        help="specific extensions that must be available (for example .pdf .docx)",
    )
    arguments = parser.parse_args(argv)
    capabilities = parser_capabilities()
    required = sorted(capabilities) if arguments.require_all else sorted(set(arguments.require))
    unknown = [extension for extension in required if extension not in capabilities]
    missing = [extension for extension in required if not capabilities.get(extension, False)]
    result = {
        "schema_version": 1,
        "capabilities": capabilities,
        "required": required,
        "unknown": unknown,
        "missing": missing,
        "status": "pass" if not unknown and not missing else "blocked",
    }
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
