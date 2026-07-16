from __future__ import annotations

import re
from pathlib import Path

from app.schemas.chat import ChatSourceStatus


def test_frontend_chat_reason_allowlist_matches_openapi_contract() -> None:
    schema = ChatSourceStatus.model_json_schema()
    backend_reasons = set(schema["properties"]["reason"]["enum"])

    contract_source = (
        Path(__file__).parents[1] / "web" / "src" / "lib" / "chat-contract.ts"
    ).read_text(encoding="utf-8")
    match = re.search(
        r'const SOURCE_REASONS = new Set<ChatSourceStatus\["reason"\]>\(\[(?P<body>.*?)\]\);',
        contract_source,
        re.DOTALL,
    )
    assert match is not None, "frontend source reason allowlist is missing"
    frontend_reasons = set(re.findall(r'"([a-z_]+)"', match.group("body")))

    assert frontend_reasons == backend_reasons
