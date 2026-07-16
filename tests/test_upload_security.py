from __future__ import annotations

import io
import urllib.error

from scripts.upload import _storage_error


def _http_error(body: bytes) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        url="https://storage.invalid/object",
        code=400,
        msg="Bad Request",
        hdrs=None,
        fp=io.BytesIO(body),
    )


def test_storage_error_rejects_xml_entities_in_untrusted_response() -> None:
    body = b"""<?xml version="1.0"?>
<!DOCTYPE Error [<!ENTITY injected "attacker-controlled">]>
<Error><Code>&injected;</Code><Message>&injected;</Message></Error>
"""
    parsed = _storage_error(_http_error(body))

    assert parsed.code == "http_error"
    assert "Bad Request" in str(parsed)
    assert "attacker-controlled" not in parsed.code
    assert "attacker-controlled" not in str(parsed)


def test_storage_error_keeps_bounded_normal_error_details() -> None:
    parsed = _storage_error(
        _http_error(b"<Error><Code>NoSuchUpload</Code><Message>gone</Message></Error>")
    )

    assert parsed.code == "NoSuchUpload"
    assert "gone" in str(parsed)
