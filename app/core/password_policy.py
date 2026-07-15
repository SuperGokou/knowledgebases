from __future__ import annotations


def validate_strong_password(value: str) -> str:
    """Validate the shared interactive-account password contract.

    Length remains a caller-specific concern: API schemas accept passwords from
    12 characters, while the production bootstrap requires at least 16.  The
    character contract is centralized so the bootstrap administrator cannot
    bypass the policy enforced for accounts created through the API.
    """

    if any(character.isspace() for character in value):
        raise ValueError("password must not contain whitespace")
    if not value.isascii() or any(not 0x21 <= ord(character) <= 0x7E for character in value):
        raise ValueError("password must contain only printable ASCII characters")
    required_classes = (
        any("a" <= character <= "z" for character in value),
        any("A" <= character <= "Z" for character in value),
        any("0" <= character <= "9" for character in value),
        any(
            not ("a" <= character <= "z" or "A" <= character <= "Z" or "0" <= character <= "9")
            for character in value
        ),
    )
    if not all(required_classes):
        raise ValueError(
            "password must contain lowercase, uppercase, numeric, and symbol characters"
        )
    return value
