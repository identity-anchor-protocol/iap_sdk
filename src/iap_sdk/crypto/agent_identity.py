"""Helpers for deriving and validating deterministic agent identities.

Agent id format:
- ed25519:<32-char-lowercase-base32-prefix>
where the prefix is derived from sha256(public_key_bytes).
"""

from __future__ import annotations

import base64
import hashlib

EXPECTED_AGENT_ID_LEN = len("ed25519:") + 32


def derive_agent_id(public_key_bytes: bytes) -> str:
    digest = hashlib.sha256(public_key_bytes).digest()
    encoded = base64.b32encode(digest).decode("ascii").rstrip("=").lower()
    return f"ed25519:{encoded[:32]}"


def decode_b64(data_b64: str) -> bytes:
    try:
        return base64.b64decode(data_b64, validate=True)
    except Exception as exc:  # pragma: no cover - exact exception class may vary
        raise ValueError("invalid base64") from exc


def validate_agent_id(public_key_bytes: bytes, agent_id: str) -> bool:
    if not agent_id.startswith("ed25519:"):
        return False
    if agent_id != agent_id.lower():
        return False
    if len(agent_id) != EXPECTED_AGENT_ID_LEN:
        return False
    return derive_agent_id(public_key_bytes) == agent_id
