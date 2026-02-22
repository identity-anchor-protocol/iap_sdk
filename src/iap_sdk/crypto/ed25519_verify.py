"""Ed25519 signature verification helper."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def verify_ed25519(signature: bytes, message: bytes, public_key: bytes) -> bool:
    try:
        key = Ed25519PublicKey.from_public_bytes(public_key)
        key.verify(signature, message)
    except Exception:
        return False
    return True
