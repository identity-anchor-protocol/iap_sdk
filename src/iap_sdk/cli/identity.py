"""Local identity management for iap-agent CLI."""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from iap_sdk.crypto.agent_identity import derive_agent_id

DEFAULT_IDENTITY_PATH = Path.home() / ".iap_agent" / "identity" / "ed25519.json"


class IdentityError(ValueError):
    """Raised when identity material is invalid or cannot be loaded."""


@dataclass(frozen=True)
class LocalIdentity:
    private_key_bytes: bytes
    public_key_bytes: bytes

    @property
    def private_key_b64(self) -> str:
        return base64.b64encode(self.private_key_bytes).decode("ascii")

    @property
    def public_key_b64(self) -> str:
        return base64.b64encode(self.public_key_bytes).decode("ascii")

    @property
    def agent_id(self) -> str:
        return derive_agent_id(self.public_key_bytes)


def _chmod_owner_only(path: Path) -> None:
    if os.name != "posix":
        return
    path.chmod(0o600)


def _load_identity(path: Path) -> LocalIdentity:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise IdentityError(f"invalid identity file: {path}") from exc

    private_key_b64 = payload.get("private_key_b64")
    public_key_b64 = payload.get("public_key_b64")
    if not isinstance(private_key_b64, str) or not isinstance(public_key_b64, str):
        raise IdentityError("identity file must contain private_key_b64 and public_key_b64")

    try:
        private_key_bytes = base64.b64decode(private_key_b64)
        public_key_bytes = base64.b64decode(public_key_b64)
    except Exception as exc:
        raise IdentityError("identity keys must be valid base64") from exc

    if len(private_key_bytes) != 32 or len(public_key_bytes) != 32:
        raise IdentityError("identity keys must decode to 32 bytes")

    # Validate keypair consistency.
    private = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    expected_public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    if expected_public != public_key_bytes:
        raise IdentityError("identity file private/public keys do not match")

    _chmod_owner_only(path)
    return LocalIdentity(private_key_bytes=private_key_bytes, public_key_bytes=public_key_bytes)


def _create_identity(path: Path) -> LocalIdentity:
    path.parent.mkdir(parents=True, exist_ok=True)

    private = Ed25519PrivateKey.generate()
    private_key_bytes = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_key_bytes = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    identity = LocalIdentity(private_key_bytes=private_key_bytes, public_key_bytes=public_key_bytes)

    serialized = {
        "private_key_b64": identity.private_key_b64,
        "public_key_b64": identity.public_key_b64,
    }
    path.write_text(json.dumps(serialized, indent=2) + "\n", encoding="utf-8")
    _chmod_owner_only(path)
    return identity


def load_or_create_identity(path: str | Path | None = None) -> tuple[LocalIdentity, bool, Path]:
    identity_path = Path(path) if path else DEFAULT_IDENTITY_PATH
    if identity_path.exists():
        return _load_identity(identity_path), False, identity_path
    return _create_identity(identity_path), True, identity_path
