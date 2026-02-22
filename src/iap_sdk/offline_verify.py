"""Offline certificate verification helpers."""

from __future__ import annotations

import base64
import json
from pathlib import Path

from iap_sdk.certificates import (
    CONTINUITY_TYPE,
    IDENTITY_TYPE,
    KEY_ROTATION_TYPE,
    LINEAGE_TYPE,
    PROTOCOL_VERSION,
    ContinuityCertificate,
    IdentityAnchorCertificate,
    KeyRotationCertificate,
    LineageCertificate,
)
from iap_sdk.crypto.agent_identity import decode_b64, validate_agent_id
from iap_sdk.crypto.ed25519_verify import verify_ed25519


def canonical_certificate_payload_bytes(certificate: dict) -> bytes:
    payload = dict(certificate)
    payload.pop("registry_signature_b64", None)
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _load_json(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def verify_certificate_dict(
    certificate: dict,
    *,
    registry_public_key_b64: str,
    identity_anchor: dict | None = None,
) -> tuple[bool, str]:
    cert_type = certificate.get("certificate_type")
    if cert_type == IDENTITY_TYPE:
        model = IdentityAnchorCertificate(**certificate)
        public_key = decode_b64(model.agent_public_key_b64)
        if not validate_agent_id(public_key, model.agent_id):
            return False, "agent_id derivation mismatch"
    elif cert_type == CONTINUITY_TYPE:
        model = ContinuityCertificate(**certificate)
        if identity_anchor is None:
            return False, "identity anchor required for non-identity certificate"
        anchor_model = IdentityAnchorCertificate(**identity_anchor)
        anchor_key = decode_b64(anchor_model.agent_public_key_b64)
        if model.agent_id != anchor_model.agent_id:
            return False, "agent_id does not match identity anchor"
        if not validate_agent_id(anchor_key, model.agent_id):
            return False, "identity anchor derivation invalid"
    elif cert_type == LINEAGE_TYPE:
        model = LineageCertificate(**certificate)
        if identity_anchor is None:
            return False, "identity anchor required for non-identity certificate"
        anchor_model = IdentityAnchorCertificate(**identity_anchor)
        anchor_key = decode_b64(anchor_model.agent_public_key_b64)
        if model.agent_id != anchor_model.agent_id:
            return False, "agent_id does not match identity anchor"
        if not validate_agent_id(anchor_key, model.agent_id):
            return False, "identity anchor derivation invalid"
    elif cert_type == KEY_ROTATION_TYPE:
        model = KeyRotationCertificate(**certificate)
        old_public_key = decode_b64(model.old_agent_public_key_b64)
        new_public_key = decode_b64(model.new_agent_public_key_b64)
        if not validate_agent_id(old_public_key, model.old_agent_id):
            return False, "old_agent_id derivation mismatch"
        if not validate_agent_id(new_public_key, model.new_agent_id):
            return False, "new_agent_id derivation mismatch"
        if model.agent_id != model.new_agent_id:
            return False, "agent_id must equal new_agent_id for key rotation"
        if identity_anchor is not None:
            anchor_model = IdentityAnchorCertificate(**identity_anchor)
            if model.old_agent_id != anchor_model.agent_id:
                return False, "old_agent_id does not match identity anchor"
    else:
        return False, "unsupported certificate_type"

    if certificate.get("certificate_version") != PROTOCOL_VERSION:
        return False, "protocol version mismatch"

    signature_b64 = certificate.get("registry_signature_b64")
    if not isinstance(signature_b64, str):
        return False, "missing registry signature"

    signature = base64.b64decode(signature_b64)
    public_key = base64.b64decode(registry_public_key_b64)
    canonical = canonical_certificate_payload_bytes(certificate)
    if not verify_ed25519(signature, canonical, public_key):
        return False, "invalid registry signature"

    return True, "ok"


def verify_certificate_file(
    certificate_path: str,
    *,
    registry_public_key_b64: str,
    identity_anchor_path: str | None = None,
) -> tuple[bool, str]:
    certificate = _load_json(certificate_path)
    anchor = _load_json(identity_anchor_path) if identity_anchor_path else None
    return verify_certificate_dict(
        certificate,
        registry_public_key_b64=registry_public_key_b64,
        identity_anchor=anchor,
    )
