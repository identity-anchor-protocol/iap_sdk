"""SDK verification helpers with profile-based checks."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Literal

from iap_sdk.certificates import CONTINUITY_TYPE, KEY_ROTATION_TYPE
from iap_sdk.crypto.agent_identity import decode_b64
from iap_sdk.crypto.ed25519_verify import verify_ed25519
from iap_sdk.offline_verify import canonical_certificate_payload_bytes, verify_certificate_dict

_ALLOWED_MANIFEST_VERSIONS = {"IAM-1"}
_MANIFEST_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


VerifyProfile = Literal["basic", "strict"]


def _load_json(path: str | None) -> dict | None:
    if path is None:
        return None
    return json.loads(Path(path).read_text(encoding="utf-8"))


def verify_certificate(
    certificate: dict,
    *,
    registry_public_key_b64: str,
    profile: VerifyProfile = "basic",
    identity_anchor: dict | None = None,
    previous_certificate: dict | None = None,
    witness_bundle: list[dict] | None = None,
    min_witnesses: int = 0,
) -> tuple[bool, str]:
    effective_identity_anchor = identity_anchor
    if (
        certificate.get("certificate_type") == CONTINUITY_TYPE
        and previous_certificate is not None
        and previous_certificate.get("certificate_type") == KEY_ROTATION_TYPE
    ):
        new_agent_id = previous_certificate.get("new_agent_id")
        new_agent_public_key_b64 = previous_certificate.get("new_agent_public_key_b64")
        if isinstance(new_agent_id, str) and isinstance(new_agent_public_key_b64, str):
            effective_identity_anchor = {
                "certificate_version": "IAP-0.1",
                "certificate_type": "IAP-Identity-0.1",
                "agent_id": new_agent_id,
                "agent_public_key_b64": new_agent_public_key_b64,
                "issued_at": previous_certificate.get("issued_at", ""),
                "registry_id": previous_certificate.get("registry_id", ""),
                "registry_signature_b64": "derived-for-strict-verification",
            }

    ok, reason = verify_certificate_dict(
        certificate,
        registry_public_key_b64=registry_public_key_b64,
        identity_anchor=effective_identity_anchor,
    )
    if not ok:
        return ok, reason

    if profile == "basic":
        return True, "ok"
    if profile != "strict":
        return False, "unsupported verify profile"

    if min_witnesses < 0:
        return False, "min_witnesses must be >= 0"

    def _enforce_witness_policy() -> tuple[bool, str]:
        if min_witnesses == 0:
            return True, "ok"
        witnesses = witness_bundle or []
        canonical = canonical_certificate_payload_bytes(certificate)
        valid = 0
        for witness in witnesses:
            witness_pub = witness.get("witness_public_key_b64")
            witness_sig = witness.get("witness_signature_b64")
            if not isinstance(witness_pub, str) or not isinstance(witness_sig, str):
                continue
            try:
                if verify_ed25519(decode_b64(witness_sig), canonical, decode_b64(witness_pub)):
                    valid += 1
            except Exception:  # pragma: no cover
                continue
        if valid < min_witnesses:
            return False, "insufficient valid witnesses"
        return True, "ok"

    if certificate.get("certificate_type") != CONTINUITY_TYPE:
        return True, "ok"

    metadata = certificate.get("metadata")
    if not isinstance(metadata, dict):
        return False, "manifest metadata missing"

    manifest_version = metadata.get("manifest_version")
    if manifest_version not in _ALLOWED_MANIFEST_VERSIONS:
        return False, "unsupported manifest_version"

    manifest_hash = metadata.get("manifest_hash")
    if not isinstance(manifest_hash, str) or not _MANIFEST_HASH_RE.fullmatch(manifest_hash):
        return False, "invalid manifest_hash"

    if previous_certificate is None:
        return _enforce_witness_policy()

    prev_ok, prev_reason = verify_certificate_dict(
        previous_certificate,
        registry_public_key_b64=registry_public_key_b64,
        identity_anchor=identity_anchor,
    )
    if not prev_ok:
        return False, f"previous certificate invalid: {prev_reason}"

    previous_type = previous_certificate.get("certificate_type")
    if previous_type == CONTINUITY_TYPE:
        if previous_certificate.get("agent_id") != certificate.get("agent_id"):
            return False, "previous certificate agent mismatch"

        prev_seq = previous_certificate.get("ledger_sequence")
        curr_seq = certificate.get("ledger_sequence")
        if not isinstance(prev_seq, int) or not isinstance(curr_seq, int):
            return False, "ledger sequence missing"
        if curr_seq <= prev_seq:
            return False, "ledger sequence not monotonic"
        if curr_seq != prev_seq + 1:
            return False, "ledger sequence gap"
    elif previous_type == KEY_ROTATION_TYPE:
        if previous_certificate.get("new_agent_id") != certificate.get("agent_id"):
            return False, "key rotation new_agent_id does not match continuity agent_id"
        curr_seq = certificate.get("ledger_sequence")
        if not isinstance(curr_seq, int) or curr_seq < 1:
            return False, "ledger sequence missing"
    else:
        return False, "previous certificate must be continuity or key rotation"

    return _enforce_witness_policy()


def verify_certificate_file(
    certificate_path: str,
    *,
    registry_public_key_b64: str,
    profile: VerifyProfile = "basic",
    identity_anchor_path: str | None = None,
    previous_certificate_path: str | None = None,
    witness_bundle: list[dict] | None = None,
    min_witnesses: int = 0,
) -> tuple[bool, str]:
    certificate = _load_json(certificate_path)
    if certificate is None:
        return False, "certificate not found"

    identity_anchor = _load_json(identity_anchor_path)
    previous_certificate = _load_json(previous_certificate_path)

    return verify_certificate(
        certificate,
        registry_public_key_b64=registry_public_key_b64,
        profile=profile,
        identity_anchor=identity_anchor,
        previous_certificate=previous_certificate,
        witness_bundle=witness_bundle,
        min_witnesses=min_witnesses,
    )


def verify_key_rotation_certificate(
    certificate: dict,
    *,
    registry_public_key_b64: str,
    identity_anchor: dict | None = None,
) -> tuple[bool, str]:
    if certificate.get("certificate_type") != KEY_ROTATION_TYPE:
        return False, "not a key rotation certificate"
    return verify_certificate(
        certificate,
        registry_public_key_b64=registry_public_key_b64,
        profile="basic",
        identity_anchor=identity_anchor,
    )
