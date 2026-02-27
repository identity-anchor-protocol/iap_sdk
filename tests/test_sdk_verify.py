from __future__ import annotations

import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from iap_sdk.certificates import CONTINUITY_TYPE, IDENTITY_TYPE, KEY_ROTATION_TYPE, PROTOCOL_VERSION
from iap_sdk.crypto.agent_identity import derive_agent_id
from iap_sdk.offline_verify import canonical_certificate_payload_bytes
from iap_sdk.verify import verify_certificate, verify_certificate_file


def _sign(private: Ed25519PrivateKey, cert: dict) -> dict:
    payload = dict(cert)
    payload.pop("registry_signature_b64", None)
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return {
        **payload,
        "registry_signature_b64": base64.b64encode(private.sign(canonical)).decode("ascii"),
    }


def _certs() -> tuple[str, dict, dict, dict, dict, dict]:
    registry_private = Ed25519PrivateKey.generate()
    registry_public_b64 = base64.b64encode(
        registry_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")

    agent_private = Ed25519PrivateKey.generate()
    agent_public = agent_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    agent_id = derive_agent_id(agent_public)

    anchor = _sign(
        registry_private,
        {
            "certificate_version": PROTOCOL_VERSION,
            "certificate_type": IDENTITY_TYPE,
            "agent_id": agent_id,
            "agent_public_key_b64": base64.b64encode(agent_public).decode("ascii"),
            "issued_at": "2026-02-22T00:00:00Z",
            "registry_id": "iap-registry-test",
            "metadata": {"agent_name": "Atlas"},
        },
    )

    continuity_1 = _sign(
        registry_private,
        {
            "certificate_version": PROTOCOL_VERSION,
            "certificate_type": CONTINUITY_TYPE,
            "agent_id": agent_id,
            "memory_root": "a" * 64,
            "ledger_sequence": 1,
            "issued_at": "2026-02-22T00:00:01Z",
            "payment_reference": "lnbits:hash-1",
            "registry_id": "iap-registry-test",
            "metadata": {
                "agent_name": "Atlas",
                "manifest_version": "IAM-1",
                "manifest_hash": "b" * 64,
            },
        },
    )

    continuity_2 = _sign(
        registry_private,
        {
            **continuity_1,
            "ledger_sequence": 2,
            "issued_at": "2026-02-22T00:00:02Z",
            "payment_reference": "lnbits:hash-2",
        },
    )
    continuity_3 = _sign(
        registry_private,
        {
            **continuity_1,
            "ledger_sequence": 3,
            "issued_at": "2026-02-22T00:00:03Z",
            "payment_reference": "lnbits:hash-3",
        },
    )

    continuity_no_manifest = _sign(
        registry_private,
        {
            "certificate_version": PROTOCOL_VERSION,
            "certificate_type": CONTINUITY_TYPE,
            "agent_id": agent_id,
            "memory_root": "c" * 64,
            "ledger_sequence": 2,
            "issued_at": "2026-02-22T00:00:09Z",
            "payment_reference": "lnbits:hash-x",
            "registry_id": "iap-registry-test",
            "metadata": {"agent_name": "Atlas"},
        },
    )

    return (
        registry_public_b64,
        anchor,
        continuity_1,
        continuity_2,
        continuity_3,
        continuity_no_manifest,
    )


def test_strict_profile_accepts_valid_continuity_chain() -> None:
    registry_public_b64, anchor, continuity_1, continuity_2, _, _ = _certs()

    ok, reason = verify_certificate(
        continuity_2,
        registry_public_key_b64=registry_public_b64,
        identity_anchor=anchor,
        profile="strict",
        previous_certificate=continuity_1,
    )
    assert ok is True
    assert reason == "ok"


def test_strict_fails_when_basic_passes_on_missing_manifest() -> None:
    registry_public_b64, anchor, _, _, _, continuity_no_manifest = _certs()

    basic_ok, _ = verify_certificate(
        continuity_no_manifest,
        registry_public_key_b64=registry_public_b64,
        identity_anchor=anchor,
        profile="basic",
    )
    strict_ok, strict_reason = verify_certificate(
        continuity_no_manifest,
        registry_public_key_b64=registry_public_b64,
        identity_anchor=anchor,
        profile="strict",
    )

    assert basic_ok is True
    assert strict_ok is False
    assert strict_reason == "unsupported manifest_version"


def test_strict_fails_on_sequence_gap() -> None:
    registry_public_b64, anchor, continuity_1, _, continuity_3, _ = _certs()

    basic_ok, _ = verify_certificate(
        continuity_3,
        registry_public_key_b64=registry_public_b64,
        identity_anchor=anchor,
        profile="basic",
        previous_certificate=continuity_1,
    )
    strict_ok, strict_reason = verify_certificate(
        continuity_3,
        registry_public_key_b64=registry_public_b64,
        identity_anchor=anchor,
        profile="strict",
        previous_certificate=continuity_1,
    )

    assert basic_ok is True
    assert strict_ok is False
    assert strict_reason == "ledger sequence gap"


def test_strict_accepts_continuity_after_key_rotation_certificate() -> None:
    registry_private = Ed25519PrivateKey.generate()
    registry_public_b64 = base64.b64encode(
        registry_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")
    old_private = Ed25519PrivateKey.generate()
    old_public = old_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    new_private = Ed25519PrivateKey.generate()
    new_public = new_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    old_agent_id = derive_agent_id(old_public)
    new_agent_id = derive_agent_id(new_public)

    anchor = _sign(
        registry_private,
        {
            "certificate_version": PROTOCOL_VERSION,
            "certificate_type": IDENTITY_TYPE,
            "agent_id": old_agent_id,
            "agent_public_key_b64": base64.b64encode(old_public).decode("ascii"),
            "issued_at": "2026-02-22T00:00:00Z",
            "registry_id": "iap-registry-test",
        },
    )
    key_rotation = _sign(
        registry_private,
        {
            "certificate_version": PROTOCOL_VERSION,
            "certificate_type": KEY_ROTATION_TYPE,
            "agent_id": new_agent_id,
            "old_agent_id": old_agent_id,
            "new_agent_id": new_agent_id,
            "old_agent_public_key_b64": base64.b64encode(old_public).decode("ascii"),
            "new_agent_public_key_b64": base64.b64encode(new_public).decode("ascii"),
            "issued_at": "2026-02-22T00:00:01Z",
            "registry_id": "iap-registry-test",
        },
    )
    continuity_new = _sign(
        registry_private,
        {
            "certificate_version": PROTOCOL_VERSION,
            "certificate_type": CONTINUITY_TYPE,
            "agent_id": new_agent_id,
            "memory_root": "a" * 64,
            "ledger_sequence": 1,
            "issued_at": "2026-02-22T00:00:02Z",
            "payment_reference": "lnbits:hash-1",
            "registry_id": "iap-registry-test",
            "metadata": {"manifest_version": "IAM-1", "manifest_hash": "b" * 64},
        },
    )

    ok, reason = verify_certificate(
        continuity_new,
        registry_public_key_b64=registry_public_b64,
        identity_anchor=anchor,
        profile="strict",
        previous_certificate=key_rotation,
    )
    assert ok is True
    assert reason == "ok"


def test_strict_witness_policy_enforced() -> None:
    registry_public_b64, anchor, continuity_1, _, _, _ = _certs()
    witness_private = Ed25519PrivateKey.generate()
    witness_public_b64 = base64.b64encode(
        witness_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")
    witness_signature_b64 = base64.b64encode(
        witness_private.sign(canonical_certificate_payload_bytes(continuity_1))
    ).decode("ascii")
    witness_bundle = [
        {
            "witness_id": "w1",
            "witness_public_key_b64": witness_public_b64,
            "witness_signature_b64": witness_signature_b64,
        }
    ]

    strict_ok, strict_reason = verify_certificate(
        continuity_1,
        registry_public_key_b64=registry_public_b64,
        identity_anchor=anchor,
        profile="strict",
        witness_bundle=witness_bundle,
        min_witnesses=2,
    )
    assert strict_ok is False
    assert strict_reason == "insufficient valid witnesses"

    strict_ok_2, strict_reason_2 = verify_certificate(
        continuity_1,
        registry_public_key_b64=registry_public_b64,
        identity_anchor=anchor,
        profile="strict",
        witness_bundle=witness_bundle,
        min_witnesses=1,
    )
    assert strict_ok_2 is True
    assert strict_reason_2 == "ok"


def test_verify_certificate_file_accepts_bundle_payload(tmp_path: Path) -> None:
    registry_public_b64, anchor, continuity_1, _, _, _ = _certs()

    cert_bundle_path = tmp_path / "continuity_record.json"
    cert_bundle_path.write_text(
        json.dumps(
            {
                "request_id": "r1",
                "certificate": continuity_1,
                "signature_b64": "unused",
                "public_key_b64": "unused",
            }
        ),
        encoding="utf-8",
    )
    anchor_bundle_path = tmp_path / "identity_anchor.json"
    anchor_bundle_path.write_text(
        json.dumps(
            {
                "request_id": "a1",
                "certificate": anchor,
            }
        ),
        encoding="utf-8",
    )

    ok, reason = verify_certificate_file(
        str(cert_bundle_path),
        registry_public_key_b64=registry_public_b64,
        profile="strict",
        identity_anchor_path=str(anchor_bundle_path),
    )
    assert ok is True
    assert reason == "ok"
