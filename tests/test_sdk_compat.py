from __future__ import annotations

import warnings

from iap_sdk.requests import build_continuity_request, build_continuity_request_legacy


def test_legacy_builder_emits_deprecation_warning() -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        payload = build_continuity_request_legacy(
            agent_public_key_b64="a",
            agent_id="ed25519:test",
            memory_root="b" * 64,
            sequence=1,
        )
    assert payload["sequence"] == 1
    assert any(isinstance(item.message, DeprecationWarning) for item in caught)


def test_continuity_request_validates_custody_class_in_sdk() -> None:
    payload = build_continuity_request(
        agent_public_key_b64="abc",
        agent_id="ed25519:test",
        memory_root="a" * 64,
        sequence=1,
        manifest_version="IAM-1",
        manifest_hash="b" * 64,
        agent_custody_class="HSM",
    )
    assert payload["agent_custody_class"] == "hsm"
