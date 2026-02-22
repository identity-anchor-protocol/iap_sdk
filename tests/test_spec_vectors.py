from __future__ import annotations

import json
from pathlib import Path

import pytest

from iap_sdk.offline_verify import verify_certificate_dict

VECTOR_DIR = Path(__file__).parent / "spec_vectors"


def _vector_files() -> list[Path]:
    return sorted(VECTOR_DIR.glob("*.json"))


@pytest.mark.parametrize("vector_path", _vector_files(), ids=lambda p: p.stem)
def test_offline_verify_spec_vectors(vector_path: Path) -> None:
    vector = json.loads(vector_path.read_text(encoding="utf-8"))

    certificate = vector["certificate"]
    registry_public_key_b64 = vector["registry_public_key_b64"]
    identity_anchor = vector.get("identity_anchor")

    exception_contains = vector.get("expect_exception_contains")
    if exception_contains is not None:
        with pytest.raises(Exception) as exc_info:
            verify_certificate_dict(
                certificate,
                registry_public_key_b64=registry_public_key_b64,
                identity_anchor=identity_anchor,
            )
        assert exception_contains in str(exc_info.value)
        return

    ok, reason = verify_certificate_dict(
        certificate,
        registry_public_key_b64=registry_public_key_b64,
        identity_anchor=identity_anchor,
    )
    assert ok is vector["expect_ok"]

    expected_reason = vector.get("expect_reason")
    if expected_reason is not None:
        assert reason == expected_reason

    expected_reason_contains = vector.get("expect_reason_contains")
    if expected_reason_contains is not None:
        assert expected_reason_contains in reason
