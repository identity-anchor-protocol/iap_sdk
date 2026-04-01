from __future__ import annotations

import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from iap_sdk.actions import IAPOperator, summarize_action_chain, verify_action_chain
from iap_sdk.crypto.agent_identity import derive_agent_id


def _write_identity(path: Path) -> tuple[bytes, bytes, str]:
    private = Ed25519PrivateKey.generate()
    private_key_bytes = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_key_bytes = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "private_key_b64": base64.b64encode(private_key_bytes).decode("ascii"),
                "public_key_b64": base64.b64encode(public_key_bytes).decode("ascii"),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return private_key_bytes, public_key_bytes, derive_agent_id(public_key_bytes)


def _write_state_root(project_root: Path, *, memory_root: str = "a" * 64) -> None:
    state_root_path = project_root / ".iap" / "state" / "state_root.json"
    state_root_path.parent.mkdir(parents=True, exist_ok=True)
    state_root_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "agent_id": "unused-for-test",
                "sequence": 0,
                "memory_root": memory_root,
                "status": "ready",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def test_summarize_and_verify_action_chain(tmp_path: Path) -> None:
    _, public_key_bytes, agent_id = _write_identity(tmp_path / ".iap" / "identity" / "ed25519.json")
    _write_state_root(tmp_path, memory_root="b" * 64)
    operator = IAPOperator.from_project(project_root=tmp_path)

    recorded = operator.mkdir(tmp_path / "memory")

    summary = summarize_action_chain(tmp_path / ".iap" / "actions")
    verified = verify_action_chain(
        tmp_path / ".iap" / "actions",
        public_key_bytes=public_key_bytes,
        expected_agent_id=agent_id,
    )

    assert recorded.state.latest_sequence == 1
    assert summary.event_count == 1
    assert summary.latest_sequence == 1
    assert summary.latest_context_root == "b" * 64
    assert summary.index_consistent is True
    assert verified.ok is True
    assert verified.signatures_verified == 1
    assert verified.agent_id == agent_id


def test_verify_action_chain_fails_when_index_missing(tmp_path: Path) -> None:
    _, public_key_bytes, agent_id = _write_identity(tmp_path / ".iap" / "identity" / "ed25519.json")
    _write_state_root(tmp_path, memory_root="c" * 64)
    operator = IAPOperator.from_project(project_root=tmp_path)
    operator.mkdir(tmp_path / "memory")

    index_path = tmp_path / ".iap" / "actions" / "index.json"
    index_path.unlink()

    verified = verify_action_chain(
        tmp_path / ".iap" / "actions",
        public_key_bytes=public_key_bytes,
        expected_agent_id=agent_id,
    )

    assert verified.ok is False
    assert "index.json" in verified.reason

