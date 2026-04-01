from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from iap_sdk.actions import (
    ActionReceiptStore,
    IAPOperator,
    action_event_hash,
    canonical_action_receipt_bytes,
    default_actions_dir,
    flush_action_receipts,
    verify_action_receipt_signature,
)
from iap_sdk.certificates import PROTOCOL_VERSION
from iap_sdk.crypto.agent_identity import derive_agent_id
from iap_sdk.errors import ActionReceiptError


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _write_identity(path: Path) -> tuple[str, str]:
    private = Ed25519PrivateKey.generate()
    private_key_bytes = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_key_bytes = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "private_key_b64": _b64(private_key_bytes),
                "public_key_b64": _b64(public_key_bytes),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return derive_agent_id(public_key_bytes), _b64(public_key_bytes)


def _write_state_root(project_root: Path, memory_root: str) -> None:
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


class FakeRegistryClient:
    def __init__(self) -> None:
        private = Ed25519PrivateKey.generate()
        self._private_key = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        self.public_key_b64 = _b64(
            private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        )
        self.latest_receipt: dict | None = None
        self.submissions: list[dict] = []

    def get_public_registry_key(self) -> dict:
        return {"public_key_b64": self.public_key_b64}

    def get_latest_action_receipt(self, agent_id: str) -> dict:
        if self.latest_receipt is None:
            return {
                "agent_id": agent_id,
                "latest_sequence": None,
                "latest_event_hash": None,
                "latest_receipt": None,
            }
        return {
            "agent_id": agent_id,
            "latest_sequence": self.latest_receipt["sequence"],
            "latest_event_hash": self.latest_receipt["event_hash"],
            "latest_receipt": self.latest_receipt,
        }

    def submit_action_receipt(self, payload: dict) -> dict:
        event = payload["event"]
        receipt = {
            "receipt_id": f"receipt-{event['sequence']}",
            "agent_id": event["agent_id"],
            "sequence": event["sequence"],
            "prev_event_hash": event["prev_event_hash"],
            "event_hash": action_event_hash(event),
            "context_root": event["context_root"],
            "timestamp_utc": event["timestamp_utc"],
            "server_timestamp_utc": "2026-04-01T00:00:00Z",
            "action_kind": event["action_kind"],
            "fork_detected": False,
            "conflicting_event_hashes": [],
            "registry_id": "test-registry",
            "protocol_version": PROTOCOL_VERSION,
        }
        signature = Ed25519PrivateKey.from_private_bytes(self._private_key).sign(
            canonical_action_receipt_bytes(receipt)
        )
        receipt["registry_signature_b64"] = _b64(signature)
        self.latest_receipt = receipt
        self.submissions.append(payload)
        return receipt


def test_verify_action_receipt_signature_accepts_valid_receipt() -> None:
    client = FakeRegistryClient()
    receipt = client.submit_action_receipt(
        {
            "event": {
                "agent_id": "ed25519:test-agent",
                "sequence": 1,
                "prev_event_hash": "0" * 64,
                "timestamp_utc": "2026-04-01T00:00:00Z",
                "action_kind": "file",
                "context_root": "a" * 64,
                "action": {
                    "file": {
                        "op": "mkdir",
                        "path": "/tmp/demo",
                    }
                    },
                    "inputs_hash": "b" * 64,
                    "outputs_hash": "c" * 64,
                    "artifacts": [],
                    "event_type": "action_event",
                    "signature": _b64(b"\0" * 64),
                    "amcs_version": "0.0.0",
                    "iap_version": "0.0.0",
                }
            }
        )

    ok, reason = verify_action_receipt_signature(
        receipt,
        registry_public_key_b64=client.public_key_b64,
    )

    assert ok is True
    assert reason == "ok"


def test_flush_action_receipts_submits_new_events_and_persists_receipts(tmp_path: Path) -> None:
    _, public_key_b64 = _write_identity(tmp_path / ".iap" / "identity" / "ed25519.json")
    _write_state_root(tmp_path, "a" * 64)

    operator = IAPOperator.from_project(project_root=tmp_path)
    operator.mkdir(tmp_path / "memory")
    operator.file_write(tmp_path / "memory" / "note.txt", "hello")

    client = FakeRegistryClient()
    result = flush_action_receipts(
        default_actions_dir(tmp_path),
        client=client,
        agent_public_key_b64=public_key_b64,
        registry_public_key_b64=client.public_key_b64,
    )

    receipt_store = ActionReceiptStore(default_actions_dir(tmp_path))
    receipts = receipt_store.read_receipts()

    assert result.submitted_count == 2
    assert result.skipped_local_receipts == 0
    assert result.latest_registry_sequence == 2
    assert len(receipts) == 2
    assert receipts[-1].sequence == 2

    second_result = flush_action_receipts(
        default_actions_dir(tmp_path),
        client=client,
        agent_public_key_b64=public_key_b64,
        registry_public_key_b64=client.public_key_b64,
    )

    assert second_result.submitted_count == 0
    assert second_result.skipped_local_receipts == 2
    assert second_result.latest_registry_sequence == 2


def test_flush_action_receipts_rejects_registry_latest_mismatch(tmp_path: Path) -> None:
    agent_id, public_key_b64 = _write_identity(tmp_path / ".iap" / "identity" / "ed25519.json")
    _write_state_root(tmp_path, "b" * 64)

    operator = IAPOperator.from_project(project_root=tmp_path)
    operator.mkdir(tmp_path / "memory")

    client = FakeRegistryClient()
    bogus = {
        "receipt_id": "receipt-1",
        "agent_id": agent_id,
        "sequence": 1,
        "prev_event_hash": "0" * 64,
        "event_hash": "f" * 64,
        "context_root": "b" * 64,
        "timestamp_utc": "2026-04-01T00:00:00Z",
        "server_timestamp_utc": "2026-04-01T00:00:00Z",
        "action_kind": "file",
        "fork_detected": False,
        "conflicting_event_hashes": [],
        "registry_id": "test-registry",
        "protocol_version": PROTOCOL_VERSION,
    }
    signature = Ed25519PrivateKey.from_private_bytes(client._private_key).sign(
        canonical_action_receipt_bytes(bogus)
    )
    bogus["registry_signature_b64"] = _b64(signature)
    client.latest_receipt = bogus

    with pytest.raises(ActionReceiptError, match="does not match the local action log"):
        flush_action_receipts(
            default_actions_dir(tmp_path),
            client=client,
            agent_public_key_b64=public_key_b64,
            registry_public_key_b64=client.public_key_b64,
        )
