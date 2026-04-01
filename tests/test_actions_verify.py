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

from iap_sdk.actions import (
    IAPOperator,
    action_event_hash,
    canonical_action_receipt_bytes,
    flush_action_receipts,
    summarize_action_chain,
    verify_action_chain,
)
from iap_sdk.certificates import PROTOCOL_VERSION
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


class FakeRegistryClient:
    def __init__(self) -> None:
        private = Ed25519PrivateKey.generate()
        self._private_key = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        self.public_key_b64 = base64.b64encode(
            private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode("ascii")
        self.latest_receipt: dict | None = None

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
        receipt["registry_signature_b64"] = base64.b64encode(signature).decode("ascii")
        self.latest_receipt = receipt
        return receipt


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
    assert summary.receipt_count == 0
    assert summary.receipt_coverage_complete is False
    assert verified.ok is True
    assert verified.signatures_verified == 1
    assert verified.receipt_count == 0
    assert verified.receipt_coverage_complete is False
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


def test_verify_action_chain_checks_local_receipts_when_present(tmp_path: Path) -> None:
    _, public_key_bytes, agent_id = _write_identity(tmp_path / ".iap" / "identity" / "ed25519.json")
    _write_state_root(tmp_path, memory_root="d" * 64)
    operator = IAPOperator.from_project(project_root=tmp_path)
    operator.mkdir(tmp_path / "memory")

    client = FakeRegistryClient()
    flush_action_receipts(
        tmp_path / ".iap" / "actions",
        client=client,
        agent_public_key_b64=base64.b64encode(public_key_bytes).decode("ascii"),
        registry_public_key_b64=client.public_key_b64,
    )

    summary = summarize_action_chain(tmp_path / ".iap" / "actions")
    verified = verify_action_chain(
        tmp_path / ".iap" / "actions",
        public_key_bytes=public_key_bytes,
        expected_agent_id=agent_id,
        registry_public_key_b64=client.public_key_b64,
    )

    assert summary.receipt_count == 1
    assert summary.receipt_log_consistent is True
    assert summary.receipt_coverage_complete is True
    assert verified.ok is True
    assert verified.receipt_count == 1
    assert verified.receipt_log_consistent is True
    assert verified.receipt_signatures_verified == 1


def test_verify_action_chain_fails_when_receipt_is_tampered(tmp_path: Path) -> None:
    _, public_key_bytes, agent_id = _write_identity(tmp_path / ".iap" / "identity" / "ed25519.json")
    _write_state_root(tmp_path, memory_root="e" * 64)
    operator = IAPOperator.from_project(project_root=tmp_path)
    operator.mkdir(tmp_path / "memory")

    client = FakeRegistryClient()
    flush_action_receipts(
        tmp_path / ".iap" / "actions",
        client=client,
        agent_public_key_b64=base64.b64encode(public_key_bytes).decode("ascii"),
        registry_public_key_b64=client.public_key_b64,
    )

    receipts_path = tmp_path / ".iap" / "actions" / "receipts.log"
    payload = json.loads(receipts_path.read_text(encoding="utf-8").splitlines()[0])
    payload["context_root"] = "f" * 64
    receipts_path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")

    verified = verify_action_chain(
        tmp_path / ".iap" / "actions",
        public_key_bytes=public_key_bytes,
        expected_agent_id=agent_id,
        registry_public_key_b64=client.public_key_b64,
    )

    assert verified.ok is False
    assert "receipt sequence 1 context_root does not match local action log" == verified.reason
