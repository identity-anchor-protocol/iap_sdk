from __future__ import annotations

import base64
import io
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from iap_sdk.actions import IAPOperator, action_event_hash, canonical_action_receipt_bytes
from iap_sdk.certificates import PROTOCOL_VERSION
from iap_sdk.cli.main import main


def _set_state_root_memory_root(project_root, memory_root: str) -> None:
    state_root_path = project_root / ".iap" / "state" / "state_root.json"
    payload = json.loads(state_root_path.read_text(encoding="utf-8"))
    payload["memory_root"] = memory_root
    state_root_path.write_text(
        json.dumps(payload, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


class _FakeRegistryClient:
    def __init__(self) -> None:
        private = Ed25519PrivateKey.generate()
        self._private_key = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        self.public_key_b64 = _b64(
            private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        )
        self.latest_receipt: dict | None = None

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
        return receipt


def test_actions_status_json_reports_latest_event(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    init_out = io.StringIO()
    init_err = io.StringIO()
    assert main(["init", "--project-local", "--json"], stdout=init_out, stderr=init_err) == 0
    _set_state_root_memory_root(tmp_path, "a" * 64)

    operator = IAPOperator.from_project(project_root=tmp_path)
    operator.mkdir(tmp_path / "memory")

    out = io.StringIO()
    err = io.StringIO()
    rc = main(["actions", "status", "--json"], stdout=out, stderr=err)

    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["event_count"] == 1
    assert payload["latest_sequence"] == 1
    assert payload["latest_context_root"] == "a" * 64
    assert payload["index_consistent"] is True


def test_actions_verify_json_succeeds_for_project_local_identity(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    init_out = io.StringIO()
    init_err = io.StringIO()
    assert main(["init", "--project-local", "--json"], stdout=init_out, stderr=init_err) == 0
    _set_state_root_memory_root(tmp_path, "b" * 64)

    operator = IAPOperator.from_project(project_root=tmp_path)
    operator.file_write(tmp_path / "note.txt", "hello")

    out = io.StringIO()
    err = io.StringIO()
    rc = main(["actions", "verify", "--project-local", "--json"], stdout=out, stderr=err)

    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["ok"] is True
    assert payload["signatures_verified"] == 1
    assert payload["latest_context_root"] == "b" * 64


def test_actions_verify_returns_exit_4_when_log_is_tampered(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    init_out = io.StringIO()
    init_err = io.StringIO()
    assert main(["init", "--project-local", "--json"], stdout=init_out, stderr=init_err) == 0
    _set_state_root_memory_root(tmp_path, "c" * 64)

    operator = IAPOperator.from_project(project_root=tmp_path)
    operator.mkdir(tmp_path / "memory")

    log_path = tmp_path / ".iap" / "actions" / "actions.log"
    lines = log_path.read_text(encoding="utf-8").splitlines()
    payload = json.loads(lines[0])
    payload["action"]["file"]["path"] = str(tmp_path / "tampered")
    lines[0] = json.dumps(payload, sort_keys=True)
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    out = io.StringIO()
    err = io.StringIO()
    rc = main(["actions", "verify", "--project-local"], stdout=out, stderr=err)

    assert rc == 4
    assert "index.json does not match replayed action log" in out.getvalue()


def test_actions_flush_json_submits_receipts(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    init_out = io.StringIO()
    init_err = io.StringIO()
    assert main(["init", "--project-local", "--json"], stdout=init_out, stderr=init_err) == 0
    _set_state_root_memory_root(tmp_path, "d" * 64)

    operator = IAPOperator.from_project(project_root=tmp_path)
    operator.file_write(tmp_path / "note.txt", "hello")

    fake_client = _FakeRegistryClient()
    monkeypatch.setattr("iap_sdk.cli.main._build_registry_client", lambda **_: fake_client)

    out = io.StringIO()
    err = io.StringIO()
    rc = main(["actions", "flush", "--project-local", "--json"], stdout=out, stderr=err)

    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["submitted_count"] == 1
    assert payload["latest_registry_sequence"] == 1
    assert payload["registry_public_key_source"] == "registry"
    assert (tmp_path / ".iap" / "actions" / "receipts.log").exists()


def test_actions_verify_json_reports_receipt_verification(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    init_out = io.StringIO()
    init_err = io.StringIO()
    assert main(["init", "--project-local", "--json"], stdout=init_out, stderr=init_err) == 0
    _set_state_root_memory_root(tmp_path, "e" * 64)

    operator = IAPOperator.from_project(project_root=tmp_path)
    operator.file_write(tmp_path / "note.txt", "hello")

    fake_client = _FakeRegistryClient()
    monkeypatch.setattr("iap_sdk.cli.main._build_registry_client", lambda **_: fake_client)

    flush_out = io.StringIO()
    flush_err = io.StringIO()
    assert (
        main(["actions", "flush", "--project-local", "--json"], stdout=flush_out, stderr=flush_err)
        == 0
    )

    out = io.StringIO()
    err = io.StringIO()
    rc = main(
        [
            "actions",
            "verify",
            "--project-local",
            "--registry-public-key-b64",
            fake_client.public_key_b64,
            "--json",
        ],
        stdout=out,
        stderr=err,
    )

    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["ok"] is True
    assert payload["receipt_count"] == 1
    assert payload["receipt_log_consistent"] is True
    assert payload["receipt_coverage_complete"] is True
    assert payload["receipt_signatures_verified"] == 1
