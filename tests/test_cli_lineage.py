from __future__ import annotations

import io
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from iap_sdk.cli.identity import LocalIdentity
from iap_sdk.cli.main import main


def _identity() -> LocalIdentity:
    private = Ed25519PrivateKey.generate()
    private_key_bytes = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_key_bytes = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return LocalIdentity(private_key_bytes=private_key_bytes, public_key_bytes=public_key_bytes)


def test_lineage_request_prefers_project_local_identity_when_present(monkeypatch, tmp_path) -> None:
    out = io.StringIO()
    err = io.StringIO()

    identity = _identity()
    expected_identity = tmp_path / ".iap" / "identity" / "ed25519.json"
    expected_identity.parent.mkdir(parents=True, exist_ok=True)
    expected_identity.write_text("{}", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    def fake_load_identity(path):
        assert Path(path) == expected_identity
        return identity, expected_identity

    monkeypatch.setattr("iap_sdk.cli.main.load_identity", fake_load_identity)

    class _Client:
        def __init__(
            self,
            *,
            base_url: str,
            api_key: str | None = None,
            account_token: str | None = None,
        ) -> None:
            self.base_url = base_url
            self.api_key = api_key
            self.account_token = account_token

        def submit_lineage_request(self, payload: dict) -> dict:
            assert payload["agent_id"] == identity.agent_id
            assert payload["parent_agent_id"] == "ed25519:parent"
            assert payload["fork_event_hash"] == "f" * 64
            return {
                "request_id": "lineage-req-1",
                "status": "WAITING_PAYMENT",
                "lnbits_payment_hash": "hash-lineage",
                "lightning_invoice": "lnbc1...",
                "amount_sats": 21,
            }

    monkeypatch.setattr("iap_sdk.cli.main.RegistryClient", _Client)

    rc = main(
        [
            "lineage",
            "request",
            "--registry-base",
            "http://registry.local",
            "--parent-agent-id",
            "ed25519:parent",
            "--fork-event-hash",
            "f" * 64,
            "--sessions-dir",
            str(tmp_path / "sessions"),
            "--json",
        ],
        stdout=out,
        stderr=err,
    )

    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["request_id"] == "lineage-req-1"
    assert payload["agent_id"] == identity.agent_id
    assert payload["parent_agent_id"] == "ed25519:parent"


def test_lineage_request_project_local_conflicts_with_identity_file(tmp_path) -> None:
    out = io.StringIO()
    err = io.StringIO()
    identity_path = tmp_path / "identity.json"

    rc = main(
        [
            "lineage",
            "request",
            "--project-local",
            "--identity-file",
            str(identity_path),
            "--fork-event-hash",
            "f" * 64,
        ],
        stdout=out,
        stderr=err,
    )

    assert rc == 1
    assert "cannot use --project-local together with --identity-file" in err.getvalue()


def test_lineage_wait_returns_certified_status(monkeypatch) -> None:
    out = io.StringIO()
    err = io.StringIO()

    class _Client:
        def __init__(
            self,
            *,
            base_url: str,
            api_key: str | None = None,
            account_token: str | None = None,
        ) -> None:
            self.base_url = base_url
            self.api_key = api_key
            self.account_token = account_token

        def get_lineage_status(self, request_id: str) -> dict:
            assert request_id == "lineage-req-1"
            return {
                "request_id": request_id,
                "status": "CERTIFIED",
                "paid_at": "2026-03-04T12:00:00Z",
            }

    monkeypatch.setattr("iap_sdk.cli.main.RegistryClient", _Client)

    rc = main(
        [
            "lineage",
            "wait",
            "--registry-base",
            "http://registry.local",
            "--request-id",
            "lineage-req-1",
            "--json",
        ],
        stdout=out,
        stderr=err,
    )

    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["status"] == "CERTIFIED"


def test_lineage_cert_writes_bundle(monkeypatch, tmp_path) -> None:
    out = io.StringIO()
    err = io.StringIO()
    output_file = tmp_path / "lineage_record.json"

    class _Client:
        def __init__(
            self,
            *,
            base_url: str,
            api_key: str | None = None,
            account_token: str | None = None,
        ) -> None:
            self.base_url = base_url
            self.api_key = api_key
            self.account_token = account_token

        def get_lineage_certificate(self, request_id: str) -> dict:
            assert request_id == "lineage-req-1"
            return {"certificate": {"certificate_type": "IAP-Lineage-0.2"}}

    monkeypatch.setattr("iap_sdk.cli.main.RegistryClient", _Client)

    rc = main(
        [
            "lineage",
            "cert",
            "--registry-base",
            "http://registry.local",
            "--request-id",
            "lineage-req-1",
            "--output-file",
            str(output_file),
            "--json",
        ],
        stdout=out,
        stderr=err,
    )

    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["certificate_type"] == "IAP-Lineage-0.2"
    assert output_file.exists()
