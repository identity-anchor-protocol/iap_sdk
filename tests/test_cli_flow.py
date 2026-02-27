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


def test_flow_run_end_to_end(monkeypatch, tmp_path) -> None:
    out = io.StringIO()
    err = io.StringIO()
    identity = _identity()

    monkeypatch.setattr(
        "iap_sdk.cli.main.load_or_create_identity",
        lambda path: (identity, True, Path(path or "id")),
    )
    monkeypatch.setattr(
        "iap_sdk.cli.main.get_amcs_root",
        lambda *, amcs_db_path, agent_id: type(
            "_AMCSResult",
            (),
            {
                "agent_id": agent_id,
                "amcs_db_path": amcs_db_path,
                "memory_root": "d" * 64,
                "sequence": 12,
            },
        )(),
    )

    class _Client:
        def __init__(self, *, base_url: str, api_key: str | None = None) -> None:
            self.base_url = base_url
            self.api_key = api_key
            self.calls = 0

        def submit_identity_anchor(self, payload: dict) -> dict:  # noqa: ARG002
            return {"request_id": "req-anchor", "status": "WAITING_PAYMENT"}

        def get_identity_anchor_status(self, request_id: str) -> dict:
            assert request_id == "req-anchor"
            return {
                "status": "WAITING_PAYMENT",
                "lnbits_payment_hash": "anchor-hash",
                "lightning_invoice": "lnbc1anchor",
            }

        def wait_for_identity_anchor(
            self, *, request_id: str, timeout: float, interval: float
        ) -> dict:  # noqa: ARG002
            assert request_id == "req-anchor"
            return {"status": "CERTIFIED"}

        def submit_continuity_request(self, payload: dict) -> dict:
            assert payload["sequence"] == 12
            return {"request_id": "req-flow", "status": "WAITING_PAYMENT"}

        def create_stripe_checkout_session(self, *, request_id: str, **kwargs) -> dict:  # noqa: ARG002
            assert request_id in {"req-anchor", "req-flow"}
            return {
                "session_id": "cs_test_123",
                "checkout_url": "https://checkout.stripe.test/session",
                "payment_status": "unpaid",
            }

        def get_continuity_status(self, request_id: str) -> dict:
            assert request_id == "req-flow"
            self.calls += 1
            if self.calls == 1:
                return {"status": "WAITING_PAYMENT"}
            return {"status": "CERTIFIED", "paid_at": "2026-02-22T00:00:00Z"}

        def get_continuity_certificate(self, request_id: str) -> dict:
            assert request_id == "req-flow"
            return {
                "request_id": request_id,
                "certificate": {"certificate_type": "IAP-Continuity-0.2"},
                "signature_b64": "sig",
                "public_key_b64": "pub",
                "witnesses": [],
            }

        def get_public_registry_key(self) -> dict:
            return {"public_key_b64": "reg_pub_key"}

    monkeypatch.setattr("iap_sdk.cli.main.RegistryClient", _Client)
    monkeypatch.setattr("iap_sdk.cli.main.verify_certificate_file", lambda *a, **k: (True, "ok"))
    monkeypatch.setattr("iap_sdk.cli.main.time.sleep", lambda _seconds: None)

    output_dir = tmp_path / "flow-output"
    rc = main(
        [
            "flow",
            "run",
            "--registry-base",
            "http://registry.local",
            "--output-dir",
            str(output_dir),
            "--json",
            "--poll-seconds",
            "1",
            "--request-timeout-seconds",
            "10",
        ],
        stdout=out,
        stderr=err,
    )

    assert rc == 0
    payload = json.loads(out.getvalue().splitlines()[-1])
    assert payload["request_id"] == "req-flow"
    assert payload["status"] == "CERTIFIED"
    assert payload["payment"]["method"] == "stripe"
    assert (output_dir / "req-flow.json").exists()
    assert (output_dir / "certificate.json").exists()
    assert (output_dir / "flow_summary.json").exists()
    assert "Step 1/8" in out.getvalue()
    assert err.getvalue().startswith("[beta]")


def test_flow_run_verification_failure(monkeypatch, tmp_path) -> None:
    out = io.StringIO()
    err = io.StringIO()
    identity = _identity()

    monkeypatch.setattr(
        "iap_sdk.cli.main.load_or_create_identity",
        lambda path: (identity, False, Path(path or "id")),
    )
    monkeypatch.setattr(
        "iap_sdk.cli.main.get_amcs_root",
        lambda *, amcs_db_path, agent_id: type(
            "_AMCSResult",
            (),
            {
                "agent_id": agent_id,
                "amcs_db_path": amcs_db_path,
                "memory_root": "f" * 64,
                "sequence": 2,
            },
        )(),
    )

    class _Client:
        def __init__(self, *, base_url: str, api_key: str | None = None) -> None:
            self.base_url = base_url
            self.api_key = api_key

        def submit_identity_anchor(self, payload: dict) -> dict:  # noqa: ARG002
            return {"request_id": "req-anchor", "status": "WAITING_PAYMENT"}

        def get_identity_anchor_status(self, request_id: str) -> dict:
            return {
                "status": "WAITING_PAYMENT",
                "lnbits_payment_hash": "anchor-hash",
                "lightning_invoice": "lnbc1anchor",
            }

        def wait_for_identity_anchor(
            self, *, request_id: str, timeout: float, interval: float
        ) -> dict:  # noqa: ARG002
            return {"status": "CERTIFIED"}

        def submit_continuity_request(self, payload: dict) -> dict:  # noqa: ARG002
            return {"request_id": "req-fail", "status": "WAITING_PAYMENT"}

        def create_stripe_checkout_session(self, *, request_id: str, **kwargs) -> dict:  # noqa: ARG002
            assert request_id in {"req-anchor", "req-fail"}
            return {"session_id": "cs_test_123", "checkout_url": "https://checkout"}

        def get_continuity_status(self, request_id: str) -> dict:  # noqa: ARG002
            return {"status": "CERTIFIED", "paid_at": "2026-02-22T00:00:00Z"}

        def get_continuity_certificate(self, request_id: str) -> dict:  # noqa: ARG002
            return {
                "request_id": "req-fail",
                "certificate": {"certificate_type": "IAP-Continuity-0.2"},
                "signature_b64": "sig",
                "public_key_b64": "pub",
                "witnesses": [],
            }

        def get_public_registry_key(self) -> dict:
            return {"public_key_b64": "reg_pub_key"}

    monkeypatch.setattr("iap_sdk.cli.main.RegistryClient", _Client)
    monkeypatch.setattr(
        "iap_sdk.cli.main.verify_certificate_file",
        lambda *a, **k: (False, "bad sig"),
    )

    rc = main(
        ["flow", "run", "--output-dir", str(tmp_path / "flow-out")],
        stdout=out,
        stderr=err,
    )

    assert rc == 4
    assert "verification failed: bad sig" in err.getvalue()
