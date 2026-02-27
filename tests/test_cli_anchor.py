from __future__ import annotations

import io
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from iap_sdk.cli.identity import IdentityError
from iap_sdk.cli.main import main
from iap_sdk.errors import RegistryUnavailableError


class _Identity:
    _private = Ed25519PrivateKey.generate()
    agent_id = "ed25519:test-agent"
    public_key_b64 = "PUBKEY"
    private_key_bytes = _private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def test_anchor_issue_success_json(monkeypatch) -> None:
    out = io.StringIO()
    err = io.StringIO()

    monkeypatch.setattr("iap_sdk.cli.main.load_identity", lambda path: (_Identity(), path))

    class _Client:
        def __init__(self, *, base_url: str) -> None:
            self.base_url = base_url

        def submit_identity_anchor(self, payload: dict) -> dict:
            assert payload["agent_id"] == "ed25519:test-agent"
            assert payload["metadata"]["agent_name"] == "Atlas"
            return {
                "request_id": "req-anchor-1",
                "status": "WAITING_PAYMENT",
            }

        def create_stripe_checkout_session(self, *, request_id: str, **kwargs) -> dict:  # noqa: ARG002
            assert request_id == "req-anchor-1"
            return {
                "session_id": "cs_anchor_1",
                "checkout_url": "https://checkout",
                "payment_status": "unpaid",
            }

    monkeypatch.setattr("iap_sdk.cli.main.RegistryClient", _Client)

    rc = main(
        [
            "anchor",
            "issue",
            "--registry-base",
            "http://registry.local",
            "--agent-name",
            "Atlas",
            "--json",
        ],
        stdout=out,
        stderr=err,
    )
    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["request_id"] == "req-anchor-1"
    assert payload["payment"]["payment_method"] == "stripe"
    assert err.getvalue().startswith("[beta]")


def test_anchor_issue_handles_existing(monkeypatch) -> None:
    out = io.StringIO()
    err = io.StringIO()

    monkeypatch.setattr("iap_sdk.cli.main.load_identity", lambda path: (_Identity(), path))

    class _Client:
        def __init__(self, *, base_url: str) -> None:
            self.base_url = base_url

        def submit_identity_anchor(self, payload: dict) -> dict:  # noqa: ARG002
            raise RegistryUnavailableError("registry request failed: 409 already exists")

    monkeypatch.setattr("iap_sdk.cli.main.RegistryClient", _Client)

    rc = main(["anchor", "issue", "--json"], stdout=out, stderr=err)
    assert rc == 2
    assert "registry error:" in err.getvalue()


def test_anchor_issue_registry_failure(monkeypatch) -> None:
    out = io.StringIO()
    err = io.StringIO()

    monkeypatch.setattr("iap_sdk.cli.main.load_identity", lambda path: (_Identity(), path))

    class _Client:
        def __init__(self, *, base_url: str) -> None:
            self.base_url = base_url

        def submit_identity_anchor(self, payload: dict) -> dict:  # noqa: ARG002
            raise RegistryUnavailableError("registry request failed: 503 service unavailable")

    monkeypatch.setattr("iap_sdk.cli.main.RegistryClient", _Client)

    rc = main(["anchor", "issue"], stdout=out, stderr=err)
    assert rc == 2
    assert "registry error:" in err.getvalue()


def test_anchor_issue_missing_identity(monkeypatch) -> None:
    out = io.StringIO()
    err = io.StringIO()

    def fail_load(path):
        raise IdentityError("identity file not found")

    monkeypatch.setattr("iap_sdk.cli.main.load_identity", fail_load)

    rc = main(["anchor", "issue"], stdout=out, stderr=err)
    assert rc == 1
    assert "identity error:" in err.getvalue()


def test_anchor_issue_uses_config_agent_name(monkeypatch, tmp_path) -> None:
    out = io.StringIO()
    err = io.StringIO()
    config_path = tmp_path / "config.toml"
    config_path.write_text("[cli]\nagent_name = \"Configured Atlas\"\n", encoding="utf-8")

    monkeypatch.setattr("iap_sdk.cli.main.load_identity", lambda path: (_Identity(), path))

    class _Client:
        def __init__(self, *, base_url: str) -> None:
            self.base_url = base_url

        def submit_identity_anchor(self, payload: dict) -> dict:
            assert payload["metadata"]["agent_name"] == "Configured Atlas"
            return {"request_id": "req-anchor-2", "status": "WAITING_PAYMENT"}

        def create_stripe_checkout_session(self, *, request_id: str, **kwargs) -> dict:  # noqa: ARG002
            return {"session_id": "cs_anchor_2", "checkout_url": "https://checkout"}

    monkeypatch.setattr("iap_sdk.cli.main.RegistryClient", _Client)

    rc = main(
        ["--config", str(config_path), "anchor", "issue", "--json"],
        stdout=out,
        stderr=err,
    )
    assert rc == 0


def test_anchor_cert_writes_bundle(monkeypatch, tmp_path) -> None:
    out = io.StringIO()
    err = io.StringIO()
    output_file = tmp_path / "identity_anchor_record.json"

    class _Client:
        def __init__(self, *, base_url: str) -> None:
            self.base_url = base_url

        def get_identity_anchor_certificate(self, request_id: str) -> dict:
            assert request_id == "anchor-req-1"
            return {
                "request_id": request_id,
                "certificate": {"certificate_type": "IAP-Identity-0.1"},
            }

    monkeypatch.setattr("iap_sdk.cli.main.RegistryClient", _Client)

    rc = main(
        [
            "anchor",
            "cert",
            "--request-id",
            "anchor-req-1",
            "--output-file",
            str(output_file),
            "--json",
        ],
        stdout=out,
        stderr=err,
    )
    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["certificate_type"] == "IAP-Identity-0.1"
    assert output_file.exists()
