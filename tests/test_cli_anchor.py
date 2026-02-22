from __future__ import annotations

import io
import json

from iap_sdk.cli.identity import IdentityError
from iap_sdk.cli.main import main
from iap_sdk.errors import RegistryUnavailableError


class _Identity:
    agent_id = "ed25519:test-agent"
    public_key_b64 = "PUBKEY"


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
                "certificate_type": "IAP-Identity-0.1",
                "agent_id": payload["agent_id"],
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
    assert payload["already_exists"] is False
    assert payload["certificate"]["certificate_type"] == "IAP-Identity-0.1"
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
    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["already_exists"] is True


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
