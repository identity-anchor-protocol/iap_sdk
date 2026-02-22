from __future__ import annotations

import io

from iap_sdk.cli.main import main
from iap_sdk.errors import RegistryUnavailableError


def test_registry_error_redacts_query_secret(monkeypatch) -> None:
    out = io.StringIO()
    err = io.StringIO()

    class _Client:
        def __init__(self, *, base_url: str) -> None:  # noqa: ARG002
            pass

        def create_stripe_checkout_session(self, *, request_id: str, **kwargs) -> dict:  # noqa: ARG002
            raise RegistryUnavailableError("stripe disabled")

        def get_continuity_status(self, request_id: str) -> dict:  # noqa: ARG002
            raise RegistryUnavailableError("upstream failed ?secret=abc123")

    monkeypatch.setattr("iap_sdk.cli.main.RegistryClient", _Client)

    rc = main(["continuity", "pay", "--request-id", "req-1"], stdout=out, stderr=err)
    assert rc == 2
    assert "secret=[REDACTED]" in err.getvalue()
    assert "abc123" not in err.getvalue()


def test_registry_error_redacts_named_secret_field(monkeypatch) -> None:
    out = io.StringIO()
    err = io.StringIO()

    class _Client:
        def __init__(self, *, base_url: str) -> None:  # noqa: ARG002
            pass

        def get_continuity_status(self, request_id: str) -> dict:  # noqa: ARG002
            raise RegistryUnavailableError("registry failed: webhook_secret=super-secret-token")

    monkeypatch.setattr("iap_sdk.cli.main.RegistryClient", _Client)

    rc = main(["continuity", "wait", "--request-id", "req-2"], stdout=out, stderr=err)
    assert rc == 2
    assert "webhook_secret=[REDACTED]" in err.getvalue()
    assert "super-secret-token" not in err.getvalue()
