from __future__ import annotations

import io
import json

from iap_sdk.cli.main import main
from iap_sdk.errors import RegistryUnavailableError


def test_continuity_pay_prefers_stripe(monkeypatch) -> None:
    out = io.StringIO()
    err = io.StringIO()

    class _Client:
        def __init__(self, *, base_url: str) -> None:
            self.base_url = base_url

        def create_stripe_checkout_session(
            self,
            *,
            request_id: str,
            success_url: str | None = None,
            cancel_url: str | None = None,
        ) -> dict:
            assert request_id == "req-1"
            _ = success_url
            _ = cancel_url
            return {
                "session_id": "cs_123",
                "checkout_url": "https://checkout.stripe.test/cs_123",
                "payment_status": "unpaid",
            }

        def get_continuity_status(self, request_id: str) -> dict:  # noqa: ARG002
            raise AssertionError("status fallback should not be called")

    monkeypatch.setattr("iap_sdk.cli.main.RegistryClient", _Client)

    rc = main(["continuity", "pay", "--request-id", "req-1", "--json"], stdout=out, stderr=err)
    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["payment_method"] == "stripe"
    assert payload["session_id"] == "cs_123"


def test_continuity_pay_falls_back_to_lightning_btc(monkeypatch) -> None:
    out = io.StringIO()
    err = io.StringIO()

    class _Client:
        def __init__(self, *, base_url: str) -> None:
            self.base_url = base_url

        def create_stripe_checkout_session(
            self,
            *,
            request_id: str,
            success_url: str | None = None,
            cancel_url: str | None = None,
        ) -> dict:  # noqa: ARG002
            raise RegistryUnavailableError("registry request failed: 503 stripe not configured")

        def get_continuity_status(self, request_id: str) -> dict:
            assert request_id == "req-2"
            return {
                "status": "WAITING_PAYMENT",
                "lnbits_payment_hash": "hash-2",
                "lightning_invoice": "lnbc1...",
            }

    monkeypatch.setattr("iap_sdk.cli.main.RegistryClient", _Client)

    rc = main(["continuity", "pay", "--request-id", "req-2", "--json"], stdout=out, stderr=err)
    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["payment_method"] == "lightning-btc"
    assert payload["provider_backend"] == "lnbits"
    assert payload["lnbits_payment_hash"] == "hash-2"


def test_continuity_pay_accepts_legacy_lnbits_alias(monkeypatch) -> None:
    out = io.StringIO()
    err = io.StringIO()

    class _Client:
        def __init__(self, *, base_url: str) -> None:
            self.base_url = base_url

        def get_continuity_status(self, request_id: str) -> dict:
            assert request_id == "req-legacy"
            return {
                "status": "WAITING_PAYMENT",
                "lnbits_payment_hash": "legacy-hash",
                "lightning_invoice": "lnbc1legacy...",
            }

    monkeypatch.setattr("iap_sdk.cli.main.RegistryClient", _Client)

    rc = main(
        [
            "continuity",
            "pay",
            "--request-id",
            "req-legacy",
            "--payment-provider",
            "lnbits",
            "--json",
        ],
        stdout=out,
        stderr=err,
    )
    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["payment_method"] == "lightning-btc"


def test_continuity_pay_returns_error_when_registry_unavailable(monkeypatch) -> None:
    out = io.StringIO()
    err = io.StringIO()

    class _Client:
        def __init__(self, *, base_url: str) -> None:
            self.base_url = base_url

        def create_stripe_checkout_session(
            self,
            *,
            request_id: str,
            success_url: str | None = None,
            cancel_url: str | None = None,
        ) -> dict:  # noqa: ARG002
            raise RegistryUnavailableError("registry request failed: 503 stripe unavailable")

        def get_continuity_status(self, request_id: str) -> dict:  # noqa: ARG002
            raise RegistryUnavailableError("registry request failed: 503 status unavailable")

    monkeypatch.setattr("iap_sdk.cli.main.RegistryClient", _Client)

    rc = main(["continuity", "pay", "--request-id", "req-3"], stdout=out, stderr=err)
    assert rc == 2
    assert "registry error:" in err.getvalue()
