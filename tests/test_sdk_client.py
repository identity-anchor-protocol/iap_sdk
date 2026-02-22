from __future__ import annotations

import pytest

from iap_sdk.client import RegistryClient
from iap_sdk.errors import SDKTimeoutError


def test_wait_for_certification_success(monkeypatch) -> None:
    client = RegistryClient(base_url="http://localhost:8080", timeout=0.1)
    states = iter([{"status": "WAITING_PAYMENT"}, {"status": "CERTIFIED"}])

    monkeypatch.setattr(client, "get_continuity_status", lambda request_id: next(states))
    result = client.wait_for_certification(request_id="req-1", timeout=2, interval=0.01)
    assert result["status"] == "CERTIFIED"


def test_wait_for_certification_timeout(monkeypatch) -> None:
    client = RegistryClient(base_url="http://localhost:8080", timeout=0.1)
    monkeypatch.setattr(
        client,
        "get_continuity_status",
        lambda request_id: {"status": "WAITING_PAYMENT"},
    )

    with pytest.raises(SDKTimeoutError):
        client.wait_for_certification(request_id="req-1", timeout=0.05, interval=0.01)
