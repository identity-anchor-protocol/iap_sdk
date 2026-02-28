from __future__ import annotations

import io
import json

from iap_sdk.cli.main import main


def test_continuity_wait_success(monkeypatch) -> None:
    out = io.StringIO()
    err = io.StringIO()

    class _Client:
        def __init__(self, *, base_url: str, api_key: str | None = None) -> None:
            self.base_url = base_url
            self.api_key = api_key

        def get_continuity_status(self, request_id: str) -> dict:
            assert request_id == "req-wait"
            return {"status": "CERTIFIED", "paid_at": "2026-02-22T00:00:00Z"}

    monkeypatch.setattr("iap_sdk.cli.main.RegistryClient", _Client)

    rc = main(["continuity", "wait", "--request-id", "req-wait", "--json"], stdout=out, stderr=err)
    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["status"] == "CERTIFIED"


def test_continuity_wait_timeout(monkeypatch) -> None:
    out = io.StringIO()
    err = io.StringIO()

    class _Client:
        def __init__(self, *, base_url: str, api_key: str | None = None) -> None:
            self.base_url = base_url
            self.api_key = api_key

        def get_continuity_status(self, request_id: str) -> dict:  # noqa: ARG002
            return {"status": "WAITING_PAYMENT"}

    class _Clock:
        def __init__(self) -> None:
            self.current = 100.0

        def time(self) -> float:
            return self.current

        def sleep(self, seconds: int) -> None:
            self.current += seconds

    clock = _Clock()
    monkeypatch.setattr("iap_sdk.cli.main.RegistryClient", _Client)
    monkeypatch.setattr("iap_sdk.cli.main.time.time", clock.time)
    monkeypatch.setattr("iap_sdk.cli.main.time.sleep", clock.sleep)

    rc = main(
        [
            "continuity",
            "wait",
            "--request-id",
            "req-timeout",
            "--timeout-seconds",
            "3",
            "--poll-seconds",
            "2",
        ],
        stdout=out,
        stderr=err,
    )
    assert rc == 3
    assert "timeout error:" in err.getvalue()


def test_continuity_cert_fetch_and_write(monkeypatch, tmp_path) -> None:
    out = io.StringIO()
    err = io.StringIO()

    class _Client:
        def __init__(self, *, base_url: str, api_key: str | None = None) -> None:
            self.base_url = base_url
            self.api_key = api_key

        def get_continuity_certificate(self, request_id: str) -> dict:
            assert request_id == "req-cert"
            return {
                "request_id": request_id,
                "certificate": {"certificate_type": "IAP-Continuity-0.2"},
                "signature_b64": "sig",
                "public_key_b64": "pub",
                "witnesses": [],
            }

    monkeypatch.setattr("iap_sdk.cli.main.RegistryClient", _Client)

    output_file = tmp_path / "cert.json"
    rc = main(
        [
            "continuity",
            "cert",
            "--request-id",
            "req-cert",
            "--output-file",
            str(output_file),
            "--json",
        ],
        stdout=out,
        stderr=err,
    )
    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["certificate_type"] == "IAP-Continuity-0.2"
    assert output_file.exists()
    written = json.loads(output_file.read_text(encoding="utf-8"))
    assert written["request_id"] == "req-cert"
