from __future__ import annotations

import io
import json

from iap_sdk.cli.main import main


def test_verify_with_explicit_public_key(monkeypatch, tmp_path) -> None:
    out = io.StringIO()
    err = io.StringIO()

    cert_path = tmp_path / "cert.json"
    cert_path.write_text("{}\n", encoding="utf-8")

    def fake_verify(*args, **kwargs):
        assert kwargs["registry_public_key_b64"] == "PUB"
        return True, "ok"

    monkeypatch.setattr("iap_sdk.cli.main.verify_certificate_file", fake_verify)

    rc = main(
        ["verify", str(cert_path), "--registry-public-key-b64", "PUB", "--json"],
        stdout=out,
        stderr=err,
    )
    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["ok"] is True
    assert payload["reason"] == "ok"


def test_verify_fetches_registry_public_key(monkeypatch, tmp_path) -> None:
    out = io.StringIO()
    err = io.StringIO()

    cert_path = tmp_path / "cert.json"
    cert_path.write_text("{}\n", encoding="utf-8")

    class _Client:
        def __init__(self, *, base_url: str) -> None:
            self.base_url = base_url

        def get_public_registry_key(self) -> dict:
            return {"public_key_b64": "FETCHED"}

    monkeypatch.setattr("iap_sdk.cli.main.RegistryClient", _Client)

    def fake_verify(*args, **kwargs):
        assert kwargs["registry_public_key_b64"] == "FETCHED"
        return True, "ok"

    monkeypatch.setattr("iap_sdk.cli.main.verify_certificate_file", fake_verify)

    rc = main(
        ["verify", str(cert_path), "--registry-base", "http://registry.local", "--json"],
        stdout=out,
        stderr=err,
    )
    assert rc == 0


def test_verify_failure_returns_exit_4(monkeypatch, tmp_path) -> None:
    out = io.StringIO()
    err = io.StringIO()

    cert_path = tmp_path / "cert.json"
    cert_path.write_text("{}\n", encoding="utf-8")

    monkeypatch.setattr(
        "iap_sdk.cli.main.verify_certificate_file",
        lambda *args, **kwargs: (False, "invalid registry signature"),
    )

    rc = main(
        ["verify", str(cert_path), "--registry-public-key-b64", "PUB"],
        stdout=out,
        stderr=err,
    )
    assert rc == 4
    assert "invalid registry signature" in out.getvalue()


def test_verify_invalid_witness_bundle_returns_error(monkeypatch, tmp_path) -> None:
    out = io.StringIO()
    err = io.StringIO()

    cert_path = tmp_path / "cert.json"
    cert_path.write_text("{}\n", encoding="utf-8")
    bad_witness = tmp_path / "witness.json"
    bad_witness.write_text("{not-json}\n", encoding="utf-8")

    monkeypatch.setattr(
        "iap_sdk.cli.main.verify_certificate_file",
        lambda *args, **kwargs: (True, "ok"),
    )

    rc = main(
        [
            "verify",
            str(cert_path),
            "--registry-public-key-b64",
            "PUB",
            "--witness-bundle",
            str(bad_witness),
        ],
        stdout=out,
        stderr=err,
    )
    assert rc == 1
    assert "verify error:" in err.getvalue()
