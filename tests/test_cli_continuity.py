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

from iap_sdk.cli.amcs import AMCSError, AMCSRootResult
from iap_sdk.cli.identity import LocalIdentity
from iap_sdk.cli.main import main
from iap_sdk.errors import RegistryRequestError


def _identity() -> LocalIdentity:
    private = Ed25519PrivateKey.generate()
    private_key_bytes = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_key_bytes = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return LocalIdentity(private_key_bytes=private_key_bytes, public_key_bytes=public_key_bytes)


def test_continuity_request_from_amcs_writes_session(monkeypatch, tmp_path) -> None:
    out = io.StringIO()
    err = io.StringIO()

    identity = _identity()
    monkeypatch.setattr(
        "iap_sdk.cli.main.load_identity",
        lambda path: (identity, Path(path or "id")),
    )
    monkeypatch.setattr(
        "iap_sdk.cli.main.get_amcs_root",
        lambda *, amcs_db_path, agent_id: AMCSRootResult(
            agent_id=agent_id,
            amcs_db_path=amcs_db_path,
            memory_root="c" * 64,
            sequence=9,
        ),
    )

    class _Client:
        def __init__(self, *, base_url: str, api_key: str | None = None) -> None:
            self.base_url = base_url
            self.api_key = api_key

        def submit_continuity_request(self, payload: dict) -> dict:
            assert payload["agent_id"] == identity.agent_id
            assert payload["memory_root"] == "c" * 64
            assert payload["sequence"] == 9
            return {
                "request_id": "req-123",
                "status": "WAITING_PAYMENT",
                "lnbits_payment_hash": "hash-abc",
                "lightning_invoice": "lnbc1...",
                "amount_sats": 21,
            }

    monkeypatch.setattr("iap_sdk.cli.main.RegistryClient", _Client)

    sessions_dir = tmp_path / "sessions"
    rc = main(
        [
            "continuity",
            "request",
            "--registry-base",
            "http://registry.local",
            "--sessions-dir",
            str(sessions_dir),
            "--json",
        ],
        stdout=out,
        stderr=err,
    )

    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["request_id"] == "req-123"
    assert payload["sequence"] == 9
    assert payload["memory_root"] == "c" * 64

    session_file = sessions_dir / "req-123.json"
    assert session_file.exists()
    session_json = json.loads(session_file.read_text(encoding="utf-8"))
    assert session_json["request_id"] == "req-123"


def test_continuity_request_explicit_root_sequence_skips_amcs(monkeypatch, tmp_path) -> None:
    out = io.StringIO()
    err = io.StringIO()

    identity = _identity()
    monkeypatch.setattr(
        "iap_sdk.cli.main.load_identity",
        lambda path: (identity, Path(path or "id")),
    )

    def fail_amcs(*, amcs_db_path: str, agent_id: str):  # noqa: ARG001
        raise AMCSError("should not call AMCS")

    monkeypatch.setattr("iap_sdk.cli.main.get_amcs_root", fail_amcs)

    class _Client:
        def __init__(self, *, base_url: str, api_key: str | None = None) -> None:
            self.base_url = base_url
            self.api_key = api_key

        def submit_continuity_request(self, payload: dict) -> dict:
            assert payload["memory_root"] == "a" * 64
            assert payload["sequence"] == 5
            return {
                "request_id": "req-555",
                "status": "WAITING_PAYMENT",
                "lnbits_payment_hash": "hash-555",
                "lightning_invoice": "lnbc1...",
                "amount_sats": 21,
            }

    monkeypatch.setattr("iap_sdk.cli.main.RegistryClient", _Client)

    rc = main(
        [
            "continuity",
            "request",
            "--memory-root",
            "a" * 64,
            "--sequence",
            "5",
            "--sessions-dir",
            str(tmp_path / "sessions"),
        ],
        stdout=out,
        stderr=err,
    )

    assert rc == 0
    assert "request_id: req-555" in out.getvalue()
    assert err.getvalue().startswith("[beta]")


def test_continuity_request_sequence_conflict_shows_actionable_hint(monkeypatch, tmp_path) -> None:
    out = io.StringIO()
    err = io.StringIO()

    identity = _identity()
    monkeypatch.setattr(
        "iap_sdk.cli.main.load_identity",
        lambda path: (identity, Path(path or "id")),
    )
    monkeypatch.setattr(
        "iap_sdk.cli.main.get_amcs_root",
        lambda *, amcs_db_path, agent_id: AMCSRootResult(
            agent_id=agent_id,
            amcs_db_path=amcs_db_path,
            memory_root="b" * 64,
            sequence=1,
        ),
    )

    class _Client:
        def __init__(self, *, base_url: str, api_key: str | None = None) -> None:
            self.base_url = base_url
            self.api_key = api_key

        def submit_continuity_request(self, payload: dict) -> dict:  # noqa: ARG002
            raise RegistryRequestError(
                "registry request failed: 409",
                status_code=409,
                detail="ledger_sequence must strictly increase; latest registry sequence is 4",
                error_code="conflict",
            )

    monkeypatch.setattr("iap_sdk.cli.main.RegistryClient", _Client)

    rc = main(
        [
            "continuity",
            "request",
            "--registry-base",
            "http://registry.local",
            "--sessions-dir",
            str(tmp_path / "sessions"),
        ],
        stdout=out,
        stderr=err,
    )

    assert rc == 2
    assert out.getvalue() == ""
    message = err.getvalue()
    assert "registry error:" in message
    assert "latest registry sequence is 4" in message
    assert "iap-agent registry status" in message


def test_continuity_request_invalid_api_key_has_actionable_error(monkeypatch, tmp_path) -> None:
    out = io.StringIO()
    err = io.StringIO()

    identity = _identity()
    monkeypatch.setattr(
        "iap_sdk.cli.main.load_identity",
        lambda path: (identity, Path(path or "id")),
    )
    monkeypatch.setattr(
        "iap_sdk.cli.main.get_amcs_root",
        lambda *, amcs_db_path, agent_id: AMCSRootResult(
            agent_id=agent_id,
            amcs_db_path=amcs_db_path,
            memory_root="b" * 64,
            sequence=1,
        ),
    )

    class _Client:
        def __init__(self, *, base_url: str, api_key: str | None = None) -> None:
            self.base_url = base_url
            self.api_key = api_key

        def submit_continuity_request(self, payload: dict) -> dict:  # noqa: ARG002
            raise RegistryRequestError(
                "registry request failed: 401 invalid api key",
                status_code=401,
                detail="invalid api key",
                error_code="unauthorized",
            )

    monkeypatch.setattr("iap_sdk.cli.main.RegistryClient", _Client)

    rc = main(
        [
            "continuity",
            "request",
            "--registry-base",
            "http://registry.local",
            "--sessions-dir",
            str(tmp_path / "sessions"),
        ],
        stdout=out,
        stderr=err,
    )

    assert rc == 2
    assert out.getvalue() == ""
    assert "invalid registry API key" in err.getvalue()


def test_continuity_request_account_tier_quota_exceeded_has_actionable_error(
    monkeypatch, tmp_path
) -> None:
    out = io.StringIO()
    err = io.StringIO()

    identity = _identity()
    monkeypatch.setattr(
        "iap_sdk.cli.main.load_identity",
        lambda path: (identity, Path(path or "id")),
    )
    monkeypatch.setattr(
        "iap_sdk.cli.main.get_amcs_root",
        lambda *, amcs_db_path, agent_id: AMCSRootResult(
            agent_id=agent_id,
            amcs_db_path=amcs_db_path,
            memory_root="b" * 64,
            sequence=1,
        ),
    )

    class _Client:
        def __init__(self, *, base_url: str, api_key: str | None = None) -> None:
            self.base_url = base_url
            self.api_key = api_key

        def submit_continuity_request(self, payload: dict) -> dict:  # noqa: ARG002
            raise RegistryRequestError(
                "registry request failed: 429 account tier quota exceeded",
                status_code=429,
                detail="account tier quota exceeded",
                error_code="rate_limited",
            )

    monkeypatch.setattr("iap_sdk.cli.main.RegistryClient", _Client)

    rc = main(
        [
            "continuity",
            "request",
            "--registry-base",
            "http://registry.local",
            "--sessions-dir",
            str(tmp_path / "sessions"),
        ],
        stdout=out,
        stderr=err,
    )

    assert rc == 2
    assert out.getvalue() == ""
    assert "monthly tier limit" in err.getvalue()
