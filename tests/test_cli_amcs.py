from __future__ import annotations

import io
import json

from iap_sdk.cli.amcs import AMCSRootResult
from iap_sdk.cli.identity import IdentityError
from iap_sdk.cli.main import main


class _Identity:
    def __init__(self, agent_id: str) -> None:
        self.agent_id = agent_id


def test_amcs_root_with_explicit_agent_id(monkeypatch) -> None:
    out = io.StringIO()
    err = io.StringIO()

    def fake_get_amcs_root(*, amcs_db_path: str, agent_id: str) -> AMCSRootResult:
        assert amcs_db_path == "./my.db"
        assert agent_id == "ed25519:testagent"
        return AMCSRootResult(
            agent_id=agent_id,
            amcs_db_path=amcs_db_path,
            memory_root="a" * 64,
            sequence=7,
        )

    monkeypatch.setattr("iap_sdk.cli.main.get_amcs_root", fake_get_amcs_root)

    rc = main(
        ["amcs", "root", "--amcs-db", "./my.db", "--agent-id", "ed25519:testagent", "--json"],
        stdout=out,
        stderr=err,
    )
    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["sequence"] == 7
    assert payload["memory_root"] == "a" * 64
    assert err.getvalue().startswith("[beta]")


def test_amcs_root_uses_identity_fallback(monkeypatch) -> None:
    out = io.StringIO()
    err = io.StringIO()

    monkeypatch.setattr(
        "iap_sdk.cli.main.load_identity",
        lambda path: (_Identity("ed25519:fromid"), path),
    )
    monkeypatch.setattr(
        "iap_sdk.cli.main.get_amcs_root",
        lambda *, amcs_db_path, agent_id: AMCSRootResult(
            agent_id=agent_id,
            amcs_db_path=amcs_db_path,
            memory_root="b" * 64,
            sequence=3,
        ),
    )

    rc = main(["amcs", "root"], stdout=out, stderr=err)
    assert rc == 0
    assert "agent_id: ed25519:fromid" in out.getvalue()


def test_amcs_root_missing_identity_returns_error(monkeypatch) -> None:
    out = io.StringIO()
    err = io.StringIO()

    def fail_load(path):
        raise IdentityError("identity file not found")

    monkeypatch.setattr("iap_sdk.cli.main.load_identity", fail_load)

    rc = main(["amcs", "root"], stdout=out, stderr=err)
    assert rc == 1
    assert "identity error:" in err.getvalue()
