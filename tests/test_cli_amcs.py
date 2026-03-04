from __future__ import annotations

import io
import json
from pathlib import Path

from iap_sdk.cli.amcs import AMCSAppendItem, AMCSAppendResult, AMCSRootResult
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


def test_amcs_root_prefers_project_local_identity_when_present(tmp_path, monkeypatch) -> None:
    out = io.StringIO()
    err = io.StringIO()
    expected_identity = tmp_path / ".iap" / "identity" / "ed25519.json"
    expected_identity.parent.mkdir(parents=True, exist_ok=True)
    expected_identity.write_text("{}", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    def fake_load_identity(path):
        assert Path(path) == expected_identity
        return _Identity("ed25519:local"), path

    monkeypatch.setattr("iap_sdk.cli.main.load_identity", fake_load_identity)
    monkeypatch.setattr(
        "iap_sdk.cli.main.get_amcs_root",
        lambda *, amcs_db_path, agent_id: AMCSRootResult(
            agent_id=agent_id,
            amcs_db_path=amcs_db_path,
            memory_root="d" * 64,
            sequence=4,
        ),
    )

    rc = main(["amcs", "root"], stdout=out, stderr=err)
    assert rc == 0
    assert "agent_id: ed25519:local" in out.getvalue()


def test_amcs_root_missing_identity_returns_error(monkeypatch) -> None:
    out = io.StringIO()
    err = io.StringIO()

    def fail_load(path):
        raise IdentityError("identity file not found")

    monkeypatch.setattr("iap_sdk.cli.main.load_identity", fail_load)

    rc = main(["amcs", "root"], stdout=out, stderr=err)
    assert rc == 1
    assert "identity error:" in err.getvalue()


def test_amcs_append_with_explicit_agent_id(monkeypatch) -> None:
    out = io.StringIO()
    err = io.StringIO()

    def fake_append_files_to_amcs(*, amcs_db_path: str, agent_id: str, file_paths: list[str]):
        assert amcs_db_path == "./my.db"
        assert agent_id == "ed25519:testagent"
        assert file_paths == ["./AGENT.md", "./SOUL.md"]
        return AMCSAppendResult(
            agent_id=agent_id,
            amcs_db_path=amcs_db_path,
            sequence=2,
            memory_root="c" * 64,
            items=[
                AMCSAppendItem(path="./AGENT.md", sequence=1, event_hash="h1"),
                AMCSAppendItem(path="./SOUL.md", sequence=2, event_hash="h2"),
            ],
        )

    monkeypatch.setattr("iap_sdk.cli.main.append_files_to_amcs", fake_append_files_to_amcs)

    rc = main(
        [
            "amcs",
            "append",
            "--amcs-db",
            "./my.db",
            "--agent-id",
            "ed25519:testagent",
            "--file",
            "./AGENT.md",
            "--file",
            "./SOUL.md",
            "--json",
        ],
        stdout=out,
        stderr=err,
    )
    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["sequence"] == 2
    assert payload["memory_root"] == "c" * 64
    assert len(payload["items"]) == 2


def test_amcs_append_requires_files(monkeypatch) -> None:
    out = io.StringIO()
    err = io.StringIO()
    monkeypatch.setattr(
        "iap_sdk.cli.main.load_identity",
        lambda path: (_Identity("ed25519:fromid"), path),
    )

    rc = main(["amcs", "append"], stdout=out, stderr=err)
    assert rc == 1
    assert "no files provided" in err.getvalue()


def test_amcs_append_prefers_project_local_identity_when_present(tmp_path, monkeypatch) -> None:
    out = io.StringIO()
    err = io.StringIO()
    expected_identity = tmp_path / ".iap" / "identity" / "ed25519.json"
    expected_identity.parent.mkdir(parents=True, exist_ok=True)
    expected_identity.write_text("{}", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    def fake_load_identity(path):
        assert Path(path) == expected_identity
        return _Identity("ed25519:local"), path

    monkeypatch.setattr("iap_sdk.cli.main.load_identity", fake_load_identity)

    def fake_append_files_to_amcs(*, amcs_db_path: str, agent_id: str, file_paths: list[str]):
        assert agent_id == "ed25519:local"
        return AMCSAppendResult(
            agent_id=agent_id,
            amcs_db_path=amcs_db_path,
            sequence=1,
            memory_root="e" * 64,
            items=[AMCSAppendItem(path="./AGENT.md", sequence=1, event_hash="h1")],
        )

    monkeypatch.setattr("iap_sdk.cli.main.append_files_to_amcs", fake_append_files_to_amcs)

    rc = main(
        ["amcs", "append", "--file", "./AGENT.md", "--json"],
        stdout=out,
        stderr=err,
    )
    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["agent_id"] == "ed25519:local"


def test_amcs_append_project_local_conflicts_with_identity_file(tmp_path) -> None:
    out = io.StringIO()
    err = io.StringIO()
    identity_path = tmp_path / "identity.json"

    rc = main(
        [
            "amcs",
            "append",
            "--project-local",
            "--identity-file",
            str(identity_path),
            "--file",
            "./AGENT.md",
        ],
        stdout=out,
        stderr=err,
    )
    assert rc == 1
    assert "cannot use --project-local together with --identity-file" in err.getvalue()
