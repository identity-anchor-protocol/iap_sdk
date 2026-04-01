from __future__ import annotations

import io
import json

from iap_sdk.actions import IAPOperator
from iap_sdk.cli.main import main


def _set_state_root_memory_root(project_root, memory_root: str) -> None:
    state_root_path = project_root / ".iap" / "state" / "state_root.json"
    payload = json.loads(state_root_path.read_text(encoding="utf-8"))
    payload["memory_root"] = memory_root
    state_root_path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def test_actions_status_json_reports_latest_event(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    init_out = io.StringIO()
    init_err = io.StringIO()
    assert main(["init", "--project-local", "--json"], stdout=init_out, stderr=init_err) == 0
    _set_state_root_memory_root(tmp_path, "a" * 64)

    operator = IAPOperator.from_project(project_root=tmp_path)
    operator.mkdir(tmp_path / "memory")

    out = io.StringIO()
    err = io.StringIO()
    rc = main(["actions", "status", "--json"], stdout=out, stderr=err)

    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["event_count"] == 1
    assert payload["latest_sequence"] == 1
    assert payload["latest_context_root"] == "a" * 64
    assert payload["index_consistent"] is True


def test_actions_verify_json_succeeds_for_project_local_identity(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    init_out = io.StringIO()
    init_err = io.StringIO()
    assert main(["init", "--project-local", "--json"], stdout=init_out, stderr=init_err) == 0
    _set_state_root_memory_root(tmp_path, "b" * 64)

    operator = IAPOperator.from_project(project_root=tmp_path)
    operator.file_write(tmp_path / "note.txt", "hello")

    out = io.StringIO()
    err = io.StringIO()
    rc = main(["actions", "verify", "--project-local", "--json"], stdout=out, stderr=err)

    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["ok"] is True
    assert payload["signatures_verified"] == 1
    assert payload["latest_context_root"] == "b" * 64


def test_actions_verify_returns_exit_4_when_log_is_tampered(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    init_out = io.StringIO()
    init_err = io.StringIO()
    assert main(["init", "--project-local", "--json"], stdout=init_out, stderr=init_err) == 0
    _set_state_root_memory_root(tmp_path, "c" * 64)

    operator = IAPOperator.from_project(project_root=tmp_path)
    operator.mkdir(tmp_path / "memory")

    log_path = tmp_path / ".iap" / "actions" / "actions.log"
    lines = log_path.read_text(encoding="utf-8").splitlines()
    payload = json.loads(lines[0])
    payload["action"]["file"]["path"] = str(tmp_path / "tampered")
    lines[0] = json.dumps(payload, sort_keys=True)
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    out = io.StringIO()
    err = io.StringIO()
    rc = main(["actions", "verify", "--project-local"], stdout=out, stderr=err)

    assert rc == 4
    assert "index.json does not match replayed action log" in out.getvalue()
