from __future__ import annotations

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from iap_sdk.actions import IAPOperator, resolve_context_root
from iap_sdk.actions.operator import default_actions_dir
from iap_sdk.cli.amcs import AMCSRootResult
from iap_sdk.crypto.agent_identity import derive_agent_id
from iap_sdk.errors import ActionContextError


def _write_identity(path: Path) -> str:
    private = Ed25519PrivateKey.generate()
    private_key_bytes = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_key_bytes = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "private_key_b64": _b64(private_key_bytes),
                "public_key_b64": _b64(public_key_bytes),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return derive_agent_id(public_key_bytes)


def _write_state_root(project_root: Path, *, memory_root: str = "a" * 64) -> None:
    state_root_path = project_root / ".iap" / "state" / "state_root.json"
    state_root_path.parent.mkdir(parents=True, exist_ok=True)
    state_root_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "agent_id": "unused-for-test",
                "sequence": 0,
                "memory_root": memory_root,
                "status": "ready",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _read_action_events(project_root: Path) -> list[dict]:
    log_path = default_actions_dir(project_root) / "actions.log"
    return [
        json.loads(line)
        for line in log_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _b64(value: bytes) -> str:
    import base64

    return base64.b64encode(value).decode("ascii")


def test_resolve_context_root_prefers_state_root_file(tmp_path: Path) -> None:
    agent_id = _write_identity(tmp_path / ".iap" / "identity" / "ed25519.json")
    _write_state_root(tmp_path, memory_root="b" * 64)

    resolved = resolve_context_root(agent_id=agent_id, project_root=tmp_path)

    assert resolved == "b" * 64


def test_run_shell_records_hash_only_and_redacts_env_values(tmp_path: Path) -> None:
    _write_identity(tmp_path / ".iap" / "identity" / "ed25519.json")
    _write_state_root(tmp_path, memory_root="c" * 64)
    operator = IAPOperator.from_project(project_root=tmp_path, logging_mode="hash_only")

    env = {
        "PATH": os.environ.get("PATH", ""),
        "SECRET_TOKEN": "super-secret-value",
    }
    recorded = operator.run_shell(
        sys.executable,
        ["-c", "import sys; print('hello'); print('warning', file=sys.stderr)"],
        cwd=tmp_path,
        env=env,
        env_allowlist=["PATH", "SECRET_TOKEN"],
    )

    log_path = default_actions_dir(tmp_path) / "actions.log"
    log_text = log_path.read_text(encoding="utf-8")
    event = _read_action_events(tmp_path)[0]

    assert recorded.result.returncode == 0
    assert event["action"]["shell"]["env_allowlist"] == ["PATH", "SECRET_TOKEN"]
    assert event["context_root"] == "c" * 64
    assert "super-secret-value" not in log_text
    assert not (default_actions_dir(tmp_path) / "artifacts").exists()


def test_http_request_records_action_and_redacts_headers(tmp_path: Path) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            _ = self.rfile.read(length)
            self.send_response(201)
            self.send_header("X-Reply", "ok")
            self.end_headers()
            self.wfile.write(b"response-body")

        def log_message(self, format: str, *args) -> None:  # noqa: A003
            return

    _write_identity(tmp_path / ".iap" / "identity" / "ed25519.json")
    _write_state_root(tmp_path, memory_root="d" * 64)
    operator = IAPOperator.from_project(project_root=tmp_path)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        recorded = operator.http_request(
            "POST",
            f"http://127.0.0.1:{server.server_port}/demo",
            headers={
                "Authorization": "Bearer top-secret",
                "X-Trace": "trace-value",
            },
            body="hello",
            header_allowlist=["X-Trace"],
            response_header_allowlist=["X-Reply"],
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    event = _read_action_events(tmp_path)[0]
    log_text = (default_actions_dir(tmp_path) / "actions.log").read_text(encoding="utf-8")

    assert recorded.result.status_code == 201
    assert event["action_kind"] == "http"
    assert event["action"]["http"]["timeout_ms"] == 5000
    assert event["context_root"] == "d" * 64
    assert "top-secret" not in log_text


def test_file_actions_local_full_store_artifacts_and_chain(tmp_path: Path) -> None:
    _write_identity(tmp_path / ".iap" / "identity" / "ed25519.json")
    _write_state_root(tmp_path, memory_root="e" * 64)
    operator = IAPOperator.from_project(project_root=tmp_path, logging_mode="local_full")

    created_dir = operator.mkdir(tmp_path / "memory").result
    written = operator.file_write(tmp_path / "memory" / "note.txt", "hello world")
    moved = operator.file_move(tmp_path / "memory" / "note.txt", tmp_path / "memory" / "note-2.txt")
    deleted = operator.file_delete(tmp_path / "memory" / "note-2.txt")

    events = _read_action_events(tmp_path)
    write_event = events[1]
    artifact_hash = write_event["artifacts"][0]["hash"]
    artifact_path = (
        default_actions_dir(tmp_path) / "artifacts" / "file_content" / f"{artifact_hash}.bin"
    )

    assert created_dir.exists()
    assert written.result == tmp_path / "memory" / "note.txt"
    assert moved.result == tmp_path / "memory" / "note-2.txt"
    assert deleted.result == tmp_path / "memory" / "note-2.txt"
    assert len(events) == 4
    assert artifact_path.read_bytes() == b"hello world"
    assert written.state.latest_sequence == 2
    assert deleted.state.latest_sequence == 4


def test_operator_uses_amcs_context_root_when_state_root_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent_id = _write_identity(tmp_path / ".iap" / "identity" / "ed25519.json")

    def fake_get_amcs_root(*, amcs_db_path: str, agent_id: str) -> AMCSRootResult:
        assert amcs_db_path == str(tmp_path / "amcs.db")
        return AMCSRootResult(
            agent_id=agent_id,
            amcs_db_path=amcs_db_path,
            memory_root="f" * 64,
            sequence=12,
        )

    monkeypatch.setattr("iap_sdk.actions.operator.get_amcs_root", fake_get_amcs_root)
    operator = IAPOperator.from_project(
        project_root=tmp_path,
        amcs_db_path=tmp_path / "amcs.db",
    )

    recorded = operator.mkdir(tmp_path / "memory")
    event = _read_action_events(tmp_path)[0]

    assert recorded.result == tmp_path / "memory"
    assert event["context_root"] == "f" * 64
    assert event["agent_id"] == agent_id


def test_operator_raises_without_context_root(tmp_path: Path) -> None:
    _write_identity(tmp_path / ".iap" / "identity" / "ed25519.json")
    operator = IAPOperator.from_project(project_root=tmp_path)

    with pytest.raises(ActionContextError):
        operator.mkdir(tmp_path / "should-not-exist")

    assert not (tmp_path / "should-not-exist").exists()

