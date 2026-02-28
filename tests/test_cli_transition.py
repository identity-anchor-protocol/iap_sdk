from __future__ import annotations

import io
import json
import os
import types
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from iap_sdk.cli.identity import LocalIdentity
from iap_sdk.cli.main import main


def _identity() -> LocalIdentity:
    private = Ed25519PrivateKey.generate()
    private_key_bytes = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_key_bytes = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return LocalIdentity(private_key_bytes=private_key_bytes, public_key_bytes=public_key_bytes)


def test_init_bootstraps_local_state_files(tmp_path) -> None:
    out = io.StringIO()
    err = io.StringIO()
    cwd = Path.cwd()
    try:
        os.chdir(tmp_path)
        identity_path = tmp_path / ".iap_agent" / "identity" / "ed25519.json"
        rc = main(["init", "--identity-file", str(identity_path)], stdout=out, stderr=err)
        assert rc == 0
        assert (tmp_path / ".iap" / "meta.json").exists()
        assert (tmp_path / ".iap" / "state" / "state_root.json").exists()
        assert (tmp_path / ".iap" / "state" / "agent_secret").exists()
        assert (tmp_path / "iap.yaml").exists()
    finally:
        os.chdir(cwd)


def test_track_command_uses_tracking_pipeline(monkeypatch, tmp_path) -> None:
    out = io.StringIO()
    err = io.StringIO()
    identity = _identity()
    monkeypatch.setattr(
        "iap_sdk.cli.main.load_identity",
        lambda path: (identity, Path(path or "id")),
    )
    monkeypatch.setattr("iap_sdk.cli.main.load_track_config", lambda _path: object())
    monkeypatch.setattr(
        "iap_sdk.cli.main.collect_tracked_files",
        lambda **kwargs: [tmp_path / "agent.md"],  # noqa: ARG005
    )
    monkeypatch.setattr(
        "iap_sdk.cli.main.build_file_record",
        lambda **kwargs: types.SimpleNamespace(path="agent.md", sha256="a" * 64, size_bytes=12),
    )
    monkeypatch.setattr(
        "iap_sdk.cli.main.append_tracking_events",
        lambda **kwargs: {
            "agent_id": identity.agent_id,
            "tracked_file_count": 1,
            "sequence_end": 7,
            "memory_root": "b" * 64,
        },
    )

    rc = main(["track", "--json"], stdout=out, stderr=err)
    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["tracked_file_count"] == 1
    assert payload["memory_root"] == "b" * 64


def test_commit_command_appends_commit_event(monkeypatch) -> None:
    out = io.StringIO()
    err = io.StringIO()
    identity = _identity()
    monkeypatch.setattr(
        "iap_sdk.cli.main.load_identity",
        lambda path: (identity, Path(path or "id")),
    )
    monkeypatch.setattr("iap_sdk.cli.main.load_track_config", lambda _path: object())
    monkeypatch.setattr("iap_sdk.cli.main.collect_tracked_files", lambda **kwargs: [])  # noqa: ARG005
    monkeypatch.setattr(
        "iap_sdk.cli.main.append_tracking_events",
        lambda **kwargs: {
            "tracked_file_count": 0,
            "memory_root": "c" * 64,
        },
    )

    class _AppendResult:
        sequence = 8
        event_hash = "d" * 64

    class _AMCSClient:
        def __init__(self, *, store, agent_id):  # noqa: ARG002
            pass

        def append(self, event_type, payload):  # noqa: ARG002
            return _AppendResult()

        def get_memory_root(self):
            return "e" * 64

    class _SQLiteEventStore:
        def __init__(self, path):  # noqa: ARG002
            pass

    fake_amcs = types.SimpleNamespace(AMCSClient=_AMCSClient, SQLiteEventStore=_SQLiteEventStore)
    monkeypatch.setitem(__import__("sys").modules, "amcs", fake_amcs)

    rc = main(["commit", "update state", "--json"], stdout=out, stderr=err)
    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["sequence"] == 8
    assert payload["memory_root"] == "e" * 64


def test_anchor_local_only_uses_provided_state(monkeypatch) -> None:
    out = io.StringIO()
    err = io.StringIO()
    identity = _identity()
    monkeypatch.setattr(
        "iap_sdk.cli.main.load_identity",
        lambda path: (identity, Path(path or "id")),
    )

    rc = main(
        [
            "anchor",
            "--local-only",
            "--memory-root",
            "f" * 64,
            "--sequence",
            "4",
            "--json",
        ],
        stdout=out,
        stderr=err,
    )
    assert rc == 0
    payload = json.loads(out.getvalue())
    assert payload["registry_submitted"] is False
    assert payload["anchor_id"].startswith("local:")
