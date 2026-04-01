from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from iap_sdk.actions import (
    ZERO_HASH,
    ActionLogStore,
    action_event_hash,
    create_action_event,
    hash_canonical_object,
    sign_action_event,
    verify_action_event_signature,
)
from iap_sdk.errors import ActionLogIntegrityError, SchemaValidationError


def _identity() -> tuple[bytes, bytes, str]:
    private = Ed25519PrivateKey.generate()
    private_bytes = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_bytes = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    agent_id = "ed25519:testagent000000000000000000000"
    return private_bytes, public_bytes, agent_id


def test_sign_and_verify_shell_action_event() -> None:
    private_bytes, public_bytes, agent_id = _identity()
    event = create_action_event(
        agent_id=agent_id,
        sequence=1,
        prev_event_hash=ZERO_HASH,
        action_kind="shell",
        action_payload={
            "command": "echo",
            "args": ["hello"],
            "cwd": "/tmp/demo",
            "env_allowlist": ["PATH"],
        },
        inputs_hash=hash_canonical_object({"command": "echo", "args": ["hello"]}),
        outputs_hash=hash_canonical_object({"exit_code": 0, "stdout_hash": "a" * 64}),
        context_root="b" * 64,
    )

    signed = sign_action_event(event, private_bytes)

    assert signed["signature"] != ""
    assert verify_action_event_signature(signed, public_bytes) is True
    assert len(base64.b64decode(signed["signature"])) == 64


def test_action_event_hash_is_stable_across_artifact_ordering_input_dicts() -> None:
    timestamp = "2026-04-01T12:00:00Z"
    artifacts_a = [
        {"type": "stdout", "hash": "1" * 64},
        {"type": "stderr", "hash": "2" * 64},
    ]
    artifacts_b = [
        {"hash": "1" * 64, "type": "stdout"},
        {"hash": "2" * 64, "type": "stderr"},
    ]
    event_a = create_action_event(
        agent_id="ed25519:testagent000000000000000000000",
        sequence=1,
        prev_event_hash=ZERO_HASH,
        action_kind="file",
        action_payload={
            "op": "write",
            "path": "./AGENT.md",
            "content_hash": "3" * 64,
        },
        inputs_hash="4" * 64,
        outputs_hash="5" * 64,
        context_root="6" * 64,
        artifacts=artifacts_a,
        timestamp_utc=timestamp,
    )
    event_b = create_action_event(
        agent_id="ed25519:testagent000000000000000000000",
        sequence=1,
        prev_event_hash=ZERO_HASH,
        action_kind="file",
        action_payload={
            "content_hash": "3" * 64,
            "path": "./AGENT.md",
            "op": "write",
        },
        inputs_hash="4" * 64,
        outputs_hash="5" * 64,
        context_root="6" * 64,
        artifacts=artifacts_b,
        timestamp_utc=timestamp,
    )
    assert action_event_hash(event_a) == action_event_hash(event_b)


def test_action_log_append_and_replay(tmp_path) -> None:
    private_bytes, _, agent_id = _identity()
    store = ActionLogStore(tmp_path / ".iap" / "actions")

    first_event = sign_action_event(
        create_action_event(
            agent_id=agent_id,
            sequence=1,
            prev_event_hash=ZERO_HASH,
            action_kind="shell",
            action_payload={
                "command": "pwd",
                "args": [],
                "cwd": "/tmp/demo",
                "env_allowlist": [],
            },
            inputs_hash="7" * 64,
            outputs_hash="8" * 64,
            context_root="9" * 64,
        ),
        private_bytes,
    )
    state = store.append(first_event)

    second_event = sign_action_event(
        create_action_event(
            agent_id=agent_id,
            sequence=2,
            prev_event_hash=state.latest_event_hash or ZERO_HASH,
            action_kind="http",
            action_payload={
                "method": "GET",
                "url": "https://example.com",
                "headers_hash": "a" * 64,
                "body_hash": "b" * 64,
                "timeout_ms": 5000,
            },
            inputs_hash="c" * 64,
            outputs_hash="d" * 64,
            context_root="e" * 64,
        ),
        private_bytes,
    )
    final_state = store.append(second_event)

    replayed = store.replay()
    index = store.load_index()

    assert final_state.latest_sequence == 2
    assert replayed.latest_sequence == 2
    assert replayed.latest_event_hash == final_state.latest_event_hash
    assert index.latest_sequence == 2
    assert index.event_count == 2


def test_action_log_replay_detects_tampered_entry(tmp_path) -> None:
    private_bytes, _, agent_id = _identity()
    store = ActionLogStore(tmp_path / ".iap" / "actions")

    first_event = sign_action_event(
        create_action_event(
            agent_id=agent_id,
            sequence=1,
            prev_event_hash=ZERO_HASH,
            action_kind="shell",
            action_payload={
                "command": "echo",
                "args": ["v1"],
                "cwd": "/tmp/demo",
                "env_allowlist": [],
            },
            inputs_hash="1" * 64,
            outputs_hash="2" * 64,
            context_root="3" * 64,
        ),
        private_bytes,
    )
    state = store.append(first_event)
    second_event = sign_action_event(
        create_action_event(
            agent_id=agent_id,
            sequence=2,
            prev_event_hash=state.latest_event_hash or ZERO_HASH,
            action_kind="file",
            action_payload={
                "op": "mkdir",
                "path": "./memory",
            },
            inputs_hash="4" * 64,
            outputs_hash="5" * 64,
            context_root="6" * 64,
        ),
        private_bytes,
    )
    store.append(second_event)

    lines = store.log_path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    tampered["action"]["shell"]["cwd"] = "/tmp/tampered"
    lines[0] = json.dumps(tampered)
    store.log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(ActionLogIntegrityError):
        store.replay()


def test_create_action_event_rejects_invalid_file_payload() -> None:
    with pytest.raises(SchemaValidationError):
        create_action_event(
            agent_id="ed25519:testagent000000000000000000000",
            sequence=1,
            prev_event_hash=ZERO_HASH,
            action_kind="file",
            action_payload={"op": "move", "path": "./from.txt"},
            inputs_hash="a" * 64,
            outputs_hash="b" * 64,
            context_root="c" * 64,
        )
