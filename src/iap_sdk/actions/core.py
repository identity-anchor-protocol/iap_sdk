"""Core local action chain primitives for Isnād Slice 1."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as pkg_version
from pathlib import Path
from typing import Any, Literal

from amcs.canonical_json import canonical_bytes, canonical_dumps
from amcs.hashing import sha256_hex
from amcs.version import __version__ as amcs_version
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from iap_sdk.crypto.ed25519_verify import verify_ed25519
from iap_sdk.errors import ActionLogIntegrityError, InvalidSignatureError, SchemaValidationError

ACTION_EVENT_TYPE = "action_event"
ZERO_HASH = "0" * 64
_HEX_64 = {ch for ch in "0123456789abcdef"}
_FILE_OPS = {"write", "delete", "move", "mkdir"}


def _sdk_version() -> str:
    for package_name in ("iap-agent", "iap-sdk"):
        try:
            return pkg_version(package_name)
        except PackageNotFoundError:
            continue
    return "0.0.0+local"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _validate_hex_64(value: str, field_name: str) -> str:
    normalized = value.strip().lower()
    if len(normalized) != 64 or any(ch not in _HEX_64 for ch in normalized):
        raise ValueError(f"{field_name} must be 64 lowercase hex chars")
    return normalized


def _validate_signature_b64(value: str) -> str:
    if value == "":
        return value
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception as exc:  # pragma: no cover
        raise ValueError("signature must be valid base64") from exc
    if len(decoded) != 64:
        raise ValueError("signature must decode to 64 bytes")
    return value


class ArtifactRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str
    hash: str

    @field_validator("hash")
    @classmethod
    def _validate_hash(cls, value: str) -> str:
        return _validate_hex_64(value, "artifact hash")


class ShellActionRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command: str
    args: list[str] = Field(default_factory=list)
    cwd: str
    env_allowlist: list[str] = Field(default_factory=list)
    stdin_hash: str | None = None

    @field_validator("stdin_hash")
    @classmethod
    def _validate_stdin_hash(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _validate_hex_64(value, "stdin_hash")


class HttpActionRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    method: str
    url: str
    headers_hash: str
    body_hash: str
    timeout_ms: int

    @field_validator("headers_hash", "body_hash")
    @classmethod
    def _validate_hashes(cls, value: str) -> str:
        return _validate_hex_64(value, "http hash")

    @field_validator("timeout_ms")
    @classmethod
    def _validate_timeout_ms(cls, value: int) -> int:
        if value < 1:
            raise ValueError("timeout_ms must be >= 1")
        return value


class FileActionRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    op: Literal["write", "delete", "move", "mkdir"]
    path: str
    dest_path: str | None = None
    content_hash: str | None = None
    mode: int | str | None = None

    @field_validator("content_hash")
    @classmethod
    def _validate_content_hash(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _validate_hex_64(value, "content_hash")

    @model_validator(mode="after")
    def _validate_file_payload(self) -> "FileActionRecord":
        if self.op == "move" and not self.dest_path:
            raise ValueError("dest_path is required for move actions")
        if self.op == "write" and not self.content_hash:
            raise ValueError("content_hash is required for write actions")
        return self


class ToolchainRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    iap_sdk_version: str = Field(default_factory=_sdk_version)
    amcs_version: str = Field(default=amcs_version)


class ActionEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    amcs_version: str = Field(default=amcs_version)
    iap_version: str = Field(default_factory=_sdk_version)
    event_type: Literal["action_event"] = ACTION_EVENT_TYPE
    agent_id: str
    sequence: int
    prev_event_hash: str
    timestamp_utc: str = Field(default_factory=_utc_now_iso)
    action_kind: Literal["shell", "http", "file"]
    action: dict[str, Any]
    inputs_hash: str
    outputs_hash: str
    artifacts: list[ArtifactRecord] = Field(default_factory=list)
    context_root: str
    signature: str = ""
    session_id: str | None = None
    host_fingerprint: str | None = None
    toolchain: ToolchainRecord | None = None
    labels: dict[str, str] | None = None

    @field_validator("agent_id")
    @classmethod
    def _validate_agent_id(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized.startswith("ed25519:"):
            raise ValueError("agent_id must start with ed25519:")
        return normalized

    @field_validator("sequence")
    @classmethod
    def _validate_sequence(cls, value: int) -> int:
        if value < 1:
            raise ValueError("sequence must be >= 1")
        return value

    @field_validator("prev_event_hash", "inputs_hash", "outputs_hash", "context_root")
    @classmethod
    def _validate_hex_hashes(cls, value: str, info) -> str:
        return _validate_hex_64(value, info.field_name)

    @field_validator("timestamp_utc")
    @classmethod
    def _validate_timestamp(cls, value: str) -> str:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("timestamp_utc must be valid RFC3339 UTC time") from exc
        if parsed.tzinfo is None:
            raise ValueError("timestamp_utc must include timezone")
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    @field_validator("host_fingerprint")
    @classmethod
    def _validate_host_fingerprint(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _validate_hex_64(value, "host_fingerprint")

    @field_validator("signature")
    @classmethod
    def _validate_signature(cls, value: str) -> str:
        return _validate_signature_b64(value)

    @model_validator(mode="after")
    def _validate_action_payload(self) -> "ActionEvent":
        keys = set(self.action.keys())
        if keys != {self.action_kind}:
            raise ValueError("action payload must contain exactly one key matching action_kind")
        payload = self.action[self.action_kind]
        if self.action_kind == "shell":
            ShellActionRecord.model_validate(payload)
        elif self.action_kind == "http":
            HttpActionRecord.model_validate(payload)
        elif self.action_kind == "file":
            FileActionRecord.model_validate(payload)
        return self


class ActionLogIndex(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int = 1
    latest_sequence: int | None = None
    latest_event_hash: str | None = None
    event_count: int = 0


@dataclass(frozen=True)
class ActionLogState:
    event_count: int
    latest_sequence: int | None
    latest_event_hash: str | None


def hash_canonical_object(payload: Any) -> str:
    return sha256_hex(canonical_bytes(payload))


def canonical_action_event_bytes(payload: dict[str, Any], *, include_signature: bool) -> bytes:
    event_payload = dict(payload)
    if not include_signature:
        event_payload["signature"] = ""
    return canonical_bytes(event_payload)


def action_event_hash(payload: dict[str, Any]) -> str:
    model = _validate_action_event(payload)
    return hash_canonical_object(model.model_dump(exclude_none=True))


def sign_action_event(payload: dict[str, Any], private_key_bytes: bytes) -> dict[str, Any]:
    model = _validate_action_event(payload)
    event_dict = model.model_dump(exclude_none=True)
    canonical = canonical_action_event_bytes(event_dict, include_signature=False)
    signature = Ed25519PrivateKey.from_private_bytes(private_key_bytes).sign(canonical)
    event_dict["signature"] = base64.b64encode(signature).decode("ascii")
    _validate_action_event(event_dict)
    return event_dict


def verify_action_event_signature(payload: dict[str, Any], public_key_bytes: bytes) -> bool:
    model = _validate_action_event(payload)
    if not model.signature:
        return False
    signature = base64.b64decode(model.signature)
    canonical = canonical_action_event_bytes(model.model_dump(exclude_none=True), include_signature=False)
    return verify_ed25519(signature, canonical, public_key_bytes)


def create_action_event(
    *,
    agent_id: str,
    sequence: int,
    prev_event_hash: str,
    action_kind: Literal["shell", "http", "file"],
    action_payload: dict[str, Any],
    inputs_hash: str,
    outputs_hash: str,
    context_root: str,
    artifacts: list[dict[str, str]] | None = None,
    timestamp_utc: str | None = None,
    session_id: str | None = None,
    host_fingerprint: str | None = None,
    toolchain: dict[str, str] | None = None,
    labels: dict[str, str] | None = None,
    amcs_version_override: str | None = None,
    iap_version_override: str | None = None,
) -> dict[str, Any]:
    payload = {
        "amcs_version": amcs_version_override or amcs_version,
        "iap_version": iap_version_override or _sdk_version(),
        "event_type": ACTION_EVENT_TYPE,
        "agent_id": agent_id,
        "sequence": sequence,
        "prev_event_hash": prev_event_hash,
        "timestamp_utc": timestamp_utc or _utc_now_iso(),
        "action_kind": action_kind,
        "action": {action_kind: action_payload},
        "inputs_hash": inputs_hash,
        "outputs_hash": outputs_hash,
        "artifacts": artifacts or [],
        "context_root": context_root,
        "signature": "",
        "session_id": session_id,
        "host_fingerprint": host_fingerprint,
        "toolchain": toolchain,
        "labels": labels,
    }
    model = _validate_action_event(payload)
    return model.model_dump(exclude_none=True)


class ActionLogStore:
    """Append-only local storage for signed action events."""

    def __init__(self, base_dir: str | Path) -> None:
        self.base_dir = Path(base_dir)
        self.log_path = self.base_dir / "actions.log"
        self.index_path = self.base_dir / "index.json"

    def replay(self) -> ActionLogState:
        if not self.log_path.exists():
            return ActionLogState(event_count=0, latest_sequence=None, latest_event_hash=None)

        latest_sequence: int | None = None
        latest_event_hash: str | None = None
        event_count = 0

        for line_number, raw_line in enumerate(
            self.log_path.read_text(encoding="utf-8").splitlines(),
            start=1,
        ):
            line = raw_line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ActionLogIntegrityError(
                    f"actions.log line {line_number} is not valid JSON"
                ) from exc

            model = _validate_action_event(event)
            if not model.signature:
                raise ActionLogIntegrityError(
                    f"actions.log line {line_number} is missing a signature"
                )

            expected_sequence = 1 if latest_sequence is None else latest_sequence + 1
            if model.sequence != expected_sequence:
                raise ActionLogIntegrityError(
                    f"actions.log line {line_number} has non-monotonic sequence"
                )

            expected_prev_hash = ZERO_HASH if latest_event_hash is None else latest_event_hash
            if model.prev_event_hash != expected_prev_hash:
                raise ActionLogIntegrityError(
                    f"actions.log line {line_number} has mismatched prev_event_hash"
                )

            latest_sequence = model.sequence
            latest_event_hash = action_event_hash(model.model_dump(exclude_none=True))
            event_count += 1

        return ActionLogState(
            event_count=event_count,
            latest_sequence=latest_sequence,
            latest_event_hash=latest_event_hash,
        )

    def append(self, payload: dict[str, Any]) -> ActionLogState:
        model = _validate_action_event(payload)
        if not model.signature:
            raise InvalidSignatureError("action event must be signed before append")

        state = self.replay()
        expected_sequence = 1 if state.latest_sequence is None else state.latest_sequence + 1
        if model.sequence != expected_sequence:
            raise ActionLogIntegrityError("action event sequence does not continue local chain")

        expected_prev_hash = ZERO_HASH if state.latest_event_hash is None else state.latest_event_hash
        if model.prev_event_hash != expected_prev_hash:
            raise ActionLogIntegrityError("action event prev_event_hash does not match local chain")

        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._append_log_line(model.model_dump(exclude_none=True))

        latest_event_hash = action_event_hash(model.model_dump(exclude_none=True))
        next_state = ActionLogState(
            event_count=state.event_count + 1,
            latest_sequence=model.sequence,
            latest_event_hash=latest_event_hash,
        )
        self._write_index(next_state)
        return next_state

    def load_index(self) -> ActionLogIndex:
        if not self.index_path.exists():
            return ActionLogIndex()
        try:
            payload = json.loads(self.index_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ActionLogIntegrityError("index.json is not valid JSON") from exc
        try:
            return ActionLogIndex.model_validate(payload)
        except ValidationError as exc:
            raise ActionLogIntegrityError("index.json is invalid") from exc

    def _append_log_line(self, payload: dict[str, Any]) -> None:
        created = not self.log_path.exists()
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(canonical_dumps(payload))
            handle.write("\n")
        if created:
            _chmod_owner_only(self.log_path)

    def _write_index(self, state: ActionLogState) -> None:
        payload = ActionLogIndex(
            latest_sequence=state.latest_sequence,
            latest_event_hash=state.latest_event_hash,
            event_count=state.event_count,
        ).model_dump(exclude_none=True)
        self.index_path.write_text(canonical_dumps(payload) + "\n", encoding="utf-8")
        _chmod_owner_only(self.index_path)


def _chmod_owner_only(path: Path) -> None:
    try:
        path.chmod(0o600)
    except OSError:  # pragma: no cover
        return


def _validate_action_event(payload: dict[str, Any]) -> ActionEvent:
    try:
        return ActionEvent.model_validate(payload)
    except ValidationError as exc:
        raise SchemaValidationError(str(exc)) from exc
