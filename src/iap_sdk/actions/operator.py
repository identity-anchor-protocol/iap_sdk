"""High-level operator wrappers for local Isnād action logging."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from iap_sdk.actions.core import (
    ZERO_HASH,
    ActionLogState,
    ActionLogStore,
    action_event_hash,
    create_action_event,
    hash_canonical_object,
    sign_action_event,
)
from iap_sdk.cli.amcs import AMCSError, get_amcs_root
from iap_sdk.crypto.agent_identity import derive_agent_id, validate_agent_id
from iap_sdk.errors import ActionContextError, ActionIdentityError

_HEX_64 = set("0123456789abcdef")


@dataclass(frozen=True)
class RecordedActionResult:
    """Result of an executed action plus its appended action event."""

    result: Any
    event: dict[str, Any]
    event_hash: str
    state: ActionLogState


def default_actions_dir(project_root: str | Path | None = None) -> Path:
    root = Path(project_root) if project_root is not None else Path.cwd()
    return root / ".iap" / "actions"


def default_project_identity_path(project_root: str | Path | None = None) -> Path:
    root = Path(project_root) if project_root is not None else Path.cwd()
    return root / ".iap" / "identity" / "ed25519.json"


def default_state_root_path(project_root: str | Path | None = None) -> Path:
    root = Path(project_root) if project_root is not None else Path.cwd()
    return root / ".iap" / "state" / "state_root.json"


def resolve_context_root(
    *,
    agent_id: str,
    project_root: str | Path | None = None,
    state_root_path: str | Path | None = None,
    amcs_db_path: str | Path | None = None,
    explicit_context_root: str | None = None,
) -> str:
    if explicit_context_root is not None:
        return _normalize_hex_hash(explicit_context_root, field_name="context_root")

    resolved_state_root = (
        Path(state_root_path)
        if state_root_path is not None
        else default_state_root_path(project_root)
    )
    if resolved_state_root.exists():
        try:
            payload = json.loads(resolved_state_root.read_text(encoding="utf-8"))
        except Exception as exc:  # pragma: no cover - exact parser failure does not matter
            raise ActionContextError(f"invalid state root file: {resolved_state_root}") from exc
        memory_root = payload.get("memory_root")
        if isinstance(memory_root, str) and memory_root.strip():
            return _normalize_hex_hash(memory_root, field_name="context_root")

    if amcs_db_path is not None:
        try:
            return get_amcs_root(
                amcs_db_path=str(amcs_db_path),
                agent_id=agent_id,
            ).memory_root
        except AMCSError as exc:
            raise ActionContextError(str(exc)) from exc

    raise ActionContextError(
        "missing context_root; provide one explicitly, populate .iap/state/state_root.json "
        "with a memory_root, or configure an AMCS database path"
    )


class IAPOperator:
    """Primary SDK integration surface for local action logging."""

    def __init__(
        self,
        *,
        private_key_bytes: bytes,
        agent_id: str | None = None,
        public_key_bytes: bytes | None = None,
        project_root: str | Path | None = None,
        actions_dir: str | Path | None = None,
        state_root_path: str | Path | None = None,
        amcs_db_path: str | Path | None = None,
        logging_mode: str = "hash_only",
        default_env_allowlist: Sequence[str] | None = None,
        default_header_allowlist: Sequence[str] | None = None,
        session_id: str | None = None,
        host_fingerprint: str | None = None,
        toolchain: Mapping[str, str] | None = None,
    ) -> None:
        if logging_mode not in {"hash_only", "local_full"}:
            raise ValueError("logging_mode must be 'hash_only' or 'local_full'")
        self.project_root = Path(project_root) if project_root is not None else Path.cwd()
        self.actions_dir = (
            Path(actions_dir)
            if actions_dir is not None
            else default_actions_dir(self.project_root)
        )
        self.state_root_path = (
            Path(state_root_path)
            if state_root_path is not None
            else default_state_root_path(self.project_root)
        )
        self.amcs_db_path = str(amcs_db_path) if amcs_db_path is not None else None
        self.private_key_bytes = private_key_bytes
        self.public_key_bytes = public_key_bytes
        derived_agent_id = (
            derive_agent_id(public_key_bytes) if public_key_bytes is not None else agent_id
        )
        if not derived_agent_id:
            raise ActionIdentityError("agent_id or public_key_bytes is required")
        if public_key_bytes is not None and not validate_agent_id(
            public_key_bytes,
            derived_agent_id,
        ):
            raise ActionIdentityError("agent identity does not match public key")
        self.agent_id = derived_agent_id
        self.logging_mode = logging_mode
        self.default_env_allowlist = _normalize_allowlist(default_env_allowlist)
        self.default_header_allowlist = _normalize_allowlist(default_header_allowlist)
        self.session_id = session_id
        self.host_fingerprint = (
            _normalize_hex_hash(host_fingerprint, field_name="host_fingerprint")
            if host_fingerprint is not None
            else None
        )
        self.toolchain = dict(toolchain) if toolchain is not None else None
        self.store = ActionLogStore(self.actions_dir)

    @classmethod
    def from_project(
        cls,
        *,
        project_root: str | Path | None = None,
        identity_path: str | Path | None = None,
        actions_dir: str | Path | None = None,
        state_root_path: str | Path | None = None,
        amcs_db_path: str | Path | None = None,
        logging_mode: str = "hash_only",
        default_env_allowlist: Sequence[str] | None = None,
        default_header_allowlist: Sequence[str] | None = None,
        session_id: str | None = None,
        host_fingerprint: str | None = None,
        toolchain: Mapping[str, str] | None = None,
    ) -> "IAPOperator":
        resolved_project_root = Path(project_root) if project_root is not None else Path.cwd()
        resolved_identity_path = (
            Path(identity_path)
            if identity_path is not None
            else default_project_identity_path(resolved_project_root)
        )
        private_key_bytes, public_key_bytes = _read_identity_file(resolved_identity_path)
        return cls(
            private_key_bytes=private_key_bytes,
            public_key_bytes=public_key_bytes,
            project_root=resolved_project_root,
            actions_dir=actions_dir,
            state_root_path=state_root_path,
            amcs_db_path=amcs_db_path,
            logging_mode=logging_mode,
            default_env_allowlist=default_env_allowlist,
            default_header_allowlist=default_header_allowlist,
            session_id=session_id,
            host_fingerprint=host_fingerprint,
            toolchain=toolchain,
        )

    def run_shell(
        self,
        command: str,
        args: Sequence[str] | None = None,
        *,
        cwd: str | Path | None = None,
        env: Mapping[str, str] | None = None,
        env_allowlist: Sequence[str] | None = None,
        stdin_bytes: bytes | str | None = None,
        timeout_seconds: float | None = None,
        check: bool = False,
        context_root: str | None = None,
        labels: Mapping[str, str] | None = None,
    ) -> RecordedActionResult:
        shell_args = list(args or [])
        effective_cwd = str(Path(cwd) if cwd is not None else self.project_root)
        allowed_env_keys = (
            self.default_env_allowlist
            if env_allowlist is None
            else _normalize_allowlist(env_allowlist)
        )
        stdin_payload = _coerce_bytes(stdin_bytes)
        action_payload: dict[str, Any] = {
            "command": command,
            "args": shell_args,
            "cwd": effective_cwd,
            "env_allowlist": allowed_env_keys,
        }
        if stdin_payload is not None:
            action_payload["stdin_hash"] = _hash_bytes(stdin_payload)

        inputs_object = {
            "command": command,
            "args": shell_args,
            "cwd": effective_cwd,
            "env_keys": allowed_env_keys,
            "stdin_hash": action_payload.get("stdin_hash"),
        }
        prepared = self._prepare_event(
            action_kind="shell",
            action_payload=action_payload,
            inputs_object=inputs_object,
            context_root=context_root,
            labels=labels,
        )

        started_at = time.monotonic()
        try:
            completed = subprocess.run(
                [command, *shell_args],
                cwd=effective_cwd,
                env=dict(env) if env is not None else None,
                input=stdin_payload,
                capture_output=True,
                check=False,
                timeout=timeout_seconds,
            )
        except Exception as exc:
            return self._record_failure(
                prepared=prepared,
                duration_ms=_duration_ms(started_at),
                error=exc,
            )

        stdout_bytes = completed.stdout or b""
        stderr_bytes = completed.stderr or b""
        outputs_object = {
            "exit_code": completed.returncode,
            "stdout_hash": _hash_bytes(stdout_bytes),
            "stderr_hash": _hash_bytes(stderr_bytes),
            "duration_ms": _duration_ms(started_at),
        }
        artifacts = [
            {"type": "stdout", "hash": outputs_object["stdout_hash"]},
            {"type": "stderr", "hash": outputs_object["stderr_hash"]},
        ]
        self._store_artifact("stdout", stdout_bytes)
        self._store_artifact("stderr", stderr_bytes)

        recorded = self._append_event(
            prepared=prepared,
            outputs_object=outputs_object,
            artifacts=artifacts,
        )
        if check and completed.returncode != 0:
            raise subprocess.CalledProcessError(
                completed.returncode,
                [command, *shell_args],
                output=completed.stdout,
                stderr=completed.stderr,
            )
        return RecordedActionResult(
            result=completed,
            event=recorded.event,
            event_hash=recorded.event_hash,
            state=recorded.state,
        )

    def http_request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | str | None = None,
        timeout_ms: int = 5000,
        header_allowlist: Sequence[str] | None = None,
        response_header_allowlist: Sequence[str] | None = None,
        context_root: str | None = None,
        labels: Mapping[str, str] | None = None,
    ) -> RecordedActionResult:
        import requests

        request_body = _coerce_bytes(body) or b""
        allowed_request_headers = (
            self.default_header_allowlist
            if header_allowlist is None
            else _normalize_allowlist(header_allowlist)
        )
        allowed_response_headers = (
            allowed_request_headers
            if response_header_allowlist is None
            else _normalize_allowlist(response_header_allowlist)
        )
        normalized_headers = _normalize_headers(headers, allowed_request_headers)
        action_payload = {
            "method": method.upper(),
            "url": url,
            "headers_hash": hash_canonical_object(normalized_headers),
            "body_hash": _hash_bytes(request_body),
            "timeout_ms": timeout_ms,
        }
        inputs_object = {
            "method": method.upper(),
            "url": url,
            "headers": normalized_headers,
            "body_hash": action_payload["body_hash"],
            "timeout_ms": timeout_ms,
        }
        prepared = self._prepare_event(
            action_kind="http",
            action_payload=action_payload,
            inputs_object=inputs_object,
            context_root=context_root,
            labels=labels,
        )

        started_at = time.monotonic()
        try:
            response = requests.request(
                method=method.upper(),
                url=url,
                headers=dict(headers or {}),
                data=request_body or None,
                timeout=timeout_ms / 1000.0,
            )
        except Exception as exc:
            return self._record_failure(
                prepared=prepared,
                duration_ms=_duration_ms(started_at),
                error=exc,
            )

        response_body = response.content or b""
        normalized_response_headers = _normalize_headers(response.headers, allowed_response_headers)
        outputs_object = {
            "status_code": response.status_code,
            "response_headers_hash": hash_canonical_object(normalized_response_headers),
            "response_body_hash": _hash_bytes(response_body),
            "duration_ms": _duration_ms(started_at),
        }
        artifacts = [{"type": "response_body", "hash": outputs_object["response_body_hash"]}]
        self._store_artifact("response_body", response_body)
        recorded = self._append_event(
            prepared=prepared,
            outputs_object=outputs_object,
            artifacts=artifacts,
        )
        return RecordedActionResult(
            result=response,
            event=recorded.event,
            event_hash=recorded.event_hash,
            state=recorded.state,
        )

    def file_write(
        self,
        path: str | Path,
        bytes_or_text: bytes | str,
        *,
        mode: int | str | None = None,
        encoding: str = "utf-8",
        context_root: str | None = None,
        labels: Mapping[str, str] | None = None,
    ) -> RecordedActionResult:
        target_path = Path(path)
        content_bytes = _coerce_bytes(bytes_or_text, encoding=encoding) or b""
        content_hash = _hash_bytes(content_bytes)
        action_payload = {
            "op": "write",
            "path": str(target_path),
            "content_hash": content_hash,
        }
        if mode is not None:
            action_payload["mode"] = mode
        inputs_object = {
            "op": "write",
            "path": str(target_path),
            "content_hash": content_hash,
            "mode": mode,
        }
        prepared = self._prepare_event(
            action_kind="file",
            action_payload=action_payload,
            inputs_object=inputs_object,
            context_root=context_root,
            labels=labels,
        )

        started_at = time.monotonic()
        try:
            if isinstance(bytes_or_text, bytes):
                target_path.write_bytes(content_bytes)
            else:
                target_path.write_text(bytes_or_text, encoding=encoding)
            if isinstance(mode, int):
                target_path.chmod(mode)
        except Exception as exc:
            return self._record_failure(
                prepared=prepared,
                duration_ms=_duration_ms(started_at),
                error=exc,
            )

        outputs_object = {
            "result": "written",
            "content_hash": content_hash,
            "duration_ms": _duration_ms(started_at),
        }
        artifacts = [{"type": "file_content", "hash": content_hash}]
        self._store_artifact("file_content", content_bytes)
        recorded = self._append_event(
            prepared=prepared,
            outputs_object=outputs_object,
            artifacts=artifacts,
        )
        return RecordedActionResult(
            result=target_path,
            event=recorded.event,
            event_hash=recorded.event_hash,
            state=recorded.state,
        )

    def file_delete(
        self,
        path: str | Path,
        *,
        context_root: str | None = None,
        labels: Mapping[str, str] | None = None,
    ) -> RecordedActionResult:
        target_path = Path(path)
        prepared = self._prepare_event(
            action_kind="file",
            action_payload={"op": "delete", "path": str(target_path)},
            inputs_object={"op": "delete", "path": str(target_path)},
            context_root=context_root,
            labels=labels,
        )

        started_at = time.monotonic()
        try:
            target_path.unlink()
        except Exception as exc:
            return self._record_failure(
                prepared=prepared,
                duration_ms=_duration_ms(started_at),
                error=exc,
            )

        recorded = self._append_event(
            prepared=prepared,
            outputs_object={"result": "deleted", "duration_ms": _duration_ms(started_at)},
            artifacts=[],
        )
        return RecordedActionResult(
            result=target_path,
            event=recorded.event,
            event_hash=recorded.event_hash,
            state=recorded.state,
        )

    def file_move(
        self,
        src: str | Path,
        dest: str | Path,
        *,
        context_root: str | None = None,
        labels: Mapping[str, str] | None = None,
    ) -> RecordedActionResult:
        source_path = Path(src)
        dest_path = Path(dest)
        prepared = self._prepare_event(
            action_kind="file",
            action_payload={
                "op": "move",
                "path": str(source_path),
                "dest_path": str(dest_path),
            },
            inputs_object={
                "op": "move",
                "path": str(source_path),
                "dest_path": str(dest_path),
            },
            context_root=context_root,
            labels=labels,
        )

        started_at = time.monotonic()
        try:
            result = source_path.rename(dest_path)
        except Exception as exc:
            return self._record_failure(
                prepared=prepared,
                duration_ms=_duration_ms(started_at),
                error=exc,
            )

        recorded = self._append_event(
            prepared=prepared,
            outputs_object={"result": "moved", "duration_ms": _duration_ms(started_at)},
            artifacts=[],
        )
        return RecordedActionResult(
            result=result,
            event=recorded.event,
            event_hash=recorded.event_hash,
            state=recorded.state,
        )

    def mkdir(
        self,
        path: str | Path,
        *,
        parents: bool = False,
        exist_ok: bool = False,
        mode: int = 0o777,
        context_root: str | None = None,
        labels: Mapping[str, str] | None = None,
    ) -> RecordedActionResult:
        target_path = Path(path)
        action_payload: dict[str, Any] = {
            "op": "mkdir",
            "path": str(target_path),
            "mode": mode,
        }
        prepared = self._prepare_event(
            action_kind="file",
            action_payload=action_payload,
            inputs_object={
                "op": "mkdir",
                "path": str(target_path),
                "mode": mode,
                "parents": parents,
                "exist_ok": exist_ok,
            },
            context_root=context_root,
            labels=labels,
        )

        started_at = time.monotonic()
        try:
            target_path.mkdir(mode=mode, parents=parents, exist_ok=exist_ok)
        except Exception as exc:
            return self._record_failure(
                prepared=prepared,
                duration_ms=_duration_ms(started_at),
                error=exc,
            )

        recorded = self._append_event(
            prepared=prepared,
            outputs_object={"result": "created", "duration_ms": _duration_ms(started_at)},
            artifacts=[],
        )
        return RecordedActionResult(
            result=target_path,
            event=recorded.event,
            event_hash=recorded.event_hash,
            state=recorded.state,
        )

    def _prepare_event(
        self,
        *,
        action_kind: str,
        action_payload: dict[str, Any],
        inputs_object: dict[str, Any],
        context_root: str | None,
        labels: Mapping[str, str] | None,
    ) -> dict[str, Any]:
        state = self.store.replay()
        next_sequence = 1 if state.latest_sequence is None else state.latest_sequence + 1
        prev_event_hash = ZERO_HASH if state.latest_event_hash is None else state.latest_event_hash
        resolved_context_root = resolve_context_root(
            agent_id=self.agent_id,
            project_root=self.project_root,
            state_root_path=self.state_root_path,
            amcs_db_path=self.amcs_db_path,
            explicit_context_root=context_root,
        )
        return {
            "sequence": next_sequence,
            "prev_event_hash": prev_event_hash,
            "context_root": resolved_context_root,
            "action_kind": action_kind,
            "action_payload": action_payload,
            "inputs_hash": hash_canonical_object(inputs_object),
            "labels": dict(labels) if labels is not None else None,
        }

    def _append_event(
        self,
        *,
        prepared: dict[str, Any],
        outputs_object: dict[str, Any],
        artifacts: list[dict[str, str]],
    ) -> RecordedActionResult:
        unsigned_event = create_action_event(
            agent_id=self.agent_id,
            sequence=prepared["sequence"],
            prev_event_hash=prepared["prev_event_hash"],
            action_kind=prepared["action_kind"],
            action_payload=prepared["action_payload"],
            inputs_hash=prepared["inputs_hash"],
            outputs_hash=hash_canonical_object(outputs_object),
            context_root=prepared["context_root"],
            artifacts=artifacts,
            session_id=self.session_id,
            host_fingerprint=self.host_fingerprint,
            toolchain=self.toolchain,
            labels=prepared["labels"],
        )
        signed_event = sign_action_event(unsigned_event, self.private_key_bytes)
        state = self.store.append(signed_event)
        return RecordedActionResult(
            result=None,
            event=signed_event,
            event_hash=action_event_hash(signed_event),
            state=state,
        )

    def _record_failure(
        self,
        *,
        prepared: dict[str, Any],
        duration_ms: int,
        error: Exception,
    ) -> RecordedActionResult:
        self._append_event(
            prepared=prepared,
            outputs_object={
                "result": "error",
                "error_type": error.__class__.__name__,
                "error_message_hash": _hash_text(str(error)),
                "duration_ms": duration_ms,
            },
            artifacts=[],
        )
        raise error

    def _store_artifact(self, artifact_type: str, payload: bytes) -> None:
        if self.logging_mode != "local_full" or payload == b"":
            return
        artifact_hash = _hash_bytes(payload)
        artifact_dir = self.actions_dir / "artifacts" / artifact_type
        artifact_dir.mkdir(parents=True, exist_ok=True)
        _chmod_owner_only_dir(self.actions_dir)
        _chmod_owner_only_dir(self.actions_dir / "artifacts")
        _chmod_owner_only_dir(artifact_dir)
        artifact_path = artifact_dir / f"{artifact_hash}.bin"
        if not artifact_path.exists():
            artifact_path.write_bytes(payload)
            _chmod_owner_only_file(artifact_path)


def _normalize_allowlist(values: Sequence[str] | None) -> list[str]:
    if not values:
        return []
    return sorted({str(value).strip() for value in values if str(value).strip()})


def _normalize_headers(
    headers: Mapping[str, str] | None,
    allowlist: Sequence[str],
) -> dict[str, str]:
    if not headers or not allowlist:
        return {}
    allowset = {value.lower() for value in allowlist}
    normalized: dict[str, str] = {}
    for key, value in headers.items():
        lowered = str(key).strip().lower()
        if lowered in allowset:
            normalized[lowered] = str(value)
    return dict(sorted(normalized.items()))


def _coerce_bytes(value: bytes | str | None, *, encoding: str = "utf-8") -> bytes | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    return value.encode(encoding)


def _duration_ms(started_at: float) -> int:
    return max(0, int(round((time.monotonic() - started_at) * 1000)))


def _hash_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _hash_text(value: str) -> str:
    return _hash_bytes(value.encode("utf-8"))


def _normalize_hex_hash(value: str, *, field_name: str) -> str:
    normalized = value.strip().lower()
    if len(normalized) != 64 or any(ch not in _HEX_64 for ch in normalized):
        raise ActionContextError(f"{field_name} must be 64 lowercase hex chars")
    return normalized


def _read_identity_file(path: Path) -> tuple[bytes, bytes]:
    if not path.exists():
        raise ActionIdentityError(f"identity file not found: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ActionIdentityError(f"invalid identity file: {path}") from exc
    private_key_b64 = payload.get("private_key_b64")
    public_key_b64 = payload.get("public_key_b64")
    if not isinstance(private_key_b64, str) or not isinstance(public_key_b64, str):
        raise ActionIdentityError("identity file must contain private_key_b64 and public_key_b64")
    try:
        private_key_bytes = base64.b64decode(private_key_b64, validate=True)
        public_key_bytes = base64.b64decode(public_key_b64, validate=True)
    except Exception as exc:
        raise ActionIdentityError("identity keys must be valid base64") from exc
    if len(private_key_bytes) != 32 or len(public_key_bytes) != 32:
        raise ActionIdentityError("identity keys must decode to 32 bytes")
    return private_key_bytes, public_key_bytes


def _chmod_owner_only_file(path: Path) -> None:
    if os.name != "posix":
        return
    try:
        path.chmod(0o600)
    except OSError:  # pragma: no cover
        return


def _chmod_owner_only_dir(path: Path) -> None:
    if os.name != "posix":
        return
    try:
        path.chmod(0o700)
    except OSError:  # pragma: no cover
        return


__all__ = [
    "IAPOperator",
    "RecordedActionResult",
    "default_actions_dir",
    "default_project_identity_path",
    "default_state_root_path",
    "resolve_context_root",
]
