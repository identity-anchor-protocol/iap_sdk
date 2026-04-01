"""Verification and summary helpers for local action chains."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from iap_sdk.actions.core import ActionEvent, ActionLogStore, action_event_hash, verify_action_event_signature
from iap_sdk.crypto.agent_identity import derive_agent_id, validate_agent_id
from iap_sdk.errors import ActionLogIntegrityError


@dataclass(frozen=True)
class ActionChainSummary:
    """Lightweight status summary for a local action chain."""

    base_dir: str
    exists: bool
    event_count: int
    latest_sequence: int | None
    latest_event_hash: str | None
    latest_context_root: str | None
    agent_id: str | None
    index_present: bool
    index_consistent: bool
    receipts_present: bool
    artifacts_present: bool


@dataclass(frozen=True)
class ActionChainVerificationResult:
    """Verification result for a local action chain."""

    ok: bool
    reason: str
    event_count: int
    latest_sequence: int | None
    latest_event_hash: str | None
    latest_context_root: str | None
    agent_id: str | None
    signatures_verified: int
    index_consistent: bool


def summarize_action_chain(base_dir: str | Path) -> ActionChainSummary:
    store = ActionLogStore(base_dir)
    state = store.replay()
    events = _read_events(store.log_path)
    latest_event = events[-1] if events else None

    index_present = store.index_path.exists()
    index_consistent = True
    if index_present:
        index = store.load_index()
        index_consistent = (
            index.event_count == state.event_count
            and index.latest_sequence == state.latest_sequence
            and index.latest_event_hash == state.latest_event_hash
        )
    elif state.event_count > 0:
        index_consistent = False

    return ActionChainSummary(
        base_dir=str(store.base_dir),
        exists=store.log_path.exists(),
        event_count=state.event_count,
        latest_sequence=state.latest_sequence,
        latest_event_hash=state.latest_event_hash,
        latest_context_root=latest_event.context_root if latest_event is not None else None,
        agent_id=latest_event.agent_id if latest_event is not None else None,
        index_present=index_present,
        index_consistent=index_consistent,
        receipts_present=(store.base_dir / "receipts.log").exists(),
        artifacts_present=(store.base_dir / "artifacts").exists(),
    )


def verify_action_chain(
    base_dir: str | Path,
    *,
    public_key_bytes: bytes | None = None,
    expected_agent_id: str | None = None,
) -> ActionChainVerificationResult:
    try:
        summary = summarize_action_chain(base_dir)
    except ActionLogIntegrityError as exc:
        return ActionChainVerificationResult(
            ok=False,
            reason=str(exc),
            event_count=0,
            latest_sequence=None,
            latest_event_hash=None,
            latest_context_root=None,
            agent_id=None,
            signatures_verified=0,
            index_consistent=False,
        )

    if summary.event_count == 0:
        return ActionChainVerificationResult(
            ok=True,
            reason="action log is empty",
            event_count=0,
            latest_sequence=None,
            latest_event_hash=None,
            latest_context_root=None,
            agent_id=None,
            signatures_verified=0,
            index_consistent=summary.index_consistent,
        )

    if not summary.index_consistent:
        return ActionChainVerificationResult(
            ok=False,
            reason="index.json does not match replayed action log",
            event_count=summary.event_count,
            latest_sequence=summary.latest_sequence,
            latest_event_hash=summary.latest_event_hash,
            latest_context_root=summary.latest_context_root,
            agent_id=summary.agent_id,
            signatures_verified=0,
            index_consistent=False,
        )

    store = ActionLogStore(base_dir)
    signatures_verified = 0
    derived_agent_id = (
        derive_agent_id(public_key_bytes) if public_key_bytes is not None else None
    )
    events = _read_events(store.log_path)

    for model in events:
        if expected_agent_id is not None and model.agent_id != expected_agent_id:
            return ActionChainVerificationResult(
                ok=False,
                reason="action log contains unexpected agent_id",
                event_count=summary.event_count,
                latest_sequence=summary.latest_sequence,
                latest_event_hash=summary.latest_event_hash,
                latest_context_root=summary.latest_context_root,
                agent_id=summary.agent_id,
                signatures_verified=signatures_verified,
                index_consistent=True,
            )
        if derived_agent_id is not None and model.agent_id != derived_agent_id:
            return ActionChainVerificationResult(
                ok=False,
                reason="identity file does not match action log agent_id",
                event_count=summary.event_count,
                latest_sequence=summary.latest_sequence,
                latest_event_hash=summary.latest_event_hash,
                latest_context_root=summary.latest_context_root,
                agent_id=summary.agent_id,
                signatures_verified=signatures_verified,
                index_consistent=True,
            )
        if public_key_bytes is not None and not validate_agent_id(public_key_bytes, model.agent_id):
            return ActionChainVerificationResult(
                ok=False,
                reason="action log agent_id derivation mismatch",
                event_count=summary.event_count,
                latest_sequence=summary.latest_sequence,
                latest_event_hash=summary.latest_event_hash,
                latest_context_root=summary.latest_context_root,
                agent_id=summary.agent_id,
                signatures_verified=signatures_verified,
                index_consistent=True,
            )
        if public_key_bytes is not None and not verify_action_event_signature(
            model.model_dump(exclude_none=True),
            public_key_bytes,
        ):
            return ActionChainVerificationResult(
                ok=False,
                reason=f"invalid action signature at sequence {model.sequence}",
                event_count=summary.event_count,
                latest_sequence=summary.latest_sequence,
                latest_event_hash=summary.latest_event_hash,
                latest_context_root=summary.latest_context_root,
                agent_id=summary.agent_id,
                signatures_verified=signatures_verified,
                index_consistent=True,
            )
        if action_event_hash(model.model_dump(exclude_none=True)) == "":
            return ActionChainVerificationResult(
                ok=False,
                reason="unable to recompute action event hash",
                event_count=summary.event_count,
                latest_sequence=summary.latest_sequence,
                latest_event_hash=summary.latest_event_hash,
                latest_context_root=summary.latest_context_root,
                agent_id=summary.agent_id,
                signatures_verified=signatures_verified,
                index_consistent=True,
            )
        if public_key_bytes is not None:
            signatures_verified += 1

    return ActionChainVerificationResult(
        ok=True,
        reason="ok",
        event_count=summary.event_count,
        latest_sequence=summary.latest_sequence,
        latest_event_hash=summary.latest_event_hash,
        latest_context_root=summary.latest_context_root,
        agent_id=summary.agent_id,
        signatures_verified=signatures_verified,
        index_consistent=True,
    )


def _read_events(log_path: Path) -> list[ActionEvent]:
    if not log_path.exists():
        return []

    models: list[ActionEvent] = []
    for line_number, raw_line in enumerate(log_path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ActionLogIntegrityError(f"actions.log line {line_number} is not valid JSON") from exc
        try:
            models.append(ActionEvent.model_validate(payload))
        except Exception as exc:
            raise ActionLogIntegrityError(f"actions.log line {line_number} is invalid") from exc
    return models


__all__ = [
    "ActionChainSummary",
    "ActionChainVerificationResult",
    "summarize_action_chain",
    "verify_action_chain",
]
