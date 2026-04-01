"""Verification and summary helpers for local action chains."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from iap_sdk.actions.core import (
    ActionLogStore,
    action_event_hash,
    verify_action_event_signature,
)
from iap_sdk.actions.receipts import summarize_action_receipts, verify_action_receipts
from iap_sdk.crypto.agent_identity import derive_agent_id, validate_agent_id
from iap_sdk.errors import ActionLogIntegrityError, ActionReceiptError


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
    receipt_count: int
    latest_receipt_sequence: int | None
    latest_receipt_event_hash: str | None
    latest_registry_id: str | None
    receipt_log_consistent: bool
    receipt_coverage_complete: bool
    fork_detected_count: int
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
    receipt_count: int
    latest_receipt_sequence: int | None
    latest_receipt_event_hash: str | None
    latest_registry_id: str | None
    receipt_log_consistent: bool
    receipt_coverage_complete: bool
    fork_detected_count: int
    receipt_signatures_verified: int


def summarize_action_chain(base_dir: str | Path) -> ActionChainSummary:
    store = ActionLogStore(base_dir)
    state = store.replay()
    events = store.read_events()
    latest_event = events[-1] if events else None
    receipts = summarize_action_receipts(base_dir)

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
        receipt_count=receipts.receipt_count,
        latest_receipt_sequence=receipts.latest_receipt_sequence,
        latest_receipt_event_hash=receipts.latest_receipt_event_hash,
        latest_registry_id=receipts.latest_registry_id,
        receipt_log_consistent=receipts.receipt_log_consistent,
        receipt_coverage_complete=receipts.receipt_coverage_complete,
        fork_detected_count=receipts.fork_detected_count,
        artifacts_present=(store.base_dir / "artifacts").exists(),
    )


def verify_action_chain(
    base_dir: str | Path,
    *,
    public_key_bytes: bytes | None = None,
    expected_agent_id: str | None = None,
    registry_public_key_b64: str | None = None,
) -> ActionChainVerificationResult:
    try:
        summary = summarize_action_chain(base_dir)
    except (ActionLogIntegrityError, ActionReceiptError) as exc:
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
            receipt_count=0,
            latest_receipt_sequence=None,
            latest_receipt_event_hash=None,
            latest_registry_id=None,
            receipt_log_consistent=False,
            receipt_coverage_complete=False,
            fork_detected_count=0,
            receipt_signatures_verified=0,
        )

    if summary.event_count == 0:
        receipt_result = verify_action_receipts(
            base_dir,
            registry_public_key_b64=registry_public_key_b64,
            expected_agent_id=expected_agent_id,
        )
        return ActionChainVerificationResult(
            ok=receipt_result.ok,
            reason=(
                "action log is empty" if receipt_result.ok else receipt_result.reason
            ),
            event_count=0,
            latest_sequence=None,
            latest_event_hash=None,
            latest_context_root=None,
            agent_id=None,
            signatures_verified=0,
            index_consistent=summary.index_consistent,
            receipt_count=receipt_result.receipt_count,
            latest_receipt_sequence=receipt_result.latest_receipt_sequence,
            latest_receipt_event_hash=receipt_result.latest_receipt_event_hash,
            latest_registry_id=receipt_result.latest_registry_id,
            receipt_log_consistent=receipt_result.receipt_log_consistent,
            receipt_coverage_complete=receipt_result.receipt_coverage_complete,
            fork_detected_count=receipt_result.fork_detected_count,
            receipt_signatures_verified=receipt_result.receipt_signatures_verified,
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
            receipt_count=summary.receipt_count,
            latest_receipt_sequence=summary.latest_receipt_sequence,
            latest_receipt_event_hash=summary.latest_receipt_event_hash,
            latest_registry_id=summary.latest_registry_id,
            receipt_log_consistent=summary.receipt_log_consistent,
            receipt_coverage_complete=summary.receipt_coverage_complete,
            fork_detected_count=summary.fork_detected_count,
            receipt_signatures_verified=0,
        )

    store = ActionLogStore(base_dir)
    signatures_verified = 0
    derived_agent_id = (
        derive_agent_id(public_key_bytes) if public_key_bytes is not None else None
    )
    events = store.read_events()

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
                receipt_count=summary.receipt_count,
                latest_receipt_sequence=summary.latest_receipt_sequence,
                latest_receipt_event_hash=summary.latest_receipt_event_hash,
                latest_registry_id=summary.latest_registry_id,
                receipt_log_consistent=summary.receipt_log_consistent,
                receipt_coverage_complete=summary.receipt_coverage_complete,
                fork_detected_count=summary.fork_detected_count,
                receipt_signatures_verified=0,
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
                receipt_count=summary.receipt_count,
                latest_receipt_sequence=summary.latest_receipt_sequence,
                latest_receipt_event_hash=summary.latest_receipt_event_hash,
                latest_registry_id=summary.latest_registry_id,
                receipt_log_consistent=summary.receipt_log_consistent,
                receipt_coverage_complete=summary.receipt_coverage_complete,
                fork_detected_count=summary.fork_detected_count,
                receipt_signatures_verified=0,
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
                receipt_count=summary.receipt_count,
                latest_receipt_sequence=summary.latest_receipt_sequence,
                latest_receipt_event_hash=summary.latest_receipt_event_hash,
                latest_registry_id=summary.latest_registry_id,
                receipt_log_consistent=summary.receipt_log_consistent,
                receipt_coverage_complete=summary.receipt_coverage_complete,
                fork_detected_count=summary.fork_detected_count,
                receipt_signatures_verified=0,
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
                receipt_count=summary.receipt_count,
                latest_receipt_sequence=summary.latest_receipt_sequence,
                latest_receipt_event_hash=summary.latest_receipt_event_hash,
                latest_registry_id=summary.latest_registry_id,
                receipt_log_consistent=summary.receipt_log_consistent,
                receipt_coverage_complete=summary.receipt_coverage_complete,
                fork_detected_count=summary.fork_detected_count,
                receipt_signatures_verified=0,
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
                receipt_count=summary.receipt_count,
                latest_receipt_sequence=summary.latest_receipt_sequence,
                latest_receipt_event_hash=summary.latest_receipt_event_hash,
                latest_registry_id=summary.latest_registry_id,
                receipt_log_consistent=summary.receipt_log_consistent,
                receipt_coverage_complete=summary.receipt_coverage_complete,
                fork_detected_count=summary.fork_detected_count,
                receipt_signatures_verified=0,
            )
        if public_key_bytes is not None:
            signatures_verified += 1

    receipt_result = verify_action_receipts(
        base_dir,
        registry_public_key_b64=registry_public_key_b64,
        expected_agent_id=expected_agent_id,
    )
    if not receipt_result.ok:
        return ActionChainVerificationResult(
            ok=False,
            reason=receipt_result.reason,
            event_count=summary.event_count,
            latest_sequence=summary.latest_sequence,
            latest_event_hash=summary.latest_event_hash,
            latest_context_root=summary.latest_context_root,
            agent_id=summary.agent_id,
            signatures_verified=signatures_verified,
            index_consistent=True,
            receipt_count=receipt_result.receipt_count,
            latest_receipt_sequence=receipt_result.latest_receipt_sequence,
            latest_receipt_event_hash=receipt_result.latest_receipt_event_hash,
            latest_registry_id=receipt_result.latest_registry_id,
            receipt_log_consistent=receipt_result.receipt_log_consistent,
            receipt_coverage_complete=receipt_result.receipt_coverage_complete,
            fork_detected_count=receipt_result.fork_detected_count,
            receipt_signatures_verified=receipt_result.receipt_signatures_verified,
        )

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
        receipt_count=receipt_result.receipt_count,
        latest_receipt_sequence=receipt_result.latest_receipt_sequence,
        latest_receipt_event_hash=receipt_result.latest_receipt_event_hash,
        latest_registry_id=receipt_result.latest_registry_id,
        receipt_log_consistent=receipt_result.receipt_log_consistent,
        receipt_coverage_complete=receipt_result.receipt_coverage_complete,
        fork_detected_count=receipt_result.fork_detected_count,
        receipt_signatures_verified=receipt_result.receipt_signatures_verified,
    )

__all__ = [
    "ActionChainSummary",
    "ActionChainVerificationResult",
    "summarize_action_chain",
    "verify_action_chain",
]
