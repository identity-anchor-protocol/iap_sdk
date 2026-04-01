"""Registry receipt helpers for Isnād action flushing."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from iap_sdk.actions.core import ActionLogStore, action_event_hash
from iap_sdk.crypto.ed25519_verify import verify_ed25519
from iap_sdk.errors import ActionReceiptError

_HEX_64 = set("0123456789abcdef")


def _validate_hex_64(value: str, field_name: str) -> str:
    normalized = value.strip().lower()
    if len(normalized) != 64 or any(ch not in _HEX_64 for ch in normalized):
        raise ValueError(f"{field_name} must be 64 lowercase hex chars")
    return normalized


def _validate_timestamp(value: str, field_name: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a valid RFC3339 UTC time") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field_name} must include timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class ActionReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    receipt_id: str
    agent_id: str
    sequence: int
    prev_event_hash: str
    event_hash: str
    context_root: str
    timestamp_utc: str
    server_timestamp_utc: str
    action_kind: str
    fork_detected: bool = False
    conflicting_event_hashes: list[str] = Field(default_factory=list)
    registry_id: str
    protocol_version: str
    registry_signature_b64: str

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

    @field_validator("prev_event_hash", "event_hash", "context_root")
    @classmethod
    def _validate_hash_fields(cls, value: str, info) -> str:
        return _validate_hex_64(value, str(info.field_name))

    @field_validator("timestamp_utc", "server_timestamp_utc")
    @classmethod
    def _validate_time_fields(cls, value: str, info) -> str:
        return _validate_timestamp(value, str(info.field_name))

    @field_validator("conflicting_event_hashes")
    @classmethod
    def _validate_conflicting_hashes(cls, value: list[str]) -> list[str]:
        return [_validate_hex_64(item, "conflicting_event_hashes item") for item in value]

    @field_validator("registry_signature_b64")
    @classmethod
    def _validate_signature_b64(cls, value: str) -> str:
        try:
            decoded = base64.b64decode(value, validate=True)
        except Exception as exc:
            raise ValueError("registry_signature_b64 must be valid base64") from exc
        if len(decoded) != 64:
            raise ValueError("registry_signature_b64 must decode to 64 bytes")
        return value

    @model_validator(mode="after")
    def _validate_action_kind(self) -> "ActionReceipt":
        if self.action_kind not in {"shell", "http", "file"}:
            raise ValueError("action_kind must be shell, http, or file")
        return self


class ActionReceiptLatest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str
    latest_sequence: int | None = None
    latest_event_hash: str | None = None
    latest_receipt: ActionReceipt | None = None

    @field_validator("latest_sequence")
    @classmethod
    def _validate_latest_sequence(cls, value: int | None) -> int | None:
        if value is None:
            return None
        if value < 1:
            raise ValueError("latest_sequence must be >= 1")
        return value

    @field_validator("latest_event_hash")
    @classmethod
    def _validate_latest_event_hash(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _validate_hex_64(value, "latest_event_hash")

    @model_validator(mode="after")
    def _validate_latest_fields(self) -> "ActionReceiptLatest":
        if self.latest_sequence is None:
            if self.latest_event_hash is not None or self.latest_receipt is not None:
                raise ValueError("latest_event_hash/latest_receipt require latest_sequence")
            return self
        if self.latest_event_hash is None or self.latest_receipt is None:
            raise ValueError(
                "latest_event_hash and latest_receipt are required when latest_sequence is set"
            )
        if self.latest_receipt.sequence != self.latest_sequence:
            raise ValueError("latest_receipt.sequence must match latest_sequence")
        if self.latest_receipt.event_hash != self.latest_event_hash:
            raise ValueError("latest_receipt.event_hash must match latest_event_hash")
        return self


@dataclass(frozen=True)
class ActionReceiptFlushResult:
    agent_id: str | None
    event_count: int
    submitted_count: int
    skipped_local_receipts: int
    skipped_registry_existing: int
    latest_registry_sequence: int | None
    latest_registry_event_hash: str | None
    fork_detected_count: int
    registry_public_key_source: str | None


@dataclass(frozen=True)
class ActionReceiptSummary:
    receipt_count: int
    latest_receipt_sequence: int | None
    latest_receipt_event_hash: str | None
    latest_registry_id: str | None
    receipt_log_consistent: bool
    receipt_coverage_complete: bool
    fork_detected_count: int
    consistency_reason: str | None


@dataclass(frozen=True)
class ActionReceiptVerificationResult:
    ok: bool
    reason: str
    receipt_count: int
    latest_receipt_sequence: int | None
    latest_receipt_event_hash: str | None
    latest_registry_id: str | None
    receipt_log_consistent: bool
    receipt_coverage_complete: bool
    fork_detected_count: int
    receipt_signatures_verified: int


class ActionReceiptStore:
    """Append-only local storage for signed registry action receipts."""

    def __init__(self, base_dir: str | Path) -> None:
        self.base_dir = Path(base_dir)
        self.log_path = self.base_dir / "receipts.log"

    def read_receipts(self) -> list[ActionReceipt]:
        if not self.log_path.exists():
            return []

        receipts: list[ActionReceipt] = []
        for line_number, raw_line in enumerate(
            self.log_path.read_text(encoding="utf-8").splitlines(),
            start=1,
        ):
            line = raw_line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ActionReceiptError(
                    f"receipts.log line {line_number} is not valid JSON"
                ) from exc
            try:
                receipts.append(ActionReceipt.model_validate(payload))
            except ValidationError as exc:
                raise ActionReceiptError(f"receipts.log line {line_number} is invalid") from exc
        return receipts

    def latest_receipt(self) -> ActionReceipt | None:
        receipts = self.read_receipts()
        return receipts[-1] if receipts else None

    def append(self, payload: dict[str, Any]) -> bool:
        model = ActionReceipt.model_validate(payload)
        existing = {receipt.event_hash for receipt in self.read_receipts()}
        if model.event_hash in existing:
            return False

        self.base_dir.mkdir(parents=True, exist_ok=True)
        created = not self.log_path.exists()
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    model.model_dump(exclude_none=True),
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            handle.write("\n")
        if created:
            _chmod_owner_only(self.log_path)
        return True


def canonical_action_receipt_bytes(receipt: dict[str, Any]) -> bytes:
    payload = dict(receipt)
    payload.pop("registry_signature_b64", None)
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def verify_action_receipt_signature(
    receipt: dict[str, Any],
    *,
    registry_public_key_b64: str,
) -> tuple[bool, str]:
    try:
        model = ActionReceipt.model_validate(receipt)
    except ValidationError as exc:
        return False, str(exc)

    try:
        signature = base64.b64decode(model.registry_signature_b64, validate=True)
        public_key = base64.b64decode(registry_public_key_b64, validate=True)
    except Exception:
        return False, "invalid registry public key or signature encoding"

    canonical = canonical_action_receipt_bytes(model.model_dump(exclude_none=True))
    if not verify_ed25519(signature, canonical, public_key):
        return False, "invalid registry signature"
    return True, "ok"


def summarize_action_receipts(base_dir: str | Path) -> ActionReceiptSummary:
    action_store = ActionLogStore(base_dir)
    action_store.replay()
    events = action_store.read_events()
    receipt_store = ActionReceiptStore(base_dir)
    receipts = receipt_store.read_receipts()
    reason = _check_receipt_log_consistency(events, receipts)
    latest_receipt = receipts[-1] if receipts else None
    return ActionReceiptSummary(
        receipt_count=len(receipts),
        latest_receipt_sequence=(
            latest_receipt.sequence if latest_receipt is not None else None
        ),
        latest_receipt_event_hash=(
            latest_receipt.event_hash if latest_receipt is not None else None
        ),
        latest_registry_id=(latest_receipt.registry_id if latest_receipt is not None else None),
        receipt_log_consistent=reason is None,
        receipt_coverage_complete=_receipt_coverage_complete(events, receipts),
        fork_detected_count=sum(1 for receipt in receipts if receipt.fork_detected),
        consistency_reason=reason,
    )


def verify_action_receipts(
    base_dir: str | Path,
    *,
    registry_public_key_b64: str | None = None,
    expected_agent_id: str | None = None,
) -> ActionReceiptVerificationResult:
    try:
        action_store = ActionLogStore(base_dir)
        action_store.replay()
        events = action_store.read_events()
        receipt_store = ActionReceiptStore(base_dir)
        receipts = receipt_store.read_receipts()
    except ActionReceiptError as exc:
        return ActionReceiptVerificationResult(
            ok=False,
            reason=str(exc),
            receipt_count=0,
            latest_receipt_sequence=None,
            latest_receipt_event_hash=None,
            latest_registry_id=None,
            receipt_log_consistent=False,
            receipt_coverage_complete=False,
            fork_detected_count=0,
            receipt_signatures_verified=0,
        )

    latest_receipt = receipts[-1] if receipts else None
    reason = _check_receipt_log_consistency(events, receipts, expected_agent_id=expected_agent_id)
    summary = ActionReceiptVerificationResult(
        ok=reason is None,
        reason=reason or ("no local receipts recorded" if not receipts else "ok"),
        receipt_count=len(receipts),
        latest_receipt_sequence=(
            latest_receipt.sequence if latest_receipt is not None else None
        ),
        latest_receipt_event_hash=(
            latest_receipt.event_hash if latest_receipt is not None else None
        ),
        latest_registry_id=(latest_receipt.registry_id if latest_receipt is not None else None),
        receipt_log_consistent=reason is None,
        receipt_coverage_complete=_receipt_coverage_complete(events, receipts),
        fork_detected_count=sum(1 for receipt in receipts if receipt.fork_detected),
        receipt_signatures_verified=0,
    )
    if reason is not None or registry_public_key_b64 is None:
        return summary

    signatures_verified = 0
    for receipt in receipts:
        valid, verification_reason = verify_action_receipt_signature(
            receipt.model_dump(exclude_none=True),
            registry_public_key_b64=registry_public_key_b64,
        )
        if not valid:
            return ActionReceiptVerificationResult(
                ok=False,
                reason=(
                    f"invalid receipt signature at sequence {receipt.sequence}: "
                    f"{verification_reason}"
                ),
                receipt_count=summary.receipt_count,
                latest_receipt_sequence=summary.latest_receipt_sequence,
                latest_receipt_event_hash=summary.latest_receipt_event_hash,
                latest_registry_id=summary.latest_registry_id,
                receipt_log_consistent=True,
                receipt_coverage_complete=summary.receipt_coverage_complete,
                fork_detected_count=summary.fork_detected_count,
                receipt_signatures_verified=signatures_verified,
            )
        signatures_verified += 1

    return ActionReceiptVerificationResult(
        ok=True,
        reason=summary.reason,
        receipt_count=summary.receipt_count,
        latest_receipt_sequence=summary.latest_receipt_sequence,
        latest_receipt_event_hash=summary.latest_receipt_event_hash,
        latest_registry_id=summary.latest_registry_id,
        receipt_log_consistent=True,
        receipt_coverage_complete=summary.receipt_coverage_complete,
        fork_detected_count=summary.fork_detected_count,
        receipt_signatures_verified=signatures_verified,
    )


def flush_action_receipts(
    base_dir: str | Path,
    *,
    client,
    agent_public_key_b64: str,
    registry_public_key_b64: str,
) -> ActionReceiptFlushResult:
    action_store = ActionLogStore(base_dir)
    action_store.replay()
    events = action_store.read_events()
    if not events:
        return ActionReceiptFlushResult(
            agent_id=None,
            event_count=0,
            submitted_count=0,
            skipped_local_receipts=0,
            skipped_registry_existing=0,
            latest_registry_sequence=None,
            latest_registry_event_hash=None,
            fork_detected_count=0,
            registry_public_key_source=None,
        )

    agent_id = events[0].agent_id
    if any(event.agent_id != agent_id for event in events):
        raise ActionReceiptError("local action log contains multiple agent_ids")

    receipt_store = ActionReceiptStore(base_dir)
    local_receipts = receipt_store.read_receipts()
    local_latest = local_receipts[-1] if local_receipts else None
    if any(receipt.agent_id != agent_id for receipt in local_receipts):
        raise ActionReceiptError("local receipt log contains a different agent_id")

    latest_payload = client.get_latest_action_receipt(agent_id)
    try:
        registry_latest = ActionReceiptLatest.model_validate(latest_payload)
    except ValidationError as exc:
        raise ActionReceiptError(f"invalid latest action receipt response: {exc}") from exc

    remote_latest_sequence = registry_latest.latest_sequence
    remote_latest_event_hash = registry_latest.latest_event_hash

    if registry_latest.latest_receipt is not None:
        valid, reason = verify_action_receipt_signature(
            registry_latest.latest_receipt.model_dump(exclude_none=True),
            registry_public_key_b64=registry_public_key_b64,
        )
        if not valid:
            raise ActionReceiptError(f"registry latest receipt failed verification: {reason}")

    if remote_latest_sequence is not None:
        if remote_latest_sequence > len(events):
            raise ActionReceiptError("registry action receipts are ahead of the local action log")
        local_event = events[remote_latest_sequence - 1]
        local_event_hash = action_event_hash(local_event.model_dump(exclude_none=True))
        if remote_latest_event_hash != local_event_hash:
            raise ActionReceiptError("registry latest receipt does not match the local action log")

    if local_latest is not None:
        if remote_latest_sequence is None:
            raise ActionReceiptError(
                "local receipt log exists but the registry reports no action receipts"
            )
        if local_latest.sequence > remote_latest_sequence:
            raise ActionReceiptError("local receipt log is ahead of the registry latest receipt")
        if (
            local_latest.sequence == remote_latest_sequence
            and local_latest.event_hash != remote_latest_event_hash
        ):
            raise ActionReceiptError("local receipt log does not match the registry latest receipt")

    local_receipt_event_hashes = {receipt.event_hash for receipt in local_receipts}
    submitted_count = 0
    skipped_local_receipts = 0
    skipped_registry_existing = 0
    fork_detected_count = 0

    for event in events:
        event_payload = event.model_dump(exclude_none=True)
        event_hash_value = action_event_hash(event_payload)
        if event_hash_value in local_receipt_event_hashes:
            skipped_local_receipts += 1
            continue
        if remote_latest_sequence is not None and event.sequence <= remote_latest_sequence:
            skipped_registry_existing += 1
            continue

        receipt_payload = client.submit_action_receipt(
            {
                "agent_public_key_b64": agent_public_key_b64,
                "event": event_payload,
            }
        )
        valid, reason = verify_action_receipt_signature(
            receipt_payload,
            registry_public_key_b64=registry_public_key_b64,
        )
        if not valid:
            raise ActionReceiptError(f"registry returned an invalid action receipt: {reason}")

        receipt = ActionReceipt.model_validate(receipt_payload)
        if receipt.agent_id != event.agent_id:
            raise ActionReceiptError(
                "registry receipt agent_id does not match the local action log"
            )
        if receipt.sequence != event.sequence:
            raise ActionReceiptError(
                "registry receipt sequence does not match the local action log"
            )
        if receipt.event_hash != event_hash_value:
            raise ActionReceiptError(
                "registry receipt event_hash does not match the local action log"
            )

        receipt_store.append(receipt.model_dump(exclude_none=True))
        local_receipt_event_hashes.add(receipt.event_hash)
        remote_latest_sequence = receipt.sequence
        remote_latest_event_hash = receipt.event_hash
        submitted_count += 1
        if receipt.fork_detected:
            fork_detected_count += 1

    return ActionReceiptFlushResult(
        agent_id=agent_id,
        event_count=len(events),
        submitted_count=submitted_count,
        skipped_local_receipts=skipped_local_receipts,
        skipped_registry_existing=skipped_registry_existing,
        latest_registry_sequence=remote_latest_sequence,
        latest_registry_event_hash=remote_latest_event_hash,
        fork_detected_count=fork_detected_count,
        registry_public_key_source="configured",
    )


def _check_receipt_log_consistency(
    events: list[Any],
    receipts: list[ActionReceipt],
    *,
    expected_agent_id: str | None = None,
) -> str | None:
    if not receipts:
        return None
    if not events:
        return "receipts.log exists but the local action log is empty"

    previous_sequence: int | None = None
    previous_agent_id: str | None = None
    seen_sequences: set[int] = set()

    for receipt in receipts:
        if expected_agent_id is not None and receipt.agent_id != expected_agent_id:
            return "receipt log contains unexpected agent_id"
        if previous_agent_id is not None and receipt.agent_id != previous_agent_id:
            return "receipt log contains multiple agent_ids"
        previous_agent_id = receipt.agent_id
        if previous_sequence is not None and receipt.sequence <= previous_sequence:
            return "receipts.log has non-monotonic sequence ordering"
        if receipt.sequence in seen_sequences:
            return "receipts.log contains duplicate sequences"
        seen_sequences.add(receipt.sequence)
        previous_sequence = receipt.sequence
        if receipt.sequence > len(events):
            return "receipts.log references a sequence beyond the local action log"

        event = events[receipt.sequence - 1]
        event_payload = event.model_dump(exclude_none=True)
        if receipt.agent_id != event.agent_id:
            return f"receipt sequence {receipt.sequence} agent_id does not match local action log"
        if receipt.prev_event_hash != event.prev_event_hash:
            return (
                f"receipt sequence {receipt.sequence} prev_event_hash does not match "
                "local action log"
            )
        if receipt.event_hash != action_event_hash(event_payload):
            return f"receipt sequence {receipt.sequence} event_hash does not match local action log"
        if receipt.context_root != event.context_root:
            return (
                f"receipt sequence {receipt.sequence} context_root does not match "
                "local action log"
            )
        if receipt.timestamp_utc != event.timestamp_utc:
            return (
                f"receipt sequence {receipt.sequence} timestamp_utc does not match "
                "local action log"
            )
        if receipt.action_kind != event.action_kind:
            return (
                f"receipt sequence {receipt.sequence} action_kind does not match "
                "local action log"
            )

    return None


def _receipt_coverage_complete(events: list[Any], receipts: list[ActionReceipt]) -> bool:
    if not events:
        return True
    receipt_sequences = {receipt.sequence for receipt in receipts}
    return receipt_sequences == set(range(1, len(events) + 1))


def _chmod_owner_only(path: Path) -> None:
    try:
        path.chmod(0o600)
    except OSError:  # pragma: no cover
        return


__all__ = [
    "ActionReceiptSummary",
    "ActionReceiptVerificationResult",
    "ActionReceipt",
    "ActionReceiptFlushResult",
    "ActionReceiptLatest",
    "ActionReceiptStore",
    "canonical_action_receipt_bytes",
    "flush_action_receipts",
    "summarize_action_receipts",
    "verify_action_receipts",
    "verify_action_receipt_signature",
]
