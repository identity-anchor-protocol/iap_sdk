#!/usr/bin/env python3
"""Minimal state-drift demo: anchor state, mutate history, detect failure."""

from __future__ import annotations

import argparse
import json
import sqlite3
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from iap_sdk.crypto.agent_identity import derive_agent_id


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256_file(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _ensure_file(path: Path, content: str) -> None:
    if not path.exists():
        path.write_text(content, encoding="utf-8")


def _append_file_event(*, client, file_path: Path) -> None:
    file_hash = _sha256_file(file_path)
    client.append(
        "state.file.track",
        {
            "path": str(file_path.name),
            "sha256": file_hash,
            "size_bytes": file_path.stat().st_size,
        },
    )


def _tamper_first_event(db_path: Path) -> None:
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT event_json FROM events WHERE sequence = 1 LIMIT 1"
        ).fetchone()
        if row is None:
            raise RuntimeError("expected at least one AMCS event")
        event = json.loads(str(row[0]))
        payload = dict(event.get("payload", {}))
        payload["sha256"] = "0" * 64
        event["payload"] = payload
        conn.execute(
            "UPDATE events SET event_json = ? WHERE sequence = 1",
            (json.dumps(event, sort_keys=True, separators=(",", ":")),),
        )
        conn.commit()


def run_demo(workdir: Path) -> int:
    try:
        from amcs import AMCSClient, SQLiteEventStore
    except Exception as exc:  # pragma: no cover
        raise SystemExit(
            "AMCS package is required for this demo. "
            "Install it first (example: pip install -e /path/to/AMCS-0.1)."
        ) from exc

    workdir.mkdir(parents=True, exist_ok=True)
    agent_path = workdir / "AGENT.md"
    soul_path = workdir / "SOUL.md"
    db_path = workdir / "amcs.db"
    anchor_path = workdir / "anchor_record.json"

    _ensure_file(
        agent_path,
        "# Agent\nName: Atlas\nRole: Continuity demo agent\n",
    )
    _ensure_file(
        soul_path,
        "# Purpose\nTrack state transitions and detect drift.\n",
    )

    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    agent_id = derive_agent_id(public)

    store = SQLiteEventStore(str(db_path))
    client = AMCSClient(store=store, agent_id=agent_id)

    print("Step 1/5: agent defined")
    print(f"agent_id={agent_id}")

    print("Step 2/5: memory appended")
    _append_file_event(client=client, file_path=agent_path)
    _append_file_event(client=client, file_path=soul_path)
    seq = store.get_latest_sequence(agent_id)
    if seq is None:
        raise RuntimeError("failed to append AMCS events")
    memory_root = client.get_memory_root()
    if memory_root is None:
        raise RuntimeError("memory_root unavailable")
    print(f"sequence={seq}")
    print(f"memory_root={memory_root}")

    print("Step 3/5: anchor created")
    anchor_record = {
        "agent_id": agent_id,
        "sequence": seq,
        "memory_root": memory_root,
        "anchored_at": _utc_now_iso(),
    }
    anchor_path.write_text(json.dumps(anchor_record, indent=2), encoding="utf-8")
    print(f"anchor_record={anchor_path}")

    before = client.verify_chain(from_seq=1, to_seq=seq)
    print(f"verify_before_ok={before.ok}")

    print("Step 4/5: memory silently modified")
    _tamper_first_event(db_path)
    print("tamper=events.sequence.1.payload.sha256 overwritten")

    print("Step 5/5: verification fails")
    after = client.verify_chain(from_seq=1, to_seq=seq)
    print(f"verify_after_ok={after.ok}")
    print(f"verify_after_error={after.error}")
    print(f"verify_after_failed_sequence={after.failed_sequence}")

    if after.ok:
        print("unexpected_result=true")
        return 1
    print("unexpected_result=false")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run state drift detection demo.")
    parser.add_argument(
        "--workdir",
        default="./state-drift-demo-output",
        help="Output directory for demo artifacts",
    )
    args = parser.parse_args()
    return run_demo(Path(args.workdir).resolve())


if __name__ == "__main__":
    raise SystemExit(main())
