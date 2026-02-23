#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Append AGENT.md and SOUL.md contents into local AMCS DB."
    )
    parser.add_argument("--amcs-db", required=True, help="Path to local AMCS SQLite database")
    parser.add_argument("--agent-id", required=True, help="Agent id (ed25519:...)")
    parser.add_argument("--agent-file", default="AGENT.md", help="Path to AGENT.md")
    parser.add_argument("--soul-file", default="SOUL.md", help="Path to SOUL.md")
    args = parser.parse_args()

    try:
        from amcs import AMCSClient, SQLiteEventStore
    except Exception as exc:  # pragma: no cover
        print("error: AMCS is not installed in this environment.")
        print("hint: install AMCS in editable mode from your local AMCS repo.")
        print(f"detail: {exc}")
        return 1

    agent_path = Path(args.agent_file)
    soul_path = Path(args.soul_file)
    if not agent_path.exists():
        print(f"error: missing file: {agent_path}")
        return 1
    if not soul_path.exists():
        print(f"error: missing file: {soul_path}")
        return 1

    store = SQLiteEventStore(args.amcs_db)
    client = AMCSClient(store=store, agent_id=args.agent_id)

    agent_text = agent_path.read_text(encoding="utf-8")
    soul_text = soul_path.read_text(encoding="utf-8")

    r1 = client.append(
        "agent.file.upsert",
        {"path": str(agent_path), "content": agent_text},
    )
    r2 = client.append(
        "agent.file.upsert",
        {"path": str(soul_path), "content": soul_text},
    )

    output = {
        "agent_id": args.agent_id,
        "amcs_db": args.amcs_db,
        "sequences": [r1.sequence, r2.sequence],
        "event_hashes": [r1.event_hash, r2.event_hash],
        "memory_root_latest": client.get_memory_root(),
    }
    print(json.dumps(output, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
