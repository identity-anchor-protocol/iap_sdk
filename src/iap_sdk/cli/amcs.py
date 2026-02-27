"""AMCS local integration helpers for iap-agent CLI."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


class AMCSError(ValueError):
    """Raised for AMCS integration failures."""


@dataclass(frozen=True)
class AMCSRootResult:
    agent_id: str
    amcs_db_path: str
    memory_root: str
    sequence: int


@dataclass(frozen=True)
class AMCSAppendItem:
    path: str
    sequence: int
    event_hash: str


@dataclass(frozen=True)
class AMCSAppendResult:
    agent_id: str
    amcs_db_path: str
    items: list[AMCSAppendItem]
    memory_root: str
    sequence: int


def _load_amcs_backend() -> tuple[Any, Any]:
    try:
        from amcs import AMCSClient, SQLiteEventStore
    except Exception as exc:  # pragma: no cover
        raise AMCSError(
            "AMCS is not available. Install AMCS in this environment to use `iap-agent amcs root`."
        ) from exc
    return AMCSClient, SQLiteEventStore


def get_amcs_root(*, amcs_db_path: str, agent_id: str) -> AMCSRootResult:
    AMCSClient, SQLiteEventStore = _load_amcs_backend()

    store = SQLiteEventStore(amcs_db_path)
    client = AMCSClient(store=store, agent_id=agent_id)

    sequence = store.get_latest_sequence(agent_id)
    if sequence is None:
        raise AMCSError(f"no AMCS events found for agent_id={agent_id}")

    memory_root = client.get_memory_root()
    if not isinstance(memory_root, str) or len(memory_root) != 64:
        raise AMCSError("AMCS returned invalid memory_root")

    return AMCSRootResult(
        agent_id=agent_id,
        amcs_db_path=amcs_db_path,
        memory_root=memory_root,
        sequence=sequence,
    )


def append_files_to_amcs(
    *,
    amcs_db_path: str,
    agent_id: str,
    file_paths: list[str],
) -> AMCSAppendResult:
    if not file_paths:
        raise AMCSError("at least one file path must be provided")

    AMCSClient, SQLiteEventStore = _load_amcs_backend()
    store = SQLiteEventStore(amcs_db_path)
    client = AMCSClient(store=store, agent_id=agent_id)

    items: list[AMCSAppendItem] = []
    for raw_path in file_paths:
        path = Path(raw_path)
        if not path.exists():
            raise AMCSError(f"missing file: {path}")
        if not path.is_file():
            raise AMCSError(f"path is not a file: {path}")
        content = path.read_text(encoding="utf-8")
        appended = client.append(
            "agent.file.upsert",
            {"path": str(path), "content": content},
        )
        items.append(
            AMCSAppendItem(
                path=str(path),
                sequence=appended.sequence,
                event_hash=appended.event_hash,
            )
        )

    memory_root = client.get_memory_root()
    if not isinstance(memory_root, str) or len(memory_root) != 64:
        raise AMCSError("AMCS returned invalid memory_root")

    return AMCSAppendResult(
        agent_id=agent_id,
        amcs_db_path=amcs_db_path,
        items=items,
        memory_root=memory_root,
        sequence=items[-1].sequence,
    )
