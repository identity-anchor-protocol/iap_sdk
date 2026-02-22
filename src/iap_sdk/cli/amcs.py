"""AMCS local integration helpers for iap-agent CLI."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class AMCSError(ValueError):
    """Raised for AMCS integration failures."""


@dataclass(frozen=True)
class AMCSRootResult:
    agent_id: str
    amcs_db_path: str
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
