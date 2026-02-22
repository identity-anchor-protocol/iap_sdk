"""Session artifact persistence for iap-agent CLI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class SessionError(ValueError):
    """Raised when a session record cannot be persisted."""


def save_session_record(*, sessions_dir: str, request_id: str, payload: dict[str, Any]) -> Path:
    root = Path(sessions_dir)
    root.mkdir(parents=True, exist_ok=True)

    session_path = root / f"{request_id}.json"
    try:
        session_path.write_text(
            json.dumps(payload, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
    except Exception as exc:  # pragma: no cover
        raise SessionError(f"failed to write session file: {session_path}") from exc
    return session_path
