"""State tracking helpers for iap-agent CLI."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from iap_sdk.cli.amcs import AMCSError

DEFAULT_TRACK_CONFIG = """prompt_files:
  - system.md
  - skills.md
  - agent.md
objective_file: objective.md
memory_path: ./memory/
"""


def _load_yaml_module() -> Any:
    try:
        import yaml
    except Exception as exc:  # pragma: no cover
        raise AMCSError(
            "YAML parser not available. Install PyYAML to use `iap-agent track`."
        ) from exc
    return yaml


def ensure_tracking_config(path: Path) -> bool:
    if path.exists():
        return False
    path.write_text(DEFAULT_TRACK_CONFIG, encoding="utf-8")
    return True


@dataclass(frozen=True)
class TrackConfig:
    prompt_files: tuple[str, ...]
    objective_file: str | None
    memory_path: str | None


def load_track_config(path: Path) -> TrackConfig:
    yaml = _load_yaml_module()
    if not path.exists():
        raise AMCSError(f"tracking config file not found: {path}")
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        raise AMCSError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise AMCSError("tracking config must be a mapping")

    prompt_files = payload.get("prompt_files", [])
    if not isinstance(prompt_files, list) or any(not isinstance(p, str) for p in prompt_files):
        raise AMCSError("prompt_files must be a list of file paths")

    objective_file = payload.get("objective_file")
    if objective_file is not None and not isinstance(objective_file, str):
        raise AMCSError("objective_file must be a string if provided")

    memory_path = payload.get("memory_path")
    if memory_path is not None and not isinstance(memory_path, str):
        raise AMCSError("memory_path must be a string if provided")

    return TrackConfig(
        prompt_files=tuple(prompt_files),
        objective_file=objective_file,
        memory_path=memory_path,
    )


@dataclass(frozen=True)
class TrackFileRecord:
    path: str
    sha256: str
    size_bytes: int


def _collect_memory_files(base_path: Path) -> list[Path]:
    if not base_path.exists():
        return []
    return sorted([p for p in base_path.rglob("*") if p.is_file()], key=lambda p: str(p))


def collect_tracked_files(*, project_root: Path, config: TrackConfig) -> list[Path]:
    files: list[Path] = []
    for relative in config.prompt_files:
        candidate = (project_root / relative).resolve()
        if candidate.exists() and candidate.is_file():
            files.append(candidate)
    if config.objective_file:
        candidate = (project_root / config.objective_file).resolve()
        if candidate.exists() and candidate.is_file():
            files.append(candidate)
    if config.memory_path:
        memory_dir = (project_root / config.memory_path).resolve()
        files.extend(_collect_memory_files(memory_dir))

    deduped: dict[str, Path] = {}
    for file_path in files:
        deduped[str(file_path)] = file_path
    return [deduped[key] for key in sorted(deduped.keys())]


def build_file_record(*, project_root: Path, file_path: Path) -> TrackFileRecord:
    data = file_path.read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()
    try:
        rel_path = str(file_path.relative_to(project_root))
    except ValueError:
        rel_path = str(file_path)
    return TrackFileRecord(path=rel_path, sha256=sha256, size_bytes=len(data))


def append_tracking_events(
    *,
    amcs_db_path: str,
    agent_id: str,
    file_records: list[TrackFileRecord],
) -> dict[str, Any]:
    try:
        from amcs import AMCSClient, SQLiteEventStore
    except Exception as exc:  # pragma: no cover
        raise AMCSError(
            "AMCS is not available. Install AMCS in this environment to use tracking commands."
        ) from exc

    store = SQLiteEventStore(amcs_db_path)
    client = AMCSClient(store=store, agent_id=agent_id)

    sequences: list[int] = []
    event_hashes: list[str] = []
    for record in file_records:
        append_result = client.append(
            "state.file.track",
            {
                "path": record.path,
                "content_sha256": record.sha256,
                "size_bytes": record.size_bytes,
            },
        )
        sequences.append(int(append_result.sequence))
        event_hashes.append(str(append_result.event_hash))

    memory_root = client.get_memory_root()
    if not isinstance(memory_root, str) or len(memory_root) != 64:
        raise AMCSError("AMCS returned invalid memory_root")

    return {
        "agent_id": agent_id,
        "amcs_db_path": amcs_db_path,
        "tracked_file_count": len(file_records),
        "tracked_files": [record.path for record in file_records],
        "sequence_start": sequences[0] if sequences else store.get_latest_sequence(agent_id),
        "sequence_end": sequences[-1] if sequences else store.get_latest_sequence(agent_id),
        "event_hashes": event_hashes,
        "memory_root": memory_root,
    }

