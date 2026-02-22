"""Identity manifest helpers for deterministic continuity roots."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from iap_sdk.errors import SchemaValidationError

DEFAULT_REQUIRED_PATHS = ("AGENT.md", "SOUL.md")
DEFAULT_MANIFEST_VERSION = "IAM-1"
DEFAULT_HASH_ALGORITHM = "sha256"


def _normalize_text(text: str) -> str:
    # Normalize line endings and preserve exact text content otherwise.
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _normalize_bytes(content: bytes) -> bytes:
    return _normalize_text(content.decode("utf-8")).encode("utf-8")


@dataclass(frozen=True)
class ManifestEntry:
    path: str
    sha256: str
    size: int


def _canonical_manifest_dict(
    *,
    manifest_version: str,
    hash_algorithm: str,
    entries: list[ManifestEntry],
) -> dict:
    return {
        "manifest_version": manifest_version,
        "hash_algorithm": hash_algorithm,
        "entries": [
            {"path": item.path, "sha256": item.sha256, "size": item.size}
            for item in sorted(entries, key=lambda value: value.path)
        ],
    }


def compute_manifest_hash(manifest: dict) -> str:
    canonical = json.dumps(
        manifest,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def build_identity_manifest(
    files: dict[str, str | bytes],
    *,
    required_paths: tuple[str, ...] = DEFAULT_REQUIRED_PATHS,
    manifest_version: str = DEFAULT_MANIFEST_VERSION,
    hash_algorithm: str = DEFAULT_HASH_ALGORITHM,
) -> dict:
    if hash_algorithm != DEFAULT_HASH_ALGORITHM:
        raise SchemaValidationError("unsupported hash_algorithm")
    if not manifest_version:
        raise SchemaValidationError("manifest_version must not be empty")

    missing = [path for path in required_paths if path not in files]
    if missing:
        raise SchemaValidationError(f"missing required manifest files: {', '.join(missing)}")

    entries: list[ManifestEntry] = []
    for path, content in files.items():
        if not path or not isinstance(path, str):
            raise SchemaValidationError("manifest entry path must be a non-empty string")

        if isinstance(content, str):
            normalized_bytes = _normalize_text(content).encode("utf-8")
        elif isinstance(content, bytes):
            normalized_bytes = _normalize_bytes(content)
        else:
            raise SchemaValidationError("manifest entry content must be str or bytes")

        entries.append(
            ManifestEntry(
                path=path,
                sha256=hashlib.sha256(normalized_bytes).hexdigest(),
                size=len(normalized_bytes),
            )
        )

    manifest = _canonical_manifest_dict(
        manifest_version=manifest_version,
        hash_algorithm=hash_algorithm,
        entries=entries,
    )
    manifest["manifest_hash"] = compute_manifest_hash(manifest)
    return manifest
