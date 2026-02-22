"""Signing custody classes and validation."""

from __future__ import annotations

from typing import Literal

CustodyClass = Literal["software-key", "tpm", "hsm", "secure-enclave"]

ALLOWED_CUSTODY_CLASSES: tuple[CustodyClass, ...] = (
    "software-key",
    "tpm",
    "hsm",
    "secure-enclave",
)


def is_valid_custody_class(value: str) -> bool:
    return value in ALLOWED_CUSTODY_CLASSES


def normalize_custody_class(value: str) -> str:
    normalized = value.strip().lower()
    if normalized not in ALLOWED_CUSTODY_CLASSES:
        raise ValueError(
            "custody class must be one of: software-key, tpm, hsm, secure-enclave"
        )
    return normalized
