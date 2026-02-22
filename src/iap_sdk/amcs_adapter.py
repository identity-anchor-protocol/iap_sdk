"""AMCS adapter contract for SDK request building."""

from __future__ import annotations

from typing import Protocol

from iap_sdk.requests import build_continuity_request


class AMCSAdapterProtocol(Protocol):
    def get_memory_root(self) -> str: ...

    def get_next_sequence(self) -> int: ...

    def get_agent_id(self) -> str: ...


def build_continuity_request_from_amcs(
    *,
    adapter: AMCSAdapterProtocol,
    agent_public_key_b64: str,
    manifest_version: str,
    manifest_hash: str,
    agent_name: str | None = None,
    agent_custody_class: str | None = None,
) -> dict:
    return build_continuity_request(
        agent_public_key_b64=agent_public_key_b64,
        agent_id=adapter.get_agent_id(),
        memory_root=adapter.get_memory_root(),
        sequence=adapter.get_next_sequence(),
        manifest_version=manifest_version,
        manifest_hash=manifest_hash,
        agent_name=agent_name,
        agent_custody_class=agent_custody_class,
    )


__all__ = ["AMCSAdapterProtocol", "build_continuity_request_from_amcs"]
