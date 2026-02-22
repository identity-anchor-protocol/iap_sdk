"""Transparency log Merkle primitives."""

from __future__ import annotations

import hashlib


def _hash_pair(left_hex: str, right_hex: str) -> str:
    return hashlib.sha256(bytes.fromhex(left_hex) + bytes.fromhex(right_hex)).hexdigest()


def merkle_root(leaves: list[str]) -> str | None:
    if not leaves:
        return None
    level = list(leaves)
    while len(level) > 1:
        next_level: list[str] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else level[i]
            next_level.append(_hash_pair(left, right))
        level = next_level
    return level[0]


def merkle_proof(leaves: list[str], leaf_index: int) -> list[str]:
    if leaf_index < 0 or leaf_index >= len(leaves):
        raise ValueError("leaf_index out of range")

    index = leaf_index
    level = list(leaves)
    proof: list[str] = []
    while len(level) > 1:
        sibling_index = index ^ 1
        if sibling_index >= len(level):
            sibling_index = index
        proof.append(level[sibling_index])

        next_level: list[str] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else level[i]
            next_level.append(_hash_pair(left, right))

        level = next_level
        index //= 2
    return proof


def verify_merkle_proof(*, leaf: str, leaf_index: int, proof: list[str], root: str) -> bool:
    if leaf_index < 0:
        return False
    current = leaf
    index = leaf_index
    for sibling in proof:
        if index % 2 == 0:
            current = _hash_pair(current, sibling)
        else:
            current = _hash_pair(sibling, current)
        index //= 2
    return current == root
