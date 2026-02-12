"""Merkle tree construction and proof generation/verification."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def _hash_leaf(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def _hash_pair(left: str, right: str) -> str:
    combined = (left + right) if left <= right else (right + left)
    return hashlib.sha256(combined.encode()).hexdigest()


def build_merkle_tree(transactions: list[dict[str, Any]]) -> tuple[str, list[list[str]]]:
    """Build a Merkle tree from a list of transactions.

    Returns (merkle_root, tree_levels) where tree_levels[0] = leaves.
    """
    if not transactions:
        return _hash_leaf("empty"), [[_hash_leaf("empty")]]

    leaves = [_hash_leaf(json.dumps(tx, sort_keys=True)) for tx in transactions]

    # Duplicate last leaf if odd count
    if len(leaves) % 2 == 1:
        leaves.append(leaves[-1])

    tree: list[list[str]] = [leaves]
    current = leaves

    while len(current) > 1:
        next_level: list[str] = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else current[i]
            next_level.append(_hash_pair(left, right))
        tree.append(next_level)
        current = next_level

    return current[0], tree


def get_merkle_proof(tree: list[list[str]], index: int) -> list[dict[str, str]]:
    """Generate a Merkle proof for the transaction at *index*.

    Returns a list of {hash, position} pairs needed to reconstruct the root.
    """
    proof: list[dict[str, str]] = []
    for level in tree[:-1]:  # skip root level
        if index % 2 == 0:
            sibling_idx = index + 1
            position = "right"
        else:
            sibling_idx = index - 1
            position = "left"

        if sibling_idx < len(level):
            proof.append({"hash": level[sibling_idx], "position": position})
        else:
            proof.append({"hash": level[index], "position": position})

        index //= 2

    return proof


def verify_merkle_proof(tx_hash: str, proof: list[dict[str, str]], root: str) -> bool:
    """Verify that tx_hash belongs to the tree with the given root."""
    current = tx_hash
    for step in proof:
        if step["position"] == "right":
            current = _hash_pair(current, step["hash"])
        else:
            current = _hash_pair(step["hash"], current)
    return current == root
