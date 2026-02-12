"""ECDSA cryptography helpers, multi-sig support, and key utilities."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from ecdsa import SECP256k1, BadSignatureError, SigningKey, VerifyingKey


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def generate_keys() -> tuple[str, str]:
    """Return (private_key_hex, public_key_hex) using SECP256k1."""
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()
    return sk.to_string().hex(), vk.to_string().hex()


def address_from_pubkey(public_key_hex: str) -> str:
    """Derive a 40-char address from a public key."""
    return hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()[:40]


# ---------------------------------------------------------------------------
# Transaction signing / verification
# ---------------------------------------------------------------------------

def tx_hash_bytes(tx_data: dict[str, Any]) -> bytes:
    """Canonical hash bytes for signing / verification."""
    exclude = {"signature", "public_key", "signatures", "public_keys"}
    canonical = json.dumps(
        {k: v for k, v in sorted(tx_data.items()) if k not in exclude},
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode()).digest()


def sign_transaction(private_key_hex: str, tx_data: dict[str, Any]) -> str:
    """Sign the canonical JSON of tx_data; return hex signature."""
    sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
    message = tx_hash_bytes(tx_data)
    return sk.sign(message).hex()


def verify_signature(public_key_hex: str, signature_hex: str, tx_data: dict[str, Any]) -> bool:
    """Verify an ECDSA signature against tx_data."""
    try:
        vk = VerifyingKey.from_string(bytes.fromhex(public_key_hex), curve=SECP256k1)
        message = tx_hash_bytes(tx_data)
        return vk.verify(bytes.fromhex(signature_hex), message)
    except (BadSignatureError, Exception):
        return False


# ---------------------------------------------------------------------------
# Multi-sig support
# ---------------------------------------------------------------------------

def verify_multisig(
    public_keys: list[str],
    signatures: list[str],
    tx_data: dict[str, Any],
    required: int,
) -> bool:
    """Verify M-of-N multi-sig: at least *required* valid signatures from the key set."""
    if len(signatures) < required:
        return False
    valid = 0
    used_keys: set[str] = set()
    for sig in signatures:
        for pk in public_keys:
            if pk in used_keys:
                continue
            if verify_signature(pk, sig, tx_data):
                valid += 1
                used_keys.add(pk)
                break
        if valid >= required:
            return True
    return False


def multisig_address(public_keys: list[str], required: int) -> str:
    """Deterministic address for an M-of-N multisig set."""
    payload = f"{required}:" + ",".join(sorted(public_keys))
    return "ms" + hashlib.sha256(payload.encode()).hexdigest()[:38]
