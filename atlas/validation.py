"""Pluggable transaction validation pipeline.

Each validator is a callable(tx, state, blockchain) -> (bool, str).
Validators are chained; first failure rejects the transaction.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Protocol, TYPE_CHECKING

if TYPE_CHECKING:
    from atlas.state import StateManager
    from atlas.blockchain import Blockchain

log = logging.getLogger("atlas.validation")

# Type alias for a validator function
Validator = Callable[["dict[str, Any]", "StateManager", "Blockchain"], tuple[bool, str]]


# ---------------------------------------------------------------------------
# Built-in validators
# ---------------------------------------------------------------------------

def validate_required_fields(tx: dict[str, Any], state: Any, bc: Any) -> tuple[bool, str]:
    """Check that all required fields are present."""
    required = {"sender", "recipient", "amount"}
    missing = required - set(tx.keys())
    if missing:
        return False, f"Missing fields: {missing}"
    return True, ""


def validate_positive_amount(tx: dict[str, Any], state: Any, bc: Any) -> tuple[bool, str]:
    """Amount must be positive."""
    if float(tx.get("amount", 0)) <= 0:
        return False, "Amount must be positive"
    return True, ""


def validate_signature(tx: dict[str, Any], state: Any, bc: Any) -> tuple[bool, str]:
    """Verify ECDSA signature (skip for coinbase)."""
    if tx.get("sender") == "MINING_REWARD":
        return True, ""

    from atlas.crypto import verify_signature
    sig = tx.get("signature", "")
    pubkey = tx.get("public_key", "")
    if not sig or not pubkey:
        return False, "Signature and public_key required"

    payload = {"sender": tx["sender"], "recipient": tx["recipient"], "amount": tx["amount"]}
    if tx.get("nonce") is not None:
        payload["nonce"] = tx["nonce"]
    if tx.get("fee") is not None:
        payload["fee"] = tx["fee"]

    if not verify_signature(pubkey, sig, payload):
        return False, "Invalid signature"
    return True, ""


def validate_multisig(tx: dict[str, Any], state: Any, bc: Any) -> tuple[bool, str]:
    """Verify multi-sig if present."""
    if tx.get("sender") == "MINING_REWARD":
        return True, ""
    if "signatures" not in tx:
        return True, ""  # Not a multisig tx

    from atlas.crypto import verify_multisig
    pubkeys = tx.get("public_keys", [])
    sigs = tx.get("signatures", [])
    required = tx.get("multisig_required", len(pubkeys))
    payload = {"sender": tx["sender"], "recipient": tx["recipient"], "amount": tx["amount"]}
    if tx.get("nonce") is not None:
        payload["nonce"] = tx["nonce"]

    if not verify_multisig(pubkeys, sigs, payload, required):
        return False, f"Multi-sig failed: need {required} of {len(pubkeys)} signatures"
    return True, ""


def validate_balance(tx: dict[str, Any], state: Any, bc: Any) -> tuple[bool, str]:
    """Check that sender has enough balance (skip for coinbase)."""
    if tx.get("sender") == "MINING_REWARD":
        return True, ""
    amount = float(tx.get("amount", 0))
    fee = float(tx.get("fee", 0))
    balance = state.get_balance(tx["sender"])
    if balance < amount + fee:
        return False, f"Insufficient balance: have {balance}, need {amount + fee}"
    return True, ""


def validate_nonce(tx: dict[str, Any], state: Any, bc: Any) -> tuple[bool, str]:
    """Check sequential nonce for replay protection (skip for coinbase)."""
    if tx.get("sender") == "MINING_REWARD":
        return True, ""
    if "nonce" not in tx:
        return True, ""  # Nonce optional for backward compat
    expected = state.get_nonce(tx["sender"])
    if tx["nonce"] != expected:
        return False, f"Invalid nonce: expected {expected}, got {tx['nonce']}"
    return True, ""


def validate_gas_limit(tx: dict[str, Any], state: Any, bc: Any) -> tuple[bool, str]:
    """Check gas limit for contract transactions."""
    if tx.get("type") == "contract_call" or tx.get("type") == "contract_deploy":
        gas_limit = tx.get("gas_limit", 0)
        if gas_limit <= 0 or gas_limit > 1_000_000:
            return False, f"Gas limit must be 1-1000000, got {gas_limit}"
    return True, ""


# ---------------------------------------------------------------------------
# Validation pipeline
# ---------------------------------------------------------------------------

class ValidationPipeline:
    """Ordered chain of validators. First failure stops execution."""

    def __init__(self) -> None:
        self._validators: list[tuple[str, Validator]] = []

    def add(self, name: str, validator: Validator) -> None:
        self._validators.append((name, validator))

    def remove(self, name: str) -> None:
        self._validators = [(n, v) for n, v in self._validators if n != name]

    def validate(self, tx: dict[str, Any], state: Any, bc: Any) -> tuple[bool, str]:
        """Run all validators in order. Return (True, '') or (False, reason)."""
        for name, validator in self._validators:
            ok, reason = validator(tx, state, bc)
            if not ok:
                log.debug("Validation '%s' failed: %s", name, reason)
                return False, f"[{name}] {reason}"
        return True, ""

    @property
    def validators(self) -> list[str]:
        return [n for n, _ in self._validators]


def create_default_pipeline() -> ValidationPipeline:
    """Standard validation pipeline for Atlas Engine."""
    pipeline = ValidationPipeline()
    pipeline.add("required_fields", validate_required_fields)
    pipeline.add("positive_amount", validate_positive_amount)
    pipeline.add("signature", validate_signature)
    pipeline.add("multisig", validate_multisig)
    pipeline.add("nonce", validate_nonce)
    pipeline.add("balance", validate_balance)
    pipeline.add("gas_limit", validate_gas_limit)
    return pipeline
