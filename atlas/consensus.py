"""Pluggable consensus engines: Proof-of-Work, Proof-of-Stake, PBFT."""

from __future__ import annotations

import hashlib
import logging
import random
import time
from abc import ABC, abstractmethod
from typing import Any

log = logging.getLogger("atlas.consensus")


class ConsensusEngine(ABC):
    """Abstract interface for consensus algorithms."""

    name: str = "abstract"

    @abstractmethod
    def create_block(
        self,
        index: int,
        transactions: list[dict[str, Any]],
        previous_hash: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Produce a new block (mining / proposing)."""

    @abstractmethod
    def validate_block(self, block: dict[str, Any], previous_block: dict[str, Any]) -> bool:
        """Verify that a block satisfies the consensus rules."""

    @abstractmethod
    def get_info(self) -> dict[str, Any]:
        """Return consensus-specific metadata for the UI."""


# ---------------------------------------------------------------------------
# Proof-of-Work
# ---------------------------------------------------------------------------

class ProofOfWork(ConsensusEngine):
    name = "PoW"

    def __init__(self, difficulty: int = 4) -> None:
        self.difficulty = difficulty

    def create_block(
        self,
        index: int,
        transactions: list[dict[str, Any]],
        previous_hash: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        last_proof = kwargs.get("last_proof", 0)
        start = time.time()
        proof = self._mine(last_proof)
        elapsed = time.time() - start
        block = {
            "index": index,
            "timestamp": time.time(),
            "transactions": transactions,
            "proof": proof,
            "previous_hash": previous_hash,
            "consensus": self.name,
            "mining_time": round(elapsed, 4),
        }
        log.info(
            "PoW block #%d mined in %.3fs (proof=%d, difficulty=%d)",
            index, elapsed, proof, self.difficulty,
        )
        return block

    def validate_block(self, block: dict[str, Any], previous_block: dict[str, Any]) -> bool:
        return self._valid_proof(previous_block["proof"], block["proof"])

    def _mine(self, last_proof: int) -> int:
        proof = 0
        while not self._valid_proof(last_proof, proof):
            proof += 1
        return proof

    def _valid_proof(self, last_proof: int, proof: int) -> bool:
        guess = f"{last_proof}{proof}".encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[: self.difficulty] == "0" * self.difficulty

    def get_info(self) -> dict[str, Any]:
        return {"engine": self.name, "difficulty": self.difficulty}


# ---------------------------------------------------------------------------
# Proof-of-Stake
# ---------------------------------------------------------------------------

class ProofOfStake(ConsensusEngine):
    name = "PoS"

    def __init__(self, min_stake: float = 10.0) -> None:
        self.min_stake = min_stake
        self._stakes: dict[str, float] = {}  # address -> staked amount
        self._validators: set[str] = set()

    def register_stake(self, address: str, amount: float) -> bool:
        """Stake tokens to become a validator."""
        if amount < self.min_stake:
            return False
        self._stakes[address] = self._stakes.get(address, 0) + amount
        if self._stakes[address] >= self.min_stake:
            self._validators.add(address)
        log.info("Stake registered: %s = %.2f ATL", address, self._stakes[address])
        return True

    def unstake(self, address: str, amount: float) -> float:
        """Unstake tokens. Returns actual amount unstaked."""
        current = self._stakes.get(address, 0)
        actual = min(amount, current)
        self._stakes[address] = current - actual
        if self._stakes[address] < self.min_stake:
            self._validators.discard(address)
        return actual

    def select_validator(self, seed: str = "") -> str | None:
        """Weighted random selection based on stake."""
        if not self._validators:
            return None
        eligible = [(addr, self._stakes[addr]) for addr in self._validators]
        total = sum(s for _, s in eligible)
        if total <= 0:
            return None

        # Deterministic selection using seed
        hash_val = int(hashlib.sha256(seed.encode()).hexdigest(), 16)
        pick = hash_val % int(total * 100) / 100.0
        cumulative = 0.0
        for addr, stake in eligible:
            cumulative += stake
            if cumulative >= pick:
                return addr
        return eligible[-1][0]

    def create_block(
        self,
        index: int,
        transactions: list[dict[str, Any]],
        previous_hash: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        validator = kwargs.get("validator") or self.select_validator(previous_hash)
        if not validator:
            # Fallback: anyone can propose if no validators registered
            validator = kwargs.get("node_id", "unknown")

        block = {
            "index": index,
            "timestamp": time.time(),
            "transactions": transactions,
            "proof": 0,  # No PoW needed
            "previous_hash": previous_hash,
            "consensus": self.name,
            "validator": validator,
            "stake": self._stakes.get(validator, 0),
        }
        log.info("PoS block #%d proposed by validator %s (stake=%.2f)",
                 index, validator[:12], self._stakes.get(validator, 0))
        return block

    def validate_block(self, block: dict[str, Any], previous_block: dict[str, Any]) -> bool:
        validator = block.get("validator", "")
        # Validator must have a stake (or be genesis)
        if block["index"] == 0:
            return True
        return validator in self._validators or not self._validators

    def get_info(self) -> dict[str, Any]:
        return {
            "engine": self.name,
            "min_stake": self.min_stake,
            "validators": len(self._validators),
            "total_staked": sum(self._stakes.values()),
            "stakes": {addr: stake for addr, stake in sorted(
                self._stakes.items(), key=lambda x: -x[1]
            )[:20]},
        }


# ---------------------------------------------------------------------------
# Practical Byzantine Fault Tolerance (simplified)
# ---------------------------------------------------------------------------

class PBFT(ConsensusEngine):
    name = "PBFT"

    def __init__(self, total_nodes: int = 4) -> None:
        self.total_nodes = max(total_nodes, 4)
        self.f = (self.total_nodes - 1) // 3  # max faulty nodes
        self._votes: dict[int, dict[str, set[str]]] = {}  # block_index -> {phase: set(voters)}
        self._view = 0
        self._leader_idx = 0

    @property
    def quorum(self) -> int:
        return 2 * self.f + 1

    def create_block(
        self,
        index: int,
        transactions: list[dict[str, Any]],
        previous_hash: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        node_id = kwargs.get("node_id", "leader")

        # Simulate PBFT phases: pre-prepare, prepare, commit
        self._votes[index] = {"pre_prepare": {node_id}, "prepare": set(), "commit": set()}

        # Simulate prepare phase (in real impl, would wait for network messages)
        for i in range(self.total_nodes):
            voter = f"node-{i}"
            if random.random() < 0.9:  # 90% honest
                self._votes[index]["prepare"].add(voter)

        # Simulate commit phase
        if len(self._votes[index]["prepare"]) >= self.quorum:
            for i in range(self.total_nodes):
                voter = f"node-{i}"
                if random.random() < 0.9:
                    self._votes[index]["commit"].add(voter)

        committed = len(self._votes[index].get("commit", set())) >= self.quorum
        prepare_count = len(self._votes[index]["prepare"])
        commit_count = len(self._votes[index].get("commit", set()))

        block = {
            "index": index,
            "timestamp": time.time(),
            "transactions": transactions,
            "proof": 0,
            "previous_hash": previous_hash,
            "consensus": self.name,
            "view": self._view,
            "prepares": prepare_count,
            "commits": commit_count,
            "finalized": committed,
        }
        log.info(
            "PBFT block #%d: prepares=%d/%d, commits=%d/%d, finalized=%s",
            index, prepare_count, self.quorum, commit_count, self.quorum, committed,
        )
        return block

    def validate_block(self, block: dict[str, Any], previous_block: dict[str, Any]) -> bool:
        if block["index"] == 0:
            return True
        return block.get("finalized", False) or block.get("commits", 0) >= self.quorum

    def get_info(self) -> dict[str, Any]:
        return {
            "engine": self.name,
            "total_nodes": self.total_nodes,
            "max_faulty": self.f,
            "quorum": self.quorum,
            "view": self._view,
        }


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

ENGINES: dict[str, type[ConsensusEngine]] = {
    "pow": ProofOfWork,
    "pos": ProofOfStake,
    "pbft": PBFT,
}


def create_engine(name: str, **kwargs: Any) -> ConsensusEngine:
    """Create a consensus engine by name."""
    cls = ENGINES.get(name.lower())
    if cls is None:
        raise ValueError(f"Unknown consensus engine: {name}. Available: {list(ENGINES.keys())}")
    return cls(**kwargs)
