"""Core blockchain — ledger, block creation, chain validation, peer management."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from typing import Any, Optional

from atlas.consensus import ConsensusEngine, ProofOfWork, create_engine
from atlas.mempool import Mempool
from atlas.merkle import build_merkle_tree
from atlas.state import StateManager
from atlas.validation import ValidationPipeline, create_default_pipeline

log = logging.getLogger("atlas.blockchain")


class Blockchain:
    """Core ledger with pluggable consensus, mempool, and Merkle trees."""

    def __init__(
        self,
        state: StateManager,
        consensus: ConsensusEngine | None = None,
        genesis_path: str = "",
    ) -> None:
        self.chain: list[dict[str, Any]] = []
        self.nodes: set[str] = set()
        self.state = state
        self.consensus: ConsensusEngine = consensus or ProofOfWork(difficulty=4)
        self.mempool = Mempool()
        self.validation = create_default_pipeline()
        self.event_subscribers: list[Any] = []
        self._genesis_path = genesis_path or os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "genesis.json")
        self._load_genesis()

    # -- genesis ------------------------------------------------------------

    def _load_genesis(self) -> None:
        default_block = {
            "index": 0, "timestamp": 0, "transactions": [],
            "proof": 100, "previous_hash": "0", "merkle_root": "",
            "consensus": self.consensus.name,
        }
        if os.path.exists(self._genesis_path):
            with open(self._genesis_path, "r") as f:
                data = json.load(f)
            genesis = data.get("block", data) if isinstance(data, dict) else default_block
            params = data.get("parameters", {})
            # Configure consensus from genesis
            if "consensus" in params:
                engine_name = params["consensus"]
                engine_kwargs: dict[str, Any] = {}
                if "difficulty_zeros" in params:
                    engine_kwargs["difficulty"] = int(params["difficulty_zeros"])
                if "min_stake" in params:
                    engine_kwargs["min_stake"] = float(params["min_stake"])
                if "total_nodes" in params:
                    engine_kwargs["total_nodes"] = int(params["total_nodes"])
                try:
                    self.consensus = create_engine(engine_name, **engine_kwargs)
                except ValueError:
                    pass
            elif "difficulty_zeros" in params and isinstance(self.consensus, ProofOfWork):
                self.consensus.difficulty = int(params["difficulty_zeros"])
            log.info("Genesis loaded (consensus=%s)", self.consensus.name)
        else:
            genesis = default_block
            log.info("Using default genesis block")
        for key, val in default_block.items():
            genesis.setdefault(key, val)
        self.chain.append(genesis)
        self.state.apply_block(genesis)

    # -- block helpers ------------------------------------------------------

    @staticmethod
    def hash_block(block: dict[str, Any]) -> str:
        encoded = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded).hexdigest()

    @property
    def last_block(self) -> dict[str, Any]:
        return self.chain[-1]

    def add_transaction(self, tx: dict[str, Any]) -> tuple[bool, str]:
        """Validate and add a transaction to the mempool."""
        ok, reason = self.validation.validate(tx, self.state, self)
        if not ok:
            return False, reason
        ok, msg = self.mempool.add(tx)
        if ok:
            self._fire_event("new_transaction", tx)
        return ok, msg

    def new_transaction(
        self, sender: str, recipient: str, amount: float,
        signature: str = "", public_key: str = "",
        fee: float = 0.0, nonce: int | None = None, **extra: Any,
    ) -> int:
        """Direct transaction add (bypasses mempool for coinbase/internal)."""
        tx: dict[str, Any] = {
            "sender": sender, "recipient": recipient, "amount": amount,
            "signature": signature, "public_key": public_key, "fee": fee,
            **extra,
        }
        if nonce is not None:
            tx["nonce"] = nonce
        self.mempool.add(tx)
        return self.last_block["index"] + 1

    def mine_block(self, miner_address: str, reward: float = 1.0, **kwargs: Any) -> dict[str, Any]:
        """Mine/propose a new block using the active consensus engine."""
        # Collect transactions from mempool
        txs = self.mempool.pop_best(max_count=200)

        # Add mining reward
        reward_tx: dict[str, Any] = {
            "sender": "MINING_REWARD", "recipient": miner_address,
            "amount": reward, "fee": 0,
        }
        # Collect fees
        total_fees = sum(float(tx.get("fee", 0)) for tx in txs)
        if total_fees > 0:
            reward_tx["amount"] += total_fees
        txs.append(reward_tx)

        # Build Merkle tree
        merkle_root, _ = build_merkle_tree(txs)

        # Create block via consensus engine
        block = self.consensus.create_block(
            index=len(self.chain),
            transactions=txs,
            previous_hash=self.hash_block(self.last_block),
            last_proof=self.last_block.get("proof", 0),
            node_id=miner_address,
            **kwargs,
        )
        block["merkle_root"] = merkle_root

        self.state.apply_block(block)
        self.chain.append(block)
        self._fire_event("new_block", block)
        return block

    # -- chain validation ---------------------------------------------------

    def valid_chain(self, chain: list[dict[str, Any]]) -> bool:
        prev = chain[0]
        for block in chain[1:]:
            if block["previous_hash"] != self.hash_block(prev):
                return False
            if not self.consensus.validate_block(block, prev):
                return False
            prev = block
        return True

    # -- peer management & consensus ----------------------------------------

    def register_node(self, address: str) -> None:
        self.nodes.add(address.rstrip("/"))
        log.info("Peer registered: %s (total: %d)", address, len(self.nodes))

    def resolve_conflicts(self) -> bool:
        import requests as req
        new_chain: Optional[list[dict[str, Any]]] = None
        max_length = len(self.chain)
        for node in self.nodes:
            try:
                resp = req.get(f"{node}/chain", timeout=5)
                if resp.status_code == 200:
                    data = resp.json()
                    length = data["length"]
                    chain = data["chain"]
                    if length > max_length and self.valid_chain(chain):
                        max_length = length
                        new_chain = chain
            except Exception as exc:
                log.warning("Could not reach peer %s: %s", node, exc)
        if new_chain:
            self.chain = new_chain
            self.state.rebuild_from_chain(new_chain)
            log.info("Chain replaced via consensus (new length: %d)", max_length)
            return True
        return False

    # -- event system -------------------------------------------------------

    def _fire_event(self, event_type: str, data: Any) -> None:
        for sub in self.event_subscribers:
            try:
                sub(event_type, data)
            except Exception:
                pass

    def subscribe(self, callback: Any) -> None:
        self.event_subscribers.append(callback)

    # -- chain export / import (replay) -------------------------------------

    def export_chain(self) -> str:
        return json.dumps({"chain": self.chain, "length": len(self.chain)}, indent=2)

    def import_chain(self, data: str) -> bool:
        parsed = json.loads(data)
        chain = parsed.get("chain", [])
        if not chain:
            return False
        if not self.valid_chain(chain):
            return False
        self.chain = chain
        self.state.rebuild_from_chain(chain)
        log.info("Chain imported (length=%d)", len(chain))
        return True

    # -- block explorer helpers ---------------------------------------------

    def get_block(self, index: int) -> Optional[dict[str, Any]]:
        if 0 <= index < len(self.chain):
            return self.chain[index]
        return None

    def get_block_by_hash(self, block_hash: str) -> Optional[dict[str, Any]]:
        for block in self.chain:
            if self.hash_block(block) == block_hash:
                return block
        return None

    def search_transactions(self, address: str = "", limit: int = 50) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for block in reversed(self.chain):
            for tx in block.get("transactions", []):
                if not address or tx.get("sender") == address or tx.get("recipient") == address:
                    results.append({**tx, "block_index": block["index"], "timestamp": block["timestamp"]})
                    if len(results) >= limit:
                        return results
        return results

    def get_chain_stats(self) -> dict[str, Any]:
        total_supply = 0.0
        total_transfers = 0
        total_fees = 0.0
        addresses: set[str] = set()
        block_times: list[float] = []
        contract_calls = 0

        for i, block in enumerate(self.chain):
            for tx in block.get("transactions", []):
                if tx.get("sender") == "MINING_REWARD":
                    total_supply += float(tx.get("amount", 0))
                else:
                    total_transfers += 1
                    total_fees += float(tx.get("fee", 0))
                if tx.get("type") in ("contract_call", "contract_deploy"):
                    contract_calls += 1
                if tx.get("recipient"):
                    addresses.add(tx["recipient"])
                if tx.get("sender") and tx["sender"] != "MINING_REWARD":
                    addresses.add(tx["sender"])
            if i > 0 and block.get("timestamp", 0) > 0 and self.chain[i - 1].get("timestamp", 0) > 0:
                block_times.append(block["timestamp"] - self.chain[i - 1]["timestamp"])

        avg_block_time = sum(block_times) / len(block_times) if block_times else 0.0
        recent = self.chain[-10:]
        recent_txs = sum(len(b.get("transactions", [])) for b in recent)
        ts = [b["timestamp"] for b in recent if b.get("timestamp", 0) > 0]
        recent_tps = 0.0
        if len(ts) >= 2 and ts[-1] - ts[0] > 0:
            recent_tps = recent_txs / (ts[-1] - ts[0])

        return {
            "total_supply": total_supply,
            "circulating_addresses": len(addresses),
            "total_blocks": len(self.chain),
            "total_transfers": total_transfers,
            "total_fees_collected": total_fees,
            "contract_calls": contract_calls,
            "recent_tps": round(recent_tps, 3),
            "avg_block_time": round(avg_block_time, 2),
            "consensus": self.consensus.name,
            "mempool_size": self.mempool.size,
            "peer_count": len(self.nodes),
            "top_holders": self.state.get_all_addresses()[:10],
        }
