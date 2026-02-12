"""Transaction mempool with fee-priority ordering, replace-by-fee, and eviction."""

from __future__ import annotations

import heapq
import logging
import time
from typing import Any

log = logging.getLogger("atlas.mempool")

# Default limits
MAX_POOL_SIZE = 5000
MAX_TX_AGE = 3600  # seconds


class Mempool:
    """Fee-priority transaction pool with replace-by-fee and eviction policies."""

    def __init__(self, max_size: int = MAX_POOL_SIZE, max_age: int = MAX_TX_AGE) -> None:
        self.max_size = max_size
        self.max_age = max_age
        # Heap entries: (-fee, timestamp, tx_id, tx)
        self._heap: list[tuple[float, float, str, dict[str, Any]]] = []
        # Quick lookup by tx_id
        self._by_id: dict[str, dict[str, Any]] = {}
        # Track by sender+nonce for replace-by-fee
        self._by_sender_nonce: dict[str, str] = {}  # "sender:nonce" -> tx_id
        self._removed: set[str] = set()  # lazy-deleted tx IDs

    @property
    def size(self) -> int:
        return len(self._by_id)

    @property
    def transactions(self) -> list[dict[str, Any]]:
        """All valid transactions, sorted by fee descending."""
        self._purge_expired()
        return [tx for tx in self._drain_sorted()]

    def _tx_id(self, tx: dict[str, Any]) -> str:
        """Generate a unique ID for the transaction."""
        import hashlib, json
        raw = json.dumps({k: v for k, v in sorted(tx.items())}, sort_keys=True)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def add(self, tx: dict[str, Any]) -> tuple[bool, str]:
        """Add a transaction. Returns (success, message)."""
        tx_id = self._tx_id(tx)

        if tx_id in self._by_id:
            return False, "Duplicate transaction"

        if self.size >= self.max_size:
            self._evict_lowest_fee()

        fee = float(tx.get("fee", 0))
        sender = tx.get("sender", "")
        nonce = tx.get("nonce")

        # Replace-by-fee: if same sender+nonce exists with lower fee, replace
        if nonce is not None and sender != "MINING_REWARD":
            key = f"{sender}:{nonce}"
            if key in self._by_sender_nonce:
                old_id = self._by_sender_nonce[key]
                if old_id in self._by_id:
                    old_fee = float(self._by_id[old_id].get("fee", 0))
                    if fee <= old_fee:
                        return False, f"Replace-by-fee requires higher fee (current: {old_fee})"
                    self._remove(old_id)
                    log.info("RBF: replaced tx %s (fee %s -> %s)", old_id, old_fee, fee)

        now = time.time()
        tx["_mempool_time"] = now
        tx["_tx_id"] = tx_id

        heapq.heappush(self._heap, (-fee, now, tx_id, tx))
        self._by_id[tx_id] = tx

        if nonce is not None and sender != "MINING_REWARD":
            self._by_sender_nonce[f"{sender}:{nonce}"] = tx_id

        log.debug("Mempool add: %s (fee=%s, pool_size=%d)", tx_id, fee, self.size)
        return True, tx_id

    def remove(self, tx_id: str) -> bool:
        """Remove a transaction by ID."""
        return self._remove(tx_id)

    def _remove(self, tx_id: str) -> bool:
        if tx_id not in self._by_id:
            return False
        tx = self._by_id.pop(tx_id)
        self._removed.add(tx_id)
        sender = tx.get("sender", "")
        nonce = tx.get("nonce")
        if nonce is not None:
            self._by_sender_nonce.pop(f"{sender}:{nonce}", None)
        return True

    def pop_best(self, max_count: int = 100) -> list[dict[str, Any]]:
        """Pop the top *max_count* highest-fee transactions for block inclusion."""
        self._purge_expired()
        result: list[dict[str, Any]] = []
        while self._heap and len(result) < max_count:
            neg_fee, ts, tx_id, tx = heapq.heappop(self._heap)
            if tx_id in self._removed:
                self._removed.discard(tx_id)
                continue
            if tx_id not in self._by_id:
                continue
            self._by_id.pop(tx_id, None)
            sender = tx.get("sender", "")
            nonce = tx.get("nonce")
            if nonce is not None:
                self._by_sender_nonce.pop(f"{sender}:{nonce}", None)
            # Clean internal fields
            tx.pop("_mempool_time", None)
            tx.pop("_tx_id", None)
            result.append(tx)
        return result

    def clear(self) -> None:
        self._heap.clear()
        self._by_id.clear()
        self._by_sender_nonce.clear()
        self._removed.clear()

    def _evict_lowest_fee(self) -> None:
        """Remove the transaction with the lowest fee."""
        # Reverse-scan heap (sorted by -fee, so largest index = lowest fee)
        if not self._by_id:
            return
        lowest_id = min(self._by_id, key=lambda tid: float(self._by_id[tid].get("fee", 0)))
        self._remove(lowest_id)
        log.debug("Evicted lowest-fee tx: %s", lowest_id)

    def _purge_expired(self) -> None:
        """Remove transactions older than max_age."""
        now = time.time()
        expired = [
            tid for tid, tx in self._by_id.items()
            if now - tx.get("_mempool_time", now) > self.max_age
        ]
        for tid in expired:
            self._remove(tid)
        if expired:
            log.debug("Purged %d expired transactions", len(expired))

    def _drain_sorted(self) -> list[dict[str, Any]]:
        """Get all transactions sorted by fee descending without removing."""
        txs = list(self._by_id.values())
        txs.sort(key=lambda t: float(t.get("fee", 0)), reverse=True)
        return txs

    def get_info(self) -> dict[str, Any]:
        """Return mempool statistics."""
        fees = [float(tx.get("fee", 0)) for tx in self._by_id.values()]
        return {
            "size": self.size,
            "max_size": self.max_size,
            "total_fees": sum(fees),
            "avg_fee": sum(fees) / len(fees) if fees else 0.0,
            "min_fee": min(fees) if fees else 0.0,
            "max_fee": max(fees) if fees else 0.0,
        }
