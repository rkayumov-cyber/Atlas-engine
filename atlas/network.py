"""Peer discovery (gossip), SSE event streaming, and fork detection."""

from __future__ import annotations

import json
import logging
import queue
import threading
import time
from typing import Any

log = logging.getLogger("atlas.network")


# ---------------------------------------------------------------------------
# SSE (Server-Sent Events) stream for real-time block/tx push
# ---------------------------------------------------------------------------

class EventStream:
    """Thread-safe SSE event broadcaster."""

    def __init__(self, max_history: int = 100) -> None:
        self._listeners: list[queue.Queue[str]] = []
        self._history: list[dict[str, Any]] = []
        self._max_history = max_history
        self._lock = threading.Lock()

    def publish(self, event_type: str, data: Any) -> None:
        msg = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
        with self._lock:
            self._history.append({"type": event_type, "data": data, "time": time.time()})
            if len(self._history) > self._max_history:
                self._history = self._history[-self._max_history:]
            dead: list[queue.Queue[str]] = []
            for q in self._listeners:
                try:
                    q.put_nowait(msg)
                except queue.Full:
                    dead.append(q)
            for q in dead:
                self._listeners.remove(q)

    def subscribe(self) -> queue.Queue[str]:
        q: queue.Queue[str] = queue.Queue(maxsize=200)
        with self._lock:
            self._listeners.append(q)
        return q

    def unsubscribe(self, q: queue.Queue[str]) -> None:
        with self._lock:
            if q in self._listeners:
                self._listeners.remove(q)

    @property
    def listener_count(self) -> int:
        return len(self._listeners)

    @property
    def history(self) -> list[dict[str, Any]]:
        return list(self._history)


# ---------------------------------------------------------------------------
# Gossip-based peer discovery
# ---------------------------------------------------------------------------

class GossipProtocol:
    """Simple gossip protocol for peer discovery."""

    def __init__(self, self_url: str, max_peers: int = 100) -> None:
        self.self_url = self_url.rstrip("/")
        self.max_peers = max_peers
        self.peers: dict[str, dict[str, Any]] = {}  # url -> info
        self._lock = threading.Lock()

    def add_peer(self, url: str, info: dict[str, Any] | None = None) -> bool:
        url = url.rstrip("/")
        if url == self.self_url:
            return False
        with self._lock:
            if len(self.peers) >= self.max_peers and url not in self.peers:
                return False
            self.peers[url] = {
                "url": url,
                "last_seen": time.time(),
                "chain_length": (info or {}).get("chain_length", 0),
                "node_id": (info or {}).get("node_id", ""),
                "version": (info or {}).get("version", ""),
                **(info or {}),
            }
        return True

    def remove_peer(self, url: str) -> None:
        with self._lock:
            self.peers.pop(url.rstrip("/"), None)

    def get_peers(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self.peers.values())

    def get_peer_urls(self) -> list[str]:
        with self._lock:
            return list(self.peers.keys())

    def gossip_payload(self) -> dict[str, Any]:
        """Data to send when gossiping."""
        return {
            "sender": self.self_url,
            "peers": self.get_peer_urls()[:20],
            "timestamp": time.time(),
        }

    def handle_gossip(self, payload: dict[str, Any]) -> list[str]:
        """Process incoming gossip and return new peers discovered."""
        sender = payload.get("sender", "")
        new_peers: list[str] = []
        if sender:
            if self.add_peer(sender):
                new_peers.append(sender)
        for peer_url in payload.get("peers", []):
            if self.add_peer(peer_url):
                new_peers.append(peer_url)
        return new_peers

    def prune_stale(self, max_age: float = 300) -> int:
        """Remove peers not seen in *max_age* seconds."""
        now = time.time()
        with self._lock:
            stale = [url for url, info in self.peers.items()
                     if now - info.get("last_seen", 0) > max_age]
            for url in stale:
                del self.peers[url]
        return len(stale)

    def do_gossip_round(self) -> None:
        """Send gossip to a random subset of peers."""
        import random
        import requests as req
        peers = self.get_peer_urls()
        if not peers:
            return
        targets = random.sample(peers, min(3, len(peers)))
        payload = self.gossip_payload()
        for url in targets:
            try:
                req.post(f"{url}/gossip", json=payload, timeout=3)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Fork detection
# ---------------------------------------------------------------------------

class ForkDetector:
    """Detect chain forks across peers."""

    def __init__(self) -> None:
        self.peer_tips: dict[str, dict[str, Any]] = {}  # peer_url -> tip info

    def update_tip(self, peer_url: str, chain_length: int, tip_hash: str) -> None:
        self.peer_tips[peer_url] = {
            "chain_length": chain_length,
            "tip_hash": tip_hash,
            "updated": time.time(),
        }

    def detect_forks(self) -> list[dict[str, Any]]:
        """Return groups of peers that disagree on the chain tip."""
        if not self.peer_tips:
            return []

        # Group by tip_hash
        groups: dict[str, list[str]] = {}
        for peer, info in self.peer_tips.items():
            h = info["tip_hash"]
            groups.setdefault(h, []).append(peer)

        if len(groups) <= 1:
            return []  # No fork

        forks: list[dict[str, Any]] = []
        for tip_hash, peers in groups.items():
            sample = self.peer_tips[peers[0]]
            forks.append({
                "tip_hash": tip_hash,
                "chain_length": sample["chain_length"],
                "peers": peers,
                "peer_count": len(peers),
            })

        forks.sort(key=lambda f: f["peer_count"], reverse=True)
        log.warning("Fork detected: %d branches", len(forks))
        return forks

    def get_status(self) -> dict[str, Any]:
        forks = self.detect_forks()
        return {
            "tracked_peers": len(self.peer_tips),
            "fork_count": len(forks),
            "forks": forks,
            "consensus_reached": len(forks) <= 1,
        }
