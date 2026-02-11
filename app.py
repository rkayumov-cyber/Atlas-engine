"""
Atlas Engine — A modular, decentralized blockchain engine.
Core logic: Blockchain ledger, ECDSA security, SQLite state management, Flask API.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import time
from typing import Any, Optional
from uuid import uuid4

from ecdsa import SECP256k1, BadSignatureError, SigningKey, VerifyingKey
from flask import Flask, jsonify, request

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("atlas")

# ---------------------------------------------------------------------------
# State Manager — SQLite persistence for accounts & contract storage
# ---------------------------------------------------------------------------

class StateManager:
    """Persist account balances and contract key-value storage in SQLite."""

    def __init__(self, db_path: str = "state.db") -> None:
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._create_tables()

    def _create_tables(self) -> None:
        cur = self._conn.cursor()
        cur.execute(
            """CREATE TABLE IF NOT EXISTS accounts (
                   address TEXT PRIMARY KEY,
                   balance REAL NOT NULL DEFAULT 0
               )"""
        )
        cur.execute(
            """CREATE TABLE IF NOT EXISTS contract_storage (
                   key TEXT PRIMARY KEY,
                   value TEXT NOT NULL
               )"""
        )
        self._conn.commit()

    # -- account helpers -----------------------------------------------------

    def get_balance(self, address: str) -> float:
        row = self._conn.execute(
            "SELECT balance FROM accounts WHERE address = ?", (address,)
        ).fetchone()
        return row[0] if row else 0.0

    def credit(self, address: str, amount: float) -> None:
        bal = self.get_balance(address)
        if bal == 0.0 and not self._account_exists(address):
            self._conn.execute(
                "INSERT INTO accounts (address, balance) VALUES (?, ?)",
                (address, amount),
            )
        else:
            self._conn.execute(
                "UPDATE accounts SET balance = balance + ? WHERE address = ?",
                (amount, address),
            )
        self._conn.commit()

    def debit(self, address: str, amount: float) -> bool:
        bal = self.get_balance(address)
        if bal < amount:
            return False
        self._conn.execute(
            "UPDATE accounts SET balance = balance - ? WHERE address = ?",
            (amount, address),
        )
        self._conn.commit()
        return True

    def _account_exists(self, address: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM accounts WHERE address = ?", (address,)
        ).fetchone()
        return row is not None

    def apply_block(self, block: dict[str, Any]) -> None:
        """Apply all transactions in a block to the state DB."""
        for tx in block.get("transactions", []):
            sender = tx.get("sender")
            recipient = tx.get("recipient")
            amount = float(tx.get("amount", 0))
            if sender == "MINING_REWARD":
                self.credit(recipient, amount)
            else:
                self.debit(sender, amount)
                self.credit(recipient, amount)

    def rebuild_from_chain(self, chain: list[dict[str, Any]]) -> None:
        """Wipe state and rebuild from an entire chain."""
        self._conn.execute("DELETE FROM accounts")
        self._conn.commit()
        for block in chain:
            self.apply_block(block)

    # -- contract storage helpers -------------------------------------------

    def store(self, key: str, value: str) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO contract_storage (key, value) VALUES (?, ?)",
            (key, value),
        )
        self._conn.commit()

    def load(self, key: str) -> Optional[str]:
        row = self._conn.execute(
            "SELECT value FROM contract_storage WHERE key = ?", (key,)
        ).fetchone()
        return row[0] if row else None


# ---------------------------------------------------------------------------
# ECDSA helpers
# ---------------------------------------------------------------------------

def generate_keys() -> tuple[str, str]:
    """Return (private_key_hex, public_key_hex) using SECP256k1."""
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()
    return sk.to_string().hex(), vk.to_string().hex()


def sign_transaction(private_key_hex: str, tx_data: dict[str, Any]) -> str:
    """Sign the canonical JSON of tx_data; return hex signature."""
    sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
    message = _tx_hash_bytes(tx_data)
    return sk.sign(message).hex()


def verify_transaction(public_key_hex: str, signature_hex: str, tx_data: dict[str, Any]) -> bool:
    """Verify an ECDSA signature against tx_data."""
    try:
        vk = VerifyingKey.from_string(bytes.fromhex(public_key_hex), curve=SECP256k1)
        message = _tx_hash_bytes(tx_data)
        return vk.verify(bytes.fromhex(signature_hex), message)
    except (BadSignatureError, Exception):
        return False


def _tx_hash_bytes(tx_data: dict[str, Any]) -> bytes:
    """Canonical hash bytes for signing / verification."""
    canonical = json.dumps(
        {k: v for k, v in sorted(tx_data.items()) if k not in ("signature", "public_key")},
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode()).digest()


# ---------------------------------------------------------------------------
# Blockchain
# ---------------------------------------------------------------------------

class Blockchain:
    """Core ledger with Proof-of-Work consensus."""

    DIFFICULTY = 4  # leading zeros required

    def __init__(self, state: StateManager) -> None:
        self.chain: list[dict[str, Any]] = []
        self.pending_transactions: list[dict[str, Any]] = []
        self.nodes: set[str] = set()
        self.state = state
        self._load_genesis()

    # -- genesis ------------------------------------------------------------

    def _load_genesis(self) -> None:
        genesis_path = os.path.join(os.path.dirname(__file__), "genesis.json")
        if os.path.exists(genesis_path):
            with open(genesis_path, "r") as f:
                genesis = json.load(f)
            log.info("Genesis block loaded from genesis.json")
        else:
            genesis = {
                "index": 0,
                "timestamp": 0,
                "transactions": [],
                "proof": 100,
                "previous_hash": "0",
            }
            log.info("Using hardcoded default genesis block")
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

    def new_block(self, proof: int) -> dict[str, Any]:
        block: dict[str, Any] = {
            "index": len(self.chain),
            "timestamp": time.time(),
            "transactions": self.pending_transactions.copy(),
            "proof": proof,
            "previous_hash": self.hash_block(self.last_block),
        }
        self.state.apply_block(block)
        self.pending_transactions.clear()
        self.chain.append(block)
        log.info("Block #%d mined (proof=%d, txs=%d)", block["index"], proof, len(block["transactions"]))
        return block

    def new_transaction(self, sender: str, recipient: str, amount: float,
                        signature: str = "", public_key: str = "") -> int:
        tx: dict[str, Any] = {
            "sender": sender,
            "recipient": recipient,
            "amount": amount,
            "signature": signature,
            "public_key": public_key,
        }
        self.pending_transactions.append(tx)
        return self.last_block["index"] + 1

    # -- proof of work ------------------------------------------------------

    def proof_of_work(self, last_proof: int) -> int:
        proof = 0
        while not self._valid_proof(last_proof, proof):
            proof += 1
        return proof

    @classmethod
    def _valid_proof(cls, last_proof: int, proof: int) -> bool:
        guess = f"{last_proof}{proof}".encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[: cls.DIFFICULTY] == "0" * cls.DIFFICULTY

    # -- chain validation ---------------------------------------------------

    @classmethod
    def valid_chain(cls, chain: list[dict[str, Any]]) -> bool:
        prev = chain[0]
        for block in chain[1:]:
            if block["previous_hash"] != cls.hash_block(prev):
                return False
            if not cls._valid_proof(prev["proof"], block["proof"]):
                return False
            prev = block
        return True

    # -- peer management & consensus ----------------------------------------

    def register_node(self, address: str) -> None:
        self.nodes.add(address.rstrip("/"))
        log.info("Peer registered: %s (total: %d)", address, len(self.nodes))

    def resolve_conflicts(self) -> bool:
        """Longest-chain consensus. Returns True if our chain was replaced."""
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


# ---------------------------------------------------------------------------
# Flask Application
# ---------------------------------------------------------------------------

app = Flask(__name__)

node_id: str = str(uuid4()).replace("-", "")
state_manager = StateManager(db_path=os.environ.get("ATLAS_DB", "state.db"))
blockchain = Blockchain(state=state_manager)

MINING_REWARD = 1.0


@app.route("/transactions/new", methods=["POST"])
def new_transaction() -> tuple:
    data = request.get_json(force=True)
    required = ("sender", "recipient", "amount", "signature", "public_key")
    if not all(k in data for k in required):
        return jsonify({"error": "Missing fields", "required": list(required)}), 400

    # Verify ECDSA signature
    tx_payload = {"sender": data["sender"], "recipient": data["recipient"], "amount": data["amount"]}
    if not verify_transaction(data["public_key"], data["signature"], tx_payload):
        return jsonify({"error": "Invalid signature"}), 401

    # Check sender balance
    if state_manager.get_balance(data["sender"]) < float(data["amount"]):
        return jsonify({"error": "Insufficient balance"}), 400

    idx = blockchain.new_transaction(
        sender=data["sender"],
        recipient=data["recipient"],
        amount=float(data["amount"]),
        signature=data["signature"],
        public_key=data["public_key"],
    )
    return jsonify({"message": f"Transaction will be added to block {idx}"}), 201


@app.route("/mine", methods=["GET"])
def mine() -> tuple:
    last_block = blockchain.last_block
    proof = blockchain.proof_of_work(last_block["proof"])

    # Mining reward — no signature needed for coinbase
    blockchain.new_transaction(
        sender="MINING_REWARD",
        recipient=node_id,
        amount=MINING_REWARD,
    )

    block = blockchain.new_block(proof)
    return jsonify({
        "message": "New block mined",
        "index": block["index"],
        "transactions": block["transactions"],
        "proof": block["proof"],
        "previous_hash": block["previous_hash"],
    }), 200


@app.route("/chain", methods=["GET"])
def full_chain() -> tuple:
    return jsonify({"chain": blockchain.chain, "length": len(blockchain.chain)}), 200


@app.route("/balance/<address>", methods=["GET"])
def get_balance(address: str) -> tuple:
    balance = state_manager.get_balance(address)
    return jsonify({"address": address, "balance": balance}), 200


@app.route("/nodes/register", methods=["POST"])
def register_nodes() -> tuple:
    data = request.get_json(force=True)
    nodes = data.get("nodes")
    if not nodes:
        return jsonify({"error": "Supply a list of nodes"}), 400

    for node in nodes:
        blockchain.register_node(node)

    return jsonify({
        "message": "Peers added",
        "total_nodes": list(blockchain.nodes),
    }), 201


@app.route("/nodes/resolve", methods=["GET"])
def consensus() -> tuple:
    replaced = blockchain.resolve_conflicts()
    if replaced:
        return jsonify({"message": "Chain was replaced", "chain": blockchain.chain}), 200
    return jsonify({"message": "Our chain is authoritative", "chain": blockchain.chain}), 200


# -- Health endpoint for explorer ------------------------------------------
@app.route("/health", methods=["GET"])
def health() -> tuple:
    return jsonify({"status": "ok", "node_id": node_id, "chain_length": len(blockchain.chain)}), 200


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("ATLAS_PORT", 5000))
    log.info("Atlas Engine starting on port %d (node %s)", port, node_id)
    app.run(host="0.0.0.0", port=port)
