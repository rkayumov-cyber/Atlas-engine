"""Flask API — all HTTP endpoints for Atlas Engine."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import os
import queue
import time
from collections import defaultdict
from functools import wraps
from typing import Any
from uuid import uuid4

from flask import Flask, Response, jsonify, request, send_from_directory

from atlas.blockchain import Blockchain
from atlas.consensus import ProofOfStake, create_engine
from atlas.crypto import (
    address_from_pubkey,
    generate_keys,
    sign_transaction,
    verify_signature,
)
from atlas.merkle import build_merkle_tree, get_merkle_proof, verify_merkle_proof
from atlas.network import EventStream, ForkDetector, GossipProtocol
from atlas.state import StateManager
from atlas.vm import AtlasVM, CONTRACT_TEMPLATES
from atlas.webhooks import WebhookDispatcher

log = logging.getLogger("atlas")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MONITOR_DIR = os.path.join(BASE_DIR, "monitor")

# ---------------------------------------------------------------------------
# Rate limiter (simple in-memory)
# ---------------------------------------------------------------------------

_rate_buckets: dict[str, list[float]] = defaultdict(list)


def rate_limit(max_calls: int = 30, window: int = 60):
    """Decorator to rate-limit an endpoint per IP."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            ip = request.remote_addr or "unknown"
            now = time.time()
            bucket = _rate_buckets[f"{f.__name__}:{ip}"]
            bucket[:] = [t for t in bucket if now - t < window]
            if len(bucket) >= max_calls:
                return jsonify({"error": "Rate limit exceeded", "retry_after": window}), 429
            bucket.append(now)
            return f(*args, **kwargs)
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_app(
    db_path: str = "",
    genesis_path: str = "",
    consensus_name: str = "",
    port: int = 5000,
) -> tuple[Flask, dict[str, Any]]:
    """Create and configure the Flask application. Returns (app, context)."""

    app = Flask(__name__)
    node_id: str = str(uuid4()).replace("-", "")

    # State
    state = StateManager(db_path=db_path or os.environ.get("ATLAS_DB", "state.db"))

    # Blockchain (consensus from genesis or override)
    bc = Blockchain(
        state=state,
        genesis_path=genesis_path or os.path.join(BASE_DIR, "genesis.json"),
    )

    # Override consensus if explicitly requested
    if consensus_name:
        kwargs: dict[str, Any] = {}
        if consensus_name == "pos":
            kwargs["min_stake"] = 10.0
        elif consensus_name == "pbft":
            kwargs["total_nodes"] = 31
        bc.consensus = create_engine(consensus_name, **kwargs)

    # Networking
    self_url = f"http://127.0.0.1:{port}"
    gossip = GossipProtocol(self_url)
    fork_detector = ForkDetector()
    event_stream = EventStream()

    # Webhooks
    webhook_dispatcher = WebhookDispatcher(state)
    bc.subscribe(webhook_dispatcher)
    bc.subscribe(lambda etype, data: event_stream.publish(etype, data))

    # VM
    vm = AtlasVM(state_loader=state)

    MINING_REWARD = 1.0

    # Context dict for external access
    ctx = {
        "node_id": node_id, "state": state, "blockchain": bc,
        "gossip": gossip, "fork_detector": fork_detector,
        "event_stream": event_stream, "vm": vm,
    }

    # ===================================================================
    # STATIC / MONITOR
    # ===================================================================

    @app.route("/")
    def index():
        return send_from_directory(MONITOR_DIR, "index.html")

    @app.route("/explorer")
    def explorer_page():
        return send_from_directory(MONITOR_DIR, "explorer.html")

    # ===================================================================
    # HEALTH
    # ===================================================================

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({
            "status": "ok",
            "node_id": node_id,
            "chain_length": len(bc.chain),
            "consensus": bc.consensus.name,
            "mempool_size": bc.mempool.size,
            "peers": len(bc.nodes),
            "uptime": time.time(),
        }), 200

    # ===================================================================
    # CHAIN
    # ===================================================================

    @app.route("/chain", methods=["GET"])
    def full_chain():
        return jsonify({"chain": bc.chain, "length": len(bc.chain)}), 200

    @app.route("/chain/export", methods=["GET"])
    def export_chain():
        return Response(
            bc.export_chain(),
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=atlas_chain.json"},
        )

    @app.route("/chain/import", methods=["POST"])
    def import_chain():
        data = request.get_data(as_text=True)
        if bc.import_chain(data):
            return jsonify({"message": "Chain imported", "length": len(bc.chain)}), 200
        return jsonify({"error": "Invalid chain data"}), 400

    # ===================================================================
    # TRANSACTIONS
    # ===================================================================

    @app.route("/transactions/new", methods=["POST"])
    @rate_limit(max_calls=60, window=60)
    def new_transaction():
        data = request.get_json(force=True)
        required = ("sender", "recipient", "amount")
        if not all(k in data for k in required):
            return jsonify({"error": "Missing fields", "required": list(required)}), 400

        tx: dict[str, Any] = {
            "sender": data["sender"],
            "recipient": data["recipient"],
            "amount": float(data["amount"]),
            "fee": float(data.get("fee", 0)),
            "signature": data.get("signature", ""),
            "public_key": data.get("public_key", ""),
        }
        if "nonce" in data:
            tx["nonce"] = data["nonce"]

        ok, msg = bc.add_transaction(tx)
        if not ok:
            return jsonify({"error": msg}), 400
        return jsonify({"message": f"Transaction accepted", "tx_id": msg}), 201

    @app.route("/transactions/pending", methods=["GET"])
    def pending_transactions():
        txs = bc.mempool._drain_sorted()
        return jsonify({"transactions": txs, "count": len(txs)}), 200

    @app.route("/transactions/search", methods=["GET"])
    def search_transactions():
        address = request.args.get("address", "")
        limit = min(int(request.args.get("limit", 50)), 200)
        txs = bc.search_transactions(address=address, limit=limit)
        return jsonify({"transactions": txs, "count": len(txs)}), 200

    # ===================================================================
    # MINING
    # ===================================================================

    @app.route("/mine", methods=["GET"])
    def mine():
        block = bc.mine_block(miner_address=node_id, reward=MINING_REWARD)
        return jsonify({
            "message": "New block mined",
            "index": block["index"],
            "transactions": block["transactions"],
            "proof": block.get("proof", 0),
            "previous_hash": block["previous_hash"],
            "merkle_root": block.get("merkle_root", ""),
            "consensus": block.get("consensus", ""),
            "mining_time": block.get("mining_time", 0),
        }), 200

    # ===================================================================
    # BLOCKS / EXPLORER
    # ===================================================================

    @app.route("/block/<int:index>", methods=["GET"])
    def get_block(index: int):
        block = bc.get_block(index)
        if not block:
            return jsonify({"error": "Block not found"}), 404
        block_hash = bc.hash_block(block)
        _, tree = build_merkle_tree(block.get("transactions", []))
        return jsonify({
            **block,
            "hash": block_hash,
            "merkle_root": block.get("merkle_root", ""),
            "tx_count": len(block.get("transactions", [])),
        }), 200

    @app.route("/block/hash/<block_hash>", methods=["GET"])
    def get_block_by_hash(block_hash: str):
        block = bc.get_block_by_hash(block_hash)
        if not block:
            return jsonify({"error": "Block not found"}), 404
        return jsonify(block), 200

    @app.route("/block/<int:index>/merkle", methods=["GET"])
    def get_merkle_info(index: int):
        block = bc.get_block(index)
        if not block:
            return jsonify({"error": "Block not found"}), 404
        txs = block.get("transactions", [])
        root, tree = build_merkle_tree(txs)
        tx_idx = request.args.get("tx_index")
        proof = None
        if tx_idx is not None:
            tx_idx = int(tx_idx)
            if 0 <= tx_idx < len(txs):
                proof = get_merkle_proof(tree, tx_idx)
        return jsonify({
            "block_index": index,
            "merkle_root": root,
            "tree_depth": len(tree),
            "leaf_count": len(tree[0]) if tree else 0,
            "proof": proof,
        }), 200

    # ===================================================================
    # BALANCE
    # ===================================================================

    @app.route("/balance/<address>", methods=["GET"])
    def get_balance(address: str):
        balance = state.get_balance(address)
        nonce = state.get_nonce(address)
        stake = state.get_stake(address)
        return jsonify({
            "address": address, "balance": balance,
            "nonce": nonce, "stake": stake,
        }), 200

    # ===================================================================
    # WALLETS
    # ===================================================================

    @app.route("/wallet/create", methods=["POST"])
    @rate_limit(max_calls=20, window=60)
    def create_wallet():
        data = request.get_json(force=True) if request.data else {}
        label = data.get("label", "")
        wallet = state.create_wallet(label)
        log.info("Wallet created: %s (label=%s)", wallet["address"], label)
        return jsonify(wallet), 201

    @app.route("/wallet/<address>", methods=["GET"])
    def get_wallet(address: str):
        wallet = state.get_wallet(address)
        if not wallet:
            return jsonify({"error": "Wallet not found"}), 404
        balance = state.get_balance(address)
        nonce = state.get_nonce(address)
        txs = state.get_address_transactions(address, bc.chain, limit=20)
        return jsonify({
            "address": wallet["address"], "label": wallet["label"],
            "public_key": wallet["public_key"], "balance": balance,
            "nonce": nonce, "transactions": txs,
        }), 200

    @app.route("/wallets", methods=["GET"])
    def list_wallets():
        wallets = state.list_wallets()
        for w in wallets:
            w["balance"] = state.get_balance(w["address"])
        return jsonify({"wallets": wallets}), 200

    # ===================================================================
    # MULTI-SIG WALLETS
    # ===================================================================

    @app.route("/multisig/create", methods=["POST"])
    @rate_limit(max_calls=10, window=60)
    def create_multisig():
        data = request.get_json(force=True)
        public_keys = data.get("public_keys", [])
        required = data.get("required", len(public_keys))
        label = data.get("label", "")
        if len(public_keys) < 2:
            return jsonify({"error": "Need at least 2 public keys"}), 400
        if required < 1 or required > len(public_keys):
            return jsonify({"error": f"Required must be 1-{len(public_keys)}"}), 400
        wallet = state.create_multisig_wallet(public_keys, required, label)
        return jsonify(wallet), 201

    @app.route("/multisig/<address>", methods=["GET"])
    def get_multisig(address: str):
        wallet = state.get_multisig_wallet(address)
        if not wallet:
            return jsonify({"error": "Multisig wallet not found"}), 404
        wallet["balance"] = state.get_balance(address)
        return jsonify(wallet), 200

    @app.route("/multisig", methods=["GET"])
    def list_multisig():
        wallets = state.list_multisig_wallets()
        for w in wallets:
            w["balance"] = state.get_balance(w["address"])
        return jsonify({"wallets": wallets}), 200

    # ===================================================================
    # TRANSFER
    # ===================================================================

    @app.route("/transfer", methods=["POST"])
    @rate_limit(max_calls=30, window=60)
    def transfer():
        data = request.get_json(force=True)
        required = ("from_address", "to_address", "amount")
        if not all(k in data for k in required):
            return jsonify({"error": "Missing fields", "required": list(required)}), 400

        amount = float(data["amount"])
        fee = float(data.get("fee", 0))
        if amount <= 0:
            return jsonify({"error": "Amount must be positive"}), 400

        sender_wallet = state.get_wallet(data["from_address"])
        if not sender_wallet:
            return jsonify({"error": "Sender wallet not found on this node"}), 404

        if state.get_balance(data["from_address"]) < amount + fee:
            return jsonify({"error": "Insufficient balance"}), 400

        nonce = state.get_nonce(data["from_address"])
        tx_payload = {
            "sender": data["from_address"], "recipient": data["to_address"],
            "amount": amount, "fee": fee, "nonce": nonce,
        }
        signature = sign_transaction(sender_wallet["private_key"], tx_payload)

        bc.new_transaction(
            sender=data["from_address"], recipient=data["to_address"],
            amount=amount, signature=signature,
            public_key=sender_wallet["public_key"], fee=fee, nonce=nonce,
        )

        block = bc.mine_block(miner_address=node_id, reward=MINING_REWARD)
        return jsonify({
            "message": "Transfer confirmed",
            "block_index": block["index"],
            "from": data["from_address"],
            "to": data["to_address"],
            "amount": amount, "fee": fee,
        }), 201

    # ===================================================================
    # FAUCET
    # ===================================================================

    @app.route("/faucet", methods=["POST"])
    @rate_limit(max_calls=10, window=60)
    def faucet():
        data = request.get_json(force=True)
        address = data.get("address")
        amount = float(data.get("amount", 10))
        if not address:
            return jsonify({"error": "Address is required"}), 400
        if amount <= 0 or amount > 100:
            return jsonify({"error": "Amount must be between 0 and 100 ATL"}), 400

        bc.new_transaction(sender="MINING_REWARD", recipient=address, amount=amount)
        block = bc.mine_block(miner_address=node_id, reward=MINING_REWARD)
        new_balance = state.get_balance(address)
        return jsonify({
            "message": "Faucet tokens delivered",
            "block_index": block["index"],
            "address": address, "amount": amount,
            "new_balance": new_balance,
        }), 201

    # ===================================================================
    # STATS
    # ===================================================================

    @app.route("/stats", methods=["GET"])
    def stats():
        return jsonify(bc.get_chain_stats()), 200

    # ===================================================================
    # CONSENSUS
    # ===================================================================

    @app.route("/consensus", methods=["GET"])
    def consensus_info():
        return jsonify(bc.consensus.get_info()), 200

    @app.route("/consensus/switch", methods=["POST"])
    def switch_consensus():
        data = request.get_json(force=True)
        engine_name = data.get("engine", "pow")
        kwargs: dict[str, Any] = {}
        if "difficulty" in data:
            kwargs["difficulty"] = int(data["difficulty"])
        if "min_stake" in data:
            kwargs["min_stake"] = float(data["min_stake"])
        if "total_nodes" in data:
            kwargs["total_nodes"] = int(data["total_nodes"])
        try:
            bc.consensus = create_engine(engine_name, **kwargs)
            log.info("Consensus switched to %s", engine_name)
            return jsonify({"message": f"Switched to {engine_name}", **bc.consensus.get_info()}), 200
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

    # ===================================================================
    # STAKING (PoS)
    # ===================================================================

    @app.route("/stake", methods=["POST"])
    def add_stake():
        data = request.get_json(force=True)
        address = data.get("address", "")
        amount = float(data.get("amount", 0))
        if not address or amount <= 0:
            return jsonify({"error": "Address and positive amount required"}), 400
        if state.get_balance(address) < amount:
            return jsonify({"error": "Insufficient balance to stake"}), 400
        state.debit(address, amount)
        total = state.add_stake(address, amount)
        if isinstance(bc.consensus, ProofOfStake):
            bc.consensus.register_stake(address, amount)
        return jsonify({"address": address, "staked": amount, "total_stake": total}), 201

    @app.route("/stake/<address>", methods=["GET"])
    def get_stake(address: str):
        return jsonify({"address": address, "stake": state.get_stake(address)}), 200

    @app.route("/stakes", methods=["GET"])
    def list_stakes():
        return jsonify({"stakes": state.get_all_stakes()}), 200

    @app.route("/unstake", methods=["POST"])
    def remove_stake():
        data = request.get_json(force=True)
        address = data.get("address", "")
        amount = float(data.get("amount", 0))
        if not address or amount <= 0:
            return jsonify({"error": "Address and positive amount required"}), 400
        actual = state.remove_stake(address, amount)
        state.credit(address, actual)
        if isinstance(bc.consensus, ProofOfStake):
            bc.consensus.unstake(address, actual)
        return jsonify({"address": address, "unstaked": actual}), 200

    # ===================================================================
    # MEMPOOL
    # ===================================================================

    @app.route("/mempool", methods=["GET"])
    def mempool_info():
        return jsonify(bc.mempool.get_info()), 200

    # ===================================================================
    # SMART CONTRACTS
    # ===================================================================

    @app.route("/contract/deploy", methods=["POST"])
    @rate_limit(max_calls=10, window=60)
    def deploy_contract():
        data = request.get_json(force=True)
        code = data.get("code", "")
        owner = data.get("owner", "")
        label = data.get("label", "")
        template = data.get("template", "")
        if template and template in CONTRACT_TEMPLATES:
            code = CONTRACT_TEMPLATES[template]
        if not code or not owner:
            return jsonify({"error": "code and owner required"}), 400
        address = state.deploy_contract(code, owner, label)
        return jsonify({"address": address, "owner": owner, "label": label}), 201

    @app.route("/contract/<address>", methods=["GET"])
    def get_contract(address: str):
        contract = state.get_contract(address)
        if not contract:
            return jsonify({"error": "Contract not found"}), 404
        return jsonify(contract), 200

    @app.route("/contract/<address>/call", methods=["POST"])
    @rate_limit(max_calls=30, window=60)
    def call_contract(address: str):
        contract = state.get_contract(address)
        if not contract:
            return jsonify({"error": "Contract not found"}), 404
        data = request.get_json(force=True)
        sender = data.get("sender", "")
        amount = float(data.get("amount", 0))
        gas_limit = int(data.get("gas_limit", 100000))

        compiled = vm.compile_source(contract["code"])
        result = vm.execute(
            compiled, sender=sender, amount=amount,
            gas_limit=gas_limit, storage=contract["storage"],
            contract_address=address,
        )

        if result.success and result.storage_writes:
            new_storage = {**contract["storage"], **result.storage_writes}
            state.update_contract_storage(address, new_storage)

        # Process transfers
        for xfer in result.transfers:
            state.credit(xfer["to"], xfer["amount"])

        return jsonify({
            "success": result.success,
            "gas_used": result.gas_used,
            "logs": result.logs,
            "return_value": result.return_value,
            "error": result.error,
            "storage_writes": result.storage_writes,
            "transfers": result.transfers,
        }), 200 if result.success else 400

    @app.route("/contracts", methods=["GET"])
    def list_contracts():
        return jsonify({"contracts": state.list_contracts()}), 200

    @app.route("/contract/templates", methods=["GET"])
    def contract_templates():
        return jsonify({
            "templates": {k: v for k, v in CONTRACT_TEMPLATES.items()}
        }), 200

    # ===================================================================
    # ADDRESS BOOK
    # ===================================================================

    @app.route("/addressbook", methods=["GET"])
    def get_address_book():
        owner = request.args.get("owner", "default")
        return jsonify({"contacts": state.get_contacts(owner)}), 200

    @app.route("/addressbook", methods=["POST"])
    def add_contact():
        data = request.get_json(force=True)
        owner = data.get("owner", "default")
        address = data.get("address", "")
        label = data.get("label", "")
        if not address or not label:
            return jsonify({"error": "address and label required"}), 400
        cid = state.add_contact(owner, address, label)
        return jsonify({"id": cid, "address": address, "label": label}), 201

    @app.route("/addressbook/<int:contact_id>", methods=["DELETE"])
    def delete_contact(contact_id: int):
        owner = request.args.get("owner", "default")
        if state.delete_contact(contact_id, owner):
            return jsonify({"message": "Deleted"}), 200
        return jsonify({"error": "Contact not found"}), 404

    # ===================================================================
    # TRANSACTION HISTORY WITH CSV EXPORT
    # ===================================================================

    @app.route("/history/<address>", methods=["GET"])
    def address_history(address: str):
        limit = min(int(request.args.get("limit", 50)), 500)
        offset = int(request.args.get("offset", 0))
        fmt = request.args.get("format", "json")
        txs = state.get_address_transactions(address, bc.chain, limit=limit, offset=offset)
        total = state.get_address_tx_count(address, bc.chain)

        if fmt == "csv":
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=[
                "block_index", "timestamp", "sender", "recipient", "amount", "fee", "direction",
            ])
            writer.writeheader()
            for tx in txs:
                writer.writerow({
                    "block_index": tx.get("block_index"), "timestamp": tx.get("timestamp"),
                    "sender": tx.get("sender"), "recipient": tx.get("recipient"),
                    "amount": tx.get("amount"), "fee": tx.get("fee", 0),
                    "direction": tx.get("direction"),
                })
            return Response(
                output.getvalue(), mimetype="text/csv",
                headers={"Content-Disposition": f"attachment; filename=history_{address}.csv"},
            )

        return jsonify({
            "address": address, "transactions": txs,
            "count": len(txs), "total": total,
            "offset": offset, "limit": limit,
        }), 200

    # ===================================================================
    # QR CODE
    # ===================================================================

    @app.route("/qr/<address>", methods=["GET"])
    def qr_code(address: str):
        """Generate a simple SVG QR-like badge for an address."""
        import hashlib
        h = hashlib.sha256(address.encode()).hexdigest()
        # Generate a deterministic pattern as SVG
        size = 210
        cell = 10
        grid = size // cell
        svg_rects = []
        for i in range(grid):
            for j in range(grid):
                idx = (i * grid + j) * 2
                if idx + 1 < len(h):
                    val = int(h[idx:idx+2], 16)
                    if val > 100:
                        svg_rects.append(
                            f'<rect x="{j*cell}" y="{i*cell}" width="{cell}" height="{cell}" fill="#6366f1"/>'
                        )
        svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size + 30}" viewBox="0 0 {size} {size + 30}">
<rect width="{size}" height="{size}" fill="white"/>
{"".join(svg_rects)}
<text x="{size//2}" y="{size + 20}" text-anchor="middle" font-size="7" font-family="monospace" fill="#333">{address[:20]}...{address[-8:]}</text>
</svg>'''
        return Response(svg, mimetype="image/svg+xml")

    # ===================================================================
    # NODES / PEERS
    # ===================================================================

    @app.route("/nodes/register", methods=["POST"])
    def register_nodes():
        data = request.get_json(force=True)
        nodes = data.get("nodes")
        if not nodes:
            return jsonify({"error": "Supply a list of nodes"}), 400
        for node in nodes:
            bc.register_node(node)
            gossip.add_peer(node)
        return jsonify({"message": "Peers added", "total_nodes": list(bc.nodes)}), 201

    @app.route("/nodes/resolve", methods=["GET"])
    def resolve():
        replaced = bc.resolve_conflicts()
        if replaced:
            return jsonify({"message": "Chain was replaced", "chain": bc.chain}), 200
        return jsonify({"message": "Our chain is authoritative", "chain": bc.chain}), 200

    @app.route("/nodes", methods=["GET"])
    def list_nodes():
        return jsonify({
            "nodes": list(bc.nodes),
            "peers": gossip.get_peers(),
            "count": len(bc.nodes),
        }), 200

    # ===================================================================
    # GOSSIP
    # ===================================================================

    @app.route("/gossip", methods=["POST"])
    def handle_gossip():
        data = request.get_json(force=True)
        new_peers = gossip.handle_gossip(data)
        for p in new_peers:
            bc.register_node(p)
        return jsonify({"new_peers": new_peers}), 200

    # ===================================================================
    # SSE (Server-Sent Events)
    # ===================================================================

    @app.route("/events", methods=["GET"])
    def sse_stream():
        q = event_stream.subscribe()
        def generate():
            try:
                while True:
                    try:
                        msg = q.get(timeout=30)
                        yield msg
                    except queue.Empty:
                        yield ": heartbeat\n\n"
            except GeneratorExit:
                event_stream.unsubscribe(q)
        return Response(generate(), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.route("/events/history", methods=["GET"])
    def event_history():
        return jsonify({"events": event_stream.history}), 200

    # ===================================================================
    # FORK DETECTION
    # ===================================================================

    @app.route("/forks", methods=["GET"])
    def fork_status():
        return jsonify(fork_detector.get_status()), 200

    # ===================================================================
    # WEBHOOKS
    # ===================================================================

    @app.route("/webhooks", methods=["GET"])
    def list_webhooks():
        return jsonify({"webhooks": state.get_webhooks()}), 200

    @app.route("/webhooks", methods=["POST"])
    def create_webhook():
        data = request.get_json(force=True)
        url = data.get("url", "")
        event = data.get("event", "")
        filter_str = data.get("filter", "")
        if not url or not event:
            return jsonify({"error": "url and event required"}), 400
        wid = state.add_webhook(url, event, filter_str)
        return jsonify({"id": wid, "url": url, "event": event}), 201

    @app.route("/webhooks/<int:webhook_id>", methods=["DELETE"])
    def delete_webhook(webhook_id: int):
        if state.delete_webhook(webhook_id):
            return jsonify({"message": "Deleted"}), 200
        return jsonify({"error": "Webhook not found"}), 404

    # ===================================================================
    # VALIDATION PIPELINE INFO
    # ===================================================================

    @app.route("/validation", methods=["GET"])
    def validation_info():
        return jsonify({"validators": bc.validation.validators}), 200

    # ===================================================================
    # ATTACK SIMULATIONS (educational)
    # ===================================================================

    @app.route("/simulate/double-spend", methods=["POST"])
    def simulate_double_spend():
        """Demonstrate a double-spend attempt."""
        data = request.get_json(force=True)
        address = data.get("address", "")
        amount = float(data.get("amount", 5))
        recipient1 = data.get("recipient1", "alice_" + node_id[:8])
        recipient2 = data.get("recipient2", "bob_" + node_id[:8])

        balance = state.get_balance(address)
        log.info("SIMULATION: Double-spend attempt from %s (balance=%.2f)", address, balance)

        results: dict[str, Any] = {
            "simulation": "double_spend",
            "attacker": address,
            "balance_before": balance,
            "attempt_1": {"to": recipient1, "amount": amount},
            "attempt_2": {"to": recipient2, "amount": amount},
        }

        # First spend
        if balance >= amount:
            bc.new_transaction(sender="MINING_REWARD", recipient=address, amount=0)
            wallet = state.get_wallet(address)
            if wallet:
                nonce = state.get_nonce(address)
                tx1 = {"sender": address, "recipient": recipient1, "amount": amount, "nonce": nonce}
                sig1 = sign_transaction(wallet["private_key"], tx1)
                bc.new_transaction(sender=address, recipient=recipient1, amount=amount,
                                   signature=sig1, public_key=wallet["public_key"], nonce=nonce)
                block1 = bc.mine_block(miner_address=node_id, reward=MINING_REWARD)
                results["attempt_1"]["block"] = block1["index"]
                results["attempt_1"]["success"] = True

                # Second spend (should fail - balance depleted)
                balance_after = state.get_balance(address)
                results["balance_after_first"] = balance_after
                if balance_after >= amount:
                    results["attempt_2"]["success"] = True
                    results["attempt_2"]["note"] = "VULNERABILITY: double spend possible!"
                else:
                    results["attempt_2"]["success"] = False
                    results["attempt_2"]["note"] = "PROTECTED: insufficient balance after first spend"
            else:
                results["error"] = "Wallet not found on this node"
        else:
            results["error"] = "Insufficient balance to simulate"

        results["balance_after"] = state.get_balance(address)
        return jsonify(results), 200

    @app.route("/simulate/51-attack", methods=["POST"])
    def simulate_51_attack():
        """Demonstrate a 51% attack (alternative chain creation)."""
        data = request.get_json(force=True)
        attacker_blocks = int(data.get("blocks", 3))
        honest_length = len(bc.chain)

        log.info("SIMULATION: 51%% attack with %d malicious blocks", attacker_blocks)

        # Save current chain state
        original_chain = list(bc.chain)
        original_length = len(original_chain)

        # Mine attacker blocks
        for i in range(attacker_blocks):
            bc.mine_block(miner_address=f"attacker_{node_id[:8]}", reward=MINING_REWARD)

        attack_length = len(bc.chain)
        attack_succeeded = attack_length > original_length

        return jsonify({
            "simulation": "51_percent_attack",
            "honest_chain_length": original_length,
            "attack_chain_length": attack_length,
            "blocks_mined_by_attacker": attacker_blocks,
            "attack_succeeded": attack_succeeded,
            "note": "In a real network, the attacker would need >50% of mining power to outpace honest nodes. This simulation mines on the same chain." if attack_succeeded else "Attack failed",
        }), 200

    @app.route("/simulate/selfish-mining", methods=["POST"])
    def simulate_selfish_mining():
        """Demonstrate selfish mining strategy."""
        data = request.get_json(force=True)
        rounds = int(data.get("rounds", 5))
        selfish_power = float(data.get("hash_power", 0.3))

        log.info("SIMULATION: Selfish mining (%d rounds, %.0f%% power)", rounds, selfish_power * 100)

        import random
        selfish_blocks = 0
        honest_blocks = 0
        wasted_blocks = 0
        selfish_secret_chain = 0

        for _ in range(rounds):
            if random.random() < selfish_power:
                selfish_secret_chain += 1
                selfish_blocks += 1
            else:
                honest_blocks += 1
                if selfish_secret_chain > 0:
                    if selfish_secret_chain > 1:
                        wasted_blocks += honest_blocks
                    else:
                        wasted_blocks += 1
                    selfish_secret_chain = 0

        return jsonify({
            "simulation": "selfish_mining",
            "rounds": rounds,
            "selfish_hash_power": selfish_power,
            "selfish_blocks_found": selfish_blocks,
            "honest_blocks_found": honest_blocks,
            "wasted_blocks": wasted_blocks,
            "selfish_advantage": selfish_blocks / max(honest_blocks, 1),
            "note": f"With {selfish_power*100:.0f}% hash power, selfish miner found {selfish_blocks}/{rounds} blocks",
        }), 200

    @app.route("/simulate/step-mine", methods=["POST"])
    def step_mine():
        """Step-through mining — shows each hash attempt."""
        try:
            data = request.get_json(force=True)
            max_steps = min(int(data.get("steps", 100)), 10000)
            last_proof = bc.last_block.get("proof", 0)
            difficulty = 4
            if hasattr(bc.consensus, "difficulty"):
                difficulty = bc.consensus.difficulty

            attempts = []
            proof = 0
            found = False
            target = "0" * difficulty

            for _ in range(max_steps):
                guess = f"{last_proof}{proof}".encode()
                guess_hash = hashlib.sha256(guess).hexdigest()
                is_valid = guess_hash[:difficulty] == target
                attempts.append({
                    "proof": proof,
                    "hash": guess_hash,
                    "valid": is_valid,
                    "prefix": guess_hash[:difficulty],
                })
                if is_valid:
                    found = True
                    break
                proof += 1

            return jsonify({
                "last_proof": last_proof,
                "difficulty": difficulty,
                "target_prefix": target,
                "attempts": attempts,
                "total_attempts": len(attempts),
                "found": found,
                "winning_proof": proof if found else None,
            }), 200
        except Exception as e:
            log.exception("step_mine error")
            return jsonify({"error": str(e)}), 500

    # ===================================================================
    # API DOCS (OpenAPI/Swagger)
    # ===================================================================

    @app.route("/docs", methods=["GET"])
    def api_docs():
        """Return OpenAPI-style documentation."""
        endpoints: list[dict[str, Any]] = []
        for rule in app.url_map.iter_rules():
            if rule.endpoint == "static":
                continue
            if rule.rule.startswith("/api/"):
                continue  # Skip proxy routes
            methods = sorted(rule.methods - {"OPTIONS", "HEAD"})
            endpoints.append({
                "path": rule.rule,
                "methods": methods,
                "endpoint": rule.endpoint,
            })
        endpoints.sort(key=lambda e: e["path"])
        return jsonify({
            "title": "Atlas Engine API",
            "version": "2.0.0",
            "description": "Modular blockchain engine with pluggable consensus, smart contracts, and more.",
            "endpoints": endpoints,
            "consensus_engines": ["pow", "pos", "pbft"],
            "contract_templates": list(CONTRACT_TEMPLATES.keys()),
        }), 200

    # ===================================================================
    # PROXY — map /api/nodeN/* for standalone monitor UI
    # ===================================================================

    proxy_routes = [
        ("/api/<node>/health", "GET", lambda n: health()),
        ("/api/<node>/chain", "GET", lambda n: full_chain()),
        ("/api/<node>/mine", "GET", lambda n: mine()),
        ("/api/<node>/balance/<address>", "GET", lambda n, a: get_balance(a)),
        ("/api/<node>/nodes/resolve", "GET", lambda n: resolve()),
        ("/api/<node>/wallet/create", "POST", lambda n: create_wallet()),
        ("/api/<node>/wallets", "GET", lambda n: list_wallets()),
        ("/api/<node>/transfer", "POST", lambda n: transfer()),
        ("/api/<node>/faucet", "POST", lambda n: faucet()),
        ("/api/<node>/stats", "GET", lambda n: stats()),
        ("/api/<node>/nodes/register", "POST", lambda n: register_nodes()),
        ("/api/<node>/consensus", "GET", lambda n: consensus_info()),
        ("/api/<node>/mempool", "GET", lambda n: mempool_info()),
        ("/api/<node>/contracts", "GET", lambda n: list_contracts()),
        ("/api/<node>/stakes", "GET", lambda n: list_stakes()),
    ]

    for i, (path, method, handler) in enumerate(proxy_routes):
        methods = [method] if isinstance(method, str) else method
        app.add_url_rule(
            path, endpoint=f"proxy_{i}", view_func=handler, methods=methods,
        )

    return app, ctx
