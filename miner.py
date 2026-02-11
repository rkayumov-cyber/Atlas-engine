"""
Atlas Engine — Auto Miner
Continuously mines blocks on a target node to generate tokens.
Usage:
    python miner.py                        # mine on node-1 (default)
    python miner.py --node http://localhost:5002 --interval 5
    python miner.py --all                  # round-robin across all nodes
"""

from __future__ import annotations

import argparse
import os
import sys
import time

import requests

# Inside Docker, nodes are reachable by service name on port 5000.
# Outside Docker, they're on localhost:5001-5006.
_env_nodes = os.environ.get("ATLAS_NODES", "")
DEFAULT_NODES = (
    [n.strip() for n in _env_nodes.split(",") if n.strip()]
    if _env_nodes
    else [
        "http://localhost:5001",
        "http://localhost:5002",
        "http://localhost:5003",
        "http://localhost:5004",
        "http://localhost:5005",
        "http://localhost:5006",
    ]
)


def mine_block(node_url: str) -> dict | None:
    """Trigger mining on a node and return the block data."""
    try:
        resp = requests.get(f"{node_url}/mine", timeout=120)
        if resp.status_code == 200:
            return resp.json()
    except requests.RequestException as exc:
        print(f"  [!] Failed to reach {node_url}: {exc}")
    return None


def get_balance(node_url: str, address: str) -> float:
    """Fetch the balance for a given address."""
    try:
        resp = requests.get(f"{node_url}/balance/{address}", timeout=5)
        if resp.status_code == 200:
            return resp.json().get("balance", 0.0)
    except requests.RequestException:
        pass
    return 0.0


def run_miner(nodes: list[str], interval: float, max_blocks: int) -> None:
    """Main mining loop."""
    mined = 0
    node_idx = 0
    total_rewards = 0.0

    print("=" * 55)
    print("  Atlas Engine — Auto Miner")
    print("=" * 55)
    print(f"  Nodes      : {', '.join(nodes)}")
    print(f"  Interval   : {interval}s between blocks")
    print(f"  Max blocks : {'unlimited' if max_blocks == 0 else max_blocks}")
    print("=" * 55)
    print()

    try:
        while max_blocks == 0 or mined < max_blocks:
            node = nodes[node_idx % len(nodes)]
            node_idx += 1

            print(f"[Block {mined + 1}] Mining on {node} ...", end=" ", flush=True)
            start = time.perf_counter()
            result = mine_block(node)
            elapsed = time.perf_counter() - start

            if result:
                mined += 1
                block_idx = result.get("index", "?")
                proof = result.get("proof", "?")
                tx_count = len(result.get("transactions", []))

                # Sum up rewards from this block
                reward = sum(
                    tx.get("amount", 0)
                    for tx in result.get("transactions", [])
                    if tx.get("sender") == "MINING_REWARD"
                )
                total_rewards += reward

                print(
                    f"OK  block #{block_idx}  "
                    f"proof={proof}  txs={tx_count}  "
                    f"reward=+{reward}  "
                    f"time={elapsed:.2f}s"
                )
            else:
                print("FAILED")

            if max_blocks == 0 or mined < max_blocks:
                time.sleep(interval)

    except KeyboardInterrupt:
        print("\n\n  Miner stopped by user.")

    print()
    print("=" * 55)
    print(f"  Blocks mined   : {mined}")
    print(f"  Total rewards  : {total_rewards}")
    print("=" * 55)


def main() -> None:
    parser = argparse.ArgumentParser(description="Atlas Engine Auto Miner")
    parser.add_argument(
        "--node",
        type=str,
        default=None,
        help="Target node URL (default: http://localhost:5001)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Round-robin mining across all 3 default nodes",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=2.0,
        help="Seconds between mining attempts (default: 2)",
    )
    parser.add_argument(
        "--blocks",
        type=int,
        default=0,
        help="Number of blocks to mine (0 = unlimited, default: 0)",
    )
    args = parser.parse_args()

    if args.all:
        nodes = DEFAULT_NODES
    elif args.node:
        nodes = [args.node.rstrip("/")]
    else:
        nodes = [DEFAULT_NODES[0]]

    run_miner(nodes, args.interval, args.blocks)


if __name__ == "__main__":
    main()
