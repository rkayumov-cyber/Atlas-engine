"""
Atlas Engine — Stress Test
Simulates 100 concurrent users sending transactions across 3 Docker nodes.
Metrics: Total TXs, Success Rate, Average Latency (ms), Throughput (TPS).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import random
import time

import httpx
from ecdsa import SECP256k1, SigningKey

NODES = [
    "http://localhost:5001",
    "http://localhost:5002",
    "http://localhost:5003",
]

CONCURRENT_USERS = 100


def _generate_keypair() -> tuple[str, str]:
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()
    return sk.to_string().hex(), vk.to_string().hex()


def _sign(private_hex: str, tx_data: dict) -> str:
    sk = SigningKey.from_string(bytes.fromhex(private_hex), curve=SECP256k1)
    canonical = json.dumps(
        {k: v for k, v in sorted(tx_data.items()) if k not in ("signature", "public_key")},
        sort_keys=True,
    )
    message = hashlib.sha256(canonical.encode()).digest()
    return sk.sign(message).hex()


async def send_transaction(client: httpx.AsyncClient, priv: str, pub: str) -> tuple[bool, float]:
    """Send a single transaction to a random node. Returns (success, latency_ms)."""
    node = random.choice(NODES)
    tx_data = {
        "sender": pub[:40],
        "recipient": "recipient_" + pub[-8:],
        "amount": round(random.uniform(0.01, 1.0), 4),
    }
    signature = _sign(priv, tx_data)
    payload = {**tx_data, "signature": signature, "public_key": pub}

    start = time.perf_counter()
    try:
        resp = await client.post(f"{node}/transactions/new", json=payload, timeout=10)
        latency = (time.perf_counter() - start) * 1000
        return resp.status_code in (200, 201), latency
    except Exception:
        latency = (time.perf_counter() - start) * 1000
        return False, latency


async def mine_on_all(client: httpx.AsyncClient) -> None:
    """Trigger mining on every node to seed initial balances."""
    for node in NODES:
        try:
            await client.get(f"{node}/mine", timeout=30)
        except Exception:
            pass


async def main() -> None:
    priv, pub = _generate_keypair()

    async with httpx.AsyncClient() as client:
        # Seed: mine a few blocks so the sender address gets funds
        print("[*] Seeding network with mining rewards ...")
        for _ in range(3):
            await mine_on_all(client)

        print(f"[*] Launching {CONCURRENT_USERS} concurrent transaction tasks ...")
        start = time.perf_counter()
        tasks = [send_transaction(client, priv, pub) for _ in range(CONCURRENT_USERS)]
        results = await asyncio.gather(*tasks)
        elapsed = time.perf_counter() - start

    successes = sum(1 for ok, _ in results if ok)
    latencies = [lat for _, lat in results]
    total = len(results)
    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    tps = total / elapsed if elapsed > 0 else 0

    print("\n" + "=" * 50)
    print("  Atlas Engine — Stress Test Results")
    print("=" * 50)
    print(f"  Total TXs Sent   : {total}")
    print(f"  Successes         : {successes}")
    print(f"  Failures          : {total - successes}")
    print(f"  Success Rate      : {successes / total * 100:.1f}%")
    print(f"  Avg Latency       : {avg_latency:.1f} ms")
    print(f"  Throughput (TPS)  : {tps:.1f}")
    print("=" * 50)


if __name__ == "__main__":
    asyncio.run(main())
