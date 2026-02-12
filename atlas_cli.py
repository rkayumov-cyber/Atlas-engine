#!/usr/bin/env python3
"""atlas-cli — Command-line interface for Atlas Engine.

Usage:
  python atlas_cli.py <command> [options]

Commands:
  status              Show node health and chain info
  mine                Mine a new block
  balance <address>   Check balance of an address
  send <from> <to> <amount>  Transfer tokens
  faucet <address> [amount]  Request tokens from faucet
  wallets             List wallets
  wallet-create [label]  Create a new wallet
  chain               Show full chain summary
  block <index>       Show block details
  mempool             Show mempool info
  peers               List connected peers
  consensus           Show consensus info
  consensus-switch <engine>  Switch consensus (pow/pos/pbft)
  contracts           List deployed contracts
  deploy <owner> <template>  Deploy a contract from template
  stakes              List all stakes
  stake <address> <amount>   Stake tokens
  stats               Show network statistics
  export <file>       Export chain to file
  import <file>       Import chain from file
  docs                Show API endpoints
  simulate <type>     Run attack simulation (double-spend/51-attack/selfish-mining/step-mine)
"""

from __future__ import annotations

import json
import sys
from typing import Any

import requests

BASE_URL = "http://127.0.0.1:5000"


def api(method: str, path: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
    url = f"{BASE_URL}{path}"
    try:
        if method == "GET":
            r = requests.get(url, timeout=120)
        elif method == "POST":
            r = requests.post(url, json=data or {}, timeout=120)
        elif method == "DELETE":
            r = requests.delete(url, timeout=10)
        else:
            r = requests.get(url, timeout=10)
        return r.json()
    except requests.ConnectionError:
        return {"error": f"Cannot connect to {BASE_URL}. Is the node running?"}
    except Exception as e:
        return {"error": str(e)}


def pp(data: Any) -> None:
    """Pretty print JSON."""
    print(json.dumps(data, indent=2, default=str))


def main() -> None:
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return

    cmd = args[0].lower()

    if cmd == "status":
        pp(api("GET", "/health"))

    elif cmd == "mine":
        print("Mining block...")
        pp(api("GET", "/mine"))

    elif cmd == "balance" and len(args) >= 2:
        pp(api("GET", f"/balance/{args[1]}"))

    elif cmd == "send" and len(args) >= 4:
        pp(api("POST", "/transfer", {
            "from_address": args[1], "to_address": args[2],
            "amount": float(args[3]), "fee": float(args[4]) if len(args) > 4 else 0,
        }))

    elif cmd == "faucet" and len(args) >= 2:
        amount = float(args[2]) if len(args) > 2 else 10
        pp(api("POST", "/faucet", {"address": args[1], "amount": amount}))

    elif cmd == "wallets":
        pp(api("GET", "/wallets"))

    elif cmd == "wallet-create":
        label = args[1] if len(args) > 1 else ""
        pp(api("POST", "/wallet/create", {"label": label}))

    elif cmd == "chain":
        data = api("GET", "/chain")
        if "chain" in data:
            print(f"Chain length: {data['length']}")
            for b in data["chain"][-10:]:
                txs = len(b.get("transactions", []))
                print(f"  Block #{b['index']}: proof={b.get('proof',0)}, txs={txs}, consensus={b.get('consensus','')}")
        else:
            pp(data)

    elif cmd == "block" and len(args) >= 2:
        pp(api("GET", f"/block/{args[1]}"))

    elif cmd == "mempool":
        pp(api("GET", "/mempool"))

    elif cmd == "peers":
        pp(api("GET", "/nodes"))

    elif cmd == "consensus":
        pp(api("GET", "/consensus"))

    elif cmd == "consensus-switch" and len(args) >= 2:
        kwargs: dict[str, Any] = {"engine": args[1]}
        if len(args) > 2:
            kwargs["difficulty"] = int(args[2])
        pp(api("POST", "/consensus/switch", kwargs))

    elif cmd == "contracts":
        pp(api("GET", "/contracts"))

    elif cmd == "deploy" and len(args) >= 3:
        pp(api("POST", "/contract/deploy", {"owner": args[1], "template": args[2]}))

    elif cmd == "stakes":
        pp(api("GET", "/stakes"))

    elif cmd == "stake" and len(args) >= 3:
        pp(api("POST", "/stake", {"address": args[1], "amount": float(args[2])}))

    elif cmd == "stats":
        pp(api("GET", "/stats"))

    elif cmd == "export" and len(args) >= 2:
        data = api("GET", "/chain/export")
        with open(args[1], "w") as f:
            json.dump(data, f, indent=2)
        print(f"Chain exported to {args[1]}")

    elif cmd == "import" and len(args) >= 2:
        with open(args[1], "r") as f:
            chain_data = f.read()
        r = requests.post(f"{BASE_URL}/chain/import", data=chain_data, timeout=30,
                          headers={"Content-Type": "application/json"})
        pp(r.json())

    elif cmd == "docs":
        pp(api("GET", "/docs"))

    elif cmd == "simulate" and len(args) >= 2:
        sim_type = args[1]
        extra: dict[str, Any] = {}
        if len(args) > 2:
            for a in args[2:]:
                if "=" in a:
                    k, v = a.split("=", 1)
                    try:
                        extra[k] = float(v) if "." in v else int(v)
                    except ValueError:
                        extra[k] = v
        if sim_type == "double-spend":
            pp(api("POST", "/simulate/double-spend", extra))
        elif sim_type == "51-attack":
            pp(api("POST", "/simulate/51-attack", extra))
        elif sim_type == "selfish-mining":
            pp(api("POST", "/simulate/selfish-mining", extra))
        elif sim_type == "step-mine":
            pp(api("POST", "/simulate/step-mine", extra))
        else:
            print(f"Unknown simulation: {sim_type}")
            print("Available: double-spend, 51-attack, selfish-mining, step-mine")

    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)


if __name__ == "__main__":
    main()
