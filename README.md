# Atlas Engine

A modular, decentralized blockchain engine built in Python. Features pluggable Proof-of-Work consensus, ECDSA transaction signing, SQLite state persistence, and a real-time network monitor with interactive controls.

![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0+-green?logo=flask&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow)

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Atlas Network                      │
│                                                      │
│   ┌──────────┐   ┌──────────┐   ┌──────────┐       │
│   │  Node 1  │◄──►  Node 2  │◄──►  Node 3  │       │
│   │  :5001   │   │  :5002   │   │  :5003   │       │
│   └────┬─────┘   └────┬─────┘   └────┬─────┘       │
│        │              │              │               │
│        └──────────────┼──────────────┘               │
│                       │                              │
│              ┌────────┴────────┐                     │
│              │   Auto Miner   │                      │
│              │  (round-robin) │                      │
│              └─────────────────┘                     │
│                                                      │
│   ┌──────────────┐        ┌──────────────────┐      │
│   │   Explorer   │        │  Network Monitor │      │
│   │    :8080     │        │      :8090       │      │
│   └──────────────┘        └──────────────────┘      │
└─────────────────────────────────────────────────────┘
```

## Features

### Core Engine (`app.py`)
- **Blockchain Ledger** — Block structure with index, timestamp, transactions, proof, and previous hash
- **Proof of Work** — SHA-256 with configurable difficulty (`0000` prefix)
- **ECDSA Signatures** — SECP256k1 curve for transaction signing and verification
- **State Manager** — SQLite persistence for account balances and contract key-value storage
- **Genesis Block** — Loaded from `genesis.json` with fallback defaults
- **Longest-Chain Consensus** — Resolves forks by adopting the longest valid chain across peers

### API Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/mine` | Mine a new block (PoW + coinbase reward) |
| `GET` | `/chain` | Return the full blockchain |
| `GET` | `/balance/<address>` | Query account balance from state DB |
| `POST` | `/transactions/new` | Submit a signed transaction to the mempool |
| `POST` | `/nodes/register` | Register peer node URLs |
| `GET` | `/nodes/resolve` | Trigger longest-chain consensus |
| `GET` | `/health` | Node health check |

### Network Monitor (`localhost:8090`)
- **Live SVG network graph** with animated transaction particles flowing between nodes
- **8 real-time metrics** — Nodes online, chain length, total TXs, tokens mined, avg block time, TPS, chain sync status, uptime
- **Interactive controls** — Mine blocks on any node, check wallet balances, trigger consensus sync
- **Block detail modal** — Click any block to inspect proof, hash, timestamp, and all transactions
- **Throughput sparkline** — Visual bar chart of TX counts per block
- **Chain comparison** — Progress bars showing each node's chain length
- **Event log** — Timestamped system events (mining, consensus, errors)

### Block Explorer (`localhost:8080`)
- Network health cards with online/offline status per node
- Auto-refreshing table of the last 5 blocks

### Auto Miner (`miner.py`)
- Continuous block mining with configurable interval
- Round-robin distribution across all nodes
- Docker-aware via `ATLAS_NODES` environment variable

## Quick Start

### With Docker (recommended)

```bash
# Start the full 3-node network + miner + explorer + monitor
docker-compose up --build

# Services:
#   Node 1:           http://localhost:5001
#   Node 2:           http://localhost:5002
#   Node 3:           http://localhost:5003
#   Block Explorer:   http://localhost:8080
#   Network Monitor:  http://localhost:8090
```

### Without Docker

```bash
# Install dependencies
pip install -r requirements.txt

# Start a single node
python app.py

# In another terminal, run the auto-miner
python miner.py --all --interval 2
```

## Usage Examples

```bash
# Mine a block
curl http://localhost:5001/mine

# View the chain
curl http://localhost:5001/chain

# Check a balance
curl http://localhost:5001/balance/<address>

# Register a peer
curl -X POST http://localhost:5001/nodes/register \
  -H "Content-Type: application/json" \
  -d '{"nodes": ["http://localhost:5002"]}'

# Trigger consensus
curl http://localhost:5001/nodes/resolve
```

## Auto Miner Options

```bash
python miner.py                          # Mine on node-1 (default)
python miner.py --all                    # Round-robin all 3 nodes
python miner.py --node http://localhost:5002  # Target specific node
python miner.py --interval 10            # 10 seconds between blocks
python miner.py --blocks 20             # Mine exactly 20 blocks
```

## Stress Testing

```bash
# Run against the Docker network (100 concurrent users)
pip install httpx ecdsa
python load_test.py
```

Output:
```
==================================================
  Atlas Engine — Stress Test Results
==================================================
  Total TXs Sent   : 100
  Successes         : 100
  Success Rate      : 100.0%
  Avg Latency       : 12.3 ms
  Throughput (TPS)  : 45.2
==================================================
```

## Project Structure

```
Atlas-engine/
├── app.py                 # Core engine (Blockchain, StateManager, ECDSA, Flask API)
├── miner.py               # Auto-miner with round-robin support
├── load_test.py           # Async stress test (asyncio + httpx)
├── genesis.json           # Genesis block configuration
├── requirements.txt       # Python dependencies
├── Dockerfile             # Container image for blockchain nodes
├── docker-compose.yml     # 3 nodes + miner + explorer + monitor
├── explorer/
│   ├── dashboard.html     # Block Explorer UI (Tailwind CSS)
│   └── nginx.conf         # Nginx reverse proxy config
├── monitor/
│   ├── index.html         # Network Monitor UI (interactive)
│   └── nginx.conf         # Nginx reverse proxy config
└── SPEC_*.md              # Design specifications
```

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3.11+, Flask |
| Cryptography | ECDSA (SECP256k1) |
| Database | SQLite (WAL mode) |
| Networking | Requests, httpx |
| Containers | Docker, Docker Compose |
| UI | Tailwind CSS, Vanilla JS, SVG |
| Web Server | Nginx (reverse proxy) |

## License

MIT
