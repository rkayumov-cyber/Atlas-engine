# Specification: P2P & API Layer

## 1. Node Discovery
- Maintain a `set()` of peer URLs.
- Endpoint `POST /nodes/register` to add new neighbors.

## 2. Consensus (Longest Chain)
- Endpoint `GET /nodes/resolve`. 
- Logic: Iterate through all peers, fetch their `/chain`. If a valid chain is longer than the local one, replace the local chain and update the SQLite State DB.

## 3. API Endpoints
- `POST /transactions/new`: Validate and add to mempool.
- `GET /mine`: Bundle mempool into a block, solve PoW, and append to chain.
- `GET /chain`: Return JSON of the full ledger.
- `GET /balance/<address>`: Query State DB for current balance.