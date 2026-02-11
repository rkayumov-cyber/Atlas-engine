# Specification: Core Ledger & Security

## 1. Blockchain Class
- **Block Structure:** index, timestamp, transactions (list), proof, previous_hash.
- **PoW Algorithm:** SHA-256 hash starting with '0000'.
- **Genesis Block:** Read from `genesis.json`. Use a hardcoded default if missing.

## 2. Security (ECDSA)
- Use `SECP256k1` curve.
- Every transaction must include a `signature` and `public_key`.
- Verification logic must check if the signature matches the transaction hash.

## 3. State Management
- Use `StateManager` class with SQLite.
- Track user balances in an `accounts` table.
- Implement a `contract_storage` table for key-value pair persistence.