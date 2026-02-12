"""SQLite state manager — accounts, wallets, nonces, contracts, address book."""

from __future__ import annotations

import hashlib
import logging
import sqlite3
import time
from typing import Any, Optional

log = logging.getLogger("atlas.state")


class StateManager:
    """Persist account balances, nonces, wallets, contracts, and address book in SQLite."""

    def __init__(self, db_path: str = "state.db") -> None:
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._create_tables()

    def _create_tables(self) -> None:
        cur = self._conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS accounts (
            address TEXT PRIMARY KEY,
            balance REAL NOT NULL DEFAULT 0,
            nonce INTEGER NOT NULL DEFAULT 0
        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS wallets (
            address TEXT PRIMARY KEY,
            private_key TEXT NOT NULL,
            public_key TEXT NOT NULL,
            label TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL
        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS multisig_wallets (
            address TEXT PRIMARY KEY,
            public_keys TEXT NOT NULL,
            required INTEGER NOT NULL,
            label TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL
        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS contracts (
            address TEXT PRIMARY KEY,
            code TEXT NOT NULL,
            owner TEXT NOT NULL,
            storage TEXT NOT NULL DEFAULT '{}',
            created_at REAL NOT NULL,
            label TEXT NOT NULL DEFAULT ''
        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS contract_storage (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS address_book (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT NOT NULL,
            address TEXT NOT NULL,
            label TEXT NOT NULL,
            created_at REAL NOT NULL
        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS webhooks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            event TEXT NOT NULL,
            filter TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL,
            active INTEGER NOT NULL DEFAULT 1
        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS stakes (
            address TEXT PRIMARY KEY,
            amount REAL NOT NULL DEFAULT 0,
            staked_at REAL NOT NULL
        )""")
        self._conn.commit()

    # -- account helpers -----------------------------------------------------

    def get_balance(self, address: str) -> float:
        row = self._conn.execute(
            "SELECT balance FROM accounts WHERE address = ?", (address,)
        ).fetchone()
        return row[0] if row else 0.0

    def get_nonce(self, address: str) -> int:
        row = self._conn.execute(
            "SELECT nonce FROM accounts WHERE address = ?", (address,)
        ).fetchone()
        return row[0] if row else 0

    def increment_nonce(self, address: str) -> int:
        nonce = self.get_nonce(address)
        if not self._account_exists(address):
            self._conn.execute(
                "INSERT INTO accounts (address, balance, nonce) VALUES (?, 0, 1)",
                (address,),
            )
        else:
            self._conn.execute(
                "UPDATE accounts SET nonce = nonce + 1 WHERE address = ?",
                (address,),
            )
        self._conn.commit()
        return nonce + 1

    def credit(self, address: str, amount: float) -> None:
        if not self._account_exists(address):
            self._conn.execute(
                "INSERT INTO accounts (address, balance, nonce) VALUES (?, ?, 0)",
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
        for tx in block.get("transactions", []):
            sender = tx.get("sender")
            recipient = tx.get("recipient")
            amount = float(tx.get("amount", 0))
            fee = float(tx.get("fee", 0))
            if sender == "MINING_REWARD":
                self.credit(recipient, amount)
            else:
                self.debit(sender, amount + fee)
                self.credit(recipient, amount)
                if sender != "MINING_REWARD" and "nonce" in tx:
                    self.increment_nonce(sender)

    def rebuild_from_chain(self, chain: list[dict[str, Any]]) -> None:
        self._conn.execute("DELETE FROM accounts")
        self._conn.commit()
        for block in chain:
            self.apply_block(block)

    def get_all_addresses(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT address, balance FROM accounts WHERE balance > 0 ORDER BY balance DESC"
        ).fetchall()
        return [{"address": r[0], "balance": r[1]} for r in rows]

    # -- wallet helpers -----------------------------------------------------

    def create_wallet(self, label: str = "") -> dict[str, str]:
        from atlas.crypto import generate_keys, address_from_pubkey
        private_key, public_key = generate_keys()
        address = address_from_pubkey(public_key)
        self._conn.execute(
            "INSERT INTO wallets (address, private_key, public_key, label, created_at) VALUES (?, ?, ?, ?, ?)",
            (address, private_key, public_key, label, time.time()),
        )
        self._conn.commit()
        return {"address": address, "private_key": private_key, "public_key": public_key, "label": label}

    def get_wallet(self, address: str) -> Optional[dict[str, Any]]:
        row = self._conn.execute(
            "SELECT address, private_key, public_key, label, created_at FROM wallets WHERE address = ?",
            (address,),
        ).fetchone()
        if not row:
            return None
        return {"address": row[0], "private_key": row[1], "public_key": row[2], "label": row[3], "created_at": row[4]}

    def list_wallets(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT address, label, created_at FROM wallets ORDER BY created_at DESC"
        ).fetchall()
        return [{"address": r[0], "label": r[1], "created_at": r[2]} for r in rows]

    # -- multi-sig wallets --------------------------------------------------

    def create_multisig_wallet(
        self, public_keys: list[str], required: int, label: str = ""
    ) -> dict[str, Any]:
        import json
        from atlas.crypto import multisig_address
        address = multisig_address(public_keys, required)
        self._conn.execute(
            "INSERT OR REPLACE INTO multisig_wallets (address, public_keys, required, label, created_at) VALUES (?, ?, ?, ?, ?)",
            (address, json.dumps(public_keys), required, label, time.time()),
        )
        self._conn.commit()
        return {"address": address, "public_keys": public_keys, "required": required, "label": label}

    def get_multisig_wallet(self, address: str) -> Optional[dict[str, Any]]:
        import json
        row = self._conn.execute(
            "SELECT address, public_keys, required, label, created_at FROM multisig_wallets WHERE address = ?",
            (address,),
        ).fetchone()
        if not row:
            return None
        return {
            "address": row[0], "public_keys": json.loads(row[1]),
            "required": row[2], "label": row[3], "created_at": row[4],
        }

    def list_multisig_wallets(self) -> list[dict[str, Any]]:
        import json
        rows = self._conn.execute(
            "SELECT address, public_keys, required, label, created_at FROM multisig_wallets ORDER BY created_at DESC"
        ).fetchall()
        return [{"address": r[0], "public_keys": json.loads(r[1]), "required": r[2], "label": r[3]} for r in rows]

    # -- address book -------------------------------------------------------

    def add_contact(self, owner: str, address: str, label: str) -> int:
        cur = self._conn.execute(
            "INSERT INTO address_book (owner, address, label, created_at) VALUES (?, ?, ?, ?)",
            (owner, address, label, time.time()),
        )
        self._conn.commit()
        return cur.lastrowid or 0

    def get_contacts(self, owner: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT id, address, label, created_at FROM address_book WHERE owner = ? ORDER BY label",
            (owner,),
        ).fetchall()
        return [{"id": r[0], "address": r[1], "label": r[2], "created_at": r[3]} for r in rows]

    def delete_contact(self, contact_id: int, owner: str) -> bool:
        cur = self._conn.execute(
            "DELETE FROM address_book WHERE id = ? AND owner = ?", (contact_id, owner),
        )
        self._conn.commit()
        return (cur.rowcount or 0) > 0

    # -- contract storage ---------------------------------------------------

    def deploy_contract(
        self, code: str, owner: str, label: str = ""
    ) -> str:
        import json
        address = "cx" + hashlib.sha256(f"{owner}{code}{time.time()}".encode()).hexdigest()[:38]
        self._conn.execute(
            "INSERT INTO contracts (address, code, owner, storage, created_at, label) VALUES (?, ?, ?, ?, ?, ?)",
            (address, code, owner, json.dumps({}), time.time(), label),
        )
        self._conn.commit()
        log.info("Contract deployed: %s by %s", address, owner)
        return address

    def get_contract(self, address: str) -> Optional[dict[str, Any]]:
        import json
        row = self._conn.execute(
            "SELECT address, code, owner, storage, created_at, label FROM contracts WHERE address = ?",
            (address,),
        ).fetchone()
        if not row:
            return None
        return {
            "address": row[0], "code": row[1], "owner": row[2],
            "storage": json.loads(row[3]), "created_at": row[4], "label": row[5],
        }

    def update_contract_storage(self, address: str, storage: dict[str, str]) -> None:
        import json
        self._conn.execute(
            "UPDATE contracts SET storage = ? WHERE address = ?",
            (json.dumps(storage), address),
        )
        self._conn.commit()

    def list_contracts(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT address, owner, label, created_at FROM contracts ORDER BY created_at DESC"
        ).fetchall()
        return [{"address": r[0], "owner": r[1], "label": r[2], "created_at": r[3]} for r in rows]

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

    # -- transaction history ------------------------------------------------

    def get_address_transactions(
        self, address: str, chain: list[dict[str, Any]], limit: int = 50, offset: int = 0
    ) -> list[dict[str, Any]]:
        txs: list[dict[str, Any]] = []
        for block in reversed(chain):
            for tx in block.get("transactions", []):
                if tx.get("sender") == address or tx.get("recipient") == address:
                    direction = "in" if tx.get("recipient") == address else "out"
                    if tx.get("sender") == "MINING_REWARD":
                        direction = "reward"
                    txs.append({
                        **tx,
                        "block_index": block["index"],
                        "timestamp": block["timestamp"],
                        "direction": direction,
                    })
        return txs[offset : offset + limit]

    def get_address_tx_count(self, address: str, chain: list[dict[str, Any]]) -> int:
        count = 0
        for block in chain:
            for tx in block.get("transactions", []):
                if tx.get("sender") == address or tx.get("recipient") == address:
                    count += 1
        return count

    # -- staking helpers ----------------------------------------------------

    def add_stake(self, address: str, amount: float) -> float:
        row = self._conn.execute(
            "SELECT amount FROM stakes WHERE address = ?", (address,)
        ).fetchone()
        if row:
            self._conn.execute(
                "UPDATE stakes SET amount = amount + ? WHERE address = ?",
                (amount, address),
            )
        else:
            self._conn.execute(
                "INSERT INTO stakes (address, amount, staked_at) VALUES (?, ?, ?)",
                (address, amount, time.time()),
            )
        self._conn.commit()
        return self.get_stake(address)

    def get_stake(self, address: str) -> float:
        row = self._conn.execute(
            "SELECT amount FROM stakes WHERE address = ?", (address,)
        ).fetchone()
        return row[0] if row else 0.0

    def remove_stake(self, address: str, amount: float) -> float:
        current = self.get_stake(address)
        actual = min(amount, current)
        self._conn.execute(
            "UPDATE stakes SET amount = amount - ? WHERE address = ?",
            (actual, address),
        )
        self._conn.commit()
        return actual

    def get_all_stakes(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT address, amount FROM stakes WHERE amount > 0 ORDER BY amount DESC"
        ).fetchall()
        return [{"address": r[0], "amount": r[1]} for r in rows]

    # -- webhook helpers ----------------------------------------------------

    def add_webhook(self, url: str, event: str, filter_str: str = "") -> int:
        cur = self._conn.execute(
            "INSERT INTO webhooks (url, event, filter, created_at) VALUES (?, ?, ?, ?)",
            (url, event, filter_str, time.time()),
        )
        self._conn.commit()
        return cur.lastrowid or 0

    def get_webhooks(self, event: str = "") -> list[dict[str, Any]]:
        if event:
            rows = self._conn.execute(
                "SELECT id, url, event, filter, active FROM webhooks WHERE event = ? AND active = 1",
                (event,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT id, url, event, filter, active FROM webhooks WHERE active = 1"
            ).fetchall()
        return [{"id": r[0], "url": r[1], "event": r[2], "filter": r[3], "active": bool(r[4])} for r in rows]

    def delete_webhook(self, webhook_id: int) -> bool:
        cur = self._conn.execute("DELETE FROM webhooks WHERE id = ?", (webhook_id,))
        self._conn.commit()
        return (cur.rowcount or 0) > 0
