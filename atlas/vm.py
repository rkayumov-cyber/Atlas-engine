"""Atlas VM — Simple stack-based virtual machine for smart contracts.

Instruction set (all operate on a stack + key-value storage):
  PUSH <val>    — push literal onto stack
  POP           — discard top
  DUP           — duplicate top
  SWAP          — swap top two
  ADD/SUB/MUL/DIV — arithmetic (pop 2, push result)
  MOD           — modulo
  EQ/LT/GT     — comparison (push 1 or 0)
  NOT           — logical not
  AND/OR        — logical
  JMP <addr>    — unconditional jump
  JMPIF <addr>  — jump if top is truthy
  STORE <key>   — pop value, store in contract storage
  LOAD <key>    — load from storage, push
  SENDER        — push transaction sender address
  AMOUNT        — push transaction amount
  BALANCE <addr>— push balance of address
  TRANSFER <addr> <amt> — transfer from contract to addr
  LOG <msg>     — emit an event log
  HALT          — stop execution
  CALL <addr>   — call another contract
  REVERT <msg>  — revert all state changes with message
"""

from __future__ import annotations

import logging
from typing import Any, Optional

log = logging.getLogger("atlas.vm")

MAX_GAS = 1_000_000
GAS_COSTS: dict[str, int] = {
    "PUSH": 1, "POP": 1, "DUP": 1, "SWAP": 1,
    "ADD": 2, "SUB": 2, "MUL": 2, "DIV": 2, "MOD": 2,
    "EQ": 2, "LT": 2, "GT": 2, "NOT": 1, "AND": 2, "OR": 2,
    "JMP": 3, "JMPIF": 3,
    "STORE": 20, "LOAD": 10,
    "SENDER": 1, "AMOUNT": 1, "BALANCE": 10,
    "TRANSFER": 50, "LOG": 5, "HALT": 0,
    "CALL": 100, "REVERT": 0,
}


class VMError(Exception):
    """Runtime error in the Atlas VM."""


class ContractResult:
    """Result of contract execution."""

    def __init__(self) -> None:
        self.success: bool = False
        self.gas_used: int = 0
        self.logs: list[str] = []
        self.storage_writes: dict[str, str] = {}
        self.transfers: list[dict[str, Any]] = []
        self.return_value: Any = None
        self.error: str = ""
        self.reverted: bool = False


class AtlasVM:
    """Stack-based virtual machine for Atlas smart contracts."""

    def __init__(self, state_loader: Any = None) -> None:
        self._state_loader = state_loader  # StateManager reference

    def execute(
        self,
        code: list[str],
        sender: str = "",
        amount: float = 0.0,
        gas_limit: int = MAX_GAS,
        storage: dict[str, str] | None = None,
        contract_address: str = "",
    ) -> ContractResult:
        """Execute compiled bytecode instructions."""
        result = ContractResult()
        stack: list[Any] = []
        local_storage: dict[str, str] = dict(storage or {})
        pc = 0  # program counter
        gas = 0

        def consume_gas(op: str) -> None:
            nonlocal gas
            cost = GAS_COSTS.get(op, 5)
            gas += cost
            if gas > gas_limit:
                raise VMError(f"Out of gas at pc={pc} (used={gas}, limit={gas_limit})")

        try:
            while pc < len(code):
                line = code[pc].strip()
                if not line or line.startswith("#") or line.startswith("//"):
                    pc += 1
                    continue

                parts = line.split(None, 1)
                op = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ""

                consume_gas(op)

                if op == "PUSH":
                    # Try numeric, else treat as string
                    try:
                        stack.append(float(arg) if "." in arg else int(arg))
                    except ValueError:
                        stack.append(arg.strip('"').strip("'"))

                elif op == "POP":
                    if stack:
                        stack.pop()

                elif op == "DUP":
                    if stack:
                        stack.append(stack[-1])

                elif op == "SWAP":
                    if len(stack) >= 2:
                        stack[-1], stack[-2] = stack[-2], stack[-1]

                elif op in ("ADD", "SUB", "MUL", "DIV", "MOD"):
                    if len(stack) < 2:
                        raise VMError(f"{op} requires 2 operands")
                    b, a = float(stack.pop()), float(stack.pop())
                    if op == "ADD": stack.append(a + b)
                    elif op == "SUB": stack.append(a - b)
                    elif op == "MUL": stack.append(a * b)
                    elif op == "DIV":
                        if b == 0: raise VMError("Division by zero")
                        stack.append(a / b)
                    elif op == "MOD":
                        if b == 0: raise VMError("Modulo by zero")
                        stack.append(a % b)

                elif op in ("EQ", "LT", "GT"):
                    if len(stack) < 2:
                        raise VMError(f"{op} requires 2 operands")
                    b, a = stack.pop(), stack.pop()
                    if op == "EQ": stack.append(1 if a == b else 0)
                    elif op == "LT": stack.append(1 if float(a) < float(b) else 0)
                    elif op == "GT": stack.append(1 if float(a) > float(b) else 0)

                elif op == "NOT":
                    if stack:
                        stack.append(0 if stack.pop() else 1)

                elif op in ("AND", "OR"):
                    if len(stack) < 2:
                        raise VMError(f"{op} requires 2 operands")
                    b, a = stack.pop(), stack.pop()
                    if op == "AND": stack.append(1 if (a and b) else 0)
                    else: stack.append(1 if (a or b) else 0)

                elif op == "JMP":
                    pc = int(arg)
                    continue

                elif op == "JMPIF":
                    if stack and stack.pop():
                        pc = int(arg)
                        continue

                elif op == "STORE":
                    if not stack:
                        raise VMError("STORE: empty stack")
                    val = str(stack.pop())
                    local_storage[arg] = val
                    result.storage_writes[arg] = val

                elif op == "LOAD":
                    val = local_storage.get(arg, "0")
                    try:
                        stack.append(float(val) if "." in val else int(val))
                    except ValueError:
                        stack.append(val)

                elif op == "SENDER":
                    stack.append(sender)

                elif op == "AMOUNT":
                    stack.append(amount)

                elif op == "BALANCE":
                    addr = arg or (stack.pop() if stack else "")
                    bal = 0.0
                    if self._state_loader:
                        bal = self._state_loader.get_balance(str(addr))
                    stack.append(bal)

                elif op == "TRANSFER":
                    if len(stack) < 2:
                        raise VMError("TRANSFER requires amount and address on stack")
                    transfer_amount = float(stack.pop())
                    transfer_to = str(stack.pop())
                    result.transfers.append({
                        "from": contract_address,
                        "to": transfer_to,
                        "amount": transfer_amount,
                    })

                elif op == "LOG":
                    msg = arg if arg else (str(stack.pop()) if stack else "")
                    result.logs.append(msg)

                elif op == "HALT":
                    break

                elif op == "REVERT":
                    result.reverted = True
                    result.error = arg or "Transaction reverted"
                    result.storage_writes.clear()
                    result.transfers.clear()
                    break

                elif op == "CALL":
                    # External contract call (simplified)
                    result.logs.append(f"CALL to {arg}")

                else:
                    raise VMError(f"Unknown opcode: {op}")

                pc += 1

            result.success = not result.reverted
            result.gas_used = gas
            result.return_value = stack[-1] if stack else None

        except VMError as e:
            result.success = False
            result.error = str(e)
            result.gas_used = gas
            result.storage_writes.clear()
            result.transfers.clear()

        return result

    def compile_source(self, source: str) -> list[str]:
        """Parse source text into instruction list (one instruction per line)."""
        lines: list[str] = []
        for line in source.strip().split("\n"):
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and not stripped.startswith("//"):
                lines.append(stripped)
        return lines


# ---------------------------------------------------------------------------
# Built-in contract templates
# ---------------------------------------------------------------------------

TOKEN_CONTRACT = """
# Simple token contract
# STORE total_supply, STORE balances:<addr>
SENDER
LOAD admin
EQ
JMPIF 8
REVERT Only admin can mint
AMOUNT
LOAD total_supply
ADD
STORE total_supply
SENDER
PUSH balance_
SENDER
ADD
LOAD balance_sender
AMOUNT
ADD
STORE balance_sender
LOG Token minted
HALT
""".strip()

ESCROW_CONTRACT = """
# Simple escrow: sender deposits, recipient can withdraw after unlock
SENDER
LOAD depositor
EQ
JMPIF 7
PUSH 0
JMP 12
AMOUNT
LOAD escrow_balance
ADD
STORE escrow_balance
LOG Deposit received
HALT
SENDER
LOAD beneficiary
EQ
JMPIF 17
REVERT Not authorized
LOAD escrow_balance
PUSH 0
GT
JMPIF 22
REVERT No funds in escrow
LOAD escrow_balance
SENDER
SWAP
TRANSFER
PUSH 0
STORE escrow_balance
LOG Escrow released
HALT
""".strip()

CONTRACT_TEMPLATES: dict[str, str] = {
    "token": TOKEN_CONTRACT,
    "escrow": ESCROW_CONTRACT,
}
