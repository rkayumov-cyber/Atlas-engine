"""Atlas Engine — Entry point.

Usage:
  python app.py                    # Start with defaults (PoW, port 5000)
  python app.py --port 5001        # Custom port
  python app.py --consensus pos    # Use Proof-of-Stake
  python app.py --consensus pbft   # Use PBFT
"""

from __future__ import annotations

import logging
import os
import sys

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("atlas")


def main() -> None:
    port = int(os.environ.get("ATLAS_PORT", 5000))
    db_path = os.environ.get("ATLAS_DB", "state.db")
    consensus = os.environ.get("ATLAS_CONSENSUS", "")

    # Parse simple CLI args
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--port" and i + 1 < len(args):
            port = int(args[i + 1]); i += 2
        elif args[i] == "--consensus" and i + 1 < len(args):
            consensus = args[i + 1]; i += 2
        elif args[i] == "--db" and i + 1 < len(args):
            db_path = args[i + 1]; i += 2
        else:
            i += 1

    from atlas.api import create_app
    app, ctx = create_app(db_path=db_path, consensus_name=consensus, port=port)

    node_id = ctx["node_id"]
    bc = ctx["blockchain"]
    log.info(
        "Atlas Engine v2.0 starting on port %d (node %s, consensus=%s)",
        port, node_id, bc.consensus.name,
    )
    app.run(host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
