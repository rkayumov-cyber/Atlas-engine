# Atlas Engine: Project Memory

## Project Overview
A modular, decentralized blockchain engine in Python. Focus on pluggable consensus and clear separation between Ledger, State, and API.

## Tech Stack
- **Backend:** Python 3.11+ (Flask, Requests, ECDSA)
- **Database:** SQLite (State Manager)
- **Container:** Docker & Docker Compose
- **UI:** Nginx, Tailwind CSS, Vanilla JS

## Build & Run Commands
- **Install Dependencies:** `pip install flask requests ecdsa httpx asyncio`
- **Run Node:** `python app.py`
- **Start Network:** `docker-compose up --build`
- **Run Stress Test:** `python stress_test.py`

## Coding Standards
- Use type hints for all function signatures.
- Log significant events (Mining, New Peers, Consensus) to the console.
- Error handling: Use try/except blocks for all P2P network requests.
- Keep the `Blockchain` class focused on logic; move state persistence to `StateManager`.