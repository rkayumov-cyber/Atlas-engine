# Specification: Infrastructure & UI

## 1. Dockerization
- **Dockerfile:** Install `flask`, `requests`, `ecdsa`. Run `app.py`.
- **Docker Compose:** - 3 Node services (`node-1`, `node-2`, `node-3`) on different ports.
  - 1 Explorer service using Nginx to host `dashboard.html`.

## 2. Block Explorer (UI)
- Single-page dashboard.
- Display "Network Health" (Online/Offline status of nodes).
- Live-updating table of the last 5 blocks using the `/chain` endpoint.