# Specification: Stress Testing

## 1. load_test.py
- Use `asyncio` and `httpx`.
- Simulate 100 concurrent users.
- Randomly distribute requests across the 3 Docker nodes.
- Metrics to track: Total TXs, Success Rate, Average Latency (ms), and Throughput (TPS).