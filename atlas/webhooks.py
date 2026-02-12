"""Webhook dispatcher — fire HTTP callbacks on blockchain events."""

from __future__ import annotations

import json
import logging
import threading
from typing import Any

log = logging.getLogger("atlas.webhooks")


class WebhookDispatcher:
    """Fire HTTP POST callbacks for subscribed events."""

    def __init__(self, state: Any = None) -> None:
        self._state = state  # StateManager for persisted hooks

    def dispatch(self, event_type: str, data: Any) -> None:
        """Fire all webhooks matching *event_type* in background threads."""
        if not self._state:
            return
        hooks = self._state.get_webhooks(event_type)
        for hook in hooks:
            t = threading.Thread(target=self._fire, args=(hook, event_type, data), daemon=True)
            t.start()

    def _fire(self, hook: dict[str, Any], event_type: str, data: Any) -> None:
        import requests as req
        try:
            payload = {
                "event": event_type,
                "data": data,
                "webhook_id": hook["id"],
            }
            resp = req.post(
                hook["url"],
                json=payload,
                timeout=10,
                headers={"Content-Type": "application/json", "X-Atlas-Event": event_type},
            )
            log.debug("Webhook %d fired: %s -> %d", hook["id"], hook["url"], resp.status_code)
        except Exception as e:
            log.warning("Webhook %d failed: %s", hook["id"], e)

    def __call__(self, event_type: str, data: Any) -> None:
        """Allow use as a blockchain event subscriber callback."""
        self.dispatch(event_type, data)
