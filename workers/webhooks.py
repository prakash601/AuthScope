"""Webhook dispatch: signed POST of reports with backoff retries and Redis DLQ."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import time

import httpx

logger = logging.getLogger("authscope.webhooks")

MAX_ATTEMPTS = 3
BACKOFF_BASE_SECONDS = 1.0
DLQ_KEY = "webhooks:dlq"
SIGNATURE_HEADER = "X-AuthScope-Signature"


def sign_payload(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


async def deliver(
    url: str,
    secret: str,
    payload: dict,
    client: httpx.AsyncClient | None = None,
) -> tuple[bool, str]:
    """Deliver one webhook with retries + exponential backoff.

    Returns (delivered, last_error).
    """
    body = json.dumps(payload, default=str).encode()
    signature = sign_payload(secret, body)
    headers = {
        "Content-Type": "application/json",
        SIGNATURE_HEADER: f"sha256={signature}",
    }
    own_client = client is None
    c = client or httpx.AsyncClient(timeout=10)
    last_error = ""
    try:
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                resp = await c.post(url, content=body, headers=headers)
                if 200 <= resp.status_code < 300:
                    return True, ""
                last_error = f"http_{resp.status_code}"
            except httpx.HTTPError as exc:
                last_error = f"{type(exc).__name__}: {exc}"[:200]
            if attempt < MAX_ATTEMPTS:
                await asyncio.sleep(BACKOFF_BASE_SECONDS * (2 ** (attempt - 1)))
        return False, last_error
    finally:
        if own_client:
            await c.aclose()


async def dead_letter(redis, entry: dict) -> None:
    """Push an undeliverable webhook onto the Redis DLQ (observable)."""
    await redis.rpush(DLQ_KEY, json.dumps({**entry, "dead_lettered_at": time.time()}))


async def dispatch_report(
    redis,
    webhooks: list[tuple[str, str]],
    report: dict,
    scan_id: str,
) -> dict[str, str]:
    """Send the report to every registered webhook. Returns url -> status."""
    statuses: dict[str, str] = {}
    for url, secret in webhooks:
        delivered, error = await deliver(url, secret, {"scan_id": scan_id, "report": report})
        statuses[url] = "delivered" if delivered else f"failed:{error}"
        if not delivered:
            await dead_letter(
                redis,
                {"url": url, "scan_id": scan_id, "error": error},
            )
    return statuses
