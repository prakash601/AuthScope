"""Proxy & identity pool management for scanning hard targets.

Pool is configured via ``AUTHSCOPE_PROXY_POOL`` env JSON:
``{"us": "http://user:pass@gw.proxy.com:8000", "de": "...", ...}``.
Empty pool = direct connections (dev default).
"""

from __future__ import annotations

import json
import logging
import os
import random

logger = logging.getLogger("authscope.proxy")


class ProxyManager:
    def __init__(self, pool: dict[str, str] | None = None) -> None:
        if pool is None:
            pool = json.loads(os.environ.get("AUTHSCOPE_PROXY_POOL", "{}"))
        self._pool = {k.lower(): v for k, v in pool.items()}

    @property
    def countries(self) -> list[str]:
        return sorted(self._pool)

    def get_proxy(self, country: str | None) -> str | None:
        if not country:
            return random.choice(list(self._pool.values())) if self._pool else None
        return self._pool.get(country.lower())

    def get_different_country_proxy(
        self, exclude_country: str | None
    ) -> tuple[str | None, str | None]:
        """Proxy from a country different from the excluded one (retry policy)."""
        candidates = {
            c: u for c, u in self._pool.items() if c != (exclude_country or "").lower()
        }
        if not candidates:
            return None, None
        country = random.choice(sorted(candidates))
        return candidates[country], country


def load_proxy_manager() -> ProxyManager:
    return ProxyManager()
