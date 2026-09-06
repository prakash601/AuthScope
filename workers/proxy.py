"""Proxy & identity pool management for scanning hard targets.

Pool is configured via ``AUTHSCOPE_PROXY_POOL`` env JSON:
``{"us": "http://user:pass@gw.proxy.com:8000", "de": "...", ...}``.
Empty pool = direct connections (dev default).

Provider plug-in: any HTTP(S)/SOCKS5 proxy works — paste the provider's
super-proxy URL per exit country (e.g. Bright Data
``http://brd-customer-<id>:<pass>@zproxy.lum-superproxy.io:22225`` with a
``-country-XX`` session suffix for geo-pinning). Credentials live in the
pool JSON, which must come from the secret store (see
``deploy/k8s/SECRETS.md``), never from the repo. Proxy URLs are never
logged — only the redacted host and country.
"""

from __future__ import annotations

import json
import logging
import os
import random
from urllib.parse import urlsplit

logger = logging.getLogger("authscope.proxy")

_ALLOWED_SCHEMES = {"http", "https", "socks5"}


def redact_proxy_url(url: str | None) -> str | None:
    """Redact credentials for safe logging (host + scheme only)."""
    if not url:
        return None
    try:
        parts = urlsplit(url)
        return f"{parts.scheme}://{parts.hostname or '?'}:{parts.port or '?'}"
    except ValueError:
        return "unparseable-proxy-url"


class ProxyManager:
    def __init__(self, pool: dict[str, str] | None = None) -> None:
        if pool is None:
            raw = os.environ.get("AUTHSCOPE_PROXY_POOL", "{}")
            try:
                pool = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"AUTHSCOPE_PROXY_POOL is not valid JSON: {exc}") from exc
            if not isinstance(pool, dict):
                raise ValueError("AUTHSCOPE_PROXY_POOL must be a JSON object")
        validated: dict[str, str] = {}
        for country, url in pool.items():
            scheme = urlsplit(url).scheme.lower() if isinstance(url, str) else ""
            if not isinstance(url, str) or scheme not in _ALLOWED_SCHEMES:
                raise ValueError(
                    f"proxy for country {country!r}: unsupported scheme "
                    f"(want one of {sorted(_ALLOWED_SCHEMES)})"
                )
            validated[country.lower()] = url
        self._pool = validated
        self._usage: dict[str, int] = {c: 0 for c in validated}

    @property
    def countries(self) -> list[str]:
        return sorted(self._pool)

    @property
    def usage_counts(self) -> dict[str, int]:
        return dict(self._usage)

    def get_proxy(self, country: str | None) -> str | None:
        if not self._pool:
            return None
        if not country:
            chosen = random.choice(sorted(self._pool))
            return self._acquire(chosen)
        key = country.lower()
        if key not in self._pool:
            logger.warning(
                "requested proxy country %r not in pool %s; using random country",
                country,
                self.countries,
            )
            chosen = random.choice(sorted(self._pool))
            return self._acquire(chosen)
        return self._acquire(key)

    def get_different_country_proxy(
        self, exclude_country: str | None
    ) -> tuple[str | None, str | None]:
        """Proxy from a country different from the excluded one (retry policy)."""
        candidates = {c: u for c, u in self._pool.items() if c != (exclude_country or "").lower()}
        if not candidates:
            if self._pool:
                logger.warning("single-country pool; retry reuses country %r", exclude_country)
            return None, None
        country = random.choice(sorted(candidates))
        return self._acquire(country), country

    def _acquire(self, country: str) -> str:
        self._usage[country] += 1
        logger.info(
            "proxy acquired country=%s via=%s (use #%d)",
            country,
            redact_proxy_url(self._pool[country]),
            self._usage[country],
        )
        return self._pool[country]


def load_proxy_manager() -> ProxyManager:
    return ProxyManager()
