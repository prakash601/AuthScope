"""Helpers for worker signature access."""

from __future__ import annotations

from engine.signatures import SignatureCache

CATEGORIES = ("auth", "antibot", "captcha", "fingerprinting")


def all_signatures(cache: SignatureCache):
    out = []
    for category in CATEGORIES:
        out.extend(cache.get(category))
    return out


async def load_fresh_cache(session_factory) -> SignatureCache:
    """Fresh cache per scan task — signatures stay current without restarts."""
    cache = SignatureCache()
    await cache.areload_from_db(session_factory)
    return cache
