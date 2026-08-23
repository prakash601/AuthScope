"""API dependencies: DB sessions, Redis, API-key auth with rate limiting."""

from __future__ import annotations

import hashlib
import logging
import time
import uuid
from dataclasses import dataclass

import redis.asyncio as aioredis
import sqlalchemy as sa
from fastapi import Depends, HTTPException, Request

from config import Settings
from db.models import ApiKey

logger = logging.getLogger("authscope.api")


@dataclass
class AuthContext:
    user_id: str
    api_key_id: str
    key_hash: str
    rate_limit_per_minute: int


def build_engine(settings: Settings):
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    engine = create_async_engine(
        settings.database.async_url,
        pool_size=settings.database.pool_size,
        max_overflow=settings.database.max_overflow,
        pool_pre_ping=True,
    )
    return engine, async_sessionmaker(engine, expire_on_commit=False)


def get_settings_from_request(request: Request) -> Settings:
    return request.app.state.settings


async def get_db(request: Request):
    session_factory = request.app.state.session_factory
    async with session_factory() as session:
        yield session


def get_redis(request: Request) -> aioredis.Redis:
    return request.app.state.redis


def _rate_limit_key(key_hash: str, window_start: int) -> str:
    return f"ratelimit:{key_hash}:{window_start}"


async def check_rate_limit(
    redis: aioredis.Redis, key_hash: str, limit_per_minute: int
) -> tuple[bool, int]:
    """Fixed 60s window via INCR+EXPIRE. Returns (allowed, retry_after_seconds)."""
    window = int(time.time()) // 60
    key = _rate_limit_key(key_hash, window)
    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, 60)
    if count > limit_per_minute:
        retry_after = 60 - (int(time.time()) % 60)
        return False, max(1, retry_after)
    return True, 0


async def require_api_key(request: Request) -> AuthContext:
    raw_key = request.headers.get("X-API-Key")
    if not raw_key:
        raise HTTPException(status_code=401, detail={"code": "missing_api_key",
                                                     "message": "X-API-Key header required"})
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    session_factory = request.app.state.session_factory
    async with session_factory() as session:
        row = (
            await session.execute(sa.select(ApiKey).where(ApiKey.key_hash == key_hash))
        ).scalar_one_or_none()
        if row is None or not row.active:
            raise HTTPException(status_code=401, detail={"code": "invalid_api_key",
                                                         "message": "unknown or inactive API key"})
        redis = get_redis(request)
        allowed, retry_after = await check_rate_limit(redis, key_hash, row.rate_limit_per_minute)
        if not allowed:
            raise HTTPException(
                status_code=429,
                detail={"code": "rate_limited", "message": "rate limit exceeded"},
                headers={"Retry-After": str(retry_after)},
            )
        ctx = AuthContext(
            user_id=str(row.user_id),
            api_key_id=str(row.id),
            key_hash=key_hash,
            rate_limit_per_minute=row.rate_limit_per_minute,
        )

    # best-effort last_used update outside the hot path
    try:
        session_factory2 = request.app.state.session_factory
        async with session_factory2() as s2:
            await s2.execute(
                sa.update(ApiKey).where(ApiKey.id == uuid.UUID(ctx.api_key_id))
                .values(last_used_at=sa.func.now())
            )
            await s2.commit()
    except Exception:  # noqa: BLE001 — telemetry must never fail requests
        logger.debug("last_used_at update failed", exc_info=True)
    return ctx


AuthDep = Depends(require_api_key)
