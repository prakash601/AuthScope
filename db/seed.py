"""Seed dev data: default user + hashed API key (DEV_API_KEY env or 'dev-key').

Usage: python -m db.seed
"""

from __future__ import annotations

import asyncio
import hashlib
import os

import sqlalchemy as sa

from config import get_settings
from db.models import ApiKey, User


async def seed() -> None:
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    settings = get_settings()
    engine = create_async_engine(settings.database.async_url)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    raw_key = os.environ.get("DEV_API_KEY", "dev-key")
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    async with session_factory() as session:
        existing = await session.execute(
            sa.select(ApiKey).where(ApiKey.key_hash == key_hash)
        )
        if existing.scalar_one_or_none():
            print("Dev API key already seeded.")
            return
        user = User(email="dev@authscope.local", name="Dev User")
        session.add(user)
        await session.flush()
        session.add(
            ApiKey(
                user_id=user.id,
                key_hash=key_hash,
                label="dev",
                rate_limit_per_minute=settings.api.rate_limit_per_minute,
            )
        )
        await session.commit()
    await engine.dispose()
    print(f"Seeded dev user with API key: {raw_key}")


if __name__ == "__main__":
    asyncio.run(seed())
