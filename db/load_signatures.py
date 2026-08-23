"""CLI: load YAML signatures from signatures/ into Postgres.

Usage: python -m db.load_signatures [dir]
"""

from __future__ import annotations

import asyncio
import sys

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from config import get_settings
from engine.signatures import load_yaml_dir, sync_to_db


async def main(directory: str) -> int:
    defs = load_yaml_dir(directory)
    print(f"Parsed {len(defs)} signatures from {directory}")
    settings = get_settings()
    engine = create_async_engine(settings.database.async_url)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        async with session.begin():
            versions = await sync_to_db(defs, session)
        await engine.dispose()
    changed = {k: v for k, v in versions.items()}
    print(f"Synced {len(changed)} signatures (name -> current version):")
    for name in sorted(changed)[:10]:
        print(f"  {name}: v{changed[name]}")
    if len(changed) > 10:
        print(f"  ... and {len(changed) - 10} more")
    return 0


if __name__ == "__main__":
    directory = sys.argv[1] if len(sys.argv) > 1 else "signatures"
    raise SystemExit(asyncio.run(main(directory)))
