"""ISS-010 tests: YAML validation, seed content, DB sync idempotency, hot reload."""

from __future__ import annotations

from pathlib import Path

import pytest

from engine.signatures import (
    SignatureCache,
    SignatureDef,
    load_yaml_dir,
    sync_to_db,
)
from tests.conftest import SIGNATURES_DIR


def test_seed_signatures_validate():
    defs = load_yaml_dir(SIGNATURES_DIR)
    assert len(defs) >= 60
    by_cat: dict[str, int] = {}
    for d in defs:
        by_cat[d.category] = by_cat.get(d.category, 0) + 1
    assert by_cat["auth"] >= 40
    for cat in ("antibot", "captcha", "fingerprinting"):
        assert by_cat[cat] >= 5, cat


def test_duplicate_names_rejected(tmp_path: Path):
    (tmp_path / "a.yaml").write_text(
        "- name: dup\n  type: captcha\n  category: captcha\n  confidence: 0.9\n"
        "  signals:\n    dom: x\n"
    )
    (tmp_path / "b.yaml").write_text(
        "- name: dup\n  type: waf\n  category: antibot\n  confidence: 0.9\n"
        "  signals:\n    dom: y\n"
    )
    with pytest.raises(ValueError, match="duplicate"):
        load_yaml_dir(tmp_path)


def test_invalid_category_rejected():
    with pytest.raises(ValueError):
        SignatureDef.model_validate(
            {"name": "x", "type": "waf", "category": "nope", "confidence": 0.9,
             "signals": {"dom": "y"}}
        )


def test_empty_signals_rejected():
    with pytest.raises(ValueError):
        SignatureDef.model_validate(
            {"name": "x", "type": "waf", "category": "antibot", "confidence": 0.9,
             "signals": {"dom": ""}}
        )


@pytest.fixture
async def db_session_factory():
    try:
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

        from config import get_settings

        settings = get_settings()
        engine = create_async_engine(settings.database.async_url)
        # probe
        async with engine.connect():
            pass
    except Exception:  # noqa: BLE001 — any connection failure skips
        pytest.skip("Postgres not reachable — run `make compose-up`")
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


async def test_db_sync_idempotent_and_versioned(db_session_factory):
    import sqlalchemy as sa

    from db.models import Signature as SignatureRow

    sig_v1 = {
        "name": "test_sig_rt",
        "type": "captcha",
        "category": "captcha",
        "confidence": 0.9,
        "signals": {"dom": "marker-one"},
        "version": 1,
    }
    sig_v2 = {**sig_v1, "signals": {"dom": "marker-two"}}

    async with db_session_factory() as session:
        async with session.begin():
            await sync_to_db([SignatureDef.model_validate(sig_v1)], session)
            rows = (
                await session.execute(
                    sa.select(SignatureRow).where(SignatureRow.name == "test_sig_rt")
                )
            ).scalars().all()
            assert len(rows) == 1 and rows[0].version == 1

            # second identical load: no duplicate, no version bump
            await sync_to_db([SignatureDef.model_validate(sig_v1)], session)
            rows = (
                await session.execute(
                    sa.select(SignatureRow).where(SignatureRow.name == "test_sig_rt")
                )
            ).scalars().all()
            assert len(rows) == 1 and rows[0].version == 1

            # changed definition: version bump, still one row
            await sync_to_db([SignatureDef.model_validate(sig_v2)], session)
            rows = (
                await session.execute(
                    sa.select(SignatureRow).where(SignatureRow.name == "test_sig_rt")
                )
            ).scalars().all()
            assert len(rows) == 1 and rows[0].version == 2

        # cleanup
        await session.execute(sa.delete(SignatureRow).where(SignatureRow.name == "test_sig_rt"))
        await session.commit()


async def test_hot_reload_new_signature_matched_without_restart(db_session_factory):
    """YAML -> DB -> cache reload -> detector sees a brand-new signature."""
    import sqlalchemy as sa

    from db.models import Signature as SignatureRow
    from engine.artifacts import DomSummary, PageArtifact
    from engine.detectors.captcha import CaptchaDetector

    dummy = SignatureDef.model_validate(
        {
            "name": "hot_reload_dummy",
            "type": "captcha",
            "category": "captcha",
            "confidence": 0.9,
            "signals": {"dom": "hot-reload-widget-xyz"},
        }
    )
    async with db_session_factory() as session, session.begin():
        await sync_to_db([dummy], session)

    cache = SignatureCache()
    cache.load_from_yaml_dir(SIGNATURES_DIR)
    assert not any(s.name == "hot_reload_dummy" for s in cache.get("captcha"))

    await cache.areload_from_db(db_session_factory)
    assert any(s.name == "hot_reload_dummy" for s in cache.get("captcha"))
    assert cache.revision == 2

    all_captchas = cache.get("captcha")
    detector = CaptchaDetector(all_captchas)
    artifact = PageArtifact(
        url="https://x.test/login",
        dom=DomSummary(raw_html='<div class="hot-reload-widget-xyz"></div>'),
    )
    findings = await detector.detect(artifact)
    assert any(f.name == "hot_reload_dummy" for f in findings)

    async with db_session_factory() as session:
        await session.execute(
            sa.delete(SignatureRow).where(SignatureRow.name == "hot_reload_dummy")
        )
        await session.commit()
