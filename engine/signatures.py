"""Signature definitions: YAML loading/validation + Postgres sync + worker cache."""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger("authscope.signatures")

VALID_CATEGORIES = {"auth", "antibot", "captcha", "fingerprinting"}


class SignatureDef(BaseModel):
    name: str
    type: str
    category: str
    confidence: float = Field(ge=0.0, le=1.0)
    variant: str | None = None
    signals: dict[str, str | list[str]]
    version: int = 1

    @field_validator("name")
    @classmethod
    def _name_nonempty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("signature name must be non-empty")
        return v.strip()

    @field_validator("category")
    @classmethod
    def _valid_category(cls, v: str) -> str:
        if v not in VALID_CATEGORIES:
            raise ValueError(f"category must be one of {sorted(VALID_CATEGORIES)}, got {v!r}")
        return v

    @field_validator("signals")
    @classmethod
    def _signals_nonempty(cls, v: dict) -> dict:
        cleaned = {}
        for key, val in v.items():
            values = [val] if isinstance(val, str) else list(val)
            values = [s for s in (str(x).strip() for x in values) if s]
            if not values:
                continue
            if isinstance(val, str):
                cleaned[key] = values[0]
            else:
                cleaned[key] = values
        if not cleaned:
            raise ValueError("signature must define at least one non-empty signal")
        return cleaned

    def definition_hash(self) -> str:
        payload = f"{self.name}|{self.type}|{self.category}|{self.signals}"
        return hashlib.sha256(payload.encode()).hexdigest()


def load_yaml_dir(path: str | Path) -> list[SignatureDef]:
    """Load and validate all signature YAML files in a directory."""
    dirpath = Path(path)
    defs: list[SignatureDef] = []
    seen: set[str] = set()
    for file in sorted(dirpath.glob("*.yaml")):
        raw = yaml.safe_load(file.read_text()) or []
        if not isinstance(raw, list):
            raise ValueError(f"{file}: expected a YAML list of signatures")
        for item in raw:
            sig = SignatureDef.model_validate(item)
            if sig.name in seen:
                raise ValueError(f"duplicate signature name: {sig.name}")
            seen.add(sig.name)
            defs.append(sig)
    return defs


async def sync_to_db(defs: list[SignatureDef], session) -> dict[str, int]:
    """Upsert signatures into the DB (AsyncSession).

    - New signature → insert with version 1.
    - Existing signature with unchanged definition hash → untouched (idempotent).
    - Changed definition → update yaml_definition and bump version.
    Returns map of name -> current version after sync.
    """
    import sqlalchemy as sa

    from db.models import Signature as SignatureRow

    out: dict[str, int] = {}
    for sig in defs:
        row = (
            await session.execute(
                sa.select(SignatureRow).where(
                    SignatureRow.name == sig.name, SignatureRow.category == sig.category
                )
            )
        ).scalar_one_or_none()
        if row is None:
            session.add(
                SignatureRow(
                    category=sig.category,
                    name=sig.name,
                    yaml_definition=sig.model_dump(),
                    version=1,
                    active=True,
                )
            )
            out[sig.name] = 1
            continue
        stored = row.yaml_definition or {}
        stored_hash = _def_hash_from_stored(stored)
        if stored_hash != sig.definition_hash():
            payload = sig.model_dump()
            payload["version"] = row.version + 1
            row.yaml_definition = payload
            row.version = row.version + 1
            row.active = True
            out[sig.name] = row.version
        else:
            out[sig.name] = row.version
    await session.flush()
    return out


def _def_hash_from_stored(stored: dict) -> str:
    try:
        probe = SignatureDef.model_validate(stored)
        return probe.definition_hash()
    except Exception:  # noqa: BLE001 — malformed/legacy rows always re-sync
        return "<invalid>"


class SignatureCache:
    """In-memory signature store for workers; atomically reloadable."""

    def __init__(self) -> None:
        self._by_category: dict[str, list[SignatureDef]] = {}
        self._revision: int = 0

    @property
    def revision(self) -> int:
        return self._revision

    def get(self, category: str) -> list[SignatureDef]:
        return self._by_category.get(category, [])

    def load_defs(self, defs: list[SignatureDef]) -> None:
        by_category: dict[str, list[SignatureDef]] = {}
        for d in defs:
            by_category.setdefault(d.category, []).append(d)
        self._by_category = by_category  # atomic swap — no mid-scan mutation
        self._revision += 1
        logger.info(
            "signature cache rev %d loaded: %s",
            self._revision,
            {k: len(v) for k, v in sorted(by_category.items())},
        )

    def load_from_yaml_dir(self, path: str | Path) -> None:
        self.load_defs(load_yaml_dir(path))

    async def areload_from_db(self, session_factory) -> None:
        """Pull active signatures from Postgres into memory (async worker path)."""
        import sqlalchemy as sa

        from db.models import Signature as SignatureRow

        async with session_factory() as session:
            rows = (
                await session.execute(
                    sa.select(SignatureRow).where(SignatureRow.active.is_(True))
                )
            ).scalars()
            defs = [SignatureDef.model_validate(r.yaml_definition) for r in rows]
        self.load_defs(defs)
