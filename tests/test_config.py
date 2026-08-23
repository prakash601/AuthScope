"""Tests for config.get_settings — env parsing, defaults, failure modes."""

from __future__ import annotations

import pytest

from config import Settings, get_settings


@pytest.fixture(autouse=True)
def _hermetic(tmp_path, monkeypatch: pytest.MonkeyPatch):
    """Run without a repo .env so tests only see explicit env vars."""
    monkeypatch.chdir(tmp_path)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _base_env() -> dict[str, str]:
    return {
        "POSTGRES_USER": "u",
        "POSTGRES_PASSWORD": "p",
        "POSTGRES_DB": "d",
        "S3_ACCESS_KEY": "ak",
        "S3_SECRET_KEY": "sk",
        "S3_BUCKET": "b",
        "REDIS_URL": "redis://r:6379/0",
    }


def test_full_env_parses(monkeypatch: pytest.MonkeyPatch) -> None:
    for k, v in {**_base_env(), "SCAN_TIMEOUT_SECONDS": "60"}.items():
        monkeypatch.setenv(k, v)
    s = get_settings()
    assert s.database.user == "u"
    assert s.database.async_url == "postgresql+asyncpg://u:p@localhost:5432/d"
    assert s.scan.timeout_seconds == 60
    assert s.redis_url == "redis://r:6379/0"


def test_missing_required_var_raises_actionable(monkeypatch: pytest.MonkeyPatch) -> None:
    for k, v in _base_env().items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("POSTGRES_PASSWORD")
    monkeypatch.delenv("POSTGRES_HOST", raising=False)
    with pytest.raises(ValueError) as exc:
        Settings(_env_file=None)
    msg = str(exc.value)
    assert "password" in msg.lower()


def test_defaults_applied(monkeypatch: pytest.MonkeyPatch) -> None:
    for k, v in _base_env().items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("POSTGRES_HOST", "dbhost")
    s = get_settings()
    assert s.scan.timeout_seconds == 45  # default
    assert s.database.host == "dbhost"


def test_get_settings_is_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    for k, v in _base_env().items():
        monkeypatch.setenv(k, v)
    a = get_settings()
    b = get_settings()
    assert a is b


def test_scan_timeout_bounds(monkeypatch: pytest.MonkeyPatch) -> None:
    for k, v in {**_base_env(), "SCAN_TIMEOUT_SECONDS": "1"}.items():
        monkeypatch.setenv(k, v)
    with pytest.raises(ValueError):
        get_settings()
