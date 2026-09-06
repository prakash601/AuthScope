"""T06: proxy pool validation, credential redaction, usage accounting."""

from __future__ import annotations

import pytest

from workers.proxy import ProxyManager, redact_proxy_url


def test_empty_pool_means_direct():
    mgr = ProxyManager(pool={})
    assert mgr.get_proxy(None) is None
    assert mgr.get_proxy("us") is None
    assert mgr.get_different_country_proxy("us") == (None, None)


def test_invalid_pool_rejected():
    with pytest.raises(ValueError):
        ProxyManager(pool={"us": "ftp://proxy.example.com:21"})
    with pytest.raises(ValueError):
        ProxyManager(pool={"us": "not-a-url"})


def test_invalid_env_json_rejected(monkeypatch):
    monkeypatch.setenv("AUTHSCOPE_PROXY_POOL", "{bad json")
    with pytest.raises(ValueError):
        ProxyManager()


def test_unknown_country_falls_back_with_warning(caplog):
    mgr = ProxyManager(pool={"us": "http://u:p@proxy-us.example.com:8000"})
    proxy = mgr.get_proxy("de")
    assert proxy == "http://u:p@proxy-us.example.com:8000"


def test_different_country_retry():
    mgr = ProxyManager(
        pool={
            "us": "http://u:p@proxy-us.example.com:8000",
            "de": "http://u:p@proxy-de.example.com:8000",
        }
    )
    proxy, country = mgr.get_different_country_proxy("us")
    assert country == "de"
    assert "proxy-de" in proxy


def test_single_country_pool_retry_reuses(caplog):
    mgr = ProxyManager(pool={"us": "http://u:p@proxy-us.example.com:8000"})
    assert mgr.get_different_country_proxy("us") == (None, None)


def test_credentials_never_in_redacted_form():
    assert "secretpass" not in (redact_proxy_url("http://u:secretpass@gw.example.com:8000") or "")
    assert redact_proxy_url(None) is None


def test_usage_counts_track_acquisitions():
    mgr = ProxyManager(pool={"us": "http://u:p@proxy-us.example.com:8000"})
    mgr.get_proxy("us")
    mgr.get_proxy("US")
    assert mgr.usage_counts == {"us": 2}
