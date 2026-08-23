"""Shared fixtures: fixture HTTP site, Playwright browser, context manager."""

from __future__ import annotations

from pathlib import Path

import pytest

from engine.browser.context_manager import BrowserContextManager
from engine.page.controller import PageController
from tests.fixtures_site import FixtureSite
from tests.fixtures_site import page as fx_page


@pytest.fixture(scope="session")
def fixture_site():
    site = FixtureSite().start()
    yield site
    site.stop()


@pytest.fixture(scope="session")
async def browser_mgr(fixture_site):
    mgr = BrowserContextManager(timeout_seconds=20)
    await mgr.start()
    yield mgr
    await mgr.stop()


@pytest.fixture
async def scan_context(browser_mgr):
    managed = await browser_mgr.acquire()
    yield managed
    await browser_mgr.release(managed)


@pytest.fixture
def controller():
    return PageController(lazy_captcha_wait_seconds=0)


@pytest.fixture
def url():
    return fx_page


FIXTURES_DIR = Path(__file__).parent / "fixtures"
SIGNATURES_DIR = Path(__file__).parent.parent / "signatures"
