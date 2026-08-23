"""Isolated browser context management: fingerprints, stealth, proxy, watchdog kill."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import tempfile
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from playwright.async_api import Browser, BrowserContext, Playwright, async_playwright

from config import get_settings
from engine.fingerprints import Fingerprint, FingerprintGenerator

logger = logging.getLogger("authscope.browser")

# Injected before any page script; hides automation markers.
STEALTH_INIT_SCRIPT = """
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
window.chrome = window.chrome || {runtime: {}};
Object.defineProperty(navigator, 'plugins', {
  get: () => [{name: 'Chrome PDF Plugin'}, {name: 'Native Client'}],
});
Object.defineProperty(navigator, 'languages', {
  get: () => navigator.languages || ['en-US', 'en'],
});
"""


@dataclass
class ManagedContext:
    """A scan-scoped browser context with lifecycle metadata."""

    id: str
    context: BrowserContext
    fingerprint: Fingerprint
    proxy_url: str | None
    created_at: datetime
    trace_path: Path


class BrowserContextManager:
    """Owns the Playwright browser and produces isolated per-scan contexts.

    - Per-context fingerprint (rotated real UA, randomized viewport/locale/tz)
    - Optional per-context proxy (Chromium per-context routing)
    - Playwright tracing started on every context
    - Hard watchdog kill after ``timeout_seconds`` (default from settings)
    """

    def __init__(
        self,
        timeout_seconds: int | None = None,
        proxy_enabled: bool = False,
    ) -> None:
        self._settings = get_settings()
        self.timeout_seconds = timeout_seconds or self._settings.scan.timeout_seconds
        self._proxy_enabled = proxy_enabled
        self._pw: Playwright | None = None
        self._browser: Browser | None = None
        self._live: dict[str, asyncio.Task] = {}
        self._fp_gen = FingerprintGenerator()

    async def start(self) -> None:
        if self._browser is not None:
            return
        self._pw = await async_playwright().start()
        launch_kwargs: dict = {
            "headless": True,
            "args": ["--disable-blink-features=AutomationControlled"],
        }
        # Chromium requires a placeholder launch proxy to allow per-context proxies.
        if self._proxy_enabled:
            launch_kwargs["proxy"] = {"server": "http://per-context"}
        self._browser = await self._pw.chromium.launch(**launch_kwargs)

    async def stop(self) -> None:
        for ctx_id in list(self._live):
            await self._kill(ctx_id)
        if self._browser is not None:
            await self._browser.close()
            self._browser = None
        if self._pw is not None:
            await self._pw.stop()
            self._pw = None

    @property
    def live_count(self) -> int:
        return len(self._live)

    async def acquire(
        self,
        proxy_url: str | None = None,
        fingerprint: Fingerprint | None = None,
    ) -> ManagedContext:
        assert self._browser is not None, "call start() first"
        fp = fingerprint or self._fp_gen.generate()
        ctx_kwargs = fp.to_context_kwargs()
        ctx_kwargs["ignore_https_errors"] = False  # detection-critical
        if proxy_url:
            ctx_kwargs["proxy"] = {"server": proxy_url}
        context = await self._browser.new_context(**ctx_kwargs)
        await context.add_init_script(STEALTH_INIT_SCRIPT)

        trace_dir = Path(tempfile.gettempdir()) / "authscope_traces"
        trace_dir.mkdir(parents=True, exist_ok=True)
        trace_path = trace_dir / f"{uuid.uuid4().hex}.zip"
        await context.tracing.start(screenshots=True, snapshots=True, sources=False)

        managed = ManagedContext(
            id=uuid.uuid4().hex[:12],
            context=context,
            fingerprint=fp,
            proxy_url=proxy_url,
            created_at=datetime.now(UTC),
            trace_path=trace_path,
        )
        self._watch(managed)
        return managed

    def _watch(self, managed: ManagedContext) -> None:
        async def _reap() -> None:
            await asyncio.sleep(self.timeout_seconds)
            logger.warning(
                "context %s exceeded %ss watchdog — killing", managed.id, self.timeout_seconds
            )
            self._live.pop(managed.id, None)
            await self._close_context(managed, save_trace=False)

        self._live[managed.id] = asyncio.create_task(_reap())

    async def release(self, managed: ManagedContext) -> None:
        task = self._live.pop(managed.id, None)
        if task is not None:
            task.cancel()
        await self._close_context(managed, save_trace=True)

    async def _kill(self, ctx_id: str) -> None:
        task = self._live.pop(ctx_id, None)
        if not task:
            return
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    async def _close_context(self, managed: ManagedContext, save_trace: bool) -> None:
        try:
            if save_trace:
                await managed.context.tracing.stop(path=str(managed.trace_path))
        except Exception:  # noqa: BLE001 — context may already be dead via watchdog
            logger.debug("tracing stop failed for %s", managed.id, exc_info=True)
        try:
            await managed.context.close()
        except Exception:  # noqa: BLE001
            logger.debug("context close failed for %s", managed.id, exc_info=True)
