"""PageController: navigation, network capture, hook injection, artifact assembly."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from dataclasses import dataclass

from playwright.async_api import Request, Response

from engine.artifacts import CapturedRequest, CookieInfo, PageArtifact
from engine.browser.context_manager import ManagedContext
from engine.page import hooks as hooks_mod
from engine.page.static_analyzer import EXTRACT_DOM_JS, build_dom_summary

logger = logging.getLogger("authscope.page")

# Body/title markers of known bot-challenge interstitials.
CHALLENGE_MARKERS: tuple[str, ...] = (
    "just a moment",
    "attention required",
    "checking your browser",
    "cf-challenge",
    "challenge-platform",
    "press & hold",
    "verifying you are human",
    "_Incapsula_resource",
)


def _har_time(ts: float | None) -> str:
    """Format epoch seconds as HAR ISO-8601; never emit the 1970 stub."""
    from datetime import UTC, datetime

    if ts is None:
        ts = time.time()
    return datetime.fromtimestamp(ts, tz=UTC).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def build_har(
    entries: list[CapturedRequest], page_url: str, scan_started_at: float | None = None
) -> dict:
    """Assemble a HAR 1.2 document from captured requests."""
    page_started = _har_time(scan_started_at)
    har_entries = []
    for r in entries:
        started = _har_time(r.started_at or scan_started_at)
        elapsed = r.duration_ms if r.duration_ms is not None else 0
        qs_pos = r.url.find("?")
        qs = []
        if qs_pos != -1:
            from urllib.parse import parse_qsl, urlsplit

            qs = [{"name": k, "value": v} for k, v in parse_qsl(urlsplit(r.url).query)]
        har_entries.append(
            {
                "startedDateTime": started,
                "time": elapsed,
                "_resourceType": r.resource_type,
                "request": {
                    "method": r.method,
                    "url": r.url,
                    "httpVersion": "HTTP/1.1",
                    "queryString": qs,
                    "headers": [{"name": k, "value": v} for k, v in r.request_headers.items()],
                    "headersSize": -1,
                    "bodySize": 0,
                },
                "response": {
                    "status": r.status or 0,
                    "statusText": "",
                    "httpVersion": "HTTP/1.1",
                    "headers": [
                        {"name": k, "value": v} for k, v in r.response_headers.items()
                    ],
                    "content": {"size": 0, "mimeType": r.response_headers.get("content-type", "")},
                    "redirectURL": r.response_headers.get("location", ""),
                    "headersSize": -1,
                    "bodySize": 0,
                },
                "cache": {},
                "timings": {"send": 0, "wait": elapsed, "receive": 0},
            }
        )
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "authscope", "version": "0.1.0"},
            "pages": [
                {
                    "id": "page_1",
                    "pageTimings": {},
                    "title": page_url,
                    "startedDateTime": page_started,
                }
            ],
            "entries": har_entries,
        }
    }


@dataclass
class CaptureResult:
    artifact: PageArtifact
    screenshot_png: bytes | None = None
    har_json: str | None = None


class PageController:
    """Drives one scan's browser context and collects the raw evidence."""

    def __init__(self, lazy_captcha_wait_seconds: int | None = None) -> None:
        settings_lazy = None
        try:
            from config import get_settings

            settings_lazy = get_settings().scan.lazy_captcha_wait_seconds
        except Exception:  # noqa: BLE001 — direct construction in unit tests
            pass
        self.lazy_wait = (
            lazy_captcha_wait_seconds
            if lazy_captcha_wait_seconds is not None
            else (settings_lazy or 0)
        )

    async def _robots_disallows(self, url: str) -> bool:
        """Check robots.txt when the org-policy flag is enabled."""
        from config import get_settings

        try:
            settings = get_settings()
        except Exception:  # noqa: BLE001 — direct construction in unit tests
            return False
        if not settings.scan.respect_robots_txt:
            return False
        import urllib.request
        from urllib.parse import urlsplit
        from urllib.robotparser import RobotFileParser

        parts = urlsplit(url)
        robots_url = f"{parts.scheme}://{parts.netloc}/robots.txt"
        try:
            with urllib.request.urlopen(robots_url, timeout=5) as resp:
                body = resp.read().decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001 — no/unreadable robots.txt = allowed
            return False
        parser = RobotFileParser()
        parser.parse(body.splitlines())
        ua = "*"
        return not parser.can_fetch(ua, url)

    async def run(
        self,
        managed: ManagedContext,
        url: str,
        deep_scan: bool = False,
    ) -> CaptureResult:
        context = managed.context
        page = await context.new_page()
        started = time.monotonic()
        scan_started_at = time.time()
        requests: dict[str, CapturedRequest] = {}
        main_response_headers: dict[str, str] = {}
        main_status: int | None = None
        final_url = url

        # CDP instrumentation (Network/Page/Security enabled per design).
        cdp = await context.new_cdp_session(page)
        for domain in ("Network", "Page", "Security"):
            try:
                await cdp.send(f"{domain}.enable")
            except Exception:  # noqa: BLE001 — Security may be unavailable headless
                logger.debug("CDP %s.enable unavailable", domain)

        async def on_response(response: Response) -> None:
            nonlocal main_status, final_url, main_response_headers
            req: Request = response.request
            now = time.time()
            entry = requests.setdefault(
                req.url,
                CapturedRequest(url=req.url, method=req.method, resource_type=req.resource_type),
            )
            if entry.started_at is None:
                entry.started_at = now
            else:
                entry.duration_ms = max(0, int((now - entry.started_at) * 1000))
            entry.is_xhr_fetch = entry.is_xhr_fetch or req.resource_type in ("xhr", "fetch")
            with contextlib.suppress(Exception):  # response may be gone already
                entry.status = response.status
                entry.response_headers = {
                    k.lower(): v for k, v in (await response.all_headers()).items()
                }
            if response.request.is_navigation_request() and response.frame == page.main_frame:
                main_status = response.status
                final_url = response.url
                with contextlib.suppress(Exception):
                    main_response_headers = {
                        k.lower(): v for k, v in (await response.all_headers()).items()
                    }

        def on_request(req: Request) -> None:
            entry = requests.setdefault(
                req.url,
                CapturedRequest(url=req.url, method=req.method, resource_type=req.resource_type),
            )
            if entry.started_at is None:
                entry.started_at = time.time()
            entry.request_headers = {k.lower(): v for k, v in req.headers.items()}

        page.on("response", lambda r: asyncio.ensure_future(on_response(r)))
        page.on("request", on_request)

        # Early hooks BEFORE any page script runs (applies to this navigation).
        await page.add_init_script(hooks_mod.HOOKS_JS)

        blocked = False
        blocked_reason: str | None = None
        goto_error: str | None = None

        # Optional robots.txt compliance (org policy flag, off by default).
        if await self._robots_disallows(url):
            logger.info("robots.txt disallows %s — skipping navigation", url)
            artifact = PageArtifact(
                url=url,
                final_url=url,
                http_status=None,
                blocked=True,
                blocked_reason="robots_disallowed",
            )
            return CaptureResult(artifact=artifact)

        try:
            await page.goto(url, wait_until="networkidle", timeout=45_000)
        except Exception as exc:  # noqa: BLE001 — timeouts/DNS/neterrors still yield partial evidence
            goto_error = f"{type(exc).__name__}: {exc}"[:300]
            logger.info("goto %s incomplete: %s", url, goto_error)

        await page.wait_for_timeout(self.lazy_wait * 1000)

        # Drain runtime hooks + probe globals + extract DOM.
        hook_data: dict = {"hookLog": [], "fingerprintReads": {}}
        window_globals: list[str] = []
        dom_data: dict = {}
        try:
            hook_data = await page.evaluate(hooks_mod.drain_hooks_js())
        except Exception:  # noqa: BLE001
            logger.debug("hook drain failed", exc_info=True)
        with contextlib.suppress(Exception):
            window_globals = await page.evaluate(hooks_mod.GLOBALS_PROBE_JS)
        with contextlib.suppress(Exception):
            dom_data = await page.evaluate(EXTRACT_DOM_JS)

        cookies_raw = await context.cookies()
        cookie_infos = [
            CookieInfo(
                name=c["name"],
                value=c.get("value", ""),
                domain=c.get("domain", ""),
                path=c.get("path", "/"),
                secure=bool(c.get("secure")),
                httponly=bool(c.get("httpOnly")),
                samesite=c.get("sameSite") or "Lax",
                expires=float(c.get("expires", -1)),
            )
            for c in cookies_raw
        ]

        # Blocked/challenge detection on the main document.
        body_sample = str(dom_data.get("bodyTextSample", "")).lower()
        html_sample = str(dom_data.get("rawHtml", ""))[:50_000].lower()
        markers_hit = [m for m in CHALLENGE_MARKERS if m in body_sample or m in html_sample]
        if markers_hit or (main_status == 403):
            blocked = True
            blocked_reason = markers_hit[0] if markers_hit else f"http_{main_status}"

        duration_ms = int((time.monotonic() - started) * 1000)
        request_list = _ordered_requests(requests)

        screenshot_png: bytes | None = None
        try:
            screenshot_png = await page.screenshot(full_page=True)
        except Exception:  # noqa: BLE001
            logger.debug("screenshot failed", exc_info=True)
        await page.close()

        har = build_har(request_list, url, scan_started_at)
        artifact = PageArtifact(
            url=url,
            final_url=final_url,
            http_status=main_status,
            blocked=blocked,
            blocked_reason=blocked_reason,
            load_duration_ms=duration_ms,
            requests=request_list,
            cookies=cookie_infos,
            headers=main_response_headers or _first_document_headers(request_list),
            dom=build_dom_summary(dom_data),
            globals=window_globals[:3000],
            hook_log=hook_data.get("hookLog", []),
            fingerprint_reads=hook_data.get("fingerprintReads", {}),
        )
        return CaptureResult(
            artifact=artifact,
            screenshot_png=screenshot_png,
            har_json=json.dumps(har),
        )


def _first_document_headers(requests: list[CapturedRequest]) -> dict[str, str]:
    for r in requests:
        if r.resource_type == "document" and r.response_headers:
            return r.response_headers
    return {}


def _ordered_requests(requests: dict[str, CapturedRequest]) -> list[CapturedRequest]:
    documents_first = sorted(
        requests.values(),
        key=lambda r: (0 if r.resource_type == "document" else 1, r.url),
    )
    return documents_first
