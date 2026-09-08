"""Canned showcase demo: 3 fixture targets through the full detection pipeline.

Runs without API/DB/Redis — starts the offline fixture site + real Chromium,
navigates each demo page, runs all 5 detectors, aggregates + scores, and
prints the expected showcase assertions.

Usage: .venv/bin/python scripts/demo.py
"""

from __future__ import annotations

import asyncio
import sys

DEMOS = [
    {
        "page": "auth0_like.html",
        "expect": "auth provider=auth0",
        "check": lambda r: r.auth.provider == "auth0",
    },
    {
        "page": "turnstile_visible.html",
        "expect": "captcha=turnstile_managed visible",
        "check": lambda r: (
            (r.antibot.captcha.type or "").startswith("turnstile")
            and r.antibot.captcha.visible is True
        ),
    },
    {
        "page": "waf_cookies.html",
        "expect": "waf includes cloudflare",
        "check": lambda r: "cloudflare" in (r.antibot.waf_providers or []),
    },
]


async def run_one(mgr, page_name: str):
    import uuid

    from engine.detectors.auth_provider import AuthProviderDetector
    from engine.detectors.captcha import CaptchaDetector
    from engine.detectors.fingerprinting import FingerprintDetector
    from engine.detectors.security import SecurityDetector
    from engine.detectors.waf import WAFDetector
    from engine.page.controller import PageController
    from engine.signatures import load_yaml_dir
    from pipeline.aggregator import aggregate
    from pipeline.runner import all_findings, run_detectors
    from pipeline.scoring import HeuristicScoring
    from tests.fixtures_site import page as fx

    sigs = load_yaml_dir("signatures")
    detectors = [
        AuthProviderDetector(sigs),
        SecurityDetector(),
        CaptchaDetector(sigs),
        WAFDetector(sigs),
        FingerprintDetector(sigs),
    ]
    managed = await mgr.acquire()
    try:
        controller = PageController(lazy_captcha_wait_seconds=0)
        result = await controller.run(managed, fx(page_name))
    finally:
        await mgr.release(managed)
    outcomes = await run_detectors(detectors, result.artifact)
    report, scores = aggregate(
        scan_id=str(uuid.uuid4()),
        url=fx(page_name),
        artifact=result.artifact,
        findings=all_findings(outcomes),
        strategy=HeuristicScoring(),
    )
    return result, report, scores


async def main() -> int:
    from engine.browser.context_manager import BrowserContextManager
    from tests.fixtures_site import FixtureSite

    site = FixtureSite().start()
    mgr = BrowserContextManager(timeout_seconds=20)
    await mgr.start()
    failures = 0
    try:
        for demo in DEMOS:
            result, report, scores = await run_one(mgr, demo["page"])
            ok = bool(demo["check"](report))
            status = "PASS" if ok else "FAIL"
            if not ok:
                failures += 1
            auth = report.auth.provider or "none"
            captcha = report.antibot.captcha.type or "none"
            wafs = ",".join(report.antibot.waf_providers or [])
            print(
                f"[{status}] {demo['page']}: expect {demo['expect']} | "
                f"auth={auth} captcha={captcha} waf=[{wafs}] "
                f"difficulty={scores.difficulty_score} risk={scores.risk_score}"
            )
    finally:
        await mgr.stop()
        site.stop()
    print("demo: all PASS" if failures == 0 else f"demo: {failures} FAILURES")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
