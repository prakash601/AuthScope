"""ISS-011 tests: parallel runner isolation, timeouts, ordering."""

from __future__ import annotations

import asyncio

from engine.artifacts import PageArtifact
from engine.detectors.base import Detector, Finding
from pipeline.runner import all_findings, run_detectors


class OkDetector(Detector):
    name = "ok"

    async def detect(self, artifact):
        await asyncio.sleep(0.01)
        return [Finding(kind="test", name="ok", confidence=0.9)]


class BoomDetector(Detector):
    name = "boom"

    async def detect(self, artifact):
        raise RuntimeError("exploded")


class SlowDetector(Detector):
    name = "slow"

    async def detect(self, artifact):
        await asyncio.sleep(5)
        return [Finding(kind="test", name="slow", confidence=0.9)]


def _artifact() -> PageArtifact:
    return PageArtifact(url="https://x.test/login")


async def test_parallel_execution_and_results():
    outcomes = await run_detectors([OkDetector(), OkDetector(), OkDetector()], _artifact())
    assert len(outcomes) == 3
    assert all(o.error is None for o in outcomes)
    findings = all_findings(outcomes)
    assert len(findings) == 3


async def test_detector_crash_is_contained():
    outcomes = await run_detectors([OkDetector(), BoomDetector()], _artifact())
    ok = next(o for o in outcomes if o.detector == "ok")
    boom = next(o for o in outcomes if o.detector == "boom")
    assert ok.findings and boom.error is not None
    assert "RuntimeError" in boom.error


async def test_detector_timeout_enforced():
    outcomes = await run_detectors(
        [SlowDetector(), OkDetector()], _artifact(), per_detector_timeout=0.1
    )
    slow = next(o for o in outcomes if o.detector == "slow")
    ok = next(o for o in outcomes if o.detector == "ok")
    assert slow.error is not None and not slow.findings
    assert ok.findings
