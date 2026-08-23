"""Parallel detector pipeline runner with per-detector timeout and fault isolation."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass

from engine.artifacts import PageArtifact
from engine.detectors.base import Detector, Finding

logger = logging.getLogger("authscope.pipeline")

DEFAULT_DETECTOR_TIMEOUT_S = 30


@dataclass
class DetectorOutcome:
    detector: str
    findings: list[Finding]
    duration_ms: int
    error: str | None = None


async def run_detectors(
    detectors: list[Detector],
    artifact: PageArtifact,
    per_detector_timeout: float = DEFAULT_DETECTOR_TIMEOUT_S,
) -> list[DetectorOutcome]:
    """Run all detectors concurrently; a failure or timeout in one never fails the scan."""

    async def _run_one(detector: Detector) -> DetectorOutcome:
        started = time.monotonic()
        try:
            findings = await asyncio.wait_for(
                detector.detect(artifact), timeout=per_detector_timeout
            )
            ms = int((time.monotonic() - started) * 1000)
            logger.info("detector %s done in %dms: %d findings", detector.name, ms, len(findings))
            return DetectorOutcome(detector.name, findings, ms)
        except Exception as exc:  # noqa: BLE001 — containment is the point
            ms = int((time.monotonic() - started) * 1000)
            err = f"{type(exc).__name__}: {exc}"[:300]
            logger.exception("detector %s failed", detector.name)
            return DetectorOutcome(detector.name, [], ms, error=err)

    outcomes = await asyncio.gather(*(_run_one(d) for d in detectors))
    return list(outcomes)


def all_findings(outcomes: list[DetectorOutcome]) -> list[Finding]:
    return [f for o in outcomes for f in o.findings]
