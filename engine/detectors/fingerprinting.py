"""Fingerprinting library detection: vendor SDKs + generic canvas/WebGL reads."""

from __future__ import annotations

from engine.artifacts import PageArtifact
from engine.detectors.base import Detector, Finding, match_signature
from engine.signatures import SignatureDef

CANVAS_READ_THRESHOLD = 2  # a single read can be benign (icon rendering)


class FingerprintDetector(Detector):
    name = "fingerprinting"

    def __init__(self, signatures: list[SignatureDef]) -> None:
        self._sigs = [s for s in signatures if s.category == "fingerprinting"]

    async def detect(self, artifact: PageArtifact) -> list[Finding]:
        findings: list[Finding] = []
        for sig in self._sigs:
            matched = match_signature(sig, artifact)
            if not matched:
                continue
            findings.append(
                Finding(
                    kind="fingerprinting",
                    name=sig.name,
                    provider=sig.name,
                    confidence=sig.confidence,
                    matched_signals=matched,
                )
            )

        reads = artifact.fingerprint_reads or {}
        canvas_reads = int(reads.get("canvas_dataurl", 0)) + int(reads.get("canvas_imagedata", 0))
        webgl_reads = int(reads.get("webgl_readpixels", 0))
        generic_signals: dict[str, int] = {}
        if canvas_reads >= CANVAS_READ_THRESHOLD:
            generic_signals["generic_canvas_read"] = canvas_reads
        if webgl_reads > 0:
            generic_signals["webgl_readpixels"] = webgl_reads
        if generic_signals:
            findings.append(
                Finding(
                    kind="fingerprinting",
                    name="browser_fingerprint_collection",
                    provider=None,
                    confidence=0.7 if canvas_reads < CANVAS_READ_THRESHOLD * 4 else 0.85,
                    extra={"signals": generic_signals},
                )
            )
        return findings
