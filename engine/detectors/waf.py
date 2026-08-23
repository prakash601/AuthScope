"""WAF/bot-protection detection + blocked-scan intelligence."""

from __future__ import annotations

from engine.artifacts import PageArtifact
from engine.detectors.base import Detector, Finding, match_signature
from engine.signatures import SignatureDef


class WAFDetector(Detector):
    name = "waf"

    def __init__(self, signatures: list[SignatureDef]) -> None:
        self._sigs = [s for s in signatures if s.category == "antibot" and s.type == "waf"]

    async def detect(self, artifact: PageArtifact) -> list[Finding]:
        findings: list[Finding] = []
        for sig in self._sigs:
            matched = match_signature(sig, artifact)
            if not matched:
                continue
            # Independent signal classes corroborate; single cookie/header hits are
            # still reported (WAF cookies like _abck are strong signals on their own).
            confidence = sig.confidence if len(matched) >= 2 else round(sig.confidence * 0.85, 3)
            findings.append(
                Finding(
                    kind="waf",
                    name=sig.name,
                    provider=sig.name,
                    confidence=confidence,
                    matched_signals=matched,
                    extra={"blocked_scan": artifact.blocked},
                )
            )

        if artifact.blocked and not findings:
            findings.append(
                Finding(
                    kind="waf",
                    name="unknown_block",
                    provider=None,
                    confidence=0.6,
                    extra={
                        "blocked_scan": True,
                        "reason": artifact.blocked_reason,
                        "note": (
                            "challenge/403 interstitial observed "
                            "but no known vendor signature matched"
                        ),
                    },
                )
            )
        return findings
