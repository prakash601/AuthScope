"""Detector strategy interface, finding model, and signal matching."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import ClassVar

from pydantic import BaseModel, Field

from engine.artifacts import PageArtifact
from engine.signatures import SignatureDef


class MatchedSignal(BaseModel):
    signal_type: str
    value: str


class Finding(BaseModel):
    kind: str  # auth_provider | security | captcha | waf | fingerprinting
    name: str
    provider: str | None = None
    confidence: float = 0.0
    matched_signals: list[MatchedSignal] = Field(default_factory=list)
    extra: dict = Field(default_factory=dict)


class Detector(ABC):
    """Strategy interface: consume a PageArtifact, emit findings.

    Implementations must be side-effect free and must not raise on odd
    input (the pipeline contains failures, but best practice is graceful).
    """

    name: ClassVar[str] = "detector"

    @abstractmethod
    async def detect(self, artifact: PageArtifact) -> list[Finding]: ...


# ---------------------------------------------------------------------------
# Signal matching
# ---------------------------------------------------------------------------

# signal key -> extractor over the artifact producing candidate strings.
def _candidates(artifact: PageArtifact, signal_type: str) -> list[str]:
    dom = artifact.dom
    if signal_type == "script_src":
        return dom.scripts
    if signal_type == "global_object":
        return artifact.globals
    if signal_type == "network":
        return [r.url for r in artifact.requests]
    if signal_type == "hook_network":
        return [str(h.get("url", "")) for h in artifact.hook_log]
    if signal_type == "form_action":
        return [f.action for f in dom.forms]
    if signal_type == "dom":
        return [dom.raw_html]
    if signal_type == "inline_js":
        return dom.inline_scripts + [dom.raw_html[:100_000]]
    if signal_type == "cookie":
        return [c.name for c in artifact.cookies]
    if signal_type == "header":
        return [f"{k}: {v}" for k, v in artifact.headers.items()]
    if signal_type == "body_text":
        return [dom.body_text_sample.lower(), dom.title.lower()]
    if signal_type == "iframe_src":
        return dom.iframes
    return []


def match_signature(sig: SignatureDef, artifact: PageArtifact) -> list[MatchedSignal]:
    """Return one MatchedSignal per distinct signal type of the signature that hit."""
    matched: list[MatchedSignal] = []
    for signal_type, pattern in sig.signals.items():
        patterns = [pattern] if isinstance(pattern, str) else list(pattern)
        candidates = _candidates(artifact, signal_type)
        hit_fn = _first_hit_boundary if signal_type in _BOUNDARY_SIGNALS else _first_hit
        hit_value = hit_fn(patterns, candidates)
        if hit_value:
            matched.append(MatchedSignal(signal_type=signal_type, value=hit_value))
    return matched


_BOUNDARY_NEXT = re.compile(r"[^A-Za-z0-9_-]")


def _boundary_hit(pattern: str, candidate: str) -> bool:
    """Substring hit requiring a token boundary right after the pattern.

    Prevents e.g. form_action "/login" from matching "/login_check".
    """
    p = pattern.lower()
    c = candidate.lower()
    start = 0
    while True:
        idx = c.find(p, start)
        if idx == -1:
            return False
        end = idx + len(p)
        if end >= len(c) or _BOUNDARY_NEXT.match(c[end]):
            return True
        start = idx + 1


def _first_hit(patterns: list[str], candidates: list[str]) -> str | None:
    lowered = [c.lower() for c in candidates]
    for pat in patterns:
        p = pat.lower()
        try:
            regex = re.compile(p) if p.startswith("re:") else None
        except re.error:
            regex = None
        for cand, cand_l in zip(candidates, lowered, strict=False):
            if regex is not None:
                if regex.search(cand):
                    return cand
            elif p in cand_l:
                return cand
    return None


_BOUNDARY_SIGNALS = {"form_action"}


def confidence_for_signals(base_confidence: float, n_matched: int, n_defined: int) -> float:
    """Scale signature confidence by independent corroborating signals.

    1 signal -> 70% of base; 2 -> 85%; >=3 (or all defined) -> full base. Capped at 0.99.
    """
    if n_matched <= 1:
        factor = 0.7
    elif n_matched == 2:
        factor = 0.85
    else:
        factor = 1.0
    if n_defined > 0 and n_matched >= n_defined and n_matched > 1:
        factor = max(factor, 0.95)
    return round(min(0.99, base_confidence * factor), 3)



def _first_hit_boundary(patterns: list[str], candidates: list[str]) -> str | None:
    for pat in patterns:
        for cand in candidates:
            if _boundary_hit(pat, cand):
                return cand
    return None
