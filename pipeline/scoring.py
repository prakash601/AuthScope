"""Automation Difficulty & Risk scoring.

Heuristic `HeuristicScoring` implements the README §Scoring weight tables behind
the `ScoringStrategy` protocol so a Phase-2 ML model (XGBoost + SHAP) can drop in
without touching callers.

Difficulty weights (category caps keep the total sane):
    WAF vendor (tiered)          22/16/10 per vendor, category cap 40
    Invisible / score captcha    20, visible challenge 12   cap 25
    Fingerprinting libraries      7 per lib cap 14; generic reads +5, cap 20
    Blocked challenge interstitial 10 (behavioral JS-challenge proxy)
    Honeypot fields                4
    CSRF token complexity          3

Risk penalties: HSTS 20, CSP 20, XFO 10, Referrer-Policy 5, Permissions-Policy 5,
cookie flag issue types 6 each (cap 18), password form without CSRF 10, no MFA signal 10.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from engine.artifacts import PageArtifact
from engine.detectors.base import Finding

# --- difficulty tables ------------------------------------------------------

WAF_TIER: dict[str, int] = {
    "akamai_bm": 1,
    "kasada": 1,
    "datadome": 1,
    "perimeterx_human": 1,
    "cloudflare": 2,
    "imperva_incapsula": 2,
    "f5_shape": 2,
}
WAF_TIER_POINTS: dict[int, int] = {1: 22, 2: 16, 3: 10}
WAF_CAP = 40
CAPTCHA_CAP = 25
FINGERPRINT_CAP = 20

GENERIC_AUTH_NAMES = {
    "generic_oidc_wellknown",
    "generic_oauth_authorize",
    "generic_oauth2_authorize",
}


@dataclass
class ScoreFactor:
    name: str
    points: int


@dataclass
class ScoreResult:
    difficulty_score: int
    risk_score: int
    reasoning: str
    factors: list[ScoreFactor] = field(default_factory=list)
    risk_factors: list[ScoreFactor] = field(default_factory=list)


class ScoringStrategy(Protocol):
    """Implementations must be deterministic and side-effect free."""

    name: str

    def score(self, findings: list[Finding], artifact: PageArtifact) -> ScoreResult: ...


def _captcha_points(f: Finding) -> int:
    extra = f.extra or {}
    if extra.get("score_based") or extra.get("variant") == "score_based_invisible":
        return 20
    if extra.get("visible"):
        return 12
    return 16  # invisible challenge (e.g. turnstile_non_interactive)


class HeuristicScoring:
    name = "heuristic_v1"

    def score(self, findings: list[Finding], artifact: PageArtifact) -> ScoreResult:
        factors = self._difficulty_factors(findings, artifact)
        risk_factors = self._risk_factors(findings, artifact)
        difficulty = min(100, sum(f.points for f in factors))
        risk = min(100, sum(f.points for f in risk_factors))
        reasoning = self._reasoning(difficulty, factors)
        return ScoreResult(
            difficulty_score=difficulty,
            risk_score=risk,
            reasoning=reasoning,
            factors=factors,
            risk_factors=risk_factors,
        )

    # -- difficulty ---------------------------------------------------------

    def _difficulty_factors(
        self, findings: list[Finding], artifact: PageArtifact
    ) -> list[ScoreFactor]:
        factors: list[ScoreFactor] = []

        waf_points = 0
        for f in sorted(
            (x for x in findings if x.kind == "waf" and x.provider),
            key=lambda x: (
                -WAF_TIER_POINTS.get(WAF_TIER.get(x.provider or "", 3), 10),
                x.provider or "",
            ),
        ):
            tier = WAF_TIER.get(f.provider or "", 3)
            pts = min(WAF_TIER_POINTS[tier], WAF_CAP - waf_points)
            if pts <= 0:
                break
            waf_points += pts
            factors.append(ScoreFactor(name=f"waf:{f.provider}", points=pts))

        captcha_points = 0
        for f in sorted(
            (x for x in findings if x.kind == "captcha"),
            key=lambda x: (-_captcha_points(x), x.name),
        ):
            base_pts = _captcha_points(f)
            if captcha_points >= CAPTCHA_CAP:
                break
            pts = min(base_pts, CAPTCHA_CAP - captcha_points)
            captcha_points += pts
            if base_pts == 20:
                label = "captcha:score_or_invisible"
            elif base_pts == 12:
                label = f"captcha:{f.name}"
            else:
                label = f"captcha:{f.name}"
            factors.append(ScoreFactor(name=label, points=pts))

        fp_points = 0
        fp_findings = [x for x in findings if x.kind == "fingerprinting"]
        for f in sorted(fp_findings, key=lambda x: x.name):
            pts = 5 if f.name == "browser_fingerprint_collection" else 7
            if fp_points >= FINGERPRINT_CAP:
                break
            pts = min(pts, FINGERPRINT_CAP - fp_points)
            fp_points += pts
            factors.append(ScoreFactor(name=f"fingerprinting:{f.name}", points=pts))

        if artifact.blocked:
            factors.append(ScoreFactor(name="behavioral:blocked_challenge", points=10))

        has_honeypot = any(
            fd.honeypot_candidate for f in artifact.dom.forms for fd in f.fields
        )
        if has_honeypot:
            factors.append(ScoreFactor(name="passive:honeypot_fields", points=4))

        security_extra = _security_extras(findings)
        if security_extra is not None and security_extra.get("has_csrf"):
            factors.append(ScoreFactor(name="passive:csrf_token", points=3))

        return [f for f in factors if f.points > 0]

    # -- risk ---------------------------------------------------------------

    def _risk_factors(
        self, findings: list[Finding], artifact: PageArtifact
    ) -> list[ScoreFactor]:
        sec = _security_extras(findings)
        factors: list[ScoreFactor] = []
        if sec is None:
            return factors

        missing = set(sec.get("missing_security_headers") or [])
        header_penalties = [
            ("missing:HSTS", 20, "strict-transport-security"),
            ("missing:CSP", 20, "content-security-policy"),
            ("missing:X-Frame-Options", 10, "x-frame-options"),
            ("missing:Referrer-Policy", 5, "referrer-policy"),
            ("missing:Permissions-Policy", 5, None),  # not tracked in missing list
        ]
        permissions_missing = not sec.get("has_permissions_policy")
        for name, pts, marker in header_penalties:
            if marker is not None and marker in missing or marker is None and permissions_missing:
                factors.append(ScoreFactor(name=name, points=pts))

        cookie_issues = (sec.get("cookie_flags") or {}).get("issues") or {}
        cookie_pts = min(18, 6 * len(cookie_issues))
        if cookie_pts:
            factors.append(
                ScoreFactor(
                    name=f"cookies:{'+'.join(sorted(cookie_issues))}",
                    points=cookie_pts,
                )
            )

        has_password_form = any(
            fd.type == "password" for f in artifact.dom.forms for fd in f.fields
        )
        if has_password_form and not sec.get("has_csrf"):
            factors.append(ScoreFactor(name="csrf:absent_on_password_form", points=10))

        if not sec.get("mfa_detected"):
            factors.append(ScoreFactor(name="mfa:no_signal_detected", points=10))

        return [f for f in factors if f.points > 0]

    # -- reasoning ----------------------------------------------------------

    @staticmethod
    def _reasoning(score: int, factors: list[ScoreFactor]) -> str:
        if not factors:
            return f"Score {score}: no automation blockers detected."
        parts = ", ".join(f"{f.name} (+{f.points})" for f in factors)
        return f"Score {score}: {parts}."


def _security_extras(findings: list[Finding]) -> dict | None:
    for f in findings:
        if f.kind == "security":
            return f.extra
    return None


# Default strategy instance used by the aggregator.
DEFAULT_STRATEGY: ScoringStrategy = HeuristicScoring()
