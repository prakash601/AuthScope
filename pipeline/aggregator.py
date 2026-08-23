"""Report aggregation: merge detector findings into the canonical ScanReport.

Conflict resolution (documented tie-break order):
  1. Specificity — vendor-specific signatures beat generic fallbacks
  2. Independent matched-signal count
  3. Confidence
  4. Finding name (ascending) — final deterministic fallback

WAF and fingerprinting findings are additive (all providers collected);
captcha picks a primary (highest confidence) but keeps the full list.
"""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field

from engine.artifacts import PageArtifact
from engine.detectors.base import Finding
from pipeline.scoring import GENERIC_AUTH_NAMES, ScoreResult, ScoringStrategy


class CaptchaSummary(BaseModel):
    type: str | None = None
    visible: bool | None = None
    score_based: bool = False


class AuthSection(BaseModel):
    provider: str | None = None
    confidence: float = 0.0
    flows: list[str] = Field(default_factory=list)
    evidence: list[dict] = Field(default_factory=list)
    other_providers: list[str] = Field(default_factory=list)


class SecuritySection(BaseModel):
    risk_score: int = 0
    has_csrf: bool = False
    has_hsts: bool = False
    has_csp: bool = False
    cookie_flags: dict = Field(default_factory=dict)
    mfa_detected: bool = False
    raw_headers: dict[str, str] = Field(default_factory=dict)
    details: dict = Field(default_factory=dict)


class AntibotSection(BaseModel):
    difficulty_score: int = 0
    difficulty_reasoning: str = ""
    captcha: CaptchaSummary = Field(default_factory=CaptchaSummary)
    waf_providers: list[str] = Field(default_factory=list)
    fingerprinting_signals: list[str] = Field(default_factory=list)
    cookies_detected: list[str] = Field(default_factory=list)
    blocked_scan: bool = False
    evidence: list[dict] = Field(default_factory=list)


class ArtifactsSection(BaseModel):
    har_url: str | None = None
    screenshot_url: str | None = None
    dom_snapshot_url: str | None = None
    trace_url: str | None = None


class ScanReport(BaseModel):
    schema_version: str = "1.0"
    scan_id: str
    url: str
    status: str = "completed"
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    scoring_strategy: str = ""
    auth: AuthSection = Field(default_factory=AuthSection)
    security: SecuritySection = Field(default_factory=SecuritySection)
    antibot: AntibotSection = Field(default_factory=AntibotSection)
    artifacts: ArtifactsSection = Field(default_factory=ArtifactsSection)


def _auth_priority(f: Finding) -> tuple:
    specificity = 0 if f.name in GENERIC_AUTH_NAMES else 1
    return (-specificity, -len(f.matched_signals), -f.confidence, f.name)


def aggregate(
    scan_id: str,
    url: str,
    artifact: PageArtifact,
    findings: list[Finding],
    strategy: ScoringStrategy,
    completed_at: datetime | None = None,
    status: str = "completed",
) -> tuple[ScanReport, ScoreResult]:
    """Merge findings + artifact into a ScanReport; compute scores."""
    scores = strategy.score(findings, artifact)

    report = ScanReport(
        scan_id=scan_id,
        url=url,
        status=status,
        completed_at=completed_at or datetime.now(UTC),
        scoring_strategy=strategy.name,
    )

    # --- auth ---------------------------------------------------------------
    auth_findings = [f for f in findings if f.kind == "auth_provider"]
    primary = min(auth_findings, key=_auth_priority) if auth_findings else None
    if primary is not None:
        flows = list(primary.extra.get("flows") or [])
        for other in auth_findings:
            if other is not primary:
                flows.extend(other.extra.get("flows") or [])
        report.auth = AuthSection(
            provider=primary.provider or primary.name,
            confidence=round(primary.confidence, 3),
            flows=sorted(set(flows)),
            evidence=[
                {
                    "signature": primary.name,
                    "signals": [m.model_dump() for m in primary.matched_signals],
                }
            ],
            other_providers=sorted({f.name for f in auth_findings if f is not primary}),
        )
    else:
        # flows can exist without a matched provider (e.g., pure oauth redirect page)
        merged_flows: list[str] = []
        for f in findings:
            merged_flows.extend(f.extra.get("flows") or [])
        if merged_flows:
            report.auth.flows = sorted(set(merged_flows))

    # --- security -----------------------------------------------------------
    sec = next((f for f in findings if f.kind == "security"), None)
    if sec is not None:
        e = sec.extra
        report.security = SecuritySection(
            risk_score=scores.risk_score,
            has_csrf=bool(e.get("has_csrf")),
            has_hsts=bool(e.get("has_hsts")),
            has_csp=bool(e.get("has_csp")),
            cookie_flags=e.get("cookie_flags") or {},
            mfa_detected=bool(e.get("mfa_detected")),
            raw_headers=dict(e.get("raw_headers") or {}),
            details={
                k: v
                for k, v in e.items()
                if k
                in (
                    "hsts_details",
                    "csp_directives",
                    "has_x_frame_options",
                    "has_coop",
                    "has_corp",
                    "has_coep",
                    "has_permissions_policy",
                    "honeypot_fields",
                    "password_policy_min_length",
                    "missing_security_headers",
                )
            },
        )

    # --- antibot ------------------------------------------------------------
    captcha_findings = [f for f in findings if f.kind == "captcha"]
    captcha_summary = CaptchaSummary()
    if captcha_findings:
        top = max(captcha_findings, key=lambda f: (f.confidence, f.name))
        captcha_summary = CaptchaSummary(
            type=top.name,
            visible=top.extra.get("visible"),
            score_based=bool(top.extra.get("score_based")),
        )

    waf_findings = [f for f in findings if f.kind == "waf" and f.provider]
    fp_findings = [f for f in findings if f.kind == "fingerprinting"]
    cookie_evidence = sorted(
        {
            m.value
            for f in findings
            if f.kind == "waf"
            for m in (f.matched_signals or [])
            if m.signal_type == "cookie"
        }
    )
    report.antibot = AntibotSection(
        difficulty_score=scores.difficulty_score,
        difficulty_reasoning=scores.reasoning,
        captcha=captcha_summary,
        waf_providers=sorted({f.provider or "" for f in waf_findings} - {""}),
        fingerprinting_signals=sorted(f.name for f in fp_findings),
        cookies_detected=cookie_evidence,
        blocked_scan=bool(artifact.blocked),
        evidence=[
            {
                "finding": f.name,
                "signals": [m.model_dump() for m in (f.matched_signals or [])],
            }
            for f in waf_findings[:5]
        ],
    )
    return report, scores
