"""ISS-016 tests: table-driven exact score math, caps, reasoning completeness."""

from __future__ import annotations

import pytest

from engine.artifacts import DomSummary, FormField, FormInfo, PageArtifact
from engine.detectors.base import Finding, MatchedSignal
from pipeline.scoring import HeuristicScoring


def make(**kw) -> PageArtifact:
    return PageArtifact(url="https://x.test/login", **kw)


def waf(name: str) -> Finding:
    return Finding(
        kind="waf",
        name=name,
        provider=name,
        confidence=0.9,
        matched_signals=[MatchedSignal(signal_type="cookie", value="c")],
    )


def captcha(visible: bool, score_based: bool = False, name="captcha_x") -> Finding:
    return Finding(
        kind="captcha",
        name=name,
        confidence=0.9,
        extra={"visible": visible, "score_based": score_based},
    )


def fp(name: str) -> Finding:
    return Finding(kind="fingerprinting", name=name, confidence=0.9)


def security(extra: dict) -> Finding:
    base = {
        "has_csrf": False,
        "has_hsts": True,
        "has_csp": True,
        "missing_security_headers": [],
        "cookie_flags": {"issues": {}},
        "mfa_detected": True,
        "raw_headers": {},
        "has_permissions_policy": True,
    }
    base.update(extra)
    return Finding(kind="security", name="posture", confidence=0.95, extra=base)


STRAT = HeuristicScoring()


# --- table-driven difficulty -------------------------------------------------

@pytest.mark.parametrize(
    "findings,artifact,expected",
    [
        # empty findings + clean artifact -> zero
        ([], make(), 0),
        # single tier-1 WAF
        ([waf("akamai_bm")], make(), 22),
        # single tier-2 WAF
        ([waf("cloudflare")], make(), 16),
        # single tier-3 (unknown vendor)
        ([waf("some_new_waf")], make(), 10),
        # two vendors: 22 + 16
        ([waf("akamai_bm"), waf("cloudflare")], make(), 38),
        # score-based captcha
        ([captcha(False, score_based=True)], make(), 20),
        # visible challenge captcha
        ([captcha(True)], make(), 12),
        # invisible challenge captcha
        ([captcha(False)], make(), 16),
        # one fingerprinting lib
        ([fp("fpjs_pro_bot_detection")], make(), 7),
        # blocked challenge
        ([], make(blocked=True), 10),
        # combined: akamai(22) + v3(20) + fpjs(7) + blocked(10)
        (
            [waf("akamai_bm"), captcha(False, score_based=True), fp("fpjs_pro_bot_detection")],
            make(blocked=True),
            59,
        ),
        # honeypot + csrf
        (
            [security({"has_csrf": True})],
            make(
                dom=DomSummary(
                    forms=[
                        FormInfo(
                            fields=[
                                FormField(name="bot", type="text", honeypot_candidate=True),
                                FormField(name="pw", type="password"),
                                FormField(name="_csrf", type="hidden"),
                            ]
                        )
                    ]
                )
            ),
            7,
        ),
    ],
)
def test_difficulty_exact(findings, artifact, expected):
    result = STRAT.score(findings, artifact)
    assert result.difficulty_score == expected


def test_waf_category_cap_40():
    findings = [waf(n) for n in ("akamai_bm", "kasada", "datadome")]  # 22*3=66 -> cap 40
    result = STRAT.score(findings, make())
    assert sum(f.points for f in result.factors if f.name.startswith("waf:")) == 40
    assert result.difficulty_score == 40


def test_captcha_category_cap_25():
    findings = [captcha(True, name=f"c{i}") for i in range(5)]  # 12*5 -> cap 25
    result = STRAT.score(findings, make())
    assert result.difficulty_score == 25


def test_fingerprint_cap_20():
    findings = [fp(f"lib_{i}") for i in range(4)]  # 7*4=28 -> cap 20
    assert STRAT.score(findings, make()).difficulty_score == 20


def test_total_never_exceeds_100():
    findings = [waf(n) for n in ("akamai_bm", "kasada", "datadome", "perimeterx_human")]
    findings += [captcha(True, name=f"v{i}") for i in range(3)]
    findings += [fp(f"l{i}") for i in range(4)]
    artifact = make(blocked=True)
    # WAF capped 40 + captcha capped 25 + fingerprint capped 20 + blocked 10
    assert STRAT.score(findings, artifact).difficulty_score == 95
    assert STRAT.score(findings, artifact).difficulty_score <= 100


def test_generic_auth_findings_do_not_add_difficulty():
    f = Finding(
        kind="auth_provider",
        name="generic_oidc_wellknown",
        provider="generic_oidc_wellknown",
        confidence=0.4,
    )
    assert STRAT.score([f], make()).difficulty_score == 0


# --- risk ----------------------------------------------------------------

RISK_TABLES = [
    ([security({"missing_security_headers": ["strict-transport-security"]})], make(), 20),
    (
        [security({"missing_security_headers": [
            "strict-transport-security", "content-security-policy",
            "x-frame-options", "referrer-policy",
        ], "has_permissions_policy": False})],
        make(),
        60,
    ),
    # cookie issue types: 2 types x 6
    (
        [
            security(
                {
                    "cookie_flags": {
                        "issues": {"missing_secure": ["s"], "missing_httponly": ["s"]}
                    }
                }
            )
        ],
        make(),
        12,
    ),
]


@pytest.mark.parametrize("findings,artifact,expected", RISK_TABLES)
def test_risk_exact(findings, artifact, expected):
    assert STRAT.score(findings, artifact).risk_score == expected


def test_risk_clean_page_reflects_only_missing_headers():
    """No security finding at all -> risk 0; headers missing -> header penalties only."""
    assert STRAT.score([], make()).risk_score == 0
    all_missing = security(
        {
            "missing_security_headers": [
                "strict-transport-security",
                "content-security-policy",
                "x-frame-options",
                "referrer-policy",
            ],
            "has_permissions_policy": False,
        }
    )
    r = STRAT.score([all_missing], make())
    assert r.risk_score == 60
    assert {f.name for f in r.risk_factors} == {
        "missing:HSTS", "missing:CSP", "missing:X-Frame-Options",
        "missing:Referrer-Policy", "missing:Permissions-Policy",
    }


def test_risk_csrf_absent_on_password_form():
    artifact = make(
        dom=DomSummary(forms=[FormInfo(fields=[FormField(name="pw", type="password")])])
    )
    no_mfa_no_csrf = security({"mfa_detected": False})
    r = STRAT.score([no_mfa_no_csrf], artifact)
    names = {f.name for f in r.risk_factors}
    assert "csrf:absent_on_password_form" in names and "mfa:no_signal_detected" in names
    assert r.risk_score == 20


# --- reasoning --------------------------------------------------------------

def test_reasoning_enumerates_every_nonzero_factor():
    findings = [waf("akamai_bm"), captcha(False, score_based=True), fp("castle")]
    artifact = make(blocked=True)
    result = STRAT.score(findings, artifact)
    for factor in result.factors:
        assert factor.name in result.reasoning
        assert f"(+{factor.points})" in result.reasoning
    assert str(result.difficulty_score) in result.reasoning


def test_reasoning_empty_case():
    result = STRAT.score([], make())
    assert "no automation blockers detected" in result.reasoning
    assert result.difficulty_score == 0
