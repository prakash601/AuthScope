"""Unit tests for detectors using hand-built PageArtifacts (no browser needed)."""

from __future__ import annotations

import pytest

from engine.artifacts import (
    CapturedRequest,
    CookieInfo,
    DomSummary,
    FormField,
    FormInfo,
    PageArtifact,
)
from engine.detectors.auth_provider import AuthProviderDetector
from engine.detectors.base import confidence_for_signals
from engine.detectors.captcha import CaptchaDetector
from engine.detectors.fingerprinting import FingerprintDetector
from engine.detectors.security import SecurityDetector
from engine.detectors.waf import WAFDetector
from engine.signatures import load_yaml_dir
from tests.conftest import SIGNATURES_DIR


@pytest.fixture(scope="module")
def all_sigs():
    return load_yaml_dir(SIGNATURES_DIR)


def make_artifact(**kwargs) -> PageArtifact:
    return PageArtifact(url="https://example.com/login", **kwargs)


# ---------------------------------------------------------------------------
# ISS-012 AuthProviderDetector
# ---------------------------------------------------------------------------

def auth0_artifact() -> PageArtifact:
    return make_artifact(
        dom=DomSummary(
            title="Sign in",
            scripts=["https://cdn.auth0.com/js/auth0-spa-js/2.0/auth0-spa-js.production.js"],
            forms=[
                FormInfo(
                    action="https://example.us.auth0.com/u/login",
                    method="POST",
                    fields=[
                        FormField(name="username", type="text"),
                        FormField(name="password", type="password"),
                    ],
                )
            ],
        ),
        globals=["auth0Client"],
        requests=[
            CapturedRequest(
                url="https://example.us.auth0.com/.well-known/openid-configuration",
                resource_type="fetch",
                is_xhr_fetch=True,
            )
        ],
        hook_log=[
            {
                "kind": "fetch",
                "method": "GET",
                "url": "https://example.us.auth0.com/.well-known/openid-configuration",
            }
        ],
    )


async def test_auth0_multi_signal_high_confidence(all_sigs):
    findings = await AuthProviderDetector(all_sigs).detect(auth0_artifact())
    auth = [f for f in findings if f.kind == "auth_provider"]
    assert len(auth) == 1
    f = auth[0]
    assert f.provider == "auth0"
    assert f.confidence >= 0.9
    assert {m.signal_type for m in f.matched_signals} >= {"script_src", "global_object"}
    assert "password" in f.extra.get("flows", [])
    assert "oauth_code" in f.extra.get("flows", [])


async def test_auth0_single_signal_lower_confidence(all_sigs):
    artifact = make_artifact(
        dom=DomSummary(scripts=["https://cdn.auth0.com/js/auth0-spa-js.js"])
    )
    findings = await AuthProviderDetector(all_sigs).detect(artifact)
    auth = [f for f in findings if f.kind == "auth_provider"]
    assert auth and auth[0].provider == "auth0"
    multi = (await AuthProviderDetector(all_sigs).detect(auth0_artifact()))[0]
    single_conf, multi_conf = auth[0].confidence, multi.confidence
    assert single_conf < multi_conf


async def test_no_signature_match_yields_custom(all_sigs):
    artifact = make_artifact(
        dom=DomSummary(
            forms=[
                FormInfo(
                    action="/login_check",
                    method="POST",
                    fields=[
                        FormField(name="_username", type="text"),
                        FormField(name="_password", type="password"),
                    ],
                )
            ]
        )
    )
    findings = await AuthProviderDetector(all_sigs).detect(artifact)
    auth = [f for f in findings if f.kind == "auth_provider"]
    assert len(auth) == 1 and auth[0].provider == "custom"
    assert "password" in auth[0].extra.get("flows", [])


async def test_generic_oidc_hint_with_custom_form_reports_custom(all_sigs):
    artifact = make_artifact(
        requests=[CapturedRequest(url="https://sso.corp.example/.well-known/openid-configuration")],
        dom=DomSummary(
            forms=[
                FormInfo(
                    action="/auth",
                    method="POST",
                    fields=[FormField(name="pw", type="password")],
                )
            ]
        ),
    )
    findings = await AuthProviderDetector(all_sigs).detect(artifact)
    auth = [f for f in findings if f.kind == "auth_provider"]
    assert auth[0].provider == "custom"


async def test_flow_detection_webauthn_otp_magic(all_sigs):
    sigs = [s for s in all_sigs if s.category != "auth"]  # force no provider match
    webauthn2 = make_artifact(
        dom=DomSummary(
            inline_scripts=["await navigator.credentials.get({ publicKey: {} })"],
            raw_html="passkey login",
        ),
        globals=["navigator.credentials"],
    )
    flows = await AuthProviderDetector([*sigs]).detect(webauthn2)
    kinds = {(f.kind, tuple(f.extra.get("flows", []))) for f in flows}
    assert any("webauthn" in fl for _, fl in kinds), flows

    otp = make_artifact(
        dom=DomSummary(
            forms=[
                FormInfo(
                    fields=[
                        FormField(
                            name="code", type="text",
                            autocomplete="one-time-code", maxlength=6,
                        )
                    ]
                )
            ],
            raw_html="enter the code we sent",
        )
    )
    otp_findings = await AuthProviderDetector([]).detect(otp)
    assert any("otp" in f.extra.get("flows", []) for f in otp_findings)

    magic = make_artifact(
        dom=DomSummary(
            forms=[FormInfo(fields=[FormField(name="email", type="email")])],
            body_text_sample="We will email you a magic link to sign in",
            raw_html="<form></form>",
        )
    )
    magic_findings = await AuthProviderDetector([]).detect(magic)
    assert any("magic_link" in f.extra.get("flows", []) for f in magic_findings)


async def test_conflict_resolution_prefers_specificity(all_sigs):
    """Generic OIDC fallback must lose to a specific vendor when both match."""
    artifact = auth0_artifact()
    artifact.requests.append(
        CapturedRequest(url="https://other.example/.well-known/openid-configuration")
    )
    findings = await AuthProviderDetector(all_sigs).detect(artifact)
    auth = [f for f in findings if f.kind == "auth_provider"][0]
    assert auth.provider == "auth0"


# ---------------------------------------------------------------------------
# ISS-013 SecurityDetector
# ---------------------------------------------------------------------------

async def test_security_full_headers_and_flags():
    artifact = make_artifact(
        headers={
            "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
            "content-security-policy": "default-src 'self'; script-src 'self' cdn",
            "x-frame-options": "DENY",
            "referrer-policy": "no-referrer",
            "permissions-policy": "geolocation=()",
        },
        cookies=[
            CookieInfo(name="sessionid", value="x", secure=True, httponly=True, samesite="Lax"),
        ],
        dom=DomSummary(
            forms=[
                FormInfo(
                    action="/login",
                    fields=[
                        FormField(name="csrf_token", type="hidden"),
                        FormField(name="user", type="text"),
                        FormField(name="pass", type="password", autocomplete="current-password"),
                    ],
                )
            ]
        ),
    )
    finding = (await SecurityDetector().detect(artifact))[0]
    e = finding.extra
    assert e["has_hsts"] and e["hsts_details"]["max_age"] == 31536000
    assert e["has_csp"] and "default-src" in e["csp_directives"]
    assert e["has_x_frame_options"] is True
    assert e["has_csrf"] is True
    assert e["missing_security_headers"] == []
    assert e["cookie_flags"]["issues"] == {}
    assert "csrf_token" not in e["honeypot_fields"]


async def test_security_missing_headers_and_cookie_issues():
    artifact = make_artifact(
        headers={"server": "nginx"},
        cookies=[
            CookieInfo(name="sessionid", value="x", secure=False, httponly=False),
            CookieInfo(name="tracking", value="y"),  # non-session: ignored
        ],
        dom=DomSummary(),
    )
    finding = (await SecurityDetector().detect(artifact))[0]
    e = finding.extra
    assert set(e["missing_security_headers"]) >= {
        "strict-transport-security",
        "content-security-policy",
    }
    assert "sessionid" in e["cookie_flags"]["issues"]["missing_secure"]
    assert "tracking" not in str(e["cookie_flags"]["issues"])
    assert e["has_csrf"] is False


async def test_security_honeypot_and_mfa_and_policy():
    artifact = make_artifact(
        dom=DomSummary(
            forms=[
                FormInfo(
                    fields=[
                        FormField(name="bot-field", type="text", honeypot_candidate=True),
                        FormField(name="code", type="text", autocomplete="one-time-code"),
                    ]
                )
            ],
            body_text_sample="Enter your two-factor authentication code",
            inline_scripts=["rules = { minLength: 12 }"],
        )
    )
    finding = (await SecurityDetector().detect(artifact))[0]
    e = finding.extra
    assert e["honeypot_fields"] == ["bot-field"]
    assert e["mfa_detected"] is True
    assert e["password_policy_min_length"] == 12


# ---------------------------------------------------------------------------
# ISS-014 Captcha / WAF / Fingerprint
# ---------------------------------------------------------------------------

async def test_recaptcha_v3_score_invisible(all_sigs):
    artifact = make_artifact(
        dom=DomSummary(
            scripts=["https://www.google.com/recaptcha/api.js?render=6LcAbCdEfGh"],
            inline_scripts=["grecaptcha.ready(() => grecaptcha.execute('6Lc'));"],
        )
    )
    findings = await CaptchaDetector(all_sigs).detect(artifact)
    assert findings and findings[0].name == "recaptcha_v3_score"
    assert findings[0].extra["score_based"] is True
    assert findings[0].extra["visible"] is False
    assert findings[0].extra["variant"] == "score_based_invisible"


async def test_turnstile_visible_vs_invisible(all_sigs):
    visible = make_artifact(
        dom=DomSummary(
            scripts=["https://challenges.cloudflare.com/turnstile/v0/api.js?onload=x"],
            raw_html='<div class="cf-turnstile" data-sitekey="0x4"></div>',
        )
    )
    invisible = make_artifact(
        dom=DomSummary(scripts=["https://challenges.cloudflare.com/turnstile/v0/api.js?onload=x"])
    )
    v = (await CaptchaDetector(all_sigs).detect(visible))
    i = (await CaptchaDetector(all_sigs).detect(invisible))
    assert any(f.name == "turnstile_managed" and f.extra["visible"] for f in v)
    assert any(f.name == "turnstile_non_interactive" and not f.extra["visible"] for f in i) or \
           any(not f.extra["visible"] for f in i)


async def test_recaptcha_v2_checkbox_visible(all_sigs):
    artifact = make_artifact(
        dom=DomSummary(
            scripts=["https://www.google.com/recaptcha/api.js"],
            raw_html='<div class="g-recaptcha" data-sitekey="6Lc"></div>'
                     '<iframe src="https://www.google.com/recaptcha/api2/anchor?ar=1"></iframe>',
        )
    )
    findings = await CaptchaDetector(all_sigs).detect(artifact)
    top = max(findings, key=lambda f: f.confidence)
    assert top.name == "recaptcha_v2_checkbox"
    assert top.extra["visible"] is True and top.extra["score_based"] is False


async def test_arkose_funaptcha_visible_vs_script_only(all_sigs):
    widget = make_artifact(
        dom=DomSummary(
            scripts=["https://client-api.arkoselabs.com/v2/1.5.5/index.js"],
            raw_html='<div id="funcaptcha"></div>',
        )
    )
    script_only = make_artifact(
        dom=DomSummary(scripts=["https://client-api.arkoselabs.com/v2/1.5.5/index.js"])
    )
    w = await CaptchaDetector(all_sigs).detect(widget)
    ark = [f for f in w if f.name == "arkose_funaptcha"][0]
    assert ark.extra["visible"] is True
    assert ark.extra["variant"] == "challenge_visible"
    s = await CaptchaDetector(all_sigs).detect(script_only)
    ark2 = [f for f in s if f.name == "arkose_funaptcha"][0]
    assert ark2.extra["visible"] is False


async def test_waf_headers_cookies_and_interstitial(all_sigs):
    cookie_only = make_artifact(
        cookies=[CookieInfo(name="_abck", value="v")],
    )
    findings = await WAFDetector(all_sigs).detect(cookie_only)
    assert any(f.provider == "akamai_bm" for f in findings)

    full = make_artifact(
        headers={"server": "cloudflare", "cf-ray": "abc"},
        cookies=[CookieInfo(name="__cf_bm", value="v")],
        blocked=True,
        blocked_reason="just a moment",
    )
    findings = await WAFDetector(all_sigs).detect(full)
    cf = [f for f in findings if f.provider == "cloudflare"][0]
    assert cf.extra["blocked_scan"] is True
    assert len(cf.matched_signals) >= 2


async def test_waf_unknown_block(all_sigs):
    artifact = make_artifact(blocked=True, blocked_reason="http_403")
    findings = await WAFDetector(all_sigs).detect(artifact)
    assert findings[0].name == "unknown_block"
    assert findings[0].extra["blocked_scan"] is True


async def test_fingerprinting_vendor_and_generic_reads(all_sigs):
    vendor = make_artifact(
        dom=DomSummary(scripts=["https://fpjscdn.net/v3/iHateBots/loader.min.js"]),
    )
    findings = await FingerprintDetector(all_sigs).detect(vendor)
    assert any(f.name == "fpjs_pro_bot_detection" for f in findings)

    generic = make_artifact(fingerprint_reads={"canvas_dataurl": 6, "canvas_imagedata": 4})
    findings = await FingerprintDetector(all_sigs).detect(generic)
    assert any(f.name == "browser_fingerprint_collection" for f in findings)

    benign = make_artifact(fingerprint_reads={"canvas_dataurl": 1})
    assert await FingerprintDetector(all_sigs).detect(benign) == []


# ---------------------------------------------------------------------------
# Confidence model
# ---------------------------------------------------------------------------

def test_confidence_scaling():
    base = 0.92
    assert confidence_for_signals(base, 1, 5) == round(base * 0.7, 3)
    assert confidence_for_signals(base, 2, 5) == round(base * 0.85, 3)
    assert confidence_for_signals(base, 3, 5) == min(0.99, base)
    # all-defined with multiple signals gets at least 95% of base
    assert confidence_for_signals(base, 5, 5) >= base * 0.95
