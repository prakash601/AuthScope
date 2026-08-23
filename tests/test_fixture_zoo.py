"""ISS-027 meta-tests: fixture zoo breadth and detection coverage."""

from __future__ import annotations

from tests.fixtures_site import HTML


def test_fixture_zoo_has_at_least_15_pages():
    html_pages = [k for k, v in HTML.items() if k.endswith(".html") or "<html" in v]
    assert len(html_pages) >= 15


def test_fixture_zoo_covers_major_detections():
    all_html = "\n".join(HTML.values()).lower()
    coverage = {
        "auth provider (auth0)": "cdn.auth0.com" in all_html,
        "captcha turnstile": "challenges.cloudflare.com/turnstile" in all_html,
        "captcha recaptcha v3": "recaptcha/api.js?render=" in all_html,
        "captcha hcaptcha": "hcaptcha.com/1/api.js" in all_html,
        "captcha arkose": "arkoselabs" in all_html,
        "waf datadome": "datadome" in all_html,
        "waf akamai": "client.akamai.com" in all_html,
        "waf perimeterx": "px-cdn.net" in all_html,
        "waf kasada challenge": "kasada" in all_html,
        "fingerprinting fpjs": "fpjs.io" in all_html or "fpjscdn" in all_html,
        "fingerprinting castle": "castle.io" in all_html,
        "honeypot fields": "bot-field" in all_html,
        "csrf token form": "csrf_token" in all_html,
        "webauthn/passkey": "publickey" in all_html,
        "magic link": "magic link" in all_html,
        "otp code input": "one-time-code" in all_html,
        "saml flow": "samlrequest" in all_html,
        "pii stripping fixture": "@example.com" in all_html,
    }
    missing = [k for k, ok in coverage.items() if not ok]
    assert not missing, f"fixture zoo missing coverage: {missing}"


def test_blocked_and_flaky_routes_exist():
    import inspect

    from tests.fixtures_site import FixtureHandler

    assert hasattr(FixtureHandler, "do_GET")
    src_text = inspect.getsource(FixtureHandler.do_GET)
    for route in ("/blocked/cloudflare", "/flaky_block.html", "/security_headers.html"):
        assert route in src_text, route
