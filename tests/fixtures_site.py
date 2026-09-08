"""Offline fixture site + HTTP server for integration tests.

Script/network signals reference vendor domains via *path prefixes*
(e.g. ``/scripts/cdn.auth0.com/app.js``) so signature matching works
without any external network access.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FIXTURE_PORT = 8931
_FLAKY_HITS = 0


def page(name: str) -> str:
    return f"http://127.0.0.1:{FIXTURE_PORT}/{name}"


HTML = {
    "index.html": "<html><head><title>Index</title></head><body>ok</body></html>",
    "auth0_like.html": """
<html><head><title>Sign in</title>
<script src="/scripts/cdn.auth0.com/auth0-spa-js.production.js"></script></head>
<body><form action="/u/login" method="POST">
<input name="username" type="text"><input name="password" type="password">
<button id="login">Log in</button></form>
<script>
fetch('/api/tenant.us.auth0.com/.well-known/openid-configuration');
</script></body></html>""",
    "auth0_script_only.html": """
<html><head><title>Sign in</title>
<script src="/scripts/cdn.auth0.com/auth0-spa-js.production.js"></script></head>
<body>hello</body></html>""",
    "csp_page.html": """
<html><head><meta http-equiv="Content-Security-Policy"
 content="default-src 'self'; script-src 'self'">
<title>CSP protected</title></head>
<body><script src="/app.js"></script></body></html>""",
    "app.js": "fetch('/api/internal/ping');",
    "xhr_page.html": """
<html><body><script>
const x = new XMLHttpRequest();
x.open('POST', '/api/xhr-endpoint');
x.send('{}');
</script></body></html>""",
    "fingerprint_read.html": """
<html><body><canvas id="c"></canvas><script>
const c = document.getElementById('c');
c.getContext('2d').getImageData(0,0,1,1);
c.toDataURL();
</script></body></html>""",
    "honeypot.html": """
<html><body><form action="/login" method="post">
<input name="email" type="email">
<input name="bot-field" type="text" style="display:none" tabindex="-1" aria-hidden="true">
<input name="password" type="password"></form></body></html>""",
    "pii_page.html": """
<html><body>Contact alice@example.com or call 555-867-5309.
token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c
</body></html>""",
    "turnstile_invisible.html": """
<html><head>
<script src="/scripts/challenges.cloudflare.com/turnstile/v0/api.js?onload=cb"></script>
</head><body><form><input type="password" name="pw"><script>cb();</script></form></body></html>""",
    "turnstile_visible.html": """
<html><head>
<script src="/scripts/challenges.cloudflare.com/turnstile/v0/api.js"></script>
</head><body><div class="cf-turnstile" data-sitekey="0x4AAAAAAAD"></div></body></html>""",
    "recaptcha_v2_checkbox.html": """
<html><head><script src="/scripts/www.gstatic.com/recaptcha/releases/render.js"></script>
<script src="/scripts/www.google.com/recaptcha/api.js"></script></head>
<body><form><div class="g-recaptcha" data-sitekey="6Lc..."></div>
<iframe src="/frames/www.google.com/recaptcha/api2/anchor"></iframe></form></body></html>""",
    "recaptcha_v3.html": """
<html><head>
<script src="/scripts/www.google.com/recaptcha/api.js?render=6LcSiteKey"></script>
</head><body><form><input type="password" name="pw"></form>
<script>grecaptcha.ready(function(){ grecaptcha.execute('6Lc', {action:'login'}); });</script>
</body></html>""",
    "hcaptcha_visible.html": """
<html><head><script src="/scripts/js.hcaptcha.com/1/api.js"></script></head>
<body><div class="h-captcha" data-sitekey="10000000-ffff"></div></body></html>""",
    "arkose.html": """
<html><head><script src="/scripts/client-api.arkoselabs.com/v2/1.5.5/index.js"></script>
</head><body><div id="funcaptcha"></div></body></html>""",
    "datadome_like.html": """
<html><head><script src="/scripts/js.datadome.co/tags.js"></script></head>
<body><form><input type="password" name="pw"></form></body></html>""",
    "akamai_like.html": """
<html><head><script src="/scripts/client.akamai.com/bm/site_js.js"></script></head>
<body><form><input type="password" name="pw"></form></body></html>""",
    "perimeterx_like.html": """
<html><head><script src="/scripts/client.px-cdn.net/main.min.js"></script></head>
<body><form><input type="password" name="pw"></form></body></html>""",
    "kasada_challenge.html": """
<html><head><title>Verifying you are human</title>
<script src="/scripts/js.kasada.io/x/kasada.js"></script></head>
<body>Please verify to continue</body></html>""",
    "fpjs_pro.html": """
<html><head><script src="/scripts/fpjs.io/v3/loader.min.js"></script></head>
<body><script>const fp = await FingerprintJS.load({apiKey: 'k'});</script></body></html>""",
    "castle_like.html": """
<html><head><script src="/scripts/castle.io/v2/mod.js"></script></head>
<body><form><input type="password" name="pw"></form></body></html>""",
    "webauthn_like.html": """
<html><body><form><input type="hidden" name="csrf_token" value="abc123">
<button onclick="navigator.credentials.get({publicKey: {}})">Passkey login</button></form>
</body></html>""",
    "magic_link.html": """
<html><body><form action="/auth/magic" method="post">
<input name="email" type="email" autocomplete="email">
<button>Send magic link</button></form></body></html>""",
    "otp_page.html": """
<html><body><form><input name="code" inputmode="numeric" autocomplete="one-time-code"
 maxlength="6" pattern="[0-9]*"></form></body></html>""",
    "saml_form.html": """
<html><body><form action="https://idp.example.com/sso" method="POST">
<input type="hidden" name="SAMLRequest" value="PHNhbWxwOkF1dGhu"></form></body></html>""",
    "ws_page.html": """
<html><body><script>
try { new WebSocket('ws://127.0.0.1:8931/socket'); } catch (e) {}
</script></body></html>""",
    "sse_page.html": """
<html><body><script>
try { new EventSource('/api/events'); } catch (e) {}
</script></body></html>""",
}


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence test noise
        pass

    def send_response(self, code, message=None):
        # Skip BaseHTTPRequestHandler's automatic Server header so fixture
        # headers (e.g. Server: cloudflare) are exact.
        self.log_request(code)
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())

    def _send(
        self,
        body: bytes,
        status: int = 200,
        headers: dict | None = None,
        content_type: str = "text/html",
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/blocked/cloudflare":
            self._send(
                b"<html><head><title>Just a moment...</title></head>"
                b"<body>Verifying you are human. This is a cf-challenge.</body></html>",
                status=403,
                headers={"Server": "cloudflare"},
            )
            return
        if path == "/flaky_block.html":
            # 403 challenge on the FIRST hit, real page afterwards (retry testing).
            global _FLAKY_HITS
            _FLAKY_HITS += 1
            if _FLAKY_HITS <= 1:
                self._send(
                    b"<html><head><title>Just a moment...</title></head>"
                    b"<body>Verifying you are human</body></html>",
                    status=403,
                )
                return
            self._send(
                HTML["password_form_like"].encode(),
                headers={"Set-Cookie": "sessionid=fresh; Path=/"},
            )
            return
        if path == "/waf_cookies.html":
            self._send(
                HTML["akamai_like.html"].encode(),
                headers={
                    "Set-Cookie": "__cf_bm=abc123; Path=/; Secure; HttpOnly",
                    "Server": "cloudflare",
                },
            )
            return
        if path == "/security_headers.html":
            body = HTML["password_form_like"].encode() if False else b"<html><body>hi</body></html>"
            self._send(
                body,
                headers={
                    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
                    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
                    "X-Frame-Options": "DENY",
                    "Permissions-Policy": "geolocation=()",
                    "Referrer-Policy": "no-referrer",
                    "Set-Cookie": "sessionid=xyz; Path=/",
                },
            )
            return
        name = path.lstrip("/") or "index.html"
        if name in HTML:
            ctype = "application/javascript" if name.endswith(".js") else "text/html"
            self._send(HTML[name].encode(), content_type=ctype)
            return
        # Vendor-domain path tricks: /scripts/<domain>/<file> and /api/<domain>/<file>
        self._send(b"", status=200, content_type="application/javascript")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        self._send(b"{}", content_type="application/json")


class FixtureSite:
    """Threading HTTP server hosting the fixture pages."""

    def __init__(self, port: int = FIXTURE_PORT) -> None:
        self.port = port
        self._server = ThreadingHTTPServer(("127.0.0.1", port), FixtureHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def start(self) -> FixtureSite:
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()


# small helper page used by the security-headers route
HTML["password_form_like"] = (
    "<html><body><form><input name='user'><input type='password' name='pass'></form></body></html>"
)
