"""Security posture detection: headers, cookie flags, CSRF, honeypots, MFA, password policy."""

from __future__ import annotations

import contextlib
import re

from engine.artifacts import CookieInfo, PageArtifact
from engine.detectors.base import Detector, Finding

SESSION_COOKIE_HINTS = ("sess", "login", "auth", "token", "sid", "jwt", "sessionid")

CSRF_INPUT_NAMES = {
    "csrf", "csrftoken", "_csrf", "csrf_token", "csrfmiddlewaretoken",
    "_token", "authenticity_token", "xsrf-token", "anticsrf",
}

MFA_TEXT_RE = re.compile(
    r"two[- ]factor|2fa|multi[- ]factor|authenticator app|verify (?:your|the) code"
    r"|enter the (?:code|otp)|one[- ]time code|backup codes",
    re.I,
)

PASSWORD_POLICY_RE = re.compile(r"(?:min(?:imum)?[-_ ]?length|minLength)\s*[:=]\s*(\d{1,3})", re.I)


def parse_hsts(value: str) -> dict:
    parts = value.lower().split(";")
    out: dict = {"present": True}
    for part in parts:
        part = part.strip()
        if part.startswith("max-age"):
            _, _, num = part.partition("=")
            with contextlib.suppress(ValueError):
                out["max_age"] = int(num.strip())
        elif part == "includesubdomains":
            out["include_subdomains"] = True
        elif part == "preload":
            out["preload"] = True
    return out


def parse_csp(value: str) -> dict:
    directives = {}
    for directive in value.split(";"):
        bits = directive.strip().split()
        if bits:
            directives[bits[0]] = " ".join(bits[1:])
    return directives


def cookie_issues(cookies: list[CookieInfo]) -> dict[str, list[str]]:
    issues: dict[str, list[str]] = {
        "missing_secure": [], "missing_httponly": [], "missing_samesite": []
    }
    for c in cookies:
        name_l = c.name.lower()
        if not any(h in name_l for h in SESSION_COOKIE_HINTS):
            continue
        if not c.secure:
            issues["missing_secure"].append(c.name)
        if not c.httponly:
            issues["missing_httponly"].append(c.name)
        if str(c.samesite).lower() == "none":
            issues["missing_samesite"].append(c.name)
    return {k: v for k, v in issues.items() if v}


def detect_csrf(artifact: PageArtifact) -> bool:
    meta_names = {m.name.lower() for m in artifact.dom.metas}
    if "csrf-token" in meta_names or "csrf" in meta_names:
        return True
    for form in artifact.dom.forms:
        for fd in form.fields:
            if fd.type == "hidden" and fd.name.lower() in CSRF_INPUT_NAMES:
                return True
    html_l = artifact.dom.raw_html[:200_000].lower()
    return 'name="csrf"' in html_l or "name='_csrf'" in html_l


class SecurityDetector(Detector):
    name = "security"

    async def detect(self, artifact: PageArtifact) -> list[Finding]:
        h = artifact.headers
        hsts_raw = h.get("strict-transport-security")
        csp_raw = h.get("content-security-policy")

        has_hsts = hsts_raw is not None
        has_csp = csp_raw is not None
        has_xfo = "x-frame-options" in h
        has_coop = "cross-origin-opener-policy" in h
        has_corp = "cross-origin-resource-policy" in h
        has_coep = "cross-origin-embedder-policy" in h
        has_permissions_policy = any(k in h for k in ("permissions-policy", "feature-policy"))
        has_referrer_policy = "referrer-policy" in h

        has_csrf = detect_csrf(artifact)
        honeypots = [
            fd.name
            for f in artifact.dom.forms
            for fd in f.fields
            if fd.honeypot_candidate
        ]
        mfa_detected = bool(MFA_TEXT_RE.search(artifact.dom.body_text_sample))

        policy_min_length: int | None = None
        inline_blob = " ".join(artifact.dom.inline_scripts)
        m = PASSWORD_POLICY_RE.search(inline_blob)
        if m:
            candidate = int(m.group(1))
            if 4 <= candidate <= 128:
                policy_min_length = candidate

        missing_headers = [
            name
            for name, present in (
                ("strict-transport-security", has_hsts),
                ("content-security-policy", has_csp),
                ("x-frame-options", has_xfo),
                ("referrer-policy", has_referrer_policy),
            )
            if not present
        ]

        extra = {
            "has_csrf": has_csrf,
            "has_hsts": has_hsts,
            "hsts_details": parse_hsts(hsts_raw) if hsts_raw else {},
            "has_csp": has_csp,
            "csp_directives": parse_csp(csp_raw) if csp_raw else {},
            "has_x_frame_options": has_xfo,
            "has_coop": has_coop,
            "has_corp": has_corp,
            "has_coep": has_coep,
            "has_permissions_policy": has_permissions_policy,
            "cookie_flags": {
                "issues": cookie_issues(artifact.cookies),
                "all_cookies": [
                    {
                        "name": c.name,
                        "secure": c.secure,
                        "httponly": c.httponly,
                        "samesite": c.samesite,
                    }
                    for c in artifact.cookies
                ],
            },
            "mfa_detected": bool(mfa_detected),
            "honeypot_fields": honeypots,
            "password_policy_min_length": policy_min_length,
            "missing_security_headers": missing_headers,
            "raw_headers": artifact.headers,
        }

        confidence = 0.95 if artifact.headers else 0.5
        return [
            Finding(
                kind="security",
                name="posture",
                provider=None,
                confidence=confidence,
                extra=extra,
            )
        ]
