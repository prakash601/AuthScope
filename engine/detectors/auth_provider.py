"""Auth provider detection: signature correlation + auth flow inference."""

from __future__ import annotations

import re

from engine.artifacts import PageArtifact
from engine.detectors.base import (
    Detector,
    Finding,
    MatchedSignal,
    confidence_for_signals,
    match_signature,
)
from engine.signatures import SignatureDef

_FLOW_URL_HINTS: dict[str, tuple[str, ...]] = {
    "oauth_code": (
        "/authorize", "/oauth2/", "response_type=code", "client_id=",
        "openid-configuration", "securetoken", "identitytoolkit",
    ),
    "saml": ("SAMLRequest", "/saml/", "saml2"),
}

_MAGIC_LINK_RE = re.compile(r"magic[- ]?link|sign[- ]?in (?:with )?(?:a )?link", re.I)
_OTP_RE = re.compile(r"\b(?:otp|one[- ]time (?:code|password)|verification code)\b", re.I)
_WEBAUTHN_RE = re.compile(r"navigator\.credentials\.(?:get|create)\s*\(\s*\{\s*publicKey", re.I)


def infer_flows(artifact: PageArtifact) -> list[str]:
    flows: list[str] = []
    urls = [r.url for r in artifact.requests] + [h.get("url", "") for h in artifact.hook_log]
    url_blob = " ".join(urls)
    form_html = artifact.dom.raw_html
    inline = " ".join(artifact.dom.inline_scripts)

    if any(h.lower() in url_blob.lower() for h in _FLOW_URL_HINTS["oauth_code"]):
        flows.append("oauth_code")
    if any(h in url_blob or h in form_html for h in _FLOW_URL_HINTS["saml"]):
        flows.append("saml")
    if any(f.fields and any(fd.type == "password" for fd in f.fields) for f in artifact.dom.forms):
        flows.append("password")
    if "PublicKeyCredential" in artifact.globals or _WEBAUTHN_RE.search(
        inline + form_html[:100_000]
    ):
        flows.append("webauthn")
    body_text = artifact.dom.body_text_sample
    has_pw_form = any(
        fd.type == "password" for f in artifact.dom.forms for fd in f.fields
    )
    if _MAGIC_LINK_RE.search(body_text + form_html) and not has_pw_form:
        flows.append("magic_link")
    if any(
        fd.autocomplete == "one-time-code"
        for f in artifact.dom.forms
        for fd in f.fields
    ) or (_OTP_RE.search(form_html) and any(
        fd.maxlength is not None and 0 < fd.maxlength <= 8
        for f in artifact.dom.forms
        for fd in f.fields
    )):
        flows.append("otp")
    return flows


class AuthProviderDetector(Detector):
    name = "auth_provider"

    def __init__(self, signatures: list[SignatureDef]) -> None:
        self._auth_sigs = [
            s for s in signatures if s.category == "auth" and s.type == "auth_provider"
        ]
        # Prefer specific vendors over generic fallbacks on ties/conflicts.
        self._generic_names = {
            "generic_oidc_wellknown",
            "generic_oauth_authorize",
            "generic_oauth2_authorize",
        }

    async def detect(self, artifact: PageArtifact) -> list[Finding]:
        candidates: list[tuple[int, int, float, str, SignatureDef, list[MatchedSignal]]] = []
        for sig in self._auth_sigs:
            matched = match_signature(sig, artifact)
            if not matched:
                continue
            conf = confidence_for_signals(sig.confidence, len(matched), len(sig.signals))
            specificity = 0 if sig.name in self._generic_names else 1
            candidates.append((specificity, len(matched), conf, sig.name, sig, matched))

        findings: list[Finding] = []
        if candidates:
            # Conflict resolution: vendor-specific > more signals > higher confidence.
            candidates.sort(key=lambda c: (-c[0], -c[1], -c[2]))
            best_spec, _, _, best_name, best_sig, best_matched = candidates[0]
            confidence = max(c[2] for c in candidates if c[0] == best_spec)

            has_password_form = bool(self._has_password_form(artifact))
            extra: dict = {"note": "generic OAuth/OIDC signals with a custom login form"} if (
                best_spec == 0 and has_password_form
            ) else {}
            provider = "custom" if (best_spec == 0 and has_password_form) else best_name
            name = best_name
            extra["signature"] = best_sig.model_dump(mode="json")
            findings.append(
                Finding(
                    kind="auth_provider",
                    name=name,
                    provider=provider,
                    confidence=confidence,
                    matched_signals=best_matched,
                    extra=extra,
                )
            )
        elif self._has_login_form(artifact):
            findings.append(
                Finding(
                    kind="auth_provider",
                    name="custom",
                    provider="custom",
                    confidence=0.5,
                    extra={"note": "no signature matched; self-hosted/custom login form detected"},
                )
            )

        flows = infer_flows(artifact)
        if flows:
            base = findings[0] if findings else None
            if base:
                base.extra["flows"] = flows
                base.confidence = min(0.99, base.confidence + 0.03 * len(flows))
            else:
                findings.append(
                    Finding(
                        kind="auth_flow",
                        name=",".join(flows),
                        confidence=0.6,
                        extra={"flows": flows},
                    )
                )
        return findings

    @staticmethod
    def _has_password_form(artifact: PageArtifact) -> bool:
        return AuthProviderDetector._has_login_form(artifact)

    @staticmethod
    def _has_login_form(artifact: PageArtifact) -> bool:
        return any(
            fd.type in ("password", "email")
            or fd.autocomplete in ("username", "email", "current-password")
            for f in artifact.dom.forms
            for fd in f.fields
        )
