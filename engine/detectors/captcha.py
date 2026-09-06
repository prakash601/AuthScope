"""Captcha detection: vendor + variant, visible vs invisible, score vs challenge."""

from __future__ import annotations

import re

from engine.artifacts import PageArtifact
from engine.detectors.base import Detector, Finding, match_signature
from engine.signatures import SignatureDef

_RENDER_PARAM_RE = re.compile(r"recaptcha/api\.js\?.*render=[A-Za-z0-9_-]+", re.I)


class CaptchaDetector(Detector):
    name = "captcha"

    def __init__(self, signatures: list[SignatureDef]) -> None:
        self._sigs = [s for s in signatures if s.category == "captcha"]
        # Vendor family -> DOM elements that prove a *rendered* widget.
        self._widget_dom_markers: dict[str, tuple[str, ...]] = {
            "recaptcha_v2_checkbox": ("g-recaptcha", "api2/anchor", "api2/bframe"),
            "recaptcha_v2_invisible": ("g-recaptcha-badges",),
            "recaptcha_v3_score": (),
            "recaptcha_enterprise_score": (),
            "hcaptcha": ("h-captcha", "hcaptcha.com/1/captcha"),
            "turnstile_managed": ("cf-turnstile",),
            "turnstile_non_interactive": (),
            "arkose_funaptcha": ("funcaptcha", "arkose"),
            "geetest_v3": ("geetest_radar_tip", "gt_slider", "geetest_box"),
            "geetest_v4": ("geetest_box", "captcha-box"),
        }
        self._score_based_names = {"recaptcha_v3_score", "recaptcha_enterprise_score"}

    async def detect(self, artifact: PageArtifact) -> list[Finding]:
        findings: list[Finding] = []
        html_l = artifact.dom.raw_html.lower()

        for sig in self._sigs:
            matched = match_signature(sig, artifact)
            if not matched:
                continue
            # A render=<sitekey> param means score-based reCAPTCHA; v2 variants
            # must not fire on it.
            blob = artifact.dom.raw_html + " ".join(artifact.dom.scripts)
            if (
                sig.name in ("recaptcha_v2_checkbox", "recaptcha_v2_invisible")
                and _RENDER_PARAM_RE.search(blob)
            ):
                continue

            widget_markers = self._widget_dom_markers.get(sig.name, ())
            visible = any(m.lower() in html_l for m in widget_markers)
            score_based = sig.name in self._score_based_names or sig.variant == "score"

            variant = "score_based_invisible" if score_based else (
                "challenge_visible" if visible else "challenge_invisible"
            )
            confidence = min(0.99, sig.confidence + 0.03) if visible else sig.confidence
            findings.append(
                Finding(
                    kind="captcha",
                    name=sig.name,
                    provider=sig.name.split("_")[0],
                    confidence=confidence,
                    matched_signals=matched,
                    extra={
                        "visible": visible,
                        "score_based": score_based,
                        "variant": variant,
                    },
                )
            )
        return findings
