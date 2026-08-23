"""Browser fingerprint generation: real UA rotation, viewport/locale randomization."""

from __future__ import annotations

import random
from dataclasses import dataclass, field

# Real-world Chrome/Firefox/Safari UA strings (subset; rotate from dataset).
USER_AGENTS: tuple[str, ...] = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
)

VIEWPORTS: tuple[tuple[int, int], ...] = (
    (1920, 1080), (1536, 864), (1440, 900), (1366, 768),
    (2560, 1440), (1680, 1050), (1600, 900), (1280, 800),
)

LOCALES: tuple[str, ...] = ("en-US", "en-GB", "en-CA", "en-AU", "de-DE", "fr-FR")
TIMEZONES: tuple[str, ...] = (
    "America/New_York", "America/Chicago", "America/Los_Angeles",
    "Europe/London", "Europe/Berlin", "Asia/Singapore",
)


@dataclass
class Fingerprint:
    user_agent: str
    viewport: dict[str, int]
    locale: str
    timezone_id: str
    color_scheme: str = "light"
    extra_headers: dict[str, str] = field(default_factory=dict)

    def to_context_kwargs(self) -> dict:
        return {
            "user_agent": self.user_agent,
            "viewport": self.viewport,
            "locale": self.locale,
            "timezone_id": self.timezone_id,
            "color_scheme": self.color_scheme,
            "extra_http_headers": {"Accept-Language": f"{self.locale},en;q=0.9"},
        }


class FingerprintGenerator:
    def __init__(self, seed: int | None = None) -> None:
        self._rng = random.Random(seed)

    def generate(self) -> Fingerprint:
        w, h = self._rng.choice(VIEWPORTS)
        locale = self._rng.choice(LOCALES)
        tz = self._rng.choice(TIMEZONES)
        return Fingerprint(
            user_agent=self._rng.choice(USER_AGENTS),
            viewport={"width": w, "height": h},
            locale=locale,
            timezone_id=tz if tz.startswith(("America", "Europe", "Asia")) and locale != "de-DE" else tz,
        )
