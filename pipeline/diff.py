"""Historical diff: what changed on a login page between two scans."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Snapshot:
    """Comparable projection of a persisted scan."""

    scan_id: str
    created_at: str
    provider: str | None
    flows: list[str]
    captcha_type: str | None
    captcha_visible: bool | None
    waf_providers: list[str]
    fingerprinting: list[str]
    has_hsts: bool
    has_csp: bool
    has_csrf: bool
    mfa_detected: bool
    difficulty_score: int | None
    security_score: int | None


@dataclass
class Change:
    kind: str
    field: str
    before: object = None
    after: object = None

    def as_dict(self) -> dict:
        return {"kind": self.kind, "field": self.field,
                "before": self.before, "after": self.after}


@dataclass
class DiffResult:
    scan_id: str
    compared_to_scan_id: str
    compared_to_created_at: str
    changes: list[Change] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "compared_to_scan_id": self.compared_to_scan_id,
            "compared_to_created_at": self.compared_to_created_at,
            "changes": [c.as_dict() for c in self.changes],
        }


def _list_delta(field_name: str, before: list[str], after: list[str]) -> list[Change]:
    changes: list[Change] = []
    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    if added:
        changes.append(Change("added", field_name, None, added))
    if removed:
        changes.append(Change("removed", field_name, removed, None))
    return changes


def compute_diff(current: Snapshot, previous: Snapshot) -> DiffResult:
    result = DiffResult(
        scan_id=current.scan_id,
        compared_to_scan_id=previous.scan_id,
        compared_to_created_at=previous.created_at,
    )
    c = result.changes

    if current.provider != previous.provider:
        c.append(Change("changed", "auth.provider",
                        previous.provider, current.provider))
    c += _list_delta("auth.flows", previous.flows, current.flows)
    if current.captcha_type != previous.captcha_type:
        c.append(Change("changed", "antibot.captcha.type",
                        previous.captcha_type, current.captcha_type))
    if current.captcha_visible != previous.captcha_visible:
        c.append(Change("changed", "antibot.captcha.visible",
                        previous.captcha_visible, current.captcha_visible))
    c += _list_delta("antibot.waf_providers",
                     previous.waf_providers, current.waf_providers)
    c += _list_delta("antibot.fingerprinting",
                     previous.fingerprinting, current.fingerprinting)

    for name, cur, prev in (
        ("security.has_hsts", current.has_hsts, previous.has_hsts),
        ("security.has_csp", current.has_csp, previous.has_csp),
        ("security.has_csrf", current.has_csrf, previous.has_csrf),
        ("security.mfa_detected", current.mfa_detected, previous.mfa_detected),
    ):
        if cur != prev:
            c.append(Change("changed", name, prev, cur))

    if (current.difficulty_score is not None
            and previous.difficulty_score is not None
            and current.difficulty_score != previous.difficulty_score):
        delta = current.difficulty_score - previous.difficulty_score
        c.append(Change("score_delta", "difficulty_score",
                        {"value": previous.difficulty_score, "delta": delta},
                        {"value": current.difficulty_score, "delta": delta}))
    if (current.security_score is not None
            and previous.security_score is not None
            and current.security_score != previous.security_score):
        delta = current.security_score - previous.security_score
        c.append(Change("score_delta", "security_score",
                        {"value": previous.security_score, "delta": delta},
                        {"value": current.security_score, "delta": delta}))
    return result
