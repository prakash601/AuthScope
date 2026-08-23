"""Feedback / false-positive loop endpoints."""

from __future__ import annotations

import uuid

import sqlalchemy as sa
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from api.deps import AuthContext, require_api_key
from db.models import Feedback, Scan

router = APIRouter(prefix="/v1", tags=["feedback"])

FINDING_KINDS = {"auth", "security", "antibot", "captcha", "waf", "fingerprinting"}
VERDICTS = {"correct", "false_positive"}


class FeedbackCreate(BaseModel):
    finding_kind: str
    verdict: str
    signature_name: str | None = None
    comment: str | None = Field(default=None, max_length=2000)


class FeedbackStatsRow(BaseModel):
    signature_name: str | None
    confirmed: int
    false_positives: int
    fp_rate: float | None


@router.post("/scans/{scan_id}/feedback", status_code=201)
async def submit_feedback(
    scan_id: str,
    body: FeedbackCreate,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> dict:
    if body.finding_kind not in FINDING_KINDS:
        raise HTTPException(status_code=422, detail={
            "code": "invalid_finding_kind",
            "message": f"finding_kind must be one of {sorted(FINDING_KINDS)}"})
    if body.verdict not in VERDICTS:
        raise HTTPException(status_code=422, detail={
            "code": "invalid_verdict",
            "message": f"verdict must be one of {sorted(VERDICTS)}"})

    session_factory = request.app.state.session_factory
    try:
        sid = uuid.UUID(scan_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail={
            "code": "not_found", "message": "scan not found"}) from exc
    async with session_factory() as session:
        scan = (
            await session.execute(
                sa.select(Scan).where(Scan.id == sid,
                                      Scan.user_id == uuid.UUID(auth.user_id))
            )
        ).scalar_one_or_none()
    if scan is None:
        raise HTTPException(status_code=404, detail={
            "code": "not_found", "message": "scan not found"})
    async with session_factory() as session, session.begin():
        fb = Feedback(
            scan_id=sid,
            finding_kind=body.finding_kind,
            signature_name=body.signature_name,
            verdict=body.verdict,
            comment=body.comment,
        )
        session.add(fb)
        await session.flush()
        return {"id": str(fb.id), "scan_id": scan_id,
                "verdict": body.verdict, "recorded": True}


@router.get("/feedback/stats")
async def feedback_stats(
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> list[FeedbackStatsRow]:
    """Aggregate confirmation / false-positive rates per signature (SQL view)."""
    session_factory = request.app.state.session_factory
    async with session_factory() as session:
        rows = (
            await session.execute(
                sa.text(
                    "SELECT signature_name, confirmed, false_positives, fp_rate "
                    "FROM signature_feedback_stats ORDER BY signature_name"
                )
            )
        ).all()
    return [
        FeedbackStatsRow(
            signature_name=r.signature_name,
            confirmed=r.confirmed,
            false_positives=r.false_positives,
            fp_rate=float(r.fp_rate) if r.fp_rate is not None else None,
        )
        for r in rows
    ]
