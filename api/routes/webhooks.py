"""Webhook management endpoints."""

from __future__ import annotations

import secrets
import uuid

import sqlalchemy as sa
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from api.deps import AuthContext, get_settings_from_request, require_api_key
from db.models import Webhook

router = APIRouter(prefix="/v1/webhooks", tags=["webhooks"])


class WebhookCreate(BaseModel):
    url: str


class WebhookOut(BaseModel):
    id: str
    url: str
    active: bool
    secret: str  # shown once at creation so clients can verify signatures


@router.post("", status_code=201)
async def register_webhook(
    body: WebhookCreate,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> WebhookOut:
    if not body.url.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_url", "message": "webhook URL must be http(s)"},
        )
    secret = secrets.token_hex(24)
    session_factory = request.app.state.session_factory
    wid = uuid.uuid4()
    async with session_factory() as session, session.begin():
        session.add(Webhook(id=wid, user_id=uuid.UUID(auth.user_id), url=body.url, secret=secret))
    return WebhookOut(id=str(wid), url=body.url, active=True, secret=secret)


@router.get("")
async def list_webhooks(
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> list[dict]:
    session_factory = request.app.state.session_factory
    async with session_factory() as session:
        rows = (
            (
                await session.execute(
                    sa.select(Webhook).where(Webhook.user_id == uuid.UUID(auth.user_id))
                )
            )
            .scalars()
            .all()
        )
    return [{"id": str(w.id), "url": w.url, "active": w.active} for w in rows]


@router.delete("/{webhook_id}", status_code=204)
async def delete_webhook(
    webhook_id: str,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> None:
    session_factory = request.app.state.session_factory
    try:
        wid = uuid.UUID(webhook_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=404, detail={"code": "not_found", "message": "webhook not found"}
        ) from exc
    async with session_factory() as session:
        async with session.begin():
            result = await session.execute(
                sa.delete(Webhook).where(
                    Webhook.id == wid,
                    Webhook.user_id == uuid.UUID(auth.user_id),
                )
            )
        if result.rowcount == 0:
            raise HTTPException(
                status_code=404, detail={"code": "not_found", "message": "webhook not found"}
            )


@router.get("/dlq")
async def list_dead_letters(
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> list[dict]:
    """Undeliverable webhook attempts for this user (re-drive via POST below)."""
    from workers.webhooks import list_dlq

    redis = request.app.state.redis
    return [
        {
            "dlq_id": e.get("dlq_id"),
            "url": e.get("url"),
            "scan_id": e.get("scan_id"),
            "error": e.get("error"),
            "dead_lettered_at": e.get("dead_lettered_at"),
        }
        for _, e in await list_dlq(redis)
        if e.get("user_id") == auth.user_id and e.get("dlq_id")
    ]


@router.post("/dlq/{dlq_id}/redrive")
async def redrive_dead_letter(
    dlq_id: str,
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> dict:
    """Re-deliver one dead-lettered webhook; drops the entry on success."""
    from workers.webhooks import deliver, list_dlq, remove_dlq_entry

    redis = request.app.state.redis
    match: tuple[str, dict] | None = None
    for raw, entry in await list_dlq(redis):
        if entry.get("dlq_id") == dlq_id and entry.get("user_id") == auth.user_id:
            match = (raw, entry)
            break
    if match is None:
        raise HTTPException(
            status_code=404, detail={"code": "not_found", "message": "dead-letter entry not found"}
        )
    raw, entry = match

    session_factory = request.app.state.session_factory
    async with session_factory() as session:
        hook = (
            (
                await session.execute(
                    sa.select(Webhook).where(
                        Webhook.user_id == uuid.UUID(auth.user_id),
                        Webhook.url == entry.get("url"),
                        Webhook.active.is_(True),
                    )
                )
            )
            .scalars()
            .first()
        )
    if hook is None:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "webhook_gone",
                "message": "no active webhook for this URL; re-register it first",
            },
        )

    from api.routes.scans import _get_scan_for_user, build_report_response

    scan_id = entry.get("scan_id")
    if not scan_id:
        raise HTTPException(
            status_code=409,
            detail={"code": "report_unavailable",
                    "message": "scan report is no longer available"},
        )
    scan = await _get_scan_for_user(session_factory, scan_id, auth.user_id)
    if scan is None or scan.status not in ("completed", "waf_blocked"):
        raise HTTPException(
            status_code=409,
            detail={"code": "report_unavailable", "message": "scan report is no longer available"},
        )
    settings = get_settings_from_request(request)
    report = await build_report_response(session_factory, scan, settings)
    delivered, error = await deliver(
        hook.url, hook.secret, {"scan_id": str(scan.id), "report": report}
    )
    if not delivered:
        raise HTTPException(
            status_code=502,
            detail={"code": "redrive_failed", "message": f"re-delivery failed: {error}"},
        )
    await remove_dlq_entry(redis, raw)
    return {"dlq_id": dlq_id, "status": "delivered"}
