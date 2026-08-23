"""Webhook management endpoints."""

from __future__ import annotations

import secrets
import uuid

import sqlalchemy as sa
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from api.deps import AuthContext, require_api_key
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
        raise HTTPException(status_code=400, detail={
            "code": "invalid_url", "message": "webhook URL must be http(s)"})
    secret = secrets.token_hex(24)
    session_factory = request.app.state.session_factory
    wid = uuid.uuid4()
    async with session_factory() as session, session.begin():
        session.add(Webhook(id=wid, user_id=uuid.UUID(auth.user_id),
                            url=body.url, secret=secret))
    return WebhookOut(id=str(wid), url=body.url, active=True, secret=secret)


@router.get("")
async def list_webhooks(
    request: Request,
    auth: AuthContext = Depends(require_api_key),
) -> list[dict]:
    session_factory = request.app.state.session_factory
    async with session_factory() as session:
        rows = (
            await session.execute(
                sa.select(Webhook).where(Webhook.user_id == uuid.UUID(auth.user_id))
            )
        ).scalars().all()
    return [
        {"id": str(w.id), "url": w.url, "active": w.active} for w in rows
    ]


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
        raise HTTPException(status_code=404, detail={
            "code": "not_found", "message": "webhook not found"}) from exc
    async with session_factory() as session:
        async with session.begin():
            result = await session.execute(
                sa.delete(Webhook).where(
                    Webhook.id == wid,
                    Webhook.user_id == uuid.UUID(auth.user_id),
                )
            )
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail={
                "code": "not_found", "message": "webhook not found"})
