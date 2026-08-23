"""Celery application factory."""

from __future__ import annotations

from celery import Celery

from config import get_settings


def make_celery_app() -> Celery:
    settings = get_settings()
    app = Celery(
        "authscope",
        broker=settings.redis_url,
        backend=settings.redis_url,
        include=["workers.tasks"],
    )
    app.conf.update(
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        timezone="UTC",
        enable_utc=True,
        task_acks_late=True,
        worker_prefetch_multiplier=1,
        task_track_started=True,
    )
    return app


celery_app = make_celery_app()
