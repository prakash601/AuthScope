"""AuthScope FastAPI application factory."""

from __future__ import annotations

import logging
import time
import uuid
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from api.deps import build_engine
from api.routes.feedback import router as feedback_router
from api.routes.scans import router as scans_router
from api.routes.webhooks import router as webhooks_router

logger = logging.getLogger("authscope.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    from telemetry import setup_tracing

    setup_tracing()
    settings = app.state.settings
    engine, session_factory = build_engine(settings)
    app.state.engine = engine
    app.state.session_factory = session_factory
    app.state.redis = aioredis.from_url(settings.redis_url, decode_responses=True)
    from workers.celery_app import celery_app

    app.state.celery_app = celery_app
    yield
    await app.state.redis.aclose()
    await engine.dispose()


def create_app(settings=None) -> FastAPI:
    if settings is None:
        from config import get_settings

        settings = get_settings()

    app = FastAPI(
        title="AuthScope API",
        version="0.1.0",
        description="Login Intelligence & Anti-Bot Detection Platform",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.include_router(scans_router)
    app.include_router(webhooks_router)
    app.include_router(feedback_router)

    from pathlib import Path as _Path

    from fastapi.staticfiles import StaticFiles

    dashboard_dir = _Path(__file__).parent.parent / "dashboard"
    if dashboard_dir.exists():
        app.mount("/dashboard", StaticFiles(directory=dashboard_dir, html=True),
                  name="dashboard")

    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        from telemetry import observe_http

        request_id = request.headers.get("X-Request-ID", uuid.uuid4().hex[:16])
        request.state.request_id = request_id
        start = time.time()
        response = await call_next(request)
        route = getattr(request.scope.get("route"), "path", request.url.path)
        observe_http(start, request.method, route, response.status_code)
        response.headers["X-Request-ID"] = request_id
        return response

    @app.get("/metrics", include_in_schema=False)
    async def metrics() -> Response:
        from fastapi.responses import Response

        from telemetry import QUEUE_DEPTH, metrics_response

        try:
            depth = await app.state.redis.llen("celery")
            QUEUE_DEPTH.labels(queue="celery").set(depth or 0)
        except Exception:  # noqa: BLE001 — metrics must not fail
            pass
        body, content_type = metrics_response()
        return Response(content=body, media_type=content_type)

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled error on %s", request.url.path)
        return JSONResponse(
            status_code=500,
            content={"detail": {"code": "internal_error",
                                "message": "unexpected server error"}},
        )

    @app.get("/healthz", tags=["health"])
    async def healthz(request: Request) -> dict:
        checks: dict[str, str] = {}
        try:
            async with request.app.state.session_factory() as session:
                await session.execute(sa_text("SELECT 1"))
            checks["postgres"] = "ok"
        except Exception:  # noqa: BLE001
            checks["postgres"] = "error"
        try:
            pong = await request.app.state.redis.ping()
            checks["redis"] = "ok" if pong else "error"
        except Exception:  # noqa: BLE001
            checks["redis"] = "error"
        healthy = all(v == "ok" for v in checks.values())
        return {"status": "healthy" if healthy else "degraded", "checks": checks}

    return app


def sa_text(query: str):
    import sqlalchemy as sa

    return sa.text(query)


app = create_app()
