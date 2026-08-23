"""Prometheus metrics + optional OpenTelemetry tracing setup."""

from __future__ import annotations

import logging
import time

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

logger = logging.getLogger("authscope.telemetry")

registry = CollectorRegistry(auto_describe=True)

HTTP_REQUESTS = Counter(
    "authscope_http_requests_total",
    "HTTP requests by method/route/status",
    ["method", "route", "status"],
    registry=registry,
)
HTTP_LATENCY = Histogram(
    "authscope_http_request_seconds",
    "HTTP request latency",
    ["method", "route"],
    registry=registry,
)
SCAN_DURATION = Histogram(
    "authscope_scan_duration_seconds",
    "End-to-end scan duration in workers",
    ["status"],
    registry=registry,
)
SCANS_TOTAL = Counter(
    "authscope_scans_total",
    "Scans by final status",
    ["status"],
    registry=registry,
)
DETECTOR_DURATION = Histogram(
    "authscope_detector_duration_seconds",
    "Per-detector execution duration",
    ["detector"],
    registry=registry,
)
BROWSER_CONTEXTS = Gauge(
    "authscope_browser_contexts_live",
    "Live browser contexts in this process",
    registry=registry,
)
QUEUE_DEPTH = Gauge(
    "authscope_queue_depth",
    "Celery queue depth (broker)",
    ["queue"],
    registry=registry,
)
WEBHOOKS_DEADLETTERED = Counter(
    "authscope_webhooks_deadlettered_total",
    "Webhooks moved to the DLQ",
    registry=registry,
)


def metrics_response() -> tuple[bytes, str]:
    return generate_latest(registry), CONTENT_TYPE_LATEST


def observe_http(start: float, method: str, route: str, status: int) -> None:
    HTTP_REQUESTS.labels(method=method, route=route, status=str(status)).inc()
    HTTP_LATENCY.labels(method=method, route=route).observe(time.time() - start)


def setup_tracing() -> bool:
    """Configure OTel exporter when an endpoint is configured.

    Returns True when real spans will be exported. No-op otherwise
    (the OpenTelemetry API's default tracer produces no-op spans).
    """
    import os

    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not endpoint:
        return False
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        provider = TracerProvider(resource=Resource.create(
            {"service.name": os.environ.get("OTEL_SERVICE_NAME", "authscope")}))
        processor = BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint))
        provider.add_span_processor(processor)
        trace.set_tracer_provider(provider)
        logger.info("OTel tracing configured → %s", endpoint)
        return True
    except Exception:  # noqa: BLE001 — telemetry must never break the app
        logger.exception("failed to configure OTel tracing")
        return False
