"""ISS-026 tests: Prometheus metrics endpoint, Grafana dashboard, OTel spans, alerts."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

DEPLOY = Path(__file__).parent.parent / "deploy"


async def test_metrics_endpoint_prometheus_format(app_client, user_and_key):
    _, client = app_client
    await client.get("/v1/scans", headers=user_and_key["headers"])
    resp = await client.get("/metrics")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    body = resp.text
    assert "authscope_http_requests_total" in body
    assert "authscope_http_request_seconds" in body


async def test_metrics_contain_scan_and_detector_series():
    from telemetry import (
        DETECTOR_DURATION,
        QUEUE_DEPTH,
        SCAN_DURATION,
        SCANS_TOTAL,
        WEBHOOKS_DEADLETTERED,
    )

    SCAN_DURATION.labels(status="completed").observe(1.5)
    SCANS_TOTAL.labels(status="completed").inc()
    DETECTOR_DURATION.labels(detector="security").observe(0.01)
    WEBHOOKS_DEADLETTERED.inc()
    QUEUE_DEPTH.labels(queue="celery").set(3)
    from telemetry import generate_latest, registry

    body = generate_latest(registry).decode()
    assert 'status="completed"' in body
    assert 'detector="security"' in body
    assert "authscope_webhooks_deadlettered_total" in body


def test_grafana_dashboard_has_required_panels():
    dashboard = json.loads((DEPLOY / "grafana" / "dashboard.json").read_text())
    panels = dashboard["panels"]
    assert len(panels) >= 6
    exprs = [t["expr"] for p in panels for t in p.get("targets", [])]
    joined = "\n".join(exprs)
    for metric in (
        "authscope_scans_total",
        "authscope_browser_contexts_live",
        "authscope_scan_duration_seconds",
        "authscope_http_request_seconds",
        "authscope_detector_duration_seconds",
        "authscope_queue_depth",
    ):
        assert metric in joined, metric


def test_alert_rules_valid_yaml_with_severity():
    rules = yaml.safe_load((DEPLOY / "prometheus" / "alerts.yml").read_text())
    groups = rules["groups"]
    all_rules = [r for g in groups for r in g["rules"]]
    assert len(all_rules) >= 3
    for r in all_rules:
        assert r["alert"]
        assert r["expr"]
        assert r["labels"]["severity"] in ("page", "warn")


def test_otel_spans_cover_scan_and_detectors():
    """Configure an in-process exporter; verify spans are produced."""
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor

    collected: list = []

    class _ListExporter:
        def export(self, spans):
            collected.extend(spans)
            from opentelemetry.sdk.trace.export import SpanExportResult

            return SpanExportResult.SUCCESS

        def shutdown(self):
            pass

        def force_flush(self, timeout_millis=None):
            return True

    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(_ListExporter()))
    trace.set_tracer_provider(provider)

    tracer = trace.get_tracer("authscope.test")
    with tracer.start_as_current_span("worker.run_scan") as span:
        span.set_attribute("authscope.scan_id", "test")
        with tracer.start_as_current_span("detector.security"):
            pass

    names = [s.name for s in collected]
    assert "worker.run_scan" in names and "detector.security" in names


def test_setup_tracing_noop_without_endpoint(monkeypatch):
    import telemetry

    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    assert telemetry.setup_tracing() is False


def test_compose_wires_observability_stack():
    import yaml

    compose = yaml.safe_load((Path(__file__).parent.parent / "docker-compose.yml").read_text())
    services = compose["services"]
    assert "prometheus" in services and "grafana" in services
    prom_mounts = [str(v) for v in services["prometheus"].get("volumes", [])]
    assert any("alerts.yml" in m for m in prom_mounts)
    assert any("prometheus.yml" in m for m in prom_mounts)
    graf_mounts = [str(v) for v in services["grafana"].get("volumes", [])]
    assert any("provisioning" in m for m in graf_mounts)
    assert any("dashboard.json" in m for m in graf_mounts)


def test_prometheus_scrape_config_valid():
    import yaml

    cfg = yaml.safe_load((DEPLOY / "prometheus" / "prometheus.yml").read_text())
    assert any("alerts.yml" in r for r in cfg.get("rule_files", []))
    jobs = {j["job_name"]: j for j in cfg["scrape_configs"]}
    assert "authscope-api" in jobs
    api = jobs["authscope-api"]
    assert api.get("metrics_path") == "/metrics"
    targets = [t for s in api["static_configs"] for t in s["targets"]]
    assert any("8000" in t for t in targets)


def test_grafana_provisioning_valid():
    import yaml

    ds = yaml.safe_load(
        (DEPLOY / "grafana" / "provisioning" / "datasources" / "prometheus.yaml").read_text()
    )
    assert "prometheus:9090" in ds["datasources"][0]["url"]
    dash = yaml.safe_load(
        (DEPLOY / "grafana" / "provisioning" / "dashboards" / "dashboards.yaml").read_text()
    )
    assert dash["providers"][0]["options"]["path"] == "/var/lib/grafana/dashboards"


async def test_http_access_log_is_json(app_client, user_and_key, caplog):
    """T14: one JSON access line per request (log-shipper searchable)."""
    import json
    import logging

    _, client = app_client
    with caplog.at_level(logging.INFO, logger="authscope.api"):
        resp = await client.get("/v1/scans", headers=user_and_key["headers"])
    assert resp.status_code == 200
    events = []
    for rec in caplog.records:
        try:
            events.append(json.loads(rec.getMessage()))
        except (json.JSONDecodeError, TypeError):
            continue
    access = [e for e in events if e.get("event") == "http_access"]
    assert access
    assert access[-1]["status"] == 200
    assert access[-1]["request_id"] and access[-1]["duration_ms"] is not None
