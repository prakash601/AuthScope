# AuthScope Runbook

## Deploy
1. Build & push images: `docker build -f Dockerfile.api -t <registry>/authscope/api:<tag> .`
   and `docker build -f Dockerfile.worker -t <registry>/authscope/worker:<tag> .`
2. Create/update secrets (`deploy/k8s/config-and-secrets.example.yaml` is a **template** —
   see `deploy/k8s/SECRETS.md` for provision/rotation commands; never commit real values).
3. Apply migrations Job: `kubectl apply -f deploy/k8s/migrations-job.yaml`.
4. Roll API + workers: `kubectl apply -f deploy/k8s/api.yaml deploy/k8s/worker.yaml`.
5. Verify: `/healthz` on the API service; Grafana dashboard `authscope-overview`.

## Observability (local)
`make compose-up` also starts Prometheus (`:9090`, alerts from
`deploy/prometheus/alerts.yml`) and Grafana (`:3000`, admin credentials via
`GRAFANA_ADMIN_USER/_PASSWORD`, dashboard auto-provisioned). Prometheus scrapes
the host API at `host.docker.internal:8000/metrics` while `make run-api` runs.

## Common failures

### waf_blocked spike (alert: AuthScopeWafBlockedSpike)
- Cause: proxy pool burned or a target hardened its protection.
- Action: rotate proxy credentials; check per-country success in scan options
  (`attempted_proxies`) and worker `proxy acquired country=...` logs;
  pool JSON is validated at load (bad URLs fail fast) — see `workers/proxy.py`.
  Consider lowering submission rate for affected targets.

### Scan failure spike (alert: AuthScopeScanFailureSpike)
- Check worker logs for OOM kills: `kubectl logs -l app=authscope,tier=worker --previous`.
- HPA scales on memory — verify it isn't pinned at maxReplicas.
- Broker down → workers idle & queue grows: check Redis connectivity from workers.

### Queue backlog (alert: AuthScopeQueueBacklog)
- Scale workers manually: `kubectl scale deploy/authscope-worker --replicas=N`
- Confirm each pod's context budget (~150MB/context) and that watchdog kills
  (45s) appear in logs.

### High scan latency (alert: AuthScopeHighScanLatency)
- Inspect `authscope_detector_duration_seconds` panels to find slow detectors.
- Check browser farm CPU saturation and network egress via proxies.

## Evidence retention
Run cleanup periodically (CRON): `python -c "from pipeline.evidence import cleanup_expired; cleanup_expired()"`.

## Signature updates
Signatures live in Git (`signatures/*.yaml`). PR → merge → run
`python -m db.load_signatures`; workers reload fresh signatures per scan task.

## Compliance notes
- Robots.txt respect is a policy flag: `SCAN_RESPECT_ROBOTS_TXT=true` (default off).
  The check fetches `robots.txt` through the scan's browser context, so it honors
  the assigned proxy/country like any other navigation.
- All reports carry the detection-only disclaimer; AuthScope never bypasses protections.

## Logs
API emits one JSON `http_access` line per request (request_id, method, route,
status, duration_ms) to stdout — point any shipper (Fluent Bit/Vector → Elasticsearch/Loki) at container logs; no dedicated log infra in compose by design.
