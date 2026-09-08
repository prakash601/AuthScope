# AuthScope — Secret Management

`deploy/k8s/config-and-secrets.example.yaml` is a **template only**.
Real values are never committed and never baked into images
(Dockerfiles set no secret `ENV`; API/worker/migrations consume secrets
exclusively via `envFrom: secretRef: authscope-secrets`).

## Provision (one-time per environment)

```bash
kubectl create secret generic authscope-secrets \
  --from-literal=POSTGRES_USER='...' \
  --from-literal=POSTGRES_PASSWORD='...' \
  --from-literal=S3_ACCESS_KEY='...' \
  --from-literal=S3_SECRET_KEY='...'
kubectl apply -f deploy/k8s/config-and-secrets.example.yaml  # ConfigMap part only is safe;
# or apply just the ConfigMap doc: kubectl apply -l app=authscope-config
```

Copy the template's ConfigMap section for non-secret values
(hosts, buckets, scan limits); keep secret values out of it.

## Secret-manager integration

Prefer your manager's operator (e.g. External Secrets `ExternalSecret`
syncing to `authscope-secrets`) over hand-created secrets. The workload
needs no changes: it reads plain env vars (`POSTGRES_*`, `S3_*`,
`REDIS_URL`), so any sync mechanism that populates the `authscope-secrets`
Secret works.

## Validation

- Boot fails fast: `config.py` raises a validation error naming the missing
  variable (no silent defaults for credentials).
- After rollout: `GET /healthz` checks Postgres + Redis connectivity.
- Policy test: `pytest tests/test_deploy_policy.py` asserts placeholders in
  the template, no baked secrets in images, and `secretRef` wiring on all
  three workloads.

## Rotation

1. Update the Secret (or the manager's source value).
2. Restart workloads: `kubectl rollout restart deploy/authscope-api deploy/authscope-worker`.
3. Verify `/healthz` and one scan end-to-end.
