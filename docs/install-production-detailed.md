# IDQE Production Installation Guide (Detailed)

This guide describes a production setup pattern for IDQE.

## 1. Production Architecture

Recommended services:

- `workflow-client` (web UI)
- `mcp-server` (API/orchestration)
- `dq-engine` (assessment/correction)
- Managed PostgreSQL (HA, backup, PITR)
- Ingress/API Gateway + TLS

Important production behavior:

- Login is required.
- `LLM Config` tab is hidden in UI.
- LLM is configured via file only.

## 2. Security Requirements

- Strong `AUTH_SECRET`
- `AUTH_MODE=production`
- `AUTH_REQUIRED=true`
- Restricted `CORS_ALLOW_ORIGINS`
- Secrets in secret manager (not Git)
- Network policies and least privilege

## 3. Build and Publish Images

```bash
cd /Users/mozesrahangmetan/Documents/DQ
docker build -f services/dq-engine/Dockerfile -t <registry>/idqe-dq-engine:1.0.0 .
docker build -f services/mcp-server/Dockerfile -t <registry>/idqe-mcp-server:1.0.0 .
docker build -f services/workflow-client/Dockerfile -t <registry>/idqe-workflow-client:1.0.0 services/workflow-client
docker push <registry>/idqe-dq-engine:1.0.0
docker push <registry>/idqe-mcp-server:1.0.0
docker push <registry>/idqe-workflow-client:1.0.0
```

## 4. Prepare Configuration Files

- Rules: `config/rules.prod.yaml`
- LLM: `config/llm.prod.yaml`

In production, update only the YAML files and redeploy/restart relevant services.

## 5. Required Environment Variables

For `mcp-server`:

- `AUTH_MODE=production`
- `AUTH_REQUIRED=true`
- `AUTH_SECRET=<strong secret>`
- `ACCESS_TOKEN_TTL_MINUTES=120` (or stricter)
- `UI_ALLOW_LLM_TAB=false`
- `CORS_ALLOW_ORIGINS=https://<your-ui-domain>`
- `DATABASE_URL=postgresql+psycopg2://...`
- `DQ_ENGINE_URL=http://dq-engine:8001`

## 6. Deploy with Compose (Production Profile Template)

Update image names in `docker-compose.prod.yml`, then run:

```bash
cd /Users/mozesrahangmetan/Documents/DQ
export AUTH_SECRET='<strong secret>'
export CORS_ALLOW_ORIGINS='https://idqe.company.com'
docker compose -f docker-compose.prod.yml up -d
```

Use this as a baseline. For enterprise, prefer Kubernetes manifests in `deploy/k8s`.

## 7. Deploy with Kubernetes (Recommended)

1. Create namespace:

```bash
kubectl apply -f deploy/k8s/namespace.yaml
```

2. Create DB and app secrets:

```bash
kubectl -n idqe create secret generic idqe-db --from-literal=database_url='postgresql+psycopg2://<user>:<pass>@<host>:5432/dq'
kubectl -n idqe create secret generic idqe-auth --from-literal=auth_secret='<strong secret>'
```

3. Create config maps:

```bash
kubectl -n idqe create configmap idqe-rules --from-file=rules.yaml=config/rules.prod.yaml -o yaml --dry-run=client | kubectl apply -f -
kubectl -n idqe create configmap idqe-llm --from-file=llm.yaml=config/llm.prod.yaml -o yaml --dry-run=client | kubectl apply -f -
```

4. Update image references in:

- `deploy/k8s/dq-engine.yaml`
- `deploy/k8s/mcp-server.yaml`
- `deploy/k8s/workflow-client.yaml`

5. Apply manifests:

```bash
kubectl apply -f deploy/k8s/dq-engine.yaml
kubectl apply -f deploy/k8s/mcp-server.yaml
kubectl apply -f deploy/k8s/workflow-client.yaml
```

## 8. Post-Deployment Validation

- Health endpoints return `ok`.
- Login works.
- Non-admin users cannot access admin features.
- Workflow runs are user-scoped.
- Shared MCP servers managed by admin only.
- LLM tab is not visible in production UI.

## 9. Operations Checklist

- Backup DB and test restore.
- Monitor API latency/error rates.
- Audit admin changes (users/shared MCP servers).
- Rotate secrets regularly.
- Pin image tags and use controlled rollout.

## 10. Rollback

- Roll back to previous image tags.
- Restore prior rules/LLM config.
- Restart `mcp-server` and `dq-engine`.
- Re-run smoke tests and critical user flows.

