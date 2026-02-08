# Intelligent Data Quality Engine (IDQE)

This repo contains a demo and production-oriented baseline for the Data Quality Engine described in `Presentation Yoda Final v01.pptx`.

Detailed runbook: `/Users/mozesrahangmetan/Documents/DQ/docs/run-demo.md`

Detailed documentation set:

- Demo installation: `/Users/mozesrahangmetan/Documents/DQ/docs/install-demo-detailed.md`
- Production installation: `/Users/mozesrahangmetan/Documents/DQ/docs/install-production-detailed.md`
- User manual: `/Users/mozesrahangmetan/Documents/DQ/docs/user-manual.md`

## What is included

- `workflow-client`: web-based MCP client for workflow management
- `mcp-server`: MCP-style server with data source connectors and workflow orchestration
- `dq-engine`: assessment/correction engine with configurable LLM settings
- `postgres`: demo data source and workflow metadata storage
- `deploy/k8s`: enterprise deployment manifests
- `docker-compose.demo.yml`: local MacBook demo
- `docker-compose.prod.yml`: production container profile template

## Architecture

1. User works in browser on `workflow-client`.
2. Client calls `mcp-server` tools (`list_data_sources`, `preview_dataset`, `run_dq_assessment`, `run_correction`, `get_workflow_runs`).
3. `mcp-server` connects to source datasets in Postgres and calls `dq-engine`.
4. `dq-engine` evaluates rules and optional LLM-assisted behavior based on config file.
5. Workflow runs are stored for traceability and governance.

## Demo run (MacBook)

Prerequisites:

- Docker Desktop
- Docker Compose v2

Start:

```bash
docker compose -f docker-compose.demo.yml up --build
```

Open:

- Workflow MCP client: `http://localhost:8080`
- MCP server A API: `http://localhost:8002/docs`
- MCP server B API: `http://localhost:8003/docs`
- DQ engine API: `http://localhost:8001/docs`

Stop:

```bash
docker compose -f docker-compose.demo.yml down
```

Reset database volume:

```bash
docker compose -f docker-compose.demo.yml down -v
```

## LLM configuration

LLM is configured through YAML mounted into `dq-engine`.

Demo config: `/Users/mozesrahangmetan/Documents/DQ/config/llm.demo.yaml`
Production config: `/Users/mozesrahangmetan/Documents/DQ/config/llm.prod.yaml`

Schema:

```yaml
llm:
  provider: mock|openai|none
  model: gpt-4.1-mini
  endpoint: https://api.openai.com/v1
  api_key_env: OPENAI_API_KEY
  temperature: 0.0
```

## DQ rule configuration

DQ rules are configured in YAML and loaded by `mcp-server`:

- Demo: `/Users/mozesrahangmetan/Documents/DQ/config/rules.demo.yaml`
- Production: `/Users/mozesrahangmetan/Documents/DQ/config/rules.prod.yaml`

Main sections:

- `data_sources`
- `assessment_rules` (per dataset type)
- `correction_rules` (per dataset type)

Supported assessment rule `type` values in this demo:

- `not_null`
- `range` (with `params.min` / `params.max`)
- `allowed_values` (with `params.values`)
- `regex` (with `params.pattern`)

You can also edit rules in the web UI (`DQ Rule Editor`) at `http://localhost:8080`.

## Testing

Automated MCP/API smoke test:

```bash
cd /Users/mozesrahangmetan/Documents/DQ
python3 scripts/test_mcp_flow.py
```

Manual UI test checklist:

- `/Users/mozesrahangmetan/Documents/DQ/tests/manual-ui-tests.md`

## Auth Modes (Demo vs Production)

`mcp-server` supports two auth profiles:

- Demo profile:
  - `AUTH_MODE=demo`
  - `AUTH_REQUIRED=false` (default in demo compose)
  - Seeds demo admin (`DEMO_ADMIN_EMAIL`, `DEMO_ADMIN_PASSWORD`) if missing
- Production profile:
  - `AUTH_MODE=production`
  - `AUTH_REQUIRED=true` (default when `AUTH_MODE=production`)
  - Requires strong passwords on registration
  - Use a strong `AUTH_SECRET` and short token TTL
  - Set `CORS_ALLOW_ORIGINS` to your approved web client origin list
  - `UI_ALLOW_LLM_TAB=false` so LLM stays file-config-only in production UI

New auth/admin tools exposed by MCP server:

- `auth_register`
- `auth_login`
- `auth_me`
- `admin_list_users`
- `admin_update_user`
- `get_user_mcp_servers`
- `save_user_mcp_servers`
- `list_available_mcp_servers`
- `admin_list_shared_mcp_servers`
- `admin_save_shared_mcp_servers`

Web UI auth/admin:

- Login/Register page gates access to the application
- `MCP Session` supports per-user MCP server catalogs (`My MCP Servers`)
- Users can connect to admin-published shared MCP servers (`Shared MCP Servers`)
- Admin-only controls:
  - `Admin` tab for user role/active management
  - shared MCP server catalog editor in `MCP Session`
- Demo default admin credentials:
  - Email: `admin@idqe.local`
  - Password: `Admin123!`

Security/data isolation notes:

- Workflow runs and suggestion decisions are user-scoped by default.
- Pending LLM suggestions are persisted in DB (safe for multi-replica mcp-server).
- Browser auth session is stored in `sessionStorage` (not persistent local storage).

## Enterprise deployment baseline

Use `/Users/mozesrahangmetan/Documents/DQ/deploy/k8s` as baseline:

- Namespace isolation
- Separate deployments for `workflow-client`, `mcp-server`, `dq-engine`
- Service-to-service connectivity
- ConfigMap for LLM config
- Secret-based database connection
- Ingress entrypoint for web client

Add in enterprise platform:

- managed PostgreSQL + read replicas
- API gateway + mTLS
- centralized IAM/RBAC
- observability stack (logs, traces, metrics)
- CI/CD with signed images
