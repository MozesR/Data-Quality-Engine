# IDQE Demo Installation Guide (Detailed)

This guide installs the full demo stack on macOS using Docker Desktop.

## 1. Prerequisites

- macOS with Docker Desktop running
- Docker Compose v2
- Free ports:
  - `8080` workflow client
  - `8001` dq-engine
  - `8002` mcp-server-a
  - `8003` mcp-server-b
  - `5432` postgres-a
  - `5433` postgres-b

Verify:

```bash
docker --version
docker compose version
```

## 2. Project Setup

```bash
cd .
```

Demo uses:

- `docker-compose.demo.yml`
- `config/rules.demo.a.yaml`
- `config/rules.demo.b.yaml`
- `config/llm.demo.yaml`

## 3. Start Demo Stack

```bash
docker compose -f docker-compose.demo.yml up --build
```

Wait until all containers are healthy.

## 4. Open Endpoints

- Workflow UI: [http://localhost:8080](http://localhost:8080)
- MCP A: [http://localhost:8002/docs](http://localhost:8002/docs)
- MCP B: [http://localhost:8003/docs](http://localhost:8003/docs)
- DQ Engine: [http://localhost:8001/docs](http://localhost:8001/docs)

## 5. Demo Login

The app shows Login/Register first.

Demo admin default:

- Email: `admin@idqe.local`
- Password: `Admin123!`

You can also register normal users from the Login/Register page.

## 6. MCP Session Setup

In `MCP Session` tab:

1. Connect `http://localhost:8002`.
2. Optional: connect `http://localhost:8003`.
3. Check `Connected MCP Servers`.
4. Use `My MCP Servers` to save personal endpoints.
5. Use `Shared MCP Servers` to connect to shared endpoints.

## 7. Run First Workflow

In `Run Workflow`:

1. Select provider and dataset type.
2. Select one or more target MCP servers.
3. Click `Preview Dataset`.
4. Click `Run Assessment`.
5. Click `Run Correction`.
6. Open `Workflow History` and view run details.

## 8. Rules Management

In `DQ Rules Editor`:

1. Click `Load Rules`.
2. Edit assessment/correction rules in table editor.
3. Click `Save Rules`.
4. Review accepted/declined suggestion decisions below.

## 9. LLM in Demo

Demo UI includes `LLM Config` tab.

If using OpenAI:

```bash
export OPENAI_API_KEY=your_key
docker compose -f docker-compose.demo.yml up --build
```

If no key is provided, keep provider `mock` or `none`.

## 10. Smoke Test

Run API smoke test:

```bash
cd .
python3 scripts/test_mcp_flow.py
```

## 11. Stop / Reset

Stop:

```bash
docker compose -f docker-compose.demo.yml down
```

Full reset (containers + volumes):

```bash
docker compose -f docker-compose.demo.yml down -v
```

## 12. Troubleshooting

- Port conflict: stop local process/container using same port.
- Login/session issues: logout and login again.
- Missing data: confirm target server and dataset type.
- Service error: inspect logs:

```bash
docker compose -f docker-compose.demo.yml logs -f
```

