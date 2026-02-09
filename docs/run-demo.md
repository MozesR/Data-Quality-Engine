# IDQE Demo Run Instructions (MacBook)

This guide explains how to run, test, and stop the Intelligent Data Quality Engine demo.

## 1. Prerequisites

- macOS with Docker Desktop installed and running
- Docker Compose v2 (`docker compose`)
- Port availability:
  - `8080` for workflow web client
  - `8002` for MCP server
  - `8001` for DQ engine
  - `5432` for Postgres

Check Docker:

```bash
docker --version
docker compose version
```

## 2. Start the demo

From project root:

```bash
cd .
docker compose -f docker-compose.demo.yml up --build
```

When startup is complete, you should see logs from:

- `dq-postgres`
- `dq-engine`
- `dq-mcp-server`
- `dq-workflow-client`

## 3. Open the applications

- Workflow MCP client: [http://localhost:8080](http://localhost:8080)
- MCP server Swagger UI: [http://localhost:8002/docs](http://localhost:8002/docs)
- MCP server B Swagger UI: [http://localhost:8003/docs](http://localhost:8003/docs)
- DQ engine Swagger UI: [http://localhost:8001/docs](http://localhost:8001/docs)

## 4. Run a workflow from the web client

1. Open [http://localhost:8080](http://localhost:8080).
2. In `MCP Session`, click `Connect Server` (default `http://localhost:8002`).
3. Click `Initialize Active`, `List Tools`, and `List Data Sources` to verify MCP connectivity.
4. Keep default values or select:
   - `Provider`: `BANK_A`
   - `Dataset Type`: `customer_profile` or `credit_facility`
   - `Dataset Id`: e.g. `demo-dataset-001`
5. Click `Preview Dataset`.
6. Click `Run Assessment`.
7. Click `Run Correction`.
8. Click `Workflow History`.

Expected output is shown in the UI `Output` panel as JSON, including:

- Quality score (`quality_index`)
- Rule violations
- Applied corrections
- Stored workflow run records

## 5. Verify services from terminal (optional)

```bash
curl http://localhost:8001/health
curl http://localhost:8002/health
curl http://localhost:8002/mcp/tools
```

## 6. Stop the demo

Press `Ctrl+C` in the terminal where compose is running, then:

```bash
docker compose -f docker-compose.demo.yml down
```

## 7. Reset demo data completely

To remove containers and database volume:

```bash
docker compose -f docker-compose.demo.yml down -v
```

Then restart:

```bash
docker compose -f docker-compose.demo.yml up --build
```

## 8. Configure LLM behavior

The DQ engine reads LLM settings from:

- `./config/llm.demo.yaml`

Current demo default:

```yaml
llm:
  provider: mock
  model: gpt-4o-mini
  endpoint: null
  api_key_env: OPENAI_API_KEY
  temperature: 0.0
```

If you switch to `openai`, set your API key in environment before startup:

```bash
export OPENAI_API_KEY=your_key_here
docker compose -f docker-compose.demo.yml up --build
```

## 9. Configure DQ rules

Two options:

1. Use web editor in [http://localhost:8080](http://localhost:8080):
   - In `DQ Rule Editor`, click `Load Rules`
   - Edit YAML
   - Click `Save Rules`
2. Edit file directly:
   - `./config/rules.demo.yaml`

Structure:

- `data_sources`: providers and supported dataset types shown in UI
- `assessment_rules`: DQ checks per dataset type
- `correction_rules`: correction actions per dataset type

After changing rules, restart `mcp-server` if it is already running:

```bash
docker compose -f docker-compose.demo.yml up --build -d mcp-server
```

Then re-run workflows in the browser.

## 10. Configure LLM and suggestion flow

1. Open `LLM Config` tab.
2. Set `Provider`:
   - `none` disables suggestions
   - `mock` or `openai` enables suggestions
3. Set model, endpoint, API key env name, and API key.
4. Click `Save LLM Config`.
5. Run `Run Assessment` from `Run Workflow` tab.
6. If the LLM finds a missing rule opportunity, a popup appears with:
   - suggested assessment rule
   - suggested correction rule (if applicable)
7. Click:
   - `Approve Suggestion`: stores the new rule and applies it in next assessment/correction runs (the UI auto-reruns both).
   - `Decline Suggestion`: skips this suggestion.

## 11. Troubleshooting

- Build error `requirements.txt not found`:
  - Ensure latest Dockerfiles are pulled from this repo state.
- Port conflict:
  - Stop local services using ports `8080`, `8002`, `8001`, or `5432`.
- Browser cannot call MCP server:
  - Check MCP server container logs:
    ```bash
    docker compose -f docker-compose.demo.yml logs -f mcp-server
    ```
- Database issues:
  - Reset with `down -v` and start again.
