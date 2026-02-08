# Manual UI Test Checklist (Tabs + LLM Suggestions Queue)

## Precondition

- Stack is running:

```bash
cd /Users/mozesrahangmetan/Documents/DQ
docker compose -f docker-compose.demo.yml up --build -d
```

- Open: http://localhost:8080

## 1. Tab navigation

1. Click each tab: `Run Workflow`, `DQ Rules Editor`, `MCP Session`, `LLM Config`.
2. Expected:
   - Only selected tab content is visible.
   - Active tab button is highlighted.

## 2. MCP session and multi-server list

1. Go to `MCP Session`.
2. With URL `http://localhost:8002`, click `Connect Server`.
3. Expected:
   - Server appears in `Connected MCP Servers` list.
   - `Active MCP server` label matches selected URL.
4. Click `List Tools (Active)`.
5. Expected tool list includes:
   - `get_llm_yaml`, `save_llm_yaml`, `approve_suggestion`, `decline_suggestion`.

## 3. LLM config save/load

1. Go to `LLM Config`.
2. Set provider to `mock`, model `gpt-4o-mini`, temperature `0.0`.
3. Click `Save LLM Config`.
4. Click `Load LLM Config`.
5. Expected:
   - Success message shown.
   - Loaded values match saved values.

## 4. Suggestion queue popup

1. Go to `Run Workflow`.
2. Select:
   - Provider: `BANK_A`
   - Dataset Type: `credit_facility`
   - Dataset Id: `queue-test-1`
3. Click `Run Assessment`.
4. Expected:
   - Suggestion popup appears.
   - Popup shows `Suggestion X / N`.

## 5. Queue actions

1. In popup click `Next Suggestion`.
2. Expected:
   - Moves to next item in queue (X increments).
3. Click `Decline Suggestion`.
4. Expected:
   - Current suggestion removed.
   - Next suggestion appears or queue ends.
5. Click `Approve Suggestion` on one suggestion.
6. Expected:
   - Suggestion approved.
   - Assessment/correction reruns.

## 6. Rule persistence after approve

1. Go to `DQ Rules Editor`.
2. Click `Load Rules`.
3. Expected:
   - YAML contains `SUG-` rule id for approved suggestion.

## 7. Disable LLM and verify no popup

1. Go to `LLM Config` and set provider to `none`.
2. Save config.
3. Go to `Run Workflow`, run assessment again.
4. Expected:
   - No suggestion popup appears.

## 8. Auto-correction on source change

1. In `Run Workflow`, enable checkbox `Run correction automatically when data source changes`.
2. Change dataset type.
3. Expected:
   - Correction runs automatically and output updates.
