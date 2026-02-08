# IDQE User Manual

This manual explains how business users, data stewards, and admins use IDQE.

## 1. Login and Roles

When you open the app, start from Login/Register.

- `User` role:
  - Run workflows
  - Edit own DQ rules
  - Manage own MCP server list
  - Use shared MCP servers
- `Admin` role:
  - All user capabilities
  - Manage users (role/active)
  - Manage shared MCP server catalog

## 2. Main Tabs

- `Run Workflow`
- `DQ Rules Editor`
- `MCP Session`
- `LLM Config` (demo/non-production only)
- `Help`
- `Admin` (admin only)

## 3. Run Workflow

Purpose: assess and correct data quality for one or more MCP servers.

Steps:

1. Select provider and dataset type.
2. Enter dataset ID.
3. Select target MCP server(s).
4. Optional: enable auto-correction when data source changes.
5. Click:
   - `Preview Dataset`
   - `Run Assessment`
   - `Run Correction`
   - `Workflow History`

Outputs include:

- quality index
- failed checks
- violations
- corrections applied

## 4. Workflow Analytics

Click `Workflow Analytics` in `Run Workflow`.

Available views:

- Quality Index Trend (line)
- Violation Severity Trend (line)
- Rule Application Trend (existing vs suggested approved vs declined)
- Correction Rule Usage split
- DQ Workflow Progress Timeline

Filters:

- Date range: all, 7, 30, 90 days
- Analytics server selection

Hover on chart points to see detailed popup context.

## 5. DQ Rules Editor

Purpose: maintain assessment and correction rules in editable form.

Steps:

1. Click `Load Rules`.
2. Select or add dataset type.
3. Edit assessment rules:
   - id, field, type, severity, params
4. Edit correction rules:
   - field, type, default
5. Click `Save Rules`.

Lower section shows:

- accepted suggested rules
- declined suggested rules

Use `Refresh Suggestion Decisions` to reload.

## 6. MCP Session

Purpose: manage active MCP connectivity and server catalogs.

Functions:

- Connect MCP server by URL
- Initialize active server
- List tools/data sources
- Show data model/dataset/FK relations

Server catalogs:

- `My MCP Servers`: user-owned list
- `Shared MCP Servers`: admin-managed shared list

Admin users can edit shared catalog in the same tab.

## 7. LLM Configuration (Demo / Non-Production)

If visible:

1. Set provider, model, endpoint, key env, key, temperature.
2. Save config.
3. Run assessment to generate rule suggestions (if enabled).

Production note:

- LLM configuration is file-based only.
- LLM tab is hidden in production UI.

## 8. Suggestion Queue

After assessment, suggested rules may appear in a review queue.

Actions:

- `Approve Suggestion`: stores rule and applies in later runs
- `Decline Suggestion`: rejects suggestion
- `Next Suggestion`: move through queue

## 9. Admin Page

Admins can:

- list users
- change role (`user` / `admin`)
- enable/disable users

Changes apply immediately.

## 10. Troubleshooting

- If actions fail with auth error:
  - login again
- If no data appears:
  - verify active MCP server and dataset type
- If run history is empty:
  - execute at least one assessment/correction first
- If shared servers missing:
  - ask admin to configure shared MCP servers

