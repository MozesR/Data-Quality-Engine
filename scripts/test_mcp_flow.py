#!/usr/bin/env python3
"""API smoke tests for IDQE MCP server.

Usage:
  python3 scripts/test_mcp_flow.py
  MCP_BASE_URL=http://localhost:8002 python3 scripts/test_mcp_flow.py
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

MCP_BASE_URL = os.getenv("MCP_BASE_URL", "http://localhost:8002").rstrip("/")


def post_json(path: str, payload: dict, token: str | None = None) -> dict:
    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(
        f"{MCP_BASE_URL}{path}",
        data=body,
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        details = e.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"HTTP {e.code} {path}: {details}") from e


def get_json(path: str, token: str | None = None) -> dict:
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(f"{MCP_BASE_URL}{path}", headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        details = e.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"HTTP {e.code} {path}: {details}") from e


def mcp_call(tool: str, arguments: dict | None = None, token: str | None = None) -> dict:
    return post_json("/mcp/call", {"tool": tool, "arguments": arguments or {}}, token=token)


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    print(f"Testing MCP server at {MCP_BASE_URL}")

    health = get_json("/health")
    assert_true(health.get("status") == "ok", "Health check failed")
    print("PASS: health")

    init = post_json("/mcp/initialize", {})
    assert_true(init.get("server"), "Initialize response missing server")
    print("PASS: initialize")

    tools = get_json("/mcp/tools")
    tool_names = {t.get("name") for t in tools.get("tools", [])}
    required_tools = {
        "run_dq_assessment",
        "run_correction",
        "simulate_rules",
        "get_rules_yaml",
        "save_rules_yaml",
        "get_llm_yaml",
        "save_llm_yaml",
        "approve_suggestion",
        "decline_suggestion",
    }
    missing = required_tools - tool_names
    assert_true(not missing, f"Missing tools: {sorted(missing)}")
    print("PASS: tools include new LLM/suggestion actions")

    # Register + login test user.
    email = f"smoke-{int(time.time())}@idqe.local"
    password = "SmokeTest123!"
    mcp_call("auth_register", {"name": "Smoke Test", "email": email, "password": password})
    login = mcp_call("auth_login", {"email": email, "password": password})
    token = (login.get("result") or {}).get("access_token")
    assert_true(bool(token), "Login failed to return access token")
    me = mcp_call("auth_me", {}, token=token)
    assert_true((me.get("result") or {}).get("authenticated") is True, "auth_me failed")
    print("PASS: auth register/login")

    # Enable LLM suggestions.
    llm_yaml_enabled = """llm:
  provider: mock
  model: gpt-4o-mini
  endpoint: null
  api_key_env: OPENAI_API_KEY
  api_key: ""
  temperature: 0.0
"""
    mcp_call("save_llm_yaml", {"yaml_text": llm_yaml_enabled}, token=token)
    print("PASS: save_llm_yaml (enabled)")

    # Use dataset likely to produce multiple suggestions.
    assess = mcp_call(
        "run_dq_assessment",
        {
            "provider": "BANK_A",
            "dataset_type": "credit_facility",
            "dataset_id": "test-suggestions-queue",
            "limit": 50,
        },
        token=token,
    )
    suggestions = (assess.get("result") or {}).get("suggestions") or []
    assert_true(len(suggestions) >= 1, "Expected at least one suggestion when LLM is enabled")
    print(f"PASS: assessment suggestions produced ({len(suggestions)} suggestion(s))")

    # Approve first suggestion.
    first_id = suggestions[0]["suggestion_id"]
    approve = mcp_call("approve_suggestion", {"suggestion_id": first_id}, token=token)
    assert_true("result" in approve, "approve_suggestion failed")
    print("PASS: approve_suggestion")

    # Decline second suggestion if present.
    if len(suggestions) > 1:
        second_id = suggestions[1]["suggestion_id"]
        decline = mcp_call("decline_suggestion", {"suggestion_id": second_id}, token=token)
        assert_true("result" in decline, "decline_suggestion failed")
        print("PASS: decline_suggestion")

    # Confirm rules now include an approved suggestion id prefix.
    rules_yaml = (mcp_call("get_rules_yaml", token=token).get("result") or {}).get("yaml_text", "")
    assert_true("SUG-" in rules_yaml, "Approved suggestion was not persisted to rules")
    print("PASS: approved suggestion persisted to rules")

    # Disable LLM and confirm suggestions stop.
    llm_yaml_disabled = """llm:
  provider: none
  model: gpt-4o-mini
  endpoint: null
  api_key_env: OPENAI_API_KEY
  api_key: ""
  temperature: 0.0
"""
    mcp_call("save_llm_yaml", {"yaml_text": llm_yaml_disabled}, token=token)
    assess_disabled = mcp_call(
        "run_dq_assessment",
        {
            "provider": "BANK_A",
            "dataset_type": "credit_facility",
            "dataset_id": "test-suggestions-disabled",
            "limit": 50,
        },
        token=token,
    )
    disabled_suggestions = (assess_disabled.get("result") or {}).get("suggestions") or []
    assert_true(len(disabled_suggestions) == 0, "Expected zero suggestions when LLM is disabled")
    print("PASS: no suggestions when LLM is disabled")

    simulation = mcp_call(
        "simulate_rules",
        {
            "provider": "BANK_A",
            "dataset_type": "credit_facility",
            "dataset_id": "test-simulation",
            "limit": 25,
        },
        token=token,
    )
    simulation_result = simulation.get("result") or {}
    assert_true(simulation_result.get("simulation") is True, "simulate_rules should return simulation=true")
    assert_true("quality_index" in simulation_result, "simulate_rules missing quality_index")
    print("PASS: simulate_rules")

    # Write endpoints require auth even in demo mode.
    try:
        mcp_call("save_rules_yaml", {"yaml_text": "data_sources: []\nassessment_rules: {}\ncorrection_rules: {}\n"})
        raise AssertionError("Expected unauthorized save_rules_yaml without token")
    except RuntimeError as e:
        assert_true("401" in str(e), "Expected 401 for unauthenticated save_rules_yaml")
    print("PASS: write endpoints require authentication")

    # Cross-user isolation: second user should not see first user's runs.
    email2 = f"smoke2-{int(time.time())}@idqe.local"
    mcp_call("auth_register", {"name": "Smoke Test 2", "email": email2, "password": password})
    login2 = mcp_call("auth_login", {"email": email2, "password": password})
    token2 = (login2.get("result") or {}).get("access_token")
    assert_true(bool(token2), "Second user login failed")
    runs_user2 = (mcp_call("get_workflow_runs", {"limit": 100}, token=token2).get("result") or [])
    assert_true(all(r.get("dataset_id") != "test-suggestions-queue" for r in runs_user2), "Run isolation failed: user2 can see user1 runs")
    print("PASS: per-user workflow run isolation")

    print("\nAll MCP smoke tests passed.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"\nTEST FAILED: {exc}")
        raise SystemExit(1)
