from __future__ import annotations

import os
from typing import Any

import yaml
from fastapi import FastAPI
from pydantic import BaseModel, Field


class LLMConfig(BaseModel):
    provider: str = "mock"
    model: str = "gpt-4o-mini"
    endpoint: str | None = None
    api_key_env: str = "OPENAI_API_KEY"
    api_key: str = ""
    temperature: float = 0.0


class Rule(BaseModel):
    id: str
    field: str
    type: str
    severity: str = "medium"
    params: dict[str, Any] = Field(default_factory=dict)


class AssessmentRequest(BaseModel):
    dataset_id: str
    dataset_type: str
    provider: str
    records: list[dict[str, Any]]
    rules: list[Rule]


class CorrectionRequest(BaseModel):
    dataset_id: str
    records: list[dict[str, Any]]
    corrections: list[dict[str, Any]]


def load_llm_config() -> LLMConfig:
    cfg_path = os.getenv("LLM_CONFIG_PATH", "/app/config/llm.yaml")
    if os.path.exists(cfg_path):
        with open(cfg_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        cfg = LLMConfig(**data.get("llm", {}))
        if not cfg.api_key:
            # Support Docker/K8s secret file path as fallback.
            secret_path = "/run/secrets/openai_api_key"
            if os.path.exists(secret_path):
                with open(secret_path, "r", encoding="utf-8") as f:
                    cfg.api_key = f.read().strip()
        return cfg
    return LLMConfig()


def to_float(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value).strip())
    except Exception:
        return None


def evaluate_rule(rule: Rule, value: Any) -> tuple[bool, str]:
    if rule.type == "not_null":
        ok = value is not None and value != ""
        return ok, "Value is missing"
    if rule.type == "range":
        min_v = to_float(rule.params.get("min"))
        max_v = to_float(rule.params.get("max"))
        val = to_float(value)
        if val is None:
            return False, "Value missing for range check"
        if min_v is not None and val < min_v:
            return False, f"Value {value} is below min {min_v}"
        if max_v is not None and val > max_v:
            return False, f"Value {value} is above max {max_v}"
        return True, ""
    if rule.type == "allowed_values":
        allowed = set(rule.params.get("values", []))
        ok = value in allowed
        return ok, f"Value {value} not in allowed set"
    if rule.type == "regex":
        import re

        pattern = rule.params.get("pattern", ".*")
        ok = isinstance(value, str) and bool(re.match(pattern, value))
        return ok, f"Value {value} does not match regex"
    return True, "Unsupported rule type treated as pass"


app = FastAPI(title="DQ Engine", version="0.1.0")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/config")
def read_config() -> dict[str, Any]:
    cfg = load_llm_config()
    return {
        "provider": cfg.provider,
        "model": cfg.model,
        "endpoint": cfg.endpoint,
        "temperature": cfg.temperature,
        "api_key_env": cfg.api_key_env,
    }


@app.post("/assess")
def assess(req: AssessmentRequest) -> dict[str, Any]:
    violations: list[dict[str, Any]] = []
    total_checks = 0
    failed_checks = 0

    for idx, record in enumerate(req.records):
        for rule in req.rules:
            total_checks += 1
            ok, reason = evaluate_rule(rule, record.get(rule.field))
            if not ok:
                failed_checks += 1
                violations.append(
                    {
                        "record_index": idx,
                        "rule_id": rule.id,
                        "field": rule.field,
                        "severity": rule.severity,
                        "reason": reason,
                        "value": record.get(rule.field),
                    }
                )

    quality_index = round((1 - (failed_checks / total_checks)) * 100, 2) if total_checks else 100.0

    llm_cfg = load_llm_config()
    llm_note = (
        "LLM suggestions enabled"
        if llm_cfg.provider != "none"
        else "LLM suggestions disabled"
    )

    return {
        "dataset_id": req.dataset_id,
        "dataset_type": req.dataset_type,
        "provider": req.provider,
        "total_records": len(req.records),
        "total_checks": total_checks,
        "failed_checks": failed_checks,
        "quality_index": quality_index,
        "violations": violations,
        "llm": {
            "provider": llm_cfg.provider,
            "model": llm_cfg.model,
            "note": llm_note,
        },
    }


@app.post("/correct")
def correct(req: CorrectionRequest) -> dict[str, Any]:
    corrected = [dict(r) for r in req.records]
    applied: list[dict[str, Any]] = []

    for correction in req.corrections:
        field = correction.get("field")
        ctype = correction.get("type")
        default = correction.get("default")

        for idx, record in enumerate(corrected):
            if ctype == "fill_default_if_null" and (record.get(field) is None or record.get(field) == ""):
                record[field] = default
                applied.append({"record_index": idx, "field": field, "action": ctype, "new_value": default})

    return {
        "dataset_id": req.dataset_id,
        "total_records": len(req.records),
        "corrections_applied": len(applied),
        "applied": applied,
        "records": corrected,
    }
