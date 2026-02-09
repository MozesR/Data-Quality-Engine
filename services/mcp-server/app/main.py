from __future__ import annotations

import base64
import csv
import difflib
import hashlib
import hmac
import json
import logging
import os
import random
import secrets
import statistics
import time
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import jwt
import yaml
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from pythonjsonlogger import jsonlogger
from sqlalchemy import JSON, Boolean, Column, DateTime, Integer, MetaData, String, Table, create_engine, text

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+psycopg2://dq:dq@postgres:5432/dq")
DQ_ENGINE_URL = os.getenv("DQ_ENGINE_URL", "http://dq-engine:8001")
RULES_CONFIG_PATH = os.getenv("RULES_CONFIG_PATH", "/app/config/rules.yaml")
LLM_CONFIG_PATH = os.getenv("LLM_CONFIG_PATH", "/app/config/llm.yaml")
MCP_SERVER_NAME = os.getenv("MCP_SERVER_NAME", "dq-workflow-mcp")
AUDIT_ARTIFACTS_DIR = os.getenv("AUDIT_ARTIFACTS_DIR", "/tmp/idqe-audit")

AUTH_MODE = os.getenv("AUTH_MODE", "demo")  # demo|production
AUTH_REQUIRED = os.getenv("AUTH_REQUIRED", "true" if AUTH_MODE == "production" else "false").lower() == "true"
AUTH_SECRET = os.getenv("AUTH_SECRET", "dev-insecure-secret-change-me")
ACCESS_TOKEN_TTL_MINUTES = int(os.getenv("ACCESS_TOKEN_TTL_MINUTES", "480"))
DEMO_ADMIN_EMAIL = os.getenv("DEMO_ADMIN_EMAIL", "admin@idqe.local")
DEMO_ADMIN_PASSWORD = os.getenv("DEMO_ADMIN_PASSWORD", "Admin123!")
CORS_ALLOW_ORIGINS = [x.strip() for x in os.getenv("CORS_ALLOW_ORIGINS", "http://localhost:8080,http://127.0.0.1:8080").split(",") if x.strip()]
UI_ALLOW_LLM_TAB = os.getenv("UI_ALLOW_LLM_TAB", "false" if AUTH_MODE == "production" else "true").lower() == "true"
LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", "8"))
LOGIN_WINDOW_SECONDS = int(os.getenv("LOGIN_WINDOW_SECONDS", "300"))
LOGIN_LOCK_SECONDS = int(os.getenv("LOGIN_LOCK_SECONDS", "900"))
PENDING_SUGGESTIONS_RETENTION_DAYS = int(os.getenv("PENDING_SUGGESTIONS_RETENTION_DAYS", "30"))
ALERT_QUALITY_THRESHOLD = float(os.getenv("ALERT_QUALITY_THRESHOLD", "95"))
EVENT_WEBHOOK_URL = os.getenv("EVENT_WEBHOOK_URL", "").strip()
TICKET_WEBHOOK_URL = os.getenv("TICKET_WEBHOOK_URL", "").strip()
MAX_QUERY_LIMIT = int(os.getenv("MAX_QUERY_LIMIT", "1000"))
MAX_LIST_LIMIT = int(os.getenv("MAX_LIST_LIMIT", "500"))
JOB_CLAIM_SECONDS = int(os.getenv("JOB_CLAIM_SECONDS", "300"))

JWT_ISSUER = os.getenv("JWT_ISSUER", MCP_SERVER_NAME)
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "idqe-ui")
REFRESH_TOKEN_TTL_DAYS = int(os.getenv("REFRESH_TOKEN_TTL_DAYS", "14"))

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# Prometheus metrics (best-effort; safe even if not scraped).
HTTP_REQUESTS_TOTAL = Counter(
    "idqe_http_requests_total",
    "Total HTTP requests",
    ["path", "method", "status"],
)
HTTP_REQUEST_LATENCY_SECONDS = Histogram(
    "idqe_http_request_latency_seconds",
    "HTTP request latency in seconds",
    ["path", "method"],
)
MCP_TOOL_CALLS_TOTAL = Counter(
    "idqe_mcp_tool_calls_total",
    "Total MCP tool calls",
    ["tool"],
)
AUTH_LOGIN_TOTAL = Counter("idqe_auth_login_total", "Total login attempts", ["outcome"])
WORKFLOW_JOB_RUN_TOTAL = Counter("idqe_workflow_job_run_total", "Total workflow job executions", ["status"])

DEFAULT_RULES_CONFIG: dict[str, Any] = {
    "data_sources": [
        {"provider": "BANK_A", "dataset_types": ["customer_profile", "credit_facility"]},
        {"provider": "BANK_B", "dataset_types": ["customer_profile"]},
    ],
    "assessment_rules": {
        "customer_profile": [
            {"id": "R001", "field": "customer_id", "type": "not_null", "severity": "high"},
            {
                "id": "R002",
                "field": "segment",
                "type": "allowed_values",
                "severity": "medium",
                "params": {"values": ["SME", "CORP", "RETAIL"]},
            },
            {
                "id": "R003",
                "field": "risk_score",
                "type": "range",
                "severity": "high",
                "params": {"min": 0, "max": 100},
            },
            {
                "id": "R004",
                "field": "country",
                "type": "regex",
                "severity": "low",
                "params": {"pattern": "^[A-Z]{2}$"},
            },
        ],
        "credit_facility": [
            {"id": "R101", "field": "facility_id", "type": "not_null", "severity": "high"},
            {
                "id": "R102",
                "field": "limit_amount",
                "type": "range",
                "severity": "high",
                "params": {"min": 0, "max": 20000000},
            },
            {
                "id": "R103",
                "field": "dpd",
                "type": "range",
                "severity": "medium",
                "params": {"min": 0, "max": 365},
            },
        ],
    },
    "correction_rules": {
        "customer_profile": [{"field": "segment", "type": "fill_default_if_null", "default": "SME"}],
        "credit_facility": [{"field": "dpd", "type": "fill_default_if_null", "default": 0}],
    },
}

DEFAULT_LLM_CONFIG: dict[str, Any] = {
    "llm": {
        "provider": "mock",
        "model": "gpt-4o-mini",
        "endpoint": None,
        "api_key_env": "OPENAI_API_KEY",
        "api_key": "",
        "temperature": 0.0,
    }
}

metadata = MetaData()
workflow_runs = Table(
    "workflow_runs",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("run_id", String(64), nullable=False, unique=True),
    Column("dataset_id", String(128), nullable=False),
    Column("dataset_type", String(64), nullable=False),
    Column("provider", String(64), nullable=False),
    Column("process_type", String(64), nullable=False),
    Column("status", String(64), nullable=False),
    Column("result", JSON, nullable=True),
    Column("owner_user_id", Integer, nullable=True),
    Column("created_at", DateTime, nullable=False),
)
suggestion_decisions = Table(
    "suggestion_decisions",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("suggestion_id", String(64), nullable=False),
    Column("dataset_type", String(64), nullable=False),
    Column("decision", String(32), nullable=False),
    Column("suggestion", JSON, nullable=False),
    Column("owner_user_id", Integer, nullable=True),
    Column("created_at", DateTime, nullable=False),
)
users = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("email", String(320), nullable=False, unique=True),
    Column("name", String(120), nullable=False),
    Column("password_hash", String(512), nullable=False),
    Column("role", String(32), nullable=False),  # admin|user
    Column("team", String(64), nullable=False, default="default"),
    Column("is_active", Boolean, nullable=False),
    Column("created_at", DateTime, nullable=False),
    Column("last_login_at", DateTime, nullable=True),
)
refresh_tokens = Table(
    "refresh_tokens",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("token_id", String(64), nullable=False, unique=True),
    Column("user_id", Integer, nullable=False),
    Column("token_hash", String(128), nullable=False),
    Column("expires_at", DateTime, nullable=False),
    Column("revoked_at", DateTime, nullable=True),
    Column("created_at", DateTime, nullable=False),
)
revoked_tokens = Table(
    "revoked_tokens",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("jti", String(64), nullable=False, unique=True),
    Column("token_type", String(16), nullable=False),  # access
    Column("user_id", Integer, nullable=False),
    Column("expires_at", DateTime, nullable=False),
    Column("created_at", DateTime, nullable=False),
)
user_settings = Table(
    "user_settings",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("user_id", Integer, nullable=False, unique=True),
    Column("rules_config", JSON, nullable=True),
    Column("created_at", DateTime, nullable=False),
    Column("updated_at", DateTime, nullable=False),
)
shared_mcp_servers = Table(
    "shared_mcp_servers",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String(120), nullable=False),
    Column("base_url", String(512), nullable=False, unique=True),
    Column("is_active", Boolean, nullable=False),
    Column("created_at", DateTime, nullable=False),
    Column("updated_at", DateTime, nullable=False),
)
pending_suggestions_store = Table(
    "pending_suggestions_store",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("suggestion_id", String(64), nullable=False, unique=True),
    Column("dataset_type", String(64), nullable=False),
    Column("suggestion", JSON, nullable=False),
    Column("owner_user_id", Integer, nullable=True),
    Column("status", String(32), nullable=False),  # pending|approved|declined
    Column("created_at", DateTime, nullable=False),
)
rule_versions = Table(
    "rule_versions",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("version_id", String(64), nullable=False, unique=True),
    Column("owner_user_id", Integer, nullable=True),
    Column("note", String(256), nullable=False),
    Column("rules_config", JSON, nullable=False),
    Column("created_at", DateTime, nullable=False),
)
workflow_jobs = Table(
    "workflow_jobs",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("job_id", String(64), nullable=False, unique=True),
    Column("owner_user_id", Integer, nullable=True),
    Column("name", String(128), nullable=False),
    Column("provider", String(64), nullable=False),
    Column("dataset_type", String(64), nullable=False),
    Column("dataset_id", String(128), nullable=False),
    Column("process_type", String(32), nullable=False),  # assessment|correction|both
    Column("interval_minutes", Integer, nullable=False),
    Column("sla_min_quality", Integer, nullable=True),
    Column("is_active", Boolean, nullable=False),
    Column("next_run_at", DateTime, nullable=False),
    Column("last_run_at", DateTime, nullable=True),
    Column("last_status", String(32), nullable=True),
    Column("last_message", String(512), nullable=True),
    Column("claimed_until", DateTime, nullable=True),
    Column("claimed_by", String(64), nullable=True),
    Column("created_at", DateTime, nullable=False),
    Column("updated_at", DateTime, nullable=False),
)
drift_baselines = Table(
    "drift_baselines",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("baseline_id", String(64), nullable=False, unique=True),
    Column("owner_user_id", Integer, nullable=True),
    Column("provider", String(64), nullable=False),
    Column("dataset_type", String(64), nullable=False),
    Column("profile", JSON, nullable=False),
    Column("created_at", DateTime, nullable=False),
)
alerts_store = Table(
    "alerts_store",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("alert_id", String(64), nullable=False, unique=True),
    Column("owner_user_id", Integer, nullable=True),
    Column("source", String(64), nullable=False),
    Column("severity", String(32), nullable=False),
    Column("message", String(512), nullable=False),
    Column("payload", JSON, nullable=True),
    Column("created_at", DateTime, nullable=False),
)
suggestion_approvals = Table(
    "suggestion_approvals",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("suggestion_id", String(64), nullable=False),
    Column("approver_user_id", Integer, nullable=False),
    Column("created_at", DateTime, nullable=False),
)
team_policies = Table(
    "team_policies",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("team", String(64), nullable=False, unique=True),
    Column("allowed_dataset_types", JSON, nullable=True),
    Column("allowed_server_urls", JSON, nullable=True),
    Column("scoped_admin", Boolean, nullable=False),
    Column("updated_at", DateTime, nullable=False),
)
admin_audit_logs = Table(
    "admin_audit_logs",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("event_id", String(64), nullable=False, unique=True),
    Column("admin_user_id", Integer, nullable=False),
    Column("action", String(128), nullable=False),
    Column("target_type", String(64), nullable=False),
    Column("target_id", String(128), nullable=True),
    Column("summary", String(512), nullable=False),
    Column("details", JSON, nullable=True),
    Column("created_at", DateTime, nullable=False),
)

engine = create_engine(DATABASE_URL, future=True)
login_attempts: dict[str, list[int | float]] = {}
login_locks: dict[str, float] = {}


class MCPCall(BaseModel):
    tool: str
    arguments: dict[str, Any]


app = FastAPI(title="Workflow MCP Server", version="0.3.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOW_ORIGINS or ["http://localhost:8080"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)

logger = logging.getLogger("idqe")


def configure_logging() -> None:
    root = logging.getLogger()
    root.setLevel(LOG_LEVEL)
    # Replace handlers to avoid duplicate logs under reload.
    root.handlers = []
    h = logging.StreamHandler()
    fmt = jsonlogger.JsonFormatter("%(asctime)s %(levelname)s %(name)s %(message)s %(request_id)s")
    h.setFormatter(fmt)
    root.addHandler(h)


@app.middleware("http")
async def request_context_middleware(request: Request, call_next):  # type: ignore[no-untyped-def]
    request_id = request.headers.get("X-Request-ID", "").strip() or f"req-{uuid.uuid4().hex}"
    request.state.request_id = request_id  # type: ignore[attr-defined]
    path = request.url.path
    method = request.method
    start = time.perf_counter()
    try:
        resp = await call_next(request)
        resp.headers["X-Request-ID"] = request_id
        status = str(resp.status_code)
        return resp
    except Exception:
        status = "500"
        raise
    finally:
        dur = max(0.0, time.perf_counter() - start)
        HTTP_REQUESTS_TOTAL.labels(path=path, method=method, status=status).inc()
        HTTP_REQUEST_LATENCY_SECONDS.labels(path=path, method=method).observe(dur)


# ---------- utility ----------
def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def to_jsonable(value: Any) -> Any:
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, dict):
        return {k: to_jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [to_jsonable(v) for v in value]
    if isinstance(value, tuple):
        return [to_jsonable(v) for v in value]
    return value


def as_json_text(value: Any) -> str:
    return json.dumps(to_jsonable(value))


def parse_json_value(value: Any, fallback: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, (dict, list)):
                return parsed
        except Exception:
            return fallback
    return fallback


def safe_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4()}"


def clamp_limit(value: Any, default: int, max_limit: int) -> int:
    try:
        n = int(value)
    except Exception:
        n = default
    return max(1, min(max_limit, n))


def load_yaml_with_default(path: str, default_obj: dict[str, Any]) -> dict[str, Any]:
    if not os.path.exists(path):
        return default_obj
    with open(path, "r", encoding="utf-8") as f:
        loaded = yaml.safe_load(f) or {}
    if not isinstance(loaded, dict):
        return default_obj
    return loaded


def save_yaml(path: str, payload: dict[str, Any]) -> None:
    target_dir = os.path.dirname(path) or "."
    os.makedirs(target_dir, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(payload, f, sort_keys=False, allow_unicode=False)


def ensure_security_defaults() -> None:
    if AUTH_MODE == "production":
        if not AUTH_REQUIRED:
            raise RuntimeError("AUTH_REQUIRED must be true in production mode")
        if AUTH_SECRET == "dev-insecure-secret-change-me":
            raise RuntimeError("AUTH_SECRET must be set to a strong secret in production mode")
    if AUTH_MODE != "demo":
        if os.getenv("DEMO_ADMIN_PASSWORD", "") == "Admin123!":
            raise RuntimeError("DEMO_ADMIN_PASSWORD must not use demo default in non-demo mode")
        if os.getenv("DEMO_ADMIN_EMAIL", "") == "admin@idqe.local":
            raise RuntimeError("DEMO_ADMIN_EMAIL must not use demo default in non-demo mode")


def enforce_authenticated_write(user: dict[str, Any] | None) -> None:
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required for write operation")


def client_ip(request: Request) -> str:
    xff = request.headers.get("X-Forwarded-For", "").strip()
    if xff:
        return xff.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def login_key(email: str, ip: str) -> str:
    return f"{email}|{ip}"


def login_is_locked(key: str) -> bool:
    now_ts = utcnow().timestamp()
    until = login_locks.get(key, 0.0)
    if until > now_ts:
        return True
    if key in login_locks:
        login_locks.pop(key, None)
    return False


def login_record_failure(key: str) -> None:
    now_ts = utcnow().timestamp()
    wins = [t for t in login_attempts.get(key, []) if now_ts - t <= LOGIN_WINDOW_SECONDS]
    wins.append(now_ts)
    login_attempts[key] = wins
    if len(wins) >= LOGIN_MAX_ATTEMPTS:
        login_locks[key] = now_ts + LOGIN_LOCK_SECONDS
        login_attempts.pop(key, None)


def login_record_success(key: str) -> None:
    login_attempts.pop(key, None)
    login_locks.pop(key, None)


# ---------- auth ----------
def password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
    return f"pbkdf2_sha256${base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(dk).decode()}"


def verify_password(password: str, hashed: str) -> bool:
    try:
        algo, salt_b64, dk_b64 = hashed.split("$", 2)
        if algo != "pbkdf2_sha256":
            return False
        salt = base64.urlsafe_b64decode(salt_b64.encode())
        expected = base64.urlsafe_b64decode(dk_b64.encode())
        got = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
        return hmac.compare_digest(got, expected)
    except Exception:
        return False


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64url_decode(data: str) -> bytes:
    pad = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode((data + pad).encode())


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def is_access_token_revoked(jti: str) -> bool:
    if not jti:
        return False
    now = utcnow()
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT 1 FROM revoked_tokens WHERE jti = :jti AND expires_at > :now LIMIT 1"),
            {"jti": jti, "now": now},
        ).first()
    return bool(row)


def revoke_access_token(jti: str, user_id: int, expires_at: datetime) -> None:
    if not jti:
        return
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO revoked_tokens (jti, token_type, user_id, expires_at, created_at)
                VALUES (:jti, 'access', :uid, :exp, :now)
                ON CONFLICT (jti) DO NOTHING
                """
            ),
            {"jti": jti, "uid": user_id, "exp": expires_at, "now": utcnow()},
        )


def make_access_token(user: dict[str, Any]) -> str:
    now = utcnow()
    exp = now + timedelta(minutes=ACCESS_TOKEN_TTL_MINUTES)
    jti = f"at-{uuid.uuid4().hex}"
    payload = {
        "typ": "access",
        "jti": jti,
        "sub": str(user["id"]),
        "email": str(user.get("email") or ""),
        "role": str(user.get("role") or "user"),
        "team": str(user.get("team") or "default"),
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
    }
    return jwt.encode(payload, AUTH_SECRET, algorithm="HS256")


def parse_access_token(token: str) -> dict[str, Any] | None:
    try:
        payload = jwt.decode(
            token,
            AUTH_SECRET,
            algorithms=["HS256"],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
        )
        if payload.get("typ") != "access":
            return None
        jti = str(payload.get("jti") or "")
        if jti and is_access_token_revoked(jti):
            return None
        return payload
    except Exception:
        return None


def make_refresh_token(user_id: int) -> str:
    token_id = f"rt-{uuid.uuid4().hex}"
    secret_part = secrets.token_urlsafe(32)
    raw = f"{token_id}.{secret_part}"
    now = utcnow()
    exp = now + timedelta(days=REFRESH_TOKEN_TTL_DAYS)
    with engine.begin() as conn:
        conn.execute(
            refresh_tokens.insert().values(
                token_id=token_id,
                user_id=user_id,
                token_hash=sha256_hex(raw),
                expires_at=exp,
                revoked_at=None,
                created_at=now,
            )
        )
    return raw


def rotate_refresh_token(raw_refresh_token: str) -> tuple[int, str] | None:
    raw = str(raw_refresh_token or "").strip()
    if "." not in raw:
        return None
    token_id = raw.split(".", 1)[0]
    now = utcnow()
    with engine.begin() as conn:
        row = conn.execute(
            text(
                """
                SELECT id, user_id, token_hash, expires_at, revoked_at
                FROM refresh_tokens
                WHERE token_id = :tid
                LIMIT 1
                """
            ),
            {"tid": token_id},
        ).mappings().first()
        if not row:
            return None
        if row.get("revoked_at") is not None:
            return None
        exp = row.get("expires_at")
        if not isinstance(exp, datetime) or exp <= now:
            return None
        if str(row.get("token_hash") or "") != sha256_hex(raw):
            return None

        # Revoke old, create new.
        conn.execute(
            text("UPDATE refresh_tokens SET revoked_at = :now WHERE token_id = :tid"),
            {"now": now, "tid": token_id},
        )
        user_id = int(row.get("user_id") or 0)
    if user_id <= 0:
        return None
    new_raw = make_refresh_token(user_id)
    return user_id, new_raw


def get_current_user(request: Request, allow_anonymous: bool = False) -> dict[str, Any] | None:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        if allow_anonymous:
            return None
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = auth[7:]
    payload = parse_access_token(token)
    if not payload:
        if allow_anonymous:
            return None
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT id, email, name, role, team, is_active FROM users WHERE id = :id LIMIT 1"),
            {"id": int(payload.get("sub", 0))},
        ).mappings().first()
    if not row:
        if allow_anonymous:
            return None
        raise HTTPException(status_code=401, detail="User not found")
    user = dict(row)
    if not user.get("is_active"):
        if allow_anonymous:
            return None
        raise HTTPException(status_code=403, detail="User is inactive")
    return user


def require_admin(user: dict[str, Any] | None) -> None:
    if not user or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")


def server_url_from_request(request: Request) -> str:
    return str(request.base_url).rstrip("/")


def get_team_policy(team: str) -> dict[str, Any] | None:
    with engine.begin() as conn:
        row = conn.execute(
            text(
                """
                SELECT team, allowed_dataset_types, allowed_server_urls, scoped_admin
                FROM team_policies
                WHERE team = :team
                LIMIT 1
                """
            ),
            {"team": team},
        ).mappings().first()
    if not row:
        return None
    return {
        "team": row.get("team"),
        "allowed_dataset_types": parse_json_value(row.get("allowed_dataset_types"), []),
        "allowed_server_urls": parse_json_value(row.get("allowed_server_urls"), []),
        "scoped_admin": bool(row.get("scoped_admin", False)),
    }


def can_manage_user(manager: dict[str, Any], target_team: str) -> bool:
    policy = get_team_policy(str(manager.get("team") or "default"))
    if not policy or not policy.get("scoped_admin"):
        return True
    return str(manager.get("team") or "default") == str(target_team or "default")


def get_user_brief(user_id: int) -> dict[str, Any] | None:
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT id, role, team, is_active FROM users WHERE id = :id LIMIT 1"),
            {"id": user_id},
        ).mappings().first()
    return dict(row) if row else None


def enforce_team_scope(
    user: dict[str, Any] | None,
    request: Request,
    dataset_type: str | None = None,
    admin_action: bool = False,
) -> None:
    if not user:
        return
    policy = get_team_policy(str(user.get("team") or "default"))
    if not policy:
        return
    allowed_servers = policy.get("allowed_server_urls") or []
    if isinstance(allowed_servers, list) and allowed_servers:
        current_url = server_url_from_request(request)
        if "*" not in allowed_servers and current_url not in allowed_servers:
            raise HTTPException(status_code=403, detail=f"Team policy denies server access: {current_url}")
    allowed_datasets = policy.get("allowed_dataset_types") or []
    if dataset_type and isinstance(allowed_datasets, list) and allowed_datasets:
        if dataset_type not in allowed_datasets:
            raise HTTPException(status_code=403, detail=f"Team policy denies dataset access: {dataset_type}")
    if admin_action and policy.get("scoped_admin") and user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Team policy requires admin role")


def validate_new_password(password: str) -> None:
    if AUTH_MODE == "production":
        if len(password) < 12:
            raise HTTPException(status_code=400, detail="Password must be at least 12 characters in production mode")
        if password.lower() == password or password.upper() == password:
            raise HTTPException(status_code=400, detail="Password must include mixed case")
        if not any(ch.isdigit() for ch in password):
            raise HTTPException(status_code=400, detail="Password must include a number")


def ensure_demo_admin() -> None:
    if AUTH_MODE != "demo":
        return
    with engine.begin() as conn:
        exists = conn.execute(text("SELECT id FROM users WHERE email = :email LIMIT 1"), {"email": DEMO_ADMIN_EMAIL}).mappings().first()
        if exists:
            return
        conn.execute(
            users.insert().values(
                email=DEMO_ADMIN_EMAIL,
                name="Demo Admin",
                password_hash=password_hash(DEMO_ADMIN_PASSWORD),
                role="admin",
                team="default",
                is_active=True,
                created_at=utcnow(),
                last_login_at=None,
            )
        )


def ensure_demo_shared_servers() -> None:
    if AUTH_MODE != "demo":
        return
    with engine.begin() as conn:
        row = conn.execute(text("SELECT COUNT(*) AS c FROM shared_mcp_servers")).mappings().first()
        if row and int(row.get("c", 0)) > 0:
            return
    save_shared_mcp_servers(
        [
            {"name": "dq-workflow-mcp-a", "base_url": "http://localhost:8002", "is_active": True},
            {"name": "dq-workflow-mcp-b", "base_url": "http://localhost:8003", "is_active": True},
        ]
    )


# ---------- user settings ----------
def get_user_settings(user_id: int) -> dict[str, Any]:
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT rules_config FROM user_settings WHERE user_id = :uid LIMIT 1"),
            {"uid": user_id},
        ).mappings().first()
    if not row:
        return {"rules_config": None}
    return {
        "rules_config": to_jsonable(row.get("rules_config")),
    }


def upsert_user_rules_config(user_id: int, config: dict[str, Any]) -> None:
    now = utcnow()
    cfg_json = json.dumps(to_jsonable(config))
    with engine.begin() as conn:
        existing = conn.execute(text("SELECT id FROM user_settings WHERE user_id = :uid LIMIT 1"), {"uid": user_id}).mappings().first()
        if existing:
            conn.execute(
                text("UPDATE user_settings SET rules_config = :cfg, updated_at = :upd WHERE user_id = :uid"),
                {"cfg": cfg_json, "upd": now, "uid": user_id},
            )
        else:
            conn.execute(
                user_settings.insert().values(
                    user_id=user_id,
                    rules_config=to_jsonable(config),
                    created_at=now,
                    updated_at=now,
                )
            )


def normalize_base_url(url: str) -> str:
    value = str(url or "").strip().rstrip("/")
    if value.startswith("http://") or value.startswith("https://"):
        return value
    return ""


def sanitize_mcp_server_entries(servers: list[dict[str, Any]], *, require_active_flag: bool = False) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in servers:
        if not isinstance(item, dict):
            continue
        base_url = normalize_base_url(str(item.get("base_url") or item.get("url") or ""))
        if not base_url or base_url in seen:
            continue
        seen.add(base_url)
        name = str(item.get("name") or "mcp-server").strip() or "mcp-server"
        entry: dict[str, Any] = {"name": name, "base_url": base_url}
        if require_active_flag:
            entry["is_active"] = bool(item.get("is_active", True))
        out.append(entry)
    return out


def get_shared_mcp_servers(include_inactive: bool = False) -> list[dict[str, Any]]:
    with engine.begin() as conn:
        if include_inactive:
            rows = conn.execute(
                text(
                    """
                    SELECT id, name, base_url, is_active, created_at, updated_at
                    FROM shared_mcp_servers
                    ORDER BY id ASC
                    """
                )
            ).mappings().all()
        else:
            rows = conn.execute(
                text(
                    """
                    SELECT id, name, base_url, is_active, created_at, updated_at
                    FROM shared_mcp_servers
                    WHERE is_active = true
                    ORDER BY id ASC
                    """
                )
            ).mappings().all()
    data: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        item["created_at"] = item["created_at"].isoformat() if item.get("created_at") else None
        item["updated_at"] = item["updated_at"].isoformat() if item.get("updated_at") else None
        data.append(to_jsonable(item))
    return data


def save_shared_mcp_servers(servers: list[dict[str, Any]]) -> None:
    clean = sanitize_mcp_server_entries(servers, require_active_flag=True)
    now = utcnow()
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM shared_mcp_servers"))
        for item in clean:
            conn.execute(
                shared_mcp_servers.insert().values(
                    name=item["name"],
                    base_url=item["base_url"],
                    is_active=bool(item.get("is_active", True)),
                    created_at=now,
                    updated_at=now,
                )
            )




# ---------- business config ----------
def load_rules_config_global() -> dict[str, Any]:
    cfg = load_yaml_with_default(RULES_CONFIG_PATH, DEFAULT_RULES_CONFIG)
    return {
        "data_sources": cfg.get("data_sources", DEFAULT_RULES_CONFIG["data_sources"]),
        "assessment_rules": cfg.get("assessment_rules", DEFAULT_RULES_CONFIG["assessment_rules"]),
        "correction_rules": cfg.get("correction_rules", DEFAULT_RULES_CONFIG["correction_rules"]),
    }


def validate_rules_config(cfg: dict[str, Any]) -> None:
    required_sections = ["data_sources", "assessment_rules", "correction_rules"]
    for section in required_sections:
        if section not in cfg:
            raise HTTPException(status_code=400, detail=f"Missing required config section: {section}")
    if not isinstance(cfg["assessment_rules"], dict):
        raise HTTPException(status_code=400, detail="assessment_rules must be a mapping/object")
    if not isinstance(cfg["correction_rules"], dict):
        raise HTTPException(status_code=400, detail="correction_rules must be a mapping/object")


def load_rules_config_for_user(user_id: int | None) -> dict[str, Any]:
    base = load_rules_config_global()
    if user_id is None:
        return base
    us = get_user_settings(user_id)
    override = us.get("rules_config")
    if isinstance(override, dict):
        merged = {
            "data_sources": override.get("data_sources", base["data_sources"]),
            "assessment_rules": override.get("assessment_rules", base["assessment_rules"]),
            "correction_rules": override.get("correction_rules", base["correction_rules"]),
        }
        validate_rules_config(merged)
        return merged
    return base


def rules_config_as_yaml_for_user(user_id: int | None) -> str:
    return yaml.safe_dump(load_rules_config_for_user(user_id), sort_keys=False, allow_unicode=False)


def save_rules_yaml_for_user(user_id: int | None, yaml_text: str) -> None:
    try:
        parsed = yaml.safe_load(yaml_text) or {}
    except yaml.YAMLError as e:
        raise HTTPException(status_code=400, detail=f"Invalid YAML: {e}") from e
    if not isinstance(parsed, dict):
        raise HTTPException(status_code=400, detail="Top-level YAML must be a mapping/object")
    validate_rules_config(parsed)
    if user_id is None:
        save_yaml(RULES_CONFIG_PATH, parsed)
    else:
        upsert_user_rules_config(user_id, parsed)
    create_rule_version(user_id, parsed, "save_rules_yaml")


def load_llm_config() -> dict[str, Any]:
    cfg = load_yaml_with_default(LLM_CONFIG_PATH, DEFAULT_LLM_CONFIG)
    llm = cfg.get("llm", {}) if isinstance(cfg, dict) else {}
    if not isinstance(llm, dict):
        llm = {}
    return {
        "llm": {
            "provider": llm.get("provider", DEFAULT_LLM_CONFIG["llm"]["provider"]),
            "model": llm.get("model", DEFAULT_LLM_CONFIG["llm"]["model"]),
            "endpoint": llm.get("endpoint", DEFAULT_LLM_CONFIG["llm"]["endpoint"]),
            "api_key_env": llm.get("api_key_env", DEFAULT_LLM_CONFIG["llm"]["api_key_env"]),
            "api_key": llm.get("api_key", DEFAULT_LLM_CONFIG["llm"].get("api_key", "")),
            "temperature": llm.get("temperature", DEFAULT_LLM_CONFIG["llm"]["temperature"]),
        }
    }


def llm_config_as_yaml() -> str:
    return yaml.safe_dump(load_llm_config(), sort_keys=False, allow_unicode=False)


def save_llm_yaml(yaml_text: str) -> None:
    try:
        parsed = yaml.safe_load(yaml_text) or {}
    except yaml.YAMLError as e:
        raise HTTPException(status_code=400, detail=f"Invalid YAML: {e}") from e
    if not isinstance(parsed, dict) or "llm" not in parsed or not isinstance(parsed["llm"], dict):
        raise HTTPException(status_code=400, detail="LLM config must contain top-level 'llm' mapping")
    save_yaml(LLM_CONFIG_PATH, parsed)


def llm_enabled() -> bool:
    provider = str(load_llm_config()["llm"].get("provider", "none")).strip().lower()
    return provider not in {"none", "disabled", "off"}


# ---------- versions / drift / jobs / alerts ----------
def create_rule_version(owner_user_id: int | None, config: dict[str, Any], note: str) -> str:
    version_id = safe_id("rv")
    with engine.begin() as conn:
        conn.execute(
            rule_versions.insert().values(
                version_id=version_id,
                owner_user_id=owner_user_id,
                note=(note or "snapshot")[:256],
                rules_config=to_jsonable(config),
                created_at=utcnow(),
            )
        )
    return version_id


def list_rule_versions(owner_user_id: int | None, limit: int = 25) -> list[dict[str, Any]]:
    with engine.begin() as conn:
        if owner_user_id is None:
            rows = conn.execute(
                text(
                    """
                    SELECT version_id, note, created_at
                    FROM rule_versions
                    WHERE owner_user_id IS NULL
                    ORDER BY id DESC
                    LIMIT :limit
                    """
                ),
                {"limit": limit},
            ).mappings().all()
        else:
            rows = conn.execute(
                text(
                    """
                    SELECT version_id, note, created_at
                    FROM rule_versions
                    WHERE owner_user_id = :uid
                    ORDER BY id DESC
                    LIMIT :limit
                    """
                ),
                {"limit": limit, "uid": owner_user_id},
            ).mappings().all()
    out: list[dict[str, Any]] = []
    for row in rows:
        out.append(
            {
                "version_id": row.get("version_id"),
                "note": row.get("note"),
                "created_at": row.get("created_at").isoformat() if row.get("created_at") else None,
            }
        )
    return out


def get_rule_version(owner_user_id: int | None, version_id: str) -> dict[str, Any] | None:
    with engine.begin() as conn:
        if owner_user_id is None:
            row = conn.execute(
                text(
                    """
                    SELECT version_id, note, rules_config, created_at
                    FROM rule_versions
                    WHERE version_id = :version_id AND owner_user_id IS NULL
                    LIMIT 1
                    """
                ),
                {"version_id": version_id},
            ).mappings().first()
        else:
            row = conn.execute(
                text(
                    """
                    SELECT version_id, note, rules_config, created_at
                    FROM rule_versions
                    WHERE version_id = :version_id AND owner_user_id = :uid
                    LIMIT 1
                    """
                ),
                {"version_id": version_id, "uid": owner_user_id},
            ).mappings().first()
    if not row:
        return None
    return {
        "version_id": row.get("version_id"),
        "note": row.get("note"),
        "created_at": row.get("created_at").isoformat() if row.get("created_at") else None,
        "rules_config": to_jsonable(row.get("rules_config")),
    }


def diff_rule_versions(owner_user_id: int | None, from_version_id: str, to_version_id: str) -> str:
    old_v = get_rule_version(owner_user_id, from_version_id)
    new_v = get_rule_version(owner_user_id, to_version_id)
    if not old_v or not new_v:
        raise HTTPException(status_code=404, detail="One or both rule versions were not found")
    old_txt = yaml.safe_dump(old_v["rules_config"], sort_keys=False, allow_unicode=False).splitlines()
    new_txt = yaml.safe_dump(new_v["rules_config"], sort_keys=False, allow_unicode=False).splitlines()
    return "\n".join(
        difflib.unified_diff(
            old_txt,
            new_txt,
            fromfile=from_version_id,
            tofile=to_version_id,
            lineterm="",
        )
    )


def profile_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    if not records:
        return {"record_count": 0, "fields": {}}
    fields: dict[str, dict[str, Any]] = {}
    total = len(records)
    all_names: set[str] = set()
    for row in records:
        all_names.update(row.keys())
    for name in sorted(all_names):
        vals = [row.get(name) for row in records]
        non_null = [v for v in vals if v is not None and v != ""]
        null_ratio = 1 - (len(non_null) / total)
        unique = set(str(v) for v in non_null)
        numeric_vals = [float(v) for v in non_null if isinstance(v, (int, float))]
        item: dict[str, Any] = {
            "null_ratio": round(null_ratio, 4),
            "distinct_count": len(unique),
            "distinct_ratio": round(len(unique) / max(1, len(non_null)), 4),
            "sample_values": list(unique)[:5],
            "value_type": "numeric" if len(numeric_vals) == len(non_null) and non_null else "mixed",
        }
        if numeric_vals:
            item["min"] = min(numeric_vals)
            item["max"] = max(numeric_vals)
            item["mean"] = round(sum(numeric_vals) / len(numeric_vals), 4)
            item["stdev"] = round(statistics.pstdev(numeric_vals), 4) if len(numeric_vals) > 1 else 0.0
        fields[name] = item
    return {"record_count": total, "fields": fields}


def latest_drift_baseline(owner_user_id: int | None, provider: str, dataset_type: str) -> dict[str, Any] | None:
    with engine.begin() as conn:
        if owner_user_id is None:
            row = conn.execute(
                text(
                    """
                    SELECT baseline_id, profile, created_at
                    FROM drift_baselines
                    WHERE owner_user_id IS NULL AND provider = :provider AND dataset_type = :dataset_type
                    ORDER BY id DESC
                    LIMIT 1
                    """
                ),
                {"provider": provider, "dataset_type": dataset_type},
            ).mappings().first()
        else:
            row = conn.execute(
                text(
                    """
                    SELECT baseline_id, profile, created_at
                    FROM drift_baselines
                    WHERE owner_user_id = :uid AND provider = :provider AND dataset_type = :dataset_type
                    ORDER BY id DESC
                    LIMIT 1
                    """
                ),
                {"uid": owner_user_id, "provider": provider, "dataset_type": dataset_type},
            ).mappings().first()
    if not row:
        return None
    return {
        "baseline_id": row.get("baseline_id"),
        "profile": to_jsonable(row.get("profile")),
        "created_at": row.get("created_at").isoformat() if row.get("created_at") else None,
    }


def save_drift_baseline(owner_user_id: int | None, provider: str, dataset_type: str, records: list[dict[str, Any]]) -> dict[str, Any]:
    profile = profile_records(records)
    baseline_id = safe_id("db")
    with engine.begin() as conn:
        conn.execute(
            drift_baselines.insert().values(
                baseline_id=baseline_id,
                owner_user_id=owner_user_id,
                provider=provider,
                dataset_type=dataset_type,
                profile=to_jsonable(profile),
                created_at=utcnow(),
            )
        )
    return {"baseline_id": baseline_id, "provider": provider, "dataset_type": dataset_type, "profile": profile}


def detect_data_drift(owner_user_id: int | None, provider: str, dataset_type: str, records: list[dict[str, Any]]) -> dict[str, Any]:
    current = profile_records(records)
    baseline = latest_drift_baseline(owner_user_id, provider, dataset_type)
    if not baseline:
        return {
            "status": "no_baseline",
            "baseline_exists": False,
            "baseline_id": None,
            "changes": [],
        }
    base_fields = (baseline["profile"] or {}).get("fields", {})
    cur_fields = current.get("fields", {})
    changes: list[dict[str, Any]] = []
    for name in sorted(set(base_fields.keys()) | set(cur_fields.keys())):
        if name not in base_fields:
            changes.append({"field": name, "change": "new_field"})
            continue
        if name not in cur_fields:
            changes.append({"field": name, "change": "missing_field"})
            continue
        prev = base_fields[name]
        now = cur_fields[name]
        if abs(float(prev.get("null_ratio", 0)) - float(now.get("null_ratio", 0))) >= 0.2:
            changes.append(
                {
                    "field": name,
                    "change": "null_ratio_shift",
                    "before": prev.get("null_ratio"),
                    "after": now.get("null_ratio"),
                }
            )
        if prev.get("value_type") == "numeric" and now.get("value_type") == "numeric":
            prev_mean = float(prev.get("mean", 0) or 0)
            now_mean = float(now.get("mean", 0) or 0)
            prev_std = max(float(prev.get("stdev", 0) or 0), 1.0)
            if abs(now_mean - prev_mean) >= 3 * prev_std:
                changes.append(
                    {
                        "field": name,
                        "change": "mean_shift",
                        "before": prev_mean,
                        "after": now_mean,
                    }
                )
    return {
        "status": "drift_detected" if changes else "stable",
        "baseline_exists": True,
        "baseline_id": baseline.get("baseline_id"),
        "changes": changes,
        "baseline_created_at": baseline.get("created_at"),
    }


async def send_event(event_type: str, payload: dict[str, Any]) -> None:
    if not EVENT_WEBHOOK_URL:
        return
    body = {"event_type": event_type, "timestamp": utcnow().isoformat(), "payload": to_jsonable(payload)}
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            await client.post(EVENT_WEBHOOK_URL, json=body)
    except Exception:
        return


def create_alert(owner_user_id: int | None, source: str, severity: str, message: str, payload: dict[str, Any] | None = None) -> str:
    alert_id = safe_id("al")
    with engine.begin() as conn:
        conn.execute(
            alerts_store.insert().values(
                alert_id=alert_id,
                owner_user_id=owner_user_id,
                source=source[:64],
                severity=severity[:32],
                message=message[:512],
                payload=to_jsonable(payload or {}),
                created_at=utcnow(),
            )
        )
    return alert_id


def get_alerts(owner_user_id: int | None, limit: int = 100, include_all: bool = False) -> list[dict[str, Any]]:
    with engine.begin() as conn:
        if include_all:
            rows = conn.execute(
                text("SELECT alert_id, source, severity, message, payload, created_at FROM alerts_store ORDER BY id DESC LIMIT :limit"),
                {"limit": limit},
            ).mappings().all()
        elif owner_user_id is None:
            rows = conn.execute(
                text(
                    "SELECT alert_id, source, severity, message, payload, created_at FROM alerts_store WHERE owner_user_id IS NULL ORDER BY id DESC LIMIT :limit"
                ),
                {"limit": limit},
            ).mappings().all()
        else:
            rows = conn.execute(
                text(
                    "SELECT alert_id, source, severity, message, payload, created_at FROM alerts_store WHERE owner_user_id = :uid ORDER BY id DESC LIMIT :limit"
                ),
                {"uid": owner_user_id, "limit": limit},
            ).mappings().all()
    out = []
    for row in rows:
        out.append(
            {
                "alert_id": row.get("alert_id"),
                "source": row.get("source"),
                "severity": row.get("severity"),
                "message": row.get("message"),
                "payload": to_jsonable(row.get("payload")),
                "created_at": row.get("created_at").isoformat() if row.get("created_at") else None,
            }
        )
    return out


def create_or_update_team_policy(team: str, allowed_dataset_types: list[str], allowed_server_urls: list[str], scoped_admin: bool) -> None:
    now = utcnow()
    with engine.begin() as conn:
        exists = conn.execute(text("SELECT id FROM team_policies WHERE team = :team LIMIT 1"), {"team": team}).mappings().first()
        if exists:
            conn.execute(
                text(
                    """
                    UPDATE team_policies
                    SET allowed_dataset_types = :datasets,
                        allowed_server_urls = :servers,
                        scoped_admin = :scoped_admin,
                        updated_at = :updated_at
                    WHERE team = :team
                    """
                ),
                {
                    "team": team,
                    "datasets": as_json_text(allowed_dataset_types),
                    "servers": as_json_text(allowed_server_urls),
                    "scoped_admin": scoped_admin,
                    "updated_at": now,
                },
            )
        else:
            conn.execute(
                team_policies.insert().values(
                    team=team,
                    allowed_dataset_types=allowed_dataset_types,
                    allowed_server_urls=allowed_server_urls,
                    scoped_admin=scoped_admin,
                    updated_at=now,
                )
            )


def list_team_policies() -> list[dict[str, Any]]:
    with engine.begin() as conn:
        rows = conn.execute(
            text("SELECT team, allowed_dataset_types, allowed_server_urls, scoped_admin, updated_at FROM team_policies ORDER BY team ASC")
        ).mappings().all()
    out: list[dict[str, Any]] = []
    for row in rows:
        out.append(
            {
                "team": row.get("team"),
                "allowed_dataset_types": parse_json_value(row.get("allowed_dataset_types"), []),
                "allowed_server_urls": parse_json_value(row.get("allowed_server_urls"), []),
                "scoped_admin": bool(row.get("scoped_admin", False)),
                "updated_at": row.get("updated_at").isoformat() if row.get("updated_at") else None,
            }
        )
    return out


def audit_admin_action(
    admin_user_id: int,
    action: str,
    target_type: str,
    target_id: str | None,
    summary: str,
    details: dict[str, Any] | None = None,
) -> str:
    event_id = safe_id("audit")
    with engine.begin() as conn:
        conn.execute(
            admin_audit_logs.insert().values(
                event_id=event_id,
                admin_user_id=admin_user_id,
                action=action[:128],
                target_type=target_type[:64],
                target_id=(target_id or "")[:128] if target_id is not None else None,
                summary=summary[:512],
                details=to_jsonable(details or {}),
                created_at=utcnow(),
            )
        )
    return event_id


def list_admin_audit_logs(limit: int = 200) -> list[dict[str, Any]]:
    with engine.begin() as conn:
        rows = conn.execute(
            text(
                """
                SELECT event_id, admin_user_id, action, target_type, target_id, summary, details, created_at
                FROM admin_audit_logs
                ORDER BY id DESC
                LIMIT :limit
                """
            ),
            {"limit": limit},
        ).mappings().all()
    out: list[dict[str, Any]] = []
    for row in rows:
        out.append(
            {
                "event_id": row.get("event_id"),
                "admin_user_id": row.get("admin_user_id"),
                "action": row.get("action"),
                "target_type": row.get("target_type"),
                "target_id": row.get("target_id"),
                "summary": row.get("summary"),
                "details": to_jsonable(row.get("details")),
                "created_at": row.get("created_at").isoformat() if row.get("created_at") else None,
            }
        )
    return out


def _extract_suggestion_severity(suggestion: Any) -> str:
    if not isinstance(suggestion, dict):
        return "unknown"
    assessment_rule = suggestion.get("assessment_rule")
    if isinstance(assessment_rule, dict):
        sev = str(assessment_rule.get("severity", "")).strip().lower()
        if sev:
            return sev
    return "unknown"


def build_admin_access_review_report(stale_days: int = 90, audit_limit: int = 200) -> dict[str, Any]:
    stale_days = max(1, int(stale_days))
    cutoff = utcnow() - timedelta(days=stale_days)

    def _aware_utc(dt: datetime) -> datetime:
        # DB drivers may return naive timestamps. Treat naive values as UTC for comparisons.
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    with engine.begin() as conn:
        users_rows = conn.execute(
            text("SELECT id, email, name, role, team, is_active, created_at, last_login_at FROM users ORDER BY id ASC")
        ).mappings().all()
        policy_rows = conn.execute(
            text("SELECT team, scoped_admin, allowed_dataset_types, allowed_server_urls, updated_at FROM team_policies ORDER BY team ASC")
        ).mappings().all()
        shared_rows = conn.execute(
            text("SELECT name, base_url, is_active, updated_at FROM shared_mcp_servers ORDER BY id ASC")
        ).mappings().all()
    audit_rows = list_admin_audit_logs(limit=max(1, int(audit_limit)))

    teams_with_policy = {str(row.get("team") or "") for row in policy_rows}
    admins: list[dict[str, Any]] = []
    stale_accounts: list[dict[str, Any]] = []
    inactive_accounts: list[dict[str, Any]] = []
    orphaned_team_users: list[dict[str, Any]] = []

    for row in users_rows:
        team = str(row.get("team") or "default")
        created_at = row.get("created_at")
        last_login_at = row.get("last_login_at")
        created_at_cmp = _aware_utc(created_at) if isinstance(created_at, datetime) else None
        last_login_cmp = _aware_utc(last_login_at) if isinstance(last_login_at, datetime) else None
        entry = {
            "user_id": row.get("id"),
            "email": row.get("email"),
            "name": row.get("name"),
            "role": row.get("role"),
            "team": team,
            "is_active": bool(row.get("is_active", False)),
            "created_at": created_at_cmp.isoformat() if created_at_cmp else None,
            "last_login_at": last_login_cmp.isoformat() if last_login_cmp else None,
        }
        if entry["role"] == "admin":
            admins.append(entry)
        if not entry["is_active"]:
            inactive_accounts.append(entry)
        stale = False
        if last_login_cmp is not None:
            stale = last_login_cmp < cutoff
        elif created_at_cmp is not None:
            stale = created_at_cmp < cutoff
        if stale:
            stale_accounts.append(entry)
        if team not in teams_with_policy:
            orphaned_team_users.append(entry)

    recommendations: list[str] = []
    if stale_accounts:
        recommendations.append("Review stale accounts and disable or enforce password reset.")
    if orphaned_team_users:
        recommendations.append("Create team policies for all teams to enforce least-privilege scope.")
    if len(admins) == 0:
        recommendations.append("Create at least one active admin account.")
    if len([x for x in admins if x.get('is_active')]) > 3:
        recommendations.append("Consider limiting number of active admins by role separation.")

    active_shared = len([x for x in shared_rows if x.get("is_active")])
    inactive_shared = len(shared_rows) - active_shared

    return {
        "generated_at": utcnow().isoformat(),
        "stale_days": stale_days,
        "summary": {
            "total_users": len(users_rows),
            "active_users": len([x for x in users_rows if x.get("is_active")]),
            "admins": len(admins),
            "inactive_accounts": len(inactive_accounts),
            "stale_accounts": len(stale_accounts),
            "teams_with_policy": len(policy_rows),
            "teams_without_policy": len({x.get("team") for x in orphaned_team_users}),
            "shared_servers_active": active_shared,
            "shared_servers_inactive": inactive_shared,
            "recent_admin_events": len(audit_rows),
        },
        "admins": admins,
        "stale_accounts": stale_accounts[:100],
        "inactive_accounts": inactive_accounts[:100],
        "orphaned_team_users": orphaned_team_users[:100],
        "team_policies": [
            {
                "team": row.get("team"),
                "scoped_admin": bool(row.get("scoped_admin", False)),
                "allowed_dataset_types": parse_json_value(row.get("allowed_dataset_types"), []),
                "allowed_server_urls": parse_json_value(row.get("allowed_server_urls"), []),
                "updated_at": row.get("updated_at").isoformat() if row.get("updated_at") else None,
            }
            for row in policy_rows
        ],
        "recommendations": recommendations,
    }


def build_admin_rule_governance_report(days: int = 30) -> dict[str, Any]:
    days = max(1, int(days))
    cutoff = utcnow() - timedelta(days=days)
    with engine.begin() as conn:
        decision_rows = conn.execute(
            text(
                """
                SELECT suggestion_id, dataset_type, decision, suggestion, created_at
                FROM suggestion_decisions
                WHERE created_at >= :cutoff
                ORDER BY id DESC
                """
            ),
            {"cutoff": cutoff},
        ).mappings().all()
        pending_rows = conn.execute(
            text(
                """
                SELECT suggestion_id, dataset_type, suggestion, status, created_at
                FROM pending_suggestions_store
                WHERE status = 'pending'
                ORDER BY id DESC
                """
            )
        ).mappings().all()
        approval_rows = conn.execute(
            text(
                """
                SELECT suggestion_id, COUNT(*) AS approvals
                FROM suggestion_approvals
                GROUP BY suggestion_id
                """
            )
        ).mappings().all()
        version_rows = conn.execute(
            text(
                """
                SELECT version_id, note, owner_user_id, created_at
                FROM rule_versions
                WHERE created_at >= :cutoff
                ORDER BY id DESC
                """
            ),
            {"cutoff": cutoff},
        ).mappings().all()
        run_rows = conn.execute(
            text(
                """
                SELECT run_id, process_type, result, created_at
                FROM workflow_runs
                WHERE created_at >= :cutoff
                ORDER BY id DESC
                """
            ),
            {"cutoff": cutoff},
        ).mappings().all()

    approval_counts = {str(row.get("suggestion_id")): int(row.get("approvals", 0) or 0) for row in approval_rows}
    by_decision: dict[str, int] = {"approved": 0, "declined": 0}
    severity_breakdown: dict[str, dict[str, int]] = {}
    high_severity_approved = 0

    for row in decision_rows:
        decision = str(row.get("decision") or "unknown").lower()
        by_decision[decision] = by_decision.get(decision, 0) + 1
        severity = _extract_suggestion_severity(to_jsonable(row.get("suggestion")))
        severity_breakdown.setdefault(severity, {"approved": 0, "declined": 0, "other": 0})
        if decision in {"approved", "declined"}:
            severity_breakdown[severity][decision] += 1
        else:
            severity_breakdown[severity]["other"] += 1
        if severity == "high" and decision == "approved":
            high_severity_approved += 1

    pending_high: list[dict[str, Any]] = []
    for row in pending_rows:
        sid = str(row.get("suggestion_id") or "")
        suggestion = to_jsonable(row.get("suggestion"))
        severity = _extract_suggestion_severity(suggestion)
        if severity != "high":
            continue
        pending_high.append(
            {
                "suggestion_id": sid,
                "dataset_type": row.get("dataset_type"),
                "status": row.get("status"),
                "approvals": approval_counts.get(sid, 0),
                "required_approvals": 2,
                "created_at": row.get("created_at").isoformat() if row.get("created_at") else None,
            }
        )

    rollback_events = [x for x in list_admin_audit_logs(limit=500) if x.get("action") == "rollback_rule_version"]
    canary_runs = 0
    drift_detected_runs = 0
    for row in run_rows:
        result = to_jsonable(row.get("result")) or {}
        if bool(result.get("canary")):
            canary_runs += 1
        drift = result.get("drift") if isinstance(result, dict) else None
        if isinstance(drift, dict) and drift.get("status") == "drift_detected":
            drift_detected_runs += 1

    return {
        "generated_at": utcnow().isoformat(),
        "window_days": days,
        "summary": {
            "suggestions_total": len(decision_rows),
            "suggestions_approved": by_decision.get("approved", 0),
            "suggestions_declined": by_decision.get("declined", 0),
            "high_severity_approved": high_severity_approved,
            "high_severity_pending": len(pending_high),
            "rule_versions_created": len(version_rows),
            "rollbacks": len(rollback_events),
            "canary_runs": canary_runs,
            "drift_detected_runs": drift_detected_runs,
        },
        "decision_breakdown": by_decision,
        "severity_breakdown": severity_breakdown,
        "pending_high_severity": pending_high[:100],
        "recent_rule_versions": [
            {
                "version_id": row.get("version_id"),
                "note": row.get("note"),
                "owner_user_id": row.get("owner_user_id"),
                "created_at": row.get("created_at").isoformat() if row.get("created_at") else None,
            }
            for row in version_rows[:50]
        ],
        "recent_rollbacks": rollback_events[:50],
    }


def build_admin_compliance_report(days: int = 30) -> dict[str, Any]:
    days = max(1, int(days))
    cutoff = utcnow() - timedelta(days=days)
    with engine.begin() as conn:
        run_rows = conn.execute(
            text(
                """
                SELECT run_id, dataset_id, dataset_type, provider, process_type, status, result, created_at
                FROM workflow_runs
                WHERE created_at >= :cutoff
                ORDER BY id DESC
                """
            ),
            {"cutoff": cutoff},
        ).mappings().all()
        alert_rows = conn.execute(
            text(
                """
                SELECT alert_id, source, severity, message, created_at
                FROM alerts_store
                WHERE created_at >= :cutoff
                ORDER BY id DESC
                """
            ),
            {"cutoff": cutoff},
        ).mappings().all()
        audit_rows = conn.execute(
            text(
                """
                SELECT event_id, action, target_type, target_id, created_at
                FROM admin_audit_logs
                WHERE created_at >= :cutoff
                ORDER BY id DESC
                """
            ),
            {"cutoff": cutoff},
        ).mappings().all()

    assessment_runs = [x for x in run_rows if str(x.get("process_type")) == "assessment"]
    correction_runs = [x for x in run_rows if str(x.get("process_type")) == "correction"]
    failed_runs = [x for x in run_rows if str(x.get("status")) != "completed"]
    quality_scores: list[float] = []
    corrections_with_lineage = 0
    for row in correction_runs:
        result = to_jsonable(row.get("result")) or {}
        applied = result.get("applied") if isinstance(result, dict) else None
        if isinstance(applied, list) and applied:
            has_traceable = any(isinstance(item, dict) and "record_index" in item and "field" in item for item in applied)
            if has_traceable:
                corrections_with_lineage += 1
    for row in assessment_runs:
        result = to_jsonable(row.get("result")) or {}
        q = result.get("quality_index") if isinstance(result, dict) else None
        if isinstance(q, (int, float)):
            quality_scores.append(float(q))

    avg_quality = round(sum(quality_scores) / len(quality_scores), 2) if quality_scores else None
    min_quality = round(min(quality_scores), 2) if quality_scores else None
    sla_alerts = [x for x in alert_rows if str(x.get("source", "")).lower() == "sla"]
    drift_alerts = [x for x in alert_rows if str(x.get("source", "")).lower() == "drift"]
    high_alerts = [x for x in alert_rows if str(x.get("severity", "")).lower() == "high"]
    lineage_coverage_pct = round((corrections_with_lineage / len(correction_runs)) * 100, 2) if correction_runs else 100.0

    return {
        "generated_at": utcnow().isoformat(),
        "window_days": days,
        "summary": {
            "total_runs": len(run_rows),
            "assessment_runs": len(assessment_runs),
            "correction_runs": len(correction_runs),
            "failed_runs": len(failed_runs),
            "avg_quality_index": avg_quality,
            "min_quality_index": min_quality,
            "alerts_total": len(alert_rows),
            "alerts_high": len(high_alerts),
            "sla_breach_alerts": len(sla_alerts),
            "drift_alerts": len(drift_alerts),
            "admin_audit_events": len(audit_rows),
            "lineage_coverage_pct": lineage_coverage_pct,
        },
        "failed_runs": [
            {
                "run_id": row.get("run_id"),
                "dataset_type": row.get("dataset_type"),
                "provider": row.get("provider"),
                "process_type": row.get("process_type"),
                "status": row.get("status"),
                "created_at": row.get("created_at").isoformat() if row.get("created_at") else None,
            }
            for row in failed_runs[:100]
        ],
        "latest_alerts": [
            {
                "alert_id": row.get("alert_id"),
                "source": row.get("source"),
                "severity": row.get("severity"),
                "message": row.get("message"),
                "created_at": row.get("created_at").isoformat() if row.get("created_at") else None,
            }
            for row in alert_rows[:100]
        ],
        "latest_audit_events": [
            {
                "event_id": row.get("event_id"),
                "action": row.get("action"),
                "target": f"{row.get('target_type')}:{row.get('target_id')}",
                "created_at": row.get("created_at").isoformat() if row.get("created_at") else None,
            }
            for row in audit_rows[:100]
        ],
    }


def write_minimal_pdf(path: Path, title: str, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text_lines = [title] + [line for line in lines if line]
    content_parts = ["BT", "/F1 10 Tf", "50 790 Td"]
    for i, line in enumerate(text_lines[:60]):
        safe = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        if i > 0:
            content_parts.append("T*")
        content_parts.append(f"({safe}) Tj")
    content_parts.append("ET")
    stream = "\n".join(content_parts).encode("latin-1", errors="replace")

    objs: list[bytes] = []
    objs.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objs.append(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    objs.append(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>")
    objs.append(f"<< /Length {len(stream)} >>\nstream\n".encode("latin-1") + stream + b"\nendstream")
    objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    header = b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n"
    offsets: list[int] = []
    body = bytearray(header)
    for idx, obj in enumerate(objs, start=1):
        offsets.append(len(body))
        body.extend(f"{idx} 0 obj\n".encode("latin-1"))
        body.extend(obj)
        body.extend(b"\nendobj\n")
    xref_pos = len(body)
    body.extend(f"xref\n0 {len(objs)+1}\n".encode("latin-1"))
    body.extend(b"0000000000 65535 f \n")
    for off in offsets:
        body.extend(f"{off:010d} 00000 n \n".encode("latin-1"))
    body.extend(
        (
            f"trailer\n<< /Size {len(objs)+1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n"
        ).encode("latin-1")
    )
    path.write_bytes(bytes(body))

# ---------- data/model ----------
def query_dataset(dataset_type: str, limit: int = 50) -> list[dict[str, Any]]:
    table_map = {
        "customer_profile": "customer_profile",
        "credit_facility": "credit_facility",
    }
    table = table_map.get(dataset_type)
    if not table:
        raise HTTPException(status_code=400, detail=f"Unsupported dataset_type: {dataset_type}")
    safe_limit = clamp_limit(limit, 50, MAX_QUERY_LIMIT)
    stmt = text(f"SELECT * FROM {table} LIMIT :limit")
    with engine.begin() as conn:
        rows = conn.execute(stmt, {"limit": safe_limit}).mappings().all()
    return [to_jsonable(dict(r)) for r in rows]


def get_data_model() -> list[dict[str, Any]]:
    with engine.begin() as conn:
        rows = conn.execute(
            text(
                """
                WITH pk_cols AS (
                  SELECT tc.table_name, kcu.column_name
                  FROM information_schema.table_constraints tc
                  JOIN information_schema.key_column_usage kcu
                    ON tc.constraint_name = kcu.constraint_name
                   AND tc.table_schema = kcu.table_schema
                  WHERE tc.constraint_type = 'PRIMARY KEY' AND tc.table_schema = 'public'
                ),
                fk_cols AS (
                  SELECT tc.table_name, kcu.column_name, ccu.table_name AS foreign_table_name, ccu.column_name AS foreign_column_name
                  FROM information_schema.table_constraints tc
                  JOIN information_schema.key_column_usage kcu
                    ON tc.constraint_name = kcu.constraint_name
                   AND tc.table_schema = kcu.table_schema
                  JOIN information_schema.constraint_column_usage ccu
                    ON tc.constraint_name = ccu.constraint_name
                   AND tc.table_schema = ccu.table_schema
                  WHERE tc.constraint_type = 'FOREIGN KEY' AND tc.table_schema = 'public'
                )
                SELECT c.table_name, c.column_name, c.data_type, c.is_nullable, c.ordinal_position,
                       (pk.column_name IS NOT NULL) AS is_primary_key,
                       (fk.column_name IS NOT NULL) AS is_foreign_key,
                       fk.foreign_table_name, fk.foreign_column_name
                FROM information_schema.columns c
                LEFT JOIN pk_cols pk ON c.table_name = pk.table_name AND c.column_name = pk.column_name
                LEFT JOIN fk_cols fk ON c.table_name = fk.table_name AND c.column_name = fk.column_name
                WHERE c.table_schema = 'public'
                ORDER BY c.table_name, c.ordinal_position
                """
            )
        ).mappings().all()
    return [to_jsonable(dict(r)) for r in rows]


def get_foreign_key_relations() -> dict[str, list[dict[str, Any]]]:
    with engine.begin() as conn:
        explicit = conn.execute(
            text(
                """
                SELECT tc.table_name AS source_table, kcu.column_name AS source_column,
                       ccu.table_name AS target_table, ccu.column_name AS target_column,
                       tc.constraint_name AS relation_name
                FROM information_schema.table_constraints tc
                JOIN information_schema.key_column_usage kcu ON tc.constraint_name = kcu.constraint_name
                JOIN information_schema.constraint_column_usage ccu ON ccu.constraint_name = tc.constraint_name
                WHERE tc.constraint_type = 'FOREIGN KEY' AND tc.table_schema = 'public'
                ORDER BY tc.table_name, kcu.column_name
                """
            )
        ).mappings().all()
        inferred = conn.execute(
            text(
                """
                SELECT c.table_name AS source_table, c.column_name AS source_column,
                       t.table_name AS target_table, c.column_name AS target_column,
                       'inferred_by_column_name' AS relation_name
                FROM information_schema.columns c
                JOIN information_schema.columns t ON c.column_name = t.column_name AND c.table_name <> t.table_name
                WHERE c.table_schema = 'public' AND t.table_schema = 'public' AND c.column_name LIKE '%_id'
                ORDER BY c.table_name, c.column_name, t.table_name
                """
            )
        ).mappings().all()
    return {
        "explicit_relations": [to_jsonable(dict(r)) for r in explicit],
        "inferred_relations": [to_jsonable(dict(r)) for r in inferred],
    }


# ---------- rules / suggestions ----------
def get_rules(dataset_type: str, user_id: int | None) -> list[dict[str, Any]]:
    cfg = load_rules_config_for_user(user_id)
    return to_jsonable(cfg["assessment_rules"].get(dataset_type, []))


def get_correction_rules(dataset_type: str, user_id: int | None) -> list[dict[str, Any]]:
    cfg = load_rules_config_for_user(user_id)
    return to_jsonable(cfg["correction_rules"].get(dataset_type, []))


def has_rule_for_field(rules: list[dict[str, Any]], field: str, rule_type: str) -> bool:
    return any(rule.get("field") == field and rule.get("type") == rule_type for rule in rules)


def infer_mode(values: list[Any]) -> Any:
    counts: dict[str, int] = {}
    first_seen: dict[str, Any] = {}
    for v in values:
        if v is None or v == "":
            continue
        k = str(v)
        counts[k] = counts.get(k, 0) + 1
        if k not in first_seen:
            first_seen[k] = v
    if not counts:
        return None
    return first_seen[max(counts.items(), key=lambda x: x[1])[0]]


def save_pending_suggestion(suggestion: dict[str, Any]) -> None:
    suggestion_json = json.dumps(to_jsonable(suggestion))
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO pending_suggestions_store (suggestion_id, dataset_type, suggestion, owner_user_id, status, created_at)
                VALUES (:sid, :dataset_type, :suggestion, :owner_user_id, 'pending', :created_at)
                ON CONFLICT (suggestion_id) DO UPDATE
                SET suggestion = EXCLUDED.suggestion, owner_user_id = EXCLUDED.owner_user_id, status = 'pending'
                """
            ),
            {
                "sid": suggestion.get("suggestion_id"),
                "dataset_type": suggestion.get("dataset_type"),
                "suggestion": suggestion_json,
                "owner_user_id": suggestion.get("owner_user_id"),
                "created_at": utcnow(),
            },
        )


def get_pending_suggestion(suggestion_id: str) -> dict[str, Any] | None:
    with engine.begin() as conn:
        row = conn.execute(
            text(
                """
                SELECT suggestion
                FROM pending_suggestions_store
                WHERE suggestion_id = :sid AND status = 'pending'
                LIMIT 1
                """
            ),
            {"sid": suggestion_id},
        ).mappings().first()
    if not row:
        return None
    return to_jsonable(row.get("suggestion"))


def mark_pending_suggestion_decided(suggestion_id: str, decision: str) -> None:
    with engine.begin() as conn:
        conn.execute(
            text("UPDATE pending_suggestions_store SET status = :status WHERE suggestion_id = :sid"),
            {"status": decision, "sid": suggestion_id},
        )


def generate_rule_suggestions(dataset_type: str, records: list[dict[str, Any]], user_id: int | None, max_suggestions: int = 3) -> list[dict[str, Any]]:
    if not llm_enabled() or not records:
        return []
    existing_assessment = get_rules(dataset_type, user_id)
    existing_correction = get_correction_rules(dataset_type, user_id)
    field_values: dict[str, list[Any]] = {}
    for row in records:
        for k, v in row.items():
            field_values.setdefault(k, []).append(v)

    suggestions: list[dict[str, Any]] = []
    llm_cfg = load_llm_config()["llm"]

    for field, values in field_values.items():
        non_null = [v for v in values if v is not None and v != ""]
        if not values:
            continue

        null_ratio = 1 - (len(non_null) / len(values))
        if 0 < null_ratio < 0.3 and not has_rule_for_field(existing_assessment, field, "not_null"):
            sid = str(uuid.uuid4())
            item = {
                "suggestion_id": sid,
                "dataset_type": dataset_type,
                "reason": f"LLM detected mostly populated field '{field}' ({round((1-null_ratio)*100,1)}% present).",
                "assessment_rule": {"id": f"SUG-{sid[:8]}", "field": field, "type": "not_null", "severity": "medium"},
                "correction_rule": None,
                "llm": {"provider": llm_cfg.get("provider"), "model": llm_cfg.get("model")},
                "owner_user_id": user_id,
            }
            suggestions.append(item)
            save_pending_suggestion(item)
            if len(suggestions) >= max_suggestions:
                return suggestions

        numeric = all(isinstance(v, (int, float)) for v in non_null) and len(non_null) >= 2
        if numeric and not has_rule_for_field(existing_assessment, field, "range"):
            sid = str(uuid.uuid4())
            item = {
                "suggestion_id": sid,
                "dataset_type": dataset_type,
                "reason": f"LLM inferred numeric guardrails for '{field}' from observed values.",
                "assessment_rule": {
                    "id": f"SUG-{sid[:8]}",
                    "field": field,
                    "type": "range",
                    "severity": "medium",
                    "params": {"min": min(non_null), "max": max(non_null)},
                },
                "correction_rule": None if has_rule_for_field(existing_correction, field, "fill_default_if_null") else {"field": field, "type": "fill_default_if_null", "default": 0},
                "llm": {"provider": llm_cfg.get("provider"), "model": llm_cfg.get("model")},
                "owner_user_id": user_id,
            }
            suggestions.append(item)
            save_pending_suggestion(item)
            if len(suggestions) >= max_suggestions:
                return suggestions

        categorical = len(non_null) >= 3 and all(isinstance(v, str) for v in non_null)
        if categorical and not has_rule_for_field(existing_assessment, field, "allowed_values"):
            distinct = sorted(set(non_null))
            if 1 < len(distinct) <= 12:
                sid = str(uuid.uuid4())
                item = {
                    "suggestion_id": sid,
                    "dataset_type": dataset_type,
                    "reason": f"LLM inferred controlled domain values for '{field}'.",
                    "assessment_rule": {
                        "id": f"SUG-{sid[:8]}",
                        "field": field,
                        "type": "allowed_values",
                        "severity": "medium",
                        "params": {"values": distinct},
                    },
                    "correction_rule": None if has_rule_for_field(existing_correction, field, "fill_default_if_null") else {"field": field, "type": "fill_default_if_null", "default": infer_mode(non_null)},
                    "llm": {"provider": llm_cfg.get("provider"), "model": llm_cfg.get("model")},
                    "owner_user_id": user_id,
                }
                suggestions.append(item)
                save_pending_suggestion(item)
                if len(suggestions) >= max_suggestions:
                    return suggestions

    return suggestions


def record_suggestion_decision(
    suggestion_id: str,
    dataset_type: str,
    decision: str,
    suggestion: dict[str, Any],
    owner_user_id: int | None,
) -> None:
    with engine.begin() as conn:
        conn.execute(
            suggestion_decisions.insert().values(
                suggestion_id=suggestion_id,
                dataset_type=dataset_type,
                decision=decision,
                suggestion=to_jsonable(suggestion),
                owner_user_id=owner_user_id,
                created_at=utcnow(),
            )
        )


def approve_suggestion(suggestion_id: str, actor: dict[str, Any] | None) -> dict[str, Any]:
    suggestion = get_pending_suggestion(suggestion_id)
    if not suggestion:
        raise HTTPException(status_code=404, detail="Suggestion not found or expired")
    if not actor:
        raise HTTPException(status_code=401, detail="Authentication required")
    actor_user_id = int(actor["id"])
    owner_user_id = suggestion.get("owner_user_id")
    if owner_user_id is None:
        raise HTTPException(status_code=400, detail="Suggestion owner is missing")
    owner_user_id = int(owner_user_id)
    owner_user = get_user_brief(owner_user_id)
    if not owner_user:
        raise HTTPException(status_code=404, detail="Suggestion owner not found")
    actor_is_owner = actor_user_id == owner_user_id
    actor_is_admin = str(actor.get("role", "")) == "admin"
    actor_team = str(actor.get("team") or "default")
    owner_team = str(owner_user.get("team") or "default")
    actor_is_peer = actor_team == owner_team
    if not (actor_is_owner or actor_is_admin or actor_is_peer):
        raise HTTPException(status_code=403, detail="Only owner/admin/peer can approve this suggestion")

    severity = str((suggestion.get("assessment_rule") or {}).get("severity") or "medium").lower()
    if severity == "high":
        with engine.begin() as conn:
            existing = conn.execute(
                text(
                    """
                    SELECT id FROM suggestion_approvals
                    WHERE suggestion_id = :sid AND approver_user_id = :uid
                    LIMIT 1
                    """
                ),
                {"sid": suggestion_id, "uid": actor_user_id},
            ).mappings().first()
            if not existing:
                conn.execute(
                    suggestion_approvals.insert().values(
                        suggestion_id=suggestion_id,
                        approver_user_id=actor_user_id,
                        created_at=utcnow(),
                    )
                )
            count_row = conn.execute(
                text(
                    """
                    SELECT
                        COUNT(DISTINCT approver_user_id) AS c,
                        COUNT(*) FILTER (WHERE approver_user_id = :owner_uid) AS owner_approved,
                        COUNT(*) FILTER (WHERE approver_user_id <> :owner_uid) AS peer_approved
                    FROM suggestion_approvals
                    WHERE suggestion_id = :sid
                    """
                ),
                {"sid": suggestion_id, "owner_uid": owner_user_id},
            ).mappings().first()
        approval_count = int((count_row or {}).get("c", 0) or 0)
        owner_approved = int((count_row or {}).get("owner_approved", 0) or 0) > 0
        peer_approved = int((count_row or {}).get("peer_approved", 0) or 0) > 0
        if not owner_approved or not peer_approved or approval_count < 2:
            return {
                "message": "High-severity suggestion recorded. Awaiting owner + peer/admin two-person approval.",
                "dataset_type": suggestion.get("dataset_type"),
                "approval_required": 2,
                "approval_count": approval_count,
                "owner_approved": owner_approved,
                "peer_or_admin_approved": peer_approved,
            }

    dataset_type = suggestion["dataset_type"]
    cfg = load_rules_config_for_user(owner_user_id)
    cfg["assessment_rules"].setdefault(dataset_type, [])
    cfg["correction_rules"].setdefault(dataset_type, [])

    if suggestion.get("assessment_rule"):
        cfg["assessment_rules"][dataset_type].append(suggestion["assessment_rule"])
    if suggestion.get("correction_rule"):
        cfg["correction_rules"][dataset_type].append(suggestion["correction_rule"])

    validate_rules_config(cfg)
    upsert_user_rules_config(owner_user_id, cfg)
    create_rule_version(owner_user_id, cfg, f"approve-suggestion:{suggestion_id}")

    mark_pending_suggestion_decided(suggestion_id, "approved")
    record_suggestion_decision(suggestion_id, dataset_type, "approved", suggestion, owner_user_id)
    return {
        "message": "Suggestion approved and saved",
        "dataset_type": dataset_type,
        "approval_required": 2 if severity == "high" else 1,
        "approval_count": 2 if severity == "high" else 1,
    }


def decline_suggestion(suggestion_id: str, actor: dict[str, Any] | None) -> dict[str, Any]:
    suggestion = get_pending_suggestion(suggestion_id)
    if not suggestion:
        raise HTTPException(status_code=404, detail="Suggestion not found or expired")
    if not actor:
        raise HTTPException(status_code=401, detail="Authentication required")
    actor_user_id = int(actor["id"])
    owner_user_id = suggestion.get("owner_user_id")
    if owner_user_id is None:
        raise HTTPException(status_code=400, detail="Suggestion owner is missing")
    owner_user_id = int(owner_user_id)
    owner_user = get_user_brief(owner_user_id)
    if not owner_user:
        raise HTTPException(status_code=404, detail="Suggestion owner not found")
    actor_is_owner = actor_user_id == owner_user_id
    actor_is_admin = str(actor.get("role", "")) == "admin"
    actor_team = str(actor.get("team") or "default")
    owner_team = str(owner_user.get("team") or "default")
    actor_is_peer = actor_team == owner_team
    if not (actor_is_owner or actor_is_admin or actor_is_peer):
        raise HTTPException(status_code=403, detail="Only owner/admin/peer can decline this suggestion")
    mark_pending_suggestion_decided(suggestion_id, "declined")
    record_suggestion_decision(suggestion_id, str(suggestion.get("dataset_type", "")), "declined", suggestion, owner_user_id)
    return {"message": "Suggestion declined"}


def get_suggestion_decisions(limit: int = 100, user_id: int | None = None, include_all: bool = False) -> dict[str, list[dict[str, Any]]]:
    with engine.begin() as conn:
        if include_all:
            rows = conn.execute(
                text(
                    """
                    SELECT suggestion_id, dataset_type, decision, suggestion, created_at
                    FROM suggestion_decisions
                    ORDER BY id DESC
                    LIMIT :limit
                    """
                ),
                {"limit": limit},
            ).mappings().all()
        elif user_id is None:
            rows = conn.execute(
                text(
                    """
                    SELECT suggestion_id, dataset_type, decision, suggestion, created_at
                    FROM suggestion_decisions
                    WHERE owner_user_id IS NULL
                    ORDER BY id DESC
                    LIMIT :limit
                    """
                ),
                {"limit": limit},
            ).mappings().all()
        else:
            rows = conn.execute(
                text(
                    """
                    SELECT suggestion_id, dataset_type, decision, suggestion, created_at
                    FROM suggestion_decisions
                    WHERE owner_user_id = :uid
                    ORDER BY id DESC
                    LIMIT :limit
                    """
                ),
                {"limit": limit, "uid": user_id},
            ).mappings().all()
    approved: list[dict[str, Any]] = []
    declined: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        item["created_at"] = item["created_at"].isoformat() if item.get("created_at") else None
        item["suggestion"] = to_jsonable(item.get("suggestion"))
        if item.get("decision") == "approved":
            approved.append(item)
        elif item.get("decision") == "declined":
            declined.append(item)
    return {"approved": approved, "declined": declined}


# ---------- workflow runs ----------
def insert_run(
    dataset_id: str,
    dataset_type: str,
    provider: str,
    process_type: str,
    status: str,
    result: dict[str, Any],
    owner_user_id: int | None,
) -> str:
    run_id = str(uuid.uuid4())
    with engine.begin() as conn:
        conn.execute(
            workflow_runs.insert().values(
                run_id=run_id,
                dataset_id=dataset_id,
                dataset_type=dataset_type,
                provider=provider,
                process_type=process_type,
                status=status,
                result=to_jsonable(result),
                owner_user_id=owner_user_id,
                created_at=utcnow(),
            )
        )
    return run_id


async def execute_assessment(
    dataset_type: str,
    dataset_id: str,
    provider: str,
    limit: int,
    user_id: int | None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows = query_dataset(dataset_type, limit)
    payload = {
        "dataset_id": dataset_id,
        "dataset_type": dataset_type,
        "provider": provider,
        "records": rows,
        "rules": get_rules(dataset_type, user_id),
    }
    async with httpx.AsyncClient(timeout=90) as client:
        response = await client.post(f"{DQ_ENGINE_URL}/assess", json=payload)
        response.raise_for_status()
        result = response.json()
    drift = detect_data_drift(user_id, provider, dataset_type, rows)
    result["drift"] = drift
    result["suggestions"] = generate_rule_suggestions(dataset_type, rows, user_id)
    if drift.get("status") == "drift_detected":
        create_alert(
            user_id,
            "drift_detection",
            "medium",
            f"Data drift detected for {dataset_type} ({provider})",
            {"dataset_type": dataset_type, "provider": provider, "drift": drift},
        )
        await send_event("data_source_change_detected", {"dataset_type": dataset_type, "provider": provider, "drift": drift})
    quality = float(result.get("quality_index", 100) or 100)
    if quality < ALERT_QUALITY_THRESHOLD:
        create_alert(
            user_id,
            "quality_threshold",
            "high",
            f"Quality index {quality}% below threshold {ALERT_QUALITY_THRESHOLD}%",
            {"dataset_type": dataset_type, "provider": provider, "dataset_id": dataset_id, "quality_index": quality},
        )
        await send_event("quality_drop_detected", {"dataset_type": dataset_type, "provider": provider, "dataset_id": dataset_id, "quality_index": quality})
    return rows, result


async def execute_correction(
    dataset_type: str,
    dataset_id: str,
    provider: str,
    limit: int,
    user_id: int | None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows = query_dataset(dataset_type, limit)
    payload = {
        "dataset_id": dataset_id,
        "records": rows,
        "corrections": get_correction_rules(dataset_type, user_id),
    }
    async with httpx.AsyncClient(timeout=90) as client:
        response = await client.post(f"{DQ_ENGINE_URL}/correct", json=payload)
        response.raise_for_status()
        result = response.json()
    return rows, result


def build_lineage(run: dict[str, Any], user_id: int | None) -> dict[str, Any]:
    result = to_jsonable(run.get("result")) or {}
    process_type = str(run.get("process_type") or "")
    dataset_type = str(run.get("dataset_type") or "")
    dataset_id = str(run.get("dataset_id") or "")
    with engine.begin() as conn:
        assessment = conn.execute(
            text(
                """
                SELECT run_id, result, created_at
                FROM workflow_runs
                WHERE owner_user_id IS NOT DISTINCT FROM :uid
                  AND dataset_id = :dataset_id
                  AND dataset_type = :dataset_type
                  AND process_type = 'assessment'
                  AND created_at <= :created_at
                ORDER BY created_at DESC
                LIMIT 1
                """
            ),
            {
                "uid": user_id,
                "dataset_id": dataset_id,
                "dataset_type": dataset_type,
                "created_at": run.get("created_at"),
            },
        ).mappings().first()
    viol_map: dict[str, dict[str, Any]] = {}
    if assessment:
        ass_result = to_jsonable(assessment.get("result")) or {}
        for v in ass_result.get("violations", []) or []:
            k = f"{v.get('record_index')}|{v.get('field')}"
            viol_map[k] = v
    downstream_map = {
        "customer_profile": {
            "customer_id": ["crm", "kyc"],
            "segment": ["risk_engine", "pricing"],
            "country": ["compliance_screening"],
        },
        "credit_facility": {
            "dpd": ["collections", "ifrs9"],
            "limit_amount": ["capital_reporting"],
        },
    }
    impacts = downstream_map.get(dataset_type, {})
    links: list[dict[str, Any]] = []
    if process_type == "correction":
        for a in result.get("applied", []) or []:
            k = f"{a.get('record_index')}|{a.get('field')}"
            v = viol_map.get(k, {})
            links.append(
                {
                    "record_index": a.get("record_index"),
                    "field": a.get("field"),
                    "violation_rule_id": v.get("rule_id"),
                    "violation_severity": v.get("severity"),
                    "violation_reason": v.get("reason"),
                    "correction_action": a.get("action"),
                    "new_value": a.get("new_value"),
                    "downstream_systems": impacts.get(a.get("field"), []),
                }
            )
    else:
        for v in result.get("violations", []) or []:
            links.append(
                {
                    "record_index": v.get("record_index"),
                    "field": v.get("field"),
                    "violation_rule_id": v.get("rule_id"),
                    "violation_severity": v.get("severity"),
                    "violation_reason": v.get("reason"),
                    "correction_action": None,
                    "new_value": None,
                    "downstream_systems": impacts.get(v.get("field"), []),
                }
            )
    return {"run_id": run.get("run_id"), "dataset_type": dataset_type, "dataset_id": dataset_id, "lineage": links}


def export_audit_pack(run: dict[str, Any], user_id: int | None, fmt: str = "both") -> dict[str, Any]:
    run_id = str(run.get("run_id"))
    result = to_jsonable(run.get("result")) or {}
    out_dir = Path(AUDIT_ARTIFACTS_DIR) / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_path = out_dir / "summary.csv"
    with summary_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["key", "value"])
        for key in ["run_id", "dataset_id", "dataset_type", "provider", "process_type", "status", "created_at"]:
            w.writerow([key, run.get(key)])
        for key in ["total_records", "total_checks", "failed_checks", "quality_index", "corrections_applied"]:
            if key in result:
                w.writerow([key, result.get(key)])

    # OpenLineage-style event (simplified).
    ol_event = {
        "eventType": "COMPLETE",
        "eventTime": utcnow().isoformat(),
        "run": {"runId": run_id},
        "job": {"namespace": "idqe", "name": f"dq:{run.get('provider')}:{run.get('dataset_type')}:{run.get('process_type')}"},
        "inputs": [{"namespace": str(run.get("provider") or "unknown"), "name": str(run.get("dataset_id") or "dataset")}],
        "outputs": [],
        "facets": {
            "dq": {
                "provider": run.get("provider"),
                "dataset_type": run.get("dataset_type"),
                "dataset_id": run.get("dataset_id"),
                "process_type": run.get("process_type"),
                "quality_index": result.get("quality_index"),
                "failed_checks": result.get("failed_checks"),
                "corrections_applied": result.get("corrections_applied"),
            }
        },
    }
    ol_path = out_dir / "openlineage.json"
    ol_path.write_text(json.dumps(to_jsonable(ol_event), indent=2), encoding="utf-8")

    files = {"summary_csv": str(summary_path), "openlineage_json": str(ol_path)}
    violations = result.get("violations", []) or []
    if violations:
        v_path = out_dir / "violations.csv"
        with v_path.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["record_index", "rule_id", "field", "severity", "reason", "value"])
            w.writeheader()
            for row in violations:
                w.writerow({k: row.get(k) for k in w.fieldnames})
        files["violations_csv"] = str(v_path)
    applied = result.get("applied", []) or []
    if applied:
        c_path = out_dir / "corrections.csv"
        with c_path.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["record_index", "field", "action", "new_value"])
            w.writeheader()
            for row in applied:
                w.writerow({k: row.get(k) for k in w.fieldnames})
        files["corrections_csv"] = str(c_path)

    if fmt in {"pdf", "both"}:
        lines = [
            f"Dataset: {run.get('dataset_id')} ({run.get('dataset_type')})",
            f"Process: {run.get('process_type')} | Status: {run.get('status')}",
            f"Created at: {run.get('created_at')}",
            f"Quality index: {result.get('quality_index', '-')}",
            f"Failed checks: {result.get('failed_checks', '-')}",
            f"Corrections applied: {result.get('corrections_applied', '-')}",
        ]
        pdf_path = out_dir / "audit-pack.pdf"
        write_minimal_pdf(pdf_path, f"IDQE Audit Pack - {run_id}", lines)
        files["audit_pdf"] = str(pdf_path)

    artifacts: list[dict[str, Any]] = []
    for key, path_str in files.items():
        p = Path(path_str)
        filename = p.name
        mime = "application/octet-stream"
        if filename.endswith(".csv"):
            mime = "text/csv"
        elif filename.endswith(".pdf"):
            mime = "application/pdf"
        elif filename.endswith(".json"):
            mime = "application/json"
        try:
            size_bytes = int(p.stat().st_size)
        except Exception:
            size_bytes = None
        artifacts.append(
            {
                "key": key,
                "filename": filename,
                "mime_type": mime,
                "size_bytes": size_bytes,
                "download_path": f"/artifacts/{run_id}/{filename}",
            }
        )

    return {"run_id": run_id, "files": files, "artifacts": artifacts, "owner_user_id": user_id}


def _artifact_owner_allowed(request: Request, run_id: str) -> tuple[dict[str, Any] | None, int | None]:
    """
    Returns (user, owner_user_id). Raises HTTPException if access denied.
    """
    user = get_current_user(request, allow_anonymous=not AUTH_REQUIRED)
    user_id = int(user["id"]) if user else None
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT owner_user_id FROM workflow_runs WHERE run_id = :run_id LIMIT 1"),
            {"run_id": run_id},
        ).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Artifact run not found")
    owner_uid = row.get("owner_user_id")
    if AUTH_REQUIRED and not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    if user and user.get("role") == "admin":
        return user, owner_uid
    if user_id is None:
        if owner_uid is not None:
            raise HTTPException(status_code=403, detail="Access denied for this artifact")
        return user, owner_uid
    if owner_uid != user_id:
        raise HTTPException(status_code=403, detail="Access denied for this artifact")
    return user, owner_uid


@app.get("/artifacts/{run_id}/{filename}")
def download_artifact(run_id: str, filename: str, request: Request) -> FileResponse:
    # Enforce run ownership and auth rules.
    _artifact_owner_allowed(request, run_id)

    base_dir = (Path(AUDIT_ARTIFACTS_DIR) / run_id).resolve()
    target = (base_dir / filename).resolve()
    if base_dir not in target.parents and target != base_dir:
        raise HTTPException(status_code=400, detail="Invalid artifact path")
    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=404, detail="Artifact not found")

    media_type = "application/octet-stream"
    if filename.endswith(".csv"):
        media_type = "text/csv"
    elif filename.endswith(".pdf"):
        media_type = "application/pdf"
    elif filename.endswith(".json"):
        media_type = "application/json"
    return FileResponse(path=str(target), media_type=media_type, filename=filename)


# ---------- lifecycle ----------
def ensure_tables() -> None:
    metadata.create_all(engine)


def ensure_schema_evolution() -> None:
    # Only apply runtime schema tweaks for Postgres. Other DBs (e.g. sqlite in tests)
    # should rely on `metadata.create_all()` or Alembic migrations.
    if engine.dialect.name != "postgresql":
        return
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE workflow_runs ADD COLUMN IF NOT EXISTS owner_user_id INTEGER"))
        conn.execute(text("ALTER TABLE suggestion_decisions ADD COLUMN IF NOT EXISTS owner_user_id INTEGER"))
        conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS team VARCHAR(64) DEFAULT 'default'"))
        conn.execute(text("UPDATE users SET team = 'default' WHERE team IS NULL OR team = ''"))
        conn.execute(text("ALTER TABLE user_settings ADD COLUMN IF NOT EXISTS rules_config JSON NULL"))
        # Avoid destructive DDL at startup (production safety). Keep legacy columns if present.
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_workflow_runs_owner_created ON workflow_runs(owner_user_id, created_at DESC)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_suggestion_decisions_owner_created ON suggestion_decisions(owner_user_id, created_at DESC)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_rule_versions_owner_created ON rule_versions(owner_user_id, created_at DESC)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_jobs_owner_next ON workflow_jobs(owner_user_id, next_run_at ASC)"))
        conn.execute(text("ALTER TABLE workflow_jobs ADD COLUMN IF NOT EXISTS claimed_until TIMESTAMP NULL"))
        conn.execute(text("ALTER TABLE workflow_jobs ADD COLUMN IF NOT EXISTS claimed_by VARCHAR(64) NULL"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_jobs_claimed_until ON workflow_jobs(claimed_until)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_alerts_owner_created ON alerts_store(owner_user_id, created_at DESC)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_drift_owner_dataset_created ON drift_baselines(owner_user_id, dataset_type, created_at DESC)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_admin_audit_created ON admin_audit_logs(created_at DESC)"))
        conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ux_suggestion_approvals_sid_uid ON suggestion_approvals(suggestion_id, approver_user_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_exp ON refresh_tokens(user_id, expires_at DESC)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_refresh_tokens_revoked ON refresh_tokens(revoked_at)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_revoked_tokens_exp ON revoked_tokens(expires_at DESC)"))
        conn.execute(
            text(
                "CREATE INDEX IF NOT EXISTS idx_pending_suggestions_status_owner_created "
                "ON pending_suggestions_store(status, owner_user_id, created_at DESC)"
            )
        )


def cleanup_suggestion_store() -> None:
    cutoff = utcnow() - timedelta(days=PENDING_SUGGESTIONS_RETENTION_DAYS)
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                DELETE FROM pending_suggestions_store
                WHERE status IN ('approved', 'declined') AND created_at < :cutoff
                """
            ),
            {"cutoff": cutoff},
        )


def cleanup_auth_tokens() -> None:
    now = utcnow()
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM revoked_tokens WHERE expires_at < :now"), {"now": now})
        conn.execute(text("DELETE FROM refresh_tokens WHERE expires_at < :now"), {"now": now})
        # Keep revoked refresh tokens for a short period for audit/debug, then purge.
        conn.execute(
            text("DELETE FROM refresh_tokens WHERE revoked_at IS NOT NULL AND revoked_at < :cutoff"),
            {"cutoff": now - timedelta(days=30)},
        )


@app.on_event("startup")
def startup() -> None:
    configure_logging()
    ensure_security_defaults()
    ensure_tables()
    ensure_schema_evolution()
    cleanup_suggestion_store()
    cleanup_auth_tokens()
    ensure_demo_admin()
    ensure_demo_shared_servers()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/metrics")
def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/mcp/initialize")
def initialize() -> dict[str, Any]:
    return {
        "server": MCP_SERVER_NAME,
        "version": "0.3.0",
        "capabilities": ["tools/list", "tools/call"],
        "ui": {
            "llm_tab_enabled": UI_ALLOW_LLM_TAB,
        },
        "timestamp": utcnow().isoformat(),
    }


@app.get("/mcp/tools")
def tools_list() -> dict[str, Any]:
    return {
        "tools": [
            {"name": "auth_register", "description": "Create user account"},
            {"name": "auth_login", "description": "Login and get bearer token"},
            {"name": "auth_refresh", "description": "Refresh access token using refresh token"},
            {"name": "auth_logout", "description": "Logout (revoke refresh token and current access token)"},
            {"name": "auth_logout_all", "description": "Logout everywhere (revoke all refresh tokens + current access token)"},
            {"name": "auth_me", "description": "Get current user profile"},
            {"name": "admin_list_users", "description": "Admin: list users"},
            {"name": "admin_update_user", "description": "Admin: update role/active state"},
            {"name": "admin_delete_user", "description": "Admin: delete a user (with safety checks)"},
            {"name": "list_shared_mcp_servers", "description": "List shared MCP servers (active only)"},
            {"name": "admin_list_shared_mcp_servers", "description": "Admin: list shared MCP servers"},
            {"name": "admin_save_shared_mcp_servers", "description": "Admin: replace shared MCP servers list"},
            {"name": "list_data_sources", "description": "List configured data providers"},
            {"name": "show_data_model", "description": "Show data model (tables, columns, datatypes)"},
            {"name": "show_dataset", "description": "Show rows for a dataset type"},
            {"name": "show_foreign_key_relations", "description": "Show explicit and inferred foreign key relations"},
            {"name": "preview_dataset", "description": "Preview rows from selected dataset"},
            {"name": "run_dq_assessment", "description": "Execute data quality checks for dataset"},
            {"name": "run_correction", "description": "Apply correction rules"},
            {"name": "simulate_rules", "description": "Simulate assessment rules without saving changes"},
            {"name": "canary_assessment", "description": "Run assessment on a sampled subset for canary testing"},
            {"name": "get_workflow_runs", "description": "Return workflow execution history"},
            {"name": "get_workflow_run_detail", "description": "Return one workflow run including full result payload"},
            {"name": "trace_lineage", "description": "Trace row-level lineage from violations to corrections and impacts"},
            {"name": "export_audit_pack", "description": "Export per-run audit pack in CSV/PDF"},
            {"name": "get_rules_yaml", "description": "Get DQ rule configuration as YAML text"},
            {"name": "save_rules_yaml", "description": "Save DQ rule configuration from YAML text"},
            {"name": "get_rules_config", "description": "Get DQ rule configuration as structured object"},
            {"name": "save_rules_config", "description": "Save DQ rule configuration as structured object"},
            {"name": "list_rule_versions", "description": "List rule configuration versions"},
            {"name": "get_rule_version", "description": "Get one rule configuration version"},
            {"name": "diff_rule_versions", "description": "Show unified diff between two rule versions"},
            {"name": "rollback_rule_version", "description": "Rollback rules to a previous version"},
            {"name": "get_llm_yaml", "description": "Get LLM configuration as YAML text"},
            {"name": "save_llm_yaml", "description": "Save LLM configuration from YAML text"},
            {"name": "suggest_rules", "description": "Generate LLM-based new DQ rule suggestions"},
            {"name": "approve_suggestion", "description": "Approve and store suggested rule"},
            {"name": "decline_suggestion", "description": "Decline suggested rule"},
            {"name": "get_suggestion_decisions", "description": "List accepted and declined suggested rules"},
            {"name": "refresh_drift_baseline", "description": "Create/refresh baseline profile for data drift checks"},
            {"name": "list_alerts", "description": "List quality/drift alerts"},
            {"name": "create_workflow_job", "description": "Create recurring workflow job"},
            {"name": "list_workflow_jobs", "description": "List recurring workflow jobs"},
            {"name": "toggle_workflow_job", "description": "Enable/disable a recurring workflow job"},
            {"name": "run_due_workflow_jobs", "description": "Execute all due recurring workflow jobs"},
            {"name": "create_ticket_from_run", "description": "Create external ticket payload/webhook from run"},
            {"name": "admin_set_team_policy", "description": "Admin: set team RBAC policy (datasets/servers/scoped-admin)"},
            {"name": "admin_list_team_policies", "description": "Admin: list team RBAC policies"},
            {"name": "get_integration_status", "description": "Get webhook/integration configuration status"},
            {"name": "send_test_event", "description": "Send a test webhook event"},
            {"name": "admin_list_audit_logs", "description": "Admin: list audit logs for admin actions"},
            {"name": "admin_access_review", "description": "Admin: least-privilege and identity/access review report"},
            {"name": "admin_rule_governance", "description": "Admin: rule governance and approval workflow report"},
            {"name": "admin_compliance_report", "description": "Admin: compliance status report (audit, lineage, quality)"},
        ]
    }


def get_request_user_for_tool(request: Request, tool: str) -> dict[str, Any] | None:
    public_tools = {"auth_register", "auth_login", "auth_me", "auth_refresh"}
    if tool in public_tools:
        return get_current_user(request, allow_anonymous=True)
    if not AUTH_REQUIRED:
        return get_current_user(request, allow_anonymous=True)
    return get_current_user(request)


async def execute_due_workflow_jobs(
    *,
    include_all: bool,
    owner_user_id: int | None,
    job_limit: int,
    row_limit: int,
) -> dict[str, Any]:
    now = utcnow()
    claim_until = now + timedelta(seconds=JOB_CLAIM_SECONDS)
    claimer = f"{MCP_SERVER_NAME}:{uuid.uuid4().hex[:8]}"
    limit = clamp_limit(job_limit, 20, MAX_LIST_LIMIT)
    with engine.begin() as conn:
        if include_all:
            rows = conn.execute(
                text(
                    """
                    WITH due AS (
                      SELECT id
                      FROM workflow_jobs
                      WHERE is_active = true
                        AND next_run_at <= :now
                        AND (claimed_until IS NULL OR claimed_until < :now)
                      ORDER BY next_run_at ASC
                      FOR UPDATE SKIP LOCKED
                      LIMIT :limit
                    )
                    UPDATE workflow_jobs j
                    SET claimed_until = :claim_until,
                        claimed_by = :claimer,
                        updated_at = :now
                    FROM due
                    WHERE j.id = due.id
                    RETURNING j.*
                    """
                ),
                {"now": now, "limit": limit, "claim_until": claim_until, "claimer": claimer},
            ).mappings().all()
        elif owner_user_id is None:
            rows = conn.execute(
                text(
                    """
                    WITH due AS (
                      SELECT id
                      FROM workflow_jobs
                      WHERE owner_user_id IS NULL
                        AND is_active = true
                        AND next_run_at <= :now
                        AND (claimed_until IS NULL OR claimed_until < :now)
                      ORDER BY next_run_at ASC
                      FOR UPDATE SKIP LOCKED
                      LIMIT :limit
                    )
                    UPDATE workflow_jobs j
                    SET claimed_until = :claim_until,
                        claimed_by = :claimer,
                        updated_at = :now
                    FROM due
                    WHERE j.id = due.id
                    RETURNING j.*
                    """
                ),
                {"now": now, "limit": limit, "claim_until": claim_until, "claimer": claimer},
            ).mappings().all()
        else:
            rows = conn.execute(
                text(
                    """
                    WITH due AS (
                      SELECT id
                      FROM workflow_jobs
                      WHERE owner_user_id = :uid
                        AND is_active = true
                        AND next_run_at <= :now
                        AND (claimed_until IS NULL OR claimed_until < :now)
                      ORDER BY next_run_at ASC
                      FOR UPDATE SKIP LOCKED
                      LIMIT :limit
                    )
                    UPDATE workflow_jobs j
                    SET claimed_until = :claim_until,
                        claimed_by = :claimer,
                        updated_at = :now
                    FROM due
                    WHERE j.id = due.id
                    RETURNING j.*
                    """
                ),
                {"uid": owner_user_id, "now": now, "limit": limit, "claim_until": claim_until, "claimer": claimer},
            ).mappings().all()

    executed: list[dict[str, Any]] = []
    rl = clamp_limit(row_limit, 50, MAX_QUERY_LIMIT)
    for row in rows:
        item = dict(row)
        jid = str(item.get("job_id"))
        owner_uid = item.get("owner_user_id")
        try:
            if item.get("process_type") in {"assessment", "both"}:
                _, assess_result = await execute_assessment(
                    str(item.get("dataset_type")),
                    str(item.get("dataset_id")),
                    str(item.get("provider")),
                    rl,
                    owner_uid,
                )
                run_id = insert_run(
                    str(item.get("dataset_id")),
                    str(item.get("dataset_type")),
                    str(item.get("provider")),
                    "assessment",
                    "completed",
                    assess_result,
                    owner_uid,
                )
                sla_target = item.get("sla_min_quality")
                if sla_target is not None and float(assess_result.get("quality_index", 100) or 100) < float(sla_target):
                    create_alert(
                        owner_uid,
                        "scheduled_sla",
                        "high",
                        f"SLA breach in job {jid}: quality {assess_result.get('quality_index')} < {sla_target}",
                        {"job_id": jid, "run_id": run_id, "quality_index": assess_result.get("quality_index")},
                    )
                    await send_event(
                        "sla_breach",
                        {"job_id": jid, "run_id": run_id, "quality_index": assess_result.get("quality_index"), "target": sla_target},
                    )
            if item.get("process_type") in {"correction", "both"}:
                _, corr_result = await execute_correction(
                    str(item.get("dataset_type")),
                    str(item.get("dataset_id")),
                    str(item.get("provider")),
                    rl,
                    owner_uid,
                )
                insert_run(
                    str(item.get("dataset_id")),
                    str(item.get("dataset_type")),
                    str(item.get("provider")),
                    "correction",
                    "completed",
                    corr_result,
                    owner_uid,
                )
            with engine.begin() as conn:
                conn.execute(
                    text(
                        """
                        UPDATE workflow_jobs
                        SET last_run_at = :now,
                            last_status = 'completed',
                            last_message = :message,
                            next_run_at = :next_run,
                            claimed_until = NULL,
                            claimed_by = NULL,
                            updated_at = :now
                        WHERE job_id = :job_id
                        """
                    ),
                    {
                        "now": now,
                        "next_run": now + timedelta(minutes=int(item.get("interval_minutes") or 60)),
                        "message": "Executed successfully",
                        "job_id": jid,
                    },
                )
            WORKFLOW_JOB_RUN_TOTAL.labels(status="completed").inc()
            executed.append({"job_id": jid, "status": "completed"})
        except Exception as exc:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        """
                        UPDATE workflow_jobs
                        SET last_run_at = :now,
                            last_status = 'failed',
                            last_message = :message,
                            next_run_at = :next_run,
                            claimed_until = NULL,
                            claimed_by = NULL,
                            updated_at = :now
                        WHERE job_id = :job_id
                        """
                    ),
                    {
                        "now": now,
                        "next_run": now + timedelta(minutes=int(item.get("interval_minutes") or 60)),
                        "message": str(exc)[:512],
                        "job_id": jid,
                    },
                )
            WORKFLOW_JOB_RUN_TOTAL.labels(status="failed").inc()
            executed.append({"job_id": jid, "status": "failed", "error": str(exc)})
    return {"executed": executed, "count": len(executed)}


@app.post("/mcp/call")
async def call_tool(call: MCPCall, request: Request) -> dict[str, Any]:
    tool = call.tool
    args = call.arguments
    MCP_TOOL_CALLS_TOTAL.labels(tool=tool).inc()
    user = get_request_user_for_tool(request, tool)
    user_id = int(user["id"]) if user else None

    # ---------- auth tools ----------
    if tool == "auth_register":
        email = str(args.get("email", "")).strip().lower()
        name = str(args.get("name", "")).strip() or "User"
        password = str(args.get("password", ""))
        if not email or "@" not in email:
            raise HTTPException(status_code=400, detail="Valid email is required")
        if len(password) < 8:
            raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
        validate_new_password(password)
        with engine.begin() as conn:
            exists = conn.execute(text("SELECT id FROM users WHERE email = :email LIMIT 1"), {"email": email}).mappings().first()
            if exists:
                raise HTTPException(status_code=409, detail="Email already registered")
            conn.execute(
                users.insert().values(
                    email=email,
                    name=name,
                    password_hash=password_hash(password),
                    role="user",
                    team="default",
                    is_active=True,
                    created_at=utcnow(),
                    last_login_at=None,
                )
            )
        return {"result": {"message": "Account created"}}

    if tool == "auth_login":
        email = str(args.get("email", "")).strip().lower()
        password = str(args.get("password", ""))
        key = login_key(email, client_ip(request))
        if login_is_locked(key):
            AUTH_LOGIN_TOTAL.labels(outcome="locked").inc()
            raise HTTPException(status_code=429, detail="Too many failed login attempts. Try again later.")
        with engine.begin() as conn:
            row = conn.execute(
                text("SELECT id, email, name, role, team, is_active, password_hash FROM users WHERE email = :email LIMIT 1"),
                {"email": email},
            ).mappings().first()
            if not row or not verify_password(password, str(row.get("password_hash", ""))):
                login_record_failure(key)
                AUTH_LOGIN_TOTAL.labels(outcome="invalid").inc()
                raise HTTPException(status_code=401, detail="Invalid credentials")
            if not row.get("is_active"):
                login_record_failure(key)
                AUTH_LOGIN_TOTAL.labels(outcome="inactive").inc()
                raise HTTPException(status_code=403, detail="User is inactive")
            conn.execute(text("UPDATE users SET last_login_at = :ts WHERE id = :id"), {"ts": utcnow(), "id": row["id"]})
        login_record_success(key)
        user_payload = {
            "id": int(row["id"]),
            "email": row["email"],
            "name": row["name"],
            "role": row["role"],
            "team": row.get("team") or "default",
        }
        token = make_access_token(user_payload)
        refresh_token = make_refresh_token(int(row["id"]))
        AUTH_LOGIN_TOTAL.labels(outcome="success").inc()
        return {
            "result": {
                "access_token": token,
                "refresh_token": refresh_token,
                "token_type": "bearer",
                "user": {
                    "id": row["id"],
                    "email": row["email"],
                    "name": row["name"],
                    "role": row["role"],
                    "team": row.get("team") or "default",
                },
            }
        }

    if tool == "auth_refresh":
        raw_rt = str(args.get("refresh_token", "")).strip()
        rotated = rotate_refresh_token(raw_rt)
        if not rotated:
            raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
        uid, new_rt = rotated
        with engine.begin() as conn:
            urow = conn.execute(
                text("SELECT id, email, name, role, team, is_active FROM users WHERE id = :id LIMIT 1"),
                {"id": uid},
            ).mappings().first()
        if not urow or not urow.get("is_active"):
            raise HTTPException(status_code=403, detail="User is inactive")
        user_payload = dict(urow)
        access = make_access_token(user_payload)
        return {
            "result": {
                "access_token": access,
                "refresh_token": new_rt,
                "token_type": "bearer",
                "user": {
                    "id": urow["id"],
                    "email": urow["email"],
                    "name": urow["name"],
                    "role": urow["role"],
                    "team": urow.get("team") or "default",
                },
            }
        }

    if tool == "auth_logout":
        enforce_authenticated_write(user)
        # Revoke refresh token if provided, plus current access token.
        raw_rt = str(args.get("refresh_token", "")).strip()
        if raw_rt and "." in raw_rt:
            tid = raw_rt.split(".", 1)[0]
            with engine.begin() as conn:
                conn.execute(
                    text("UPDATE refresh_tokens SET revoked_at = :now WHERE token_id = :tid AND user_id = :uid"),
                    {"now": utcnow(), "tid": tid, "uid": int(user.get("id") or 0)},
                )
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            payload = parse_access_token(auth[7:]) or {}
            jti = str(payload.get("jti") or "")
            exp_ts = int(payload.get("exp") or 0)
            if jti and exp_ts:
                revoke_access_token(jti, int(user.get("id") or 0), datetime.fromtimestamp(exp_ts, tz=timezone.utc))
        return {"result": {"message": "Logged out"}}

    if tool == "auth_logout_all":
        enforce_authenticated_write(user)
        uid = int(user.get("id") or 0)
        with engine.begin() as conn:
            conn.execute(
                text("UPDATE refresh_tokens SET revoked_at = :now WHERE user_id = :uid AND revoked_at IS NULL"),
                {"now": utcnow(), "uid": uid},
            )
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            payload = parse_access_token(auth[7:]) or {}
            jti = str(payload.get("jti") or "")
            exp_ts = int(payload.get("exp") or 0)
            if jti and exp_ts:
                revoke_access_token(jti, uid, datetime.fromtimestamp(exp_ts, tz=timezone.utc))
        return {"result": {"message": "Logged out on all sessions"}}

    if tool == "auth_me":
        if not user:
            return {"result": {"authenticated": False}}
        return {"result": {"authenticated": True, "user": user}}

    # below requires authenticated user in required mode
    if AUTH_REQUIRED and not user:
        raise HTTPException(status_code=401, detail="Authentication required")

    if tool == "admin_list_users":
        require_admin(user)
        enforce_team_scope(user, request, admin_action=True)
        with engine.begin() as conn:
            rows = conn.execute(
                text("SELECT id, email, name, role, team, is_active, created_at, last_login_at FROM users ORDER BY id ASC")
            ).mappings().all()
        if user and get_team_policy(str(user.get("team") or "default")) and get_team_policy(str(user.get("team") or "default")).get("scoped_admin"):
            rows = [r for r in rows if str(r.get("team") or "default") == str(user.get("team") or "default")]
        data = []
        for r in rows:
            item = dict(r)
            item["created_at"] = item["created_at"].isoformat() if item.get("created_at") else None
            item["last_login_at"] = item["last_login_at"].isoformat() if item.get("last_login_at") else None
            data.append(item)
        return {"result": data}

    if tool == "admin_update_user":
        enforce_authenticated_write(user)
        require_admin(user)
        enforce_team_scope(user, request, admin_action=True)
        target_user_id = int(args.get("user_id", 0))
        role = args.get("role")
        team = args.get("team")
        is_active = args.get("is_active")
        if target_user_id <= 0:
            raise HTTPException(status_code=400, detail="user_id is required")
        with engine.begin() as conn:
            target = conn.execute(
                text("SELECT team, role, is_active FROM users WHERE id = :id LIMIT 1"),
                {"id": target_user_id},
            ).mappings().first()
        if not target:
            raise HTTPException(status_code=404, detail="Target user not found")
        if user and not can_manage_user(user, str(target.get("team") or "default")):
            raise HTTPException(status_code=403, detail="Scoped admin policy denies managing this user")
        target_role = str(target.get("role") or "user")
        target_active = bool(target.get("is_active", False))
        next_role = str(role) if role is not None else target_role
        next_active = bool(is_active) if is_active is not None else target_active
        if target_role == "admin" and target_active and (next_role != "admin" or not next_active):
            with engine.begin() as conn:
                count_row = conn.execute(
                    text("SELECT COUNT(*) AS c FROM users WHERE role = 'admin' AND is_active = true")
                ).mappings().first()
            active_admins = int((count_row or {}).get("c", 0) or 0)
            if active_admins <= 1:
                raise HTTPException(status_code=400, detail="Cannot deactivate or demote the last active admin")
        updates = []
        params: dict[str, Any] = {"id": target_user_id}
        if role is not None:
            if role not in {"admin", "user"}:
                raise HTTPException(status_code=400, detail="role must be admin or user")
            updates.append("role = :role")
            params["role"] = role
        if team is not None:
            team_val = str(team).strip() or "default"
            updates.append("team = :team")
            params["team"] = team_val
        if is_active is not None:
            updates.append("is_active = :is_active")
            params["is_active"] = bool(is_active)
        if not updates:
            raise HTTPException(status_code=400, detail="No update fields provided")
        with engine.begin() as conn:
            conn.execute(text(f"UPDATE users SET {', '.join(updates)} WHERE id = :id"), params)
        if user:
            audit_admin_action(
                int(user["id"]),
                "admin_update_user",
                "user",
                str(target_user_id),
                f"Updated user {target_user_id}",
                {"updates": {k: v for k, v in params.items() if k != "id"}},
            )
        return {"result": {"message": "User updated"}}

    if tool == "admin_delete_user":
        enforce_authenticated_write(user)
        require_admin(user)
        enforce_team_scope(user, request, admin_action=True)
        target_user_id = int(args.get("user_id", 0))
        confirm = bool(args.get("confirm", False))
        if target_user_id <= 0:
            raise HTTPException(status_code=400, detail="user_id is required")
        if not confirm:
            raise HTTPException(status_code=400, detail="confirm=true is required to delete a user")
        if user and int(user.get("id") or 0) == target_user_id:
            raise HTTPException(status_code=400, detail="Cannot delete your own account")

        with engine.begin() as conn:
            target = conn.execute(
                text("SELECT id, email, team, role, is_active FROM users WHERE id = :id LIMIT 1"),
                {"id": target_user_id},
            ).mappings().first()
            if not target:
                raise HTTPException(status_code=404, detail="Target user not found")
            if user and not can_manage_user(user, str(target.get("team") or "default")):
                raise HTTPException(status_code=403, detail="Scoped admin policy denies managing this user")
            if str(target.get("role") or "user") == "admin" and bool(target.get("is_active", False)):
                count_row = conn.execute(
                    text("SELECT COUNT(*) AS c FROM users WHERE role = 'admin' AND is_active = true")
                ).mappings().first()
                active_admins = int((count_row or {}).get("c", 0) or 0)
                if active_admins <= 1:
                    raise HTTPException(status_code=400, detail="Cannot delete the last active admin")

            # Keep historical records but anonymize ownership (do not hard-delete history tables).
            owner_tables = [
                ("workflow_runs", "owner_user_id"),
                ("suggestion_decisions", "owner_user_id"),
                ("pending_suggestions_store", "owner_user_id"),
                ("rule_versions", "owner_user_id"),
                ("workflow_jobs", "owner_user_id"),
                ("drift_baselines", "owner_user_id"),
                ("alerts_store", "owner_user_id"),
            ]
            for table, col in owner_tables:
                conn.execute(text(f"UPDATE {table} SET {col} = NULL WHERE {col} = :id"), {"id": target_user_id})

            # Remove per-user settings and approval records.
            conn.execute(text("DELETE FROM user_settings WHERE user_id = :id"), {"id": target_user_id})
            conn.execute(text("DELETE FROM suggestion_approvals WHERE approver_user_id = :id"), {"id": target_user_id})

            # Finally delete the user record itself.
            conn.execute(text("DELETE FROM users WHERE id = :id"), {"id": target_user_id})

        if user:
            audit_admin_action(
                int(user["id"]),
                "admin_delete_user",
                "user",
                str(target_user_id),
                f"Deleted user {target_user_id}",
                {
                    "deleted_user": {
                        "id": int(target.get("id")),
                        "email": str(target.get("email") or ""),
                        "team": str(target.get("team") or "default"),
                        "role": str(target.get("role") or "user"),
                        "was_active": bool(target.get("is_active", False)),
                    }
                },
            )
        return {"result": {"message": "User deleted"}}

    if tool == "list_shared_mcp_servers":
        # Non-admin read-only view (active servers only).
        if AUTH_REQUIRED and not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        return {"result": {"servers": get_shared_mcp_servers(include_inactive=False)}}

    if tool == "admin_list_shared_mcp_servers":
        require_admin(user)
        return {"result": {"servers": get_shared_mcp_servers(include_inactive=True)}}

    if tool == "admin_save_shared_mcp_servers":
        enforce_authenticated_write(user)
        require_admin(user)
        servers = args.get("servers", [])
        if not isinstance(servers, list):
            raise HTTPException(status_code=400, detail="servers must be a list")
        save_shared_mcp_servers(servers)
        if user:
            audit_admin_action(
                int(user["id"]),
                "admin_save_shared_mcp_servers",
                "shared_mcp_servers",
                None,
                "Replaced shared MCP servers catalog",
                {"server_count": len(servers)},
            )
        return {"result": {"message": "Shared MCP servers saved"}}

    if tool == "list_data_sources":
        cfg = load_rules_config_for_user(user_id)
        data_sources = to_jsonable(cfg["data_sources"])
        policy = get_team_policy(str((user or {}).get("team") or "default")) if user else None
        allowed = (policy or {}).get("allowed_dataset_types") if policy else None
        if isinstance(allowed, list) and allowed:
            filtered = []
            for ds in data_sources:
                if not isinstance(ds, dict):
                    continue
                dts = [x for x in (ds.get("dataset_types") or []) if x in allowed]
                if dts:
                    filtered.append({**ds, "dataset_types": dts})
            data_sources = filtered
        return {"result": data_sources}

    if tool == "show_data_model":
        return {"result": get_data_model()}

    if tool == "show_dataset":
        dataset_type = args.get("dataset_type", "customer_profile")
        enforce_team_scope(user, request, dataset_type=dataset_type)
        limit = clamp_limit(args.get("limit", 50), 50, MAX_QUERY_LIMIT)
        return {"result": query_dataset(dataset_type, limit)}

    if tool == "show_foreign_key_relations":
        return {"result": get_foreign_key_relations()}

    if tool == "preview_dataset":
        dataset_type = args.get("dataset_type", "customer_profile")
        enforce_team_scope(user, request, dataset_type=dataset_type)
        limit = clamp_limit(args.get("limit", 20), 20, MAX_QUERY_LIMIT)
        return {"result": query_dataset(dataset_type, limit)}

    if tool == "run_dq_assessment":
        if AUTH_REQUIRED and not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        dataset_type = args.get("dataset_type", "customer_profile")
        enforce_team_scope(user, request, dataset_type=dataset_type)
        dataset_id = args.get("dataset_id", f"{dataset_type}-{utcnow().strftime('%Y%m%d%H%M%S')}")
        provider = args.get("provider", "BANK_A")
        _, result = await execute_assessment(
            dataset_type,
            dataset_id,
            provider,
            clamp_limit(args.get("limit", 50), 50, MAX_QUERY_LIMIT),
            user_id,
        )
        run_id = insert_run(dataset_id, dataset_type, provider, "assessment", "completed", result, user_id)
        return {"run_id": run_id, "result": result}

    if tool == "run_correction":
        if AUTH_REQUIRED and not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        dataset_type = args.get("dataset_type", "customer_profile")
        enforce_team_scope(user, request, dataset_type=dataset_type)
        dataset_id = args.get("dataset_id", f"{dataset_type}-{utcnow().strftime('%Y%m%d%H%M%S')}")
        provider = args.get("provider", "BANK_A")
        _, result = await execute_correction(
            dataset_type,
            dataset_id,
            provider,
            clamp_limit(args.get("limit", 50), 50, MAX_QUERY_LIMIT),
            user_id,
        )
        run_id = insert_run(dataset_id, dataset_type, provider, "correction", "completed", result, user_id)
        return {"run_id": run_id, "result": result}

    if tool == "simulate_rules":
        if AUTH_REQUIRED and not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        dataset_type = args.get("dataset_type", "customer_profile")
        enforce_team_scope(user, request, dataset_type=dataset_type)
        dataset_id = args.get("dataset_id", f"{dataset_type}-simulation")
        provider = args.get("provider", "BANK_A")
        rows = query_dataset(dataset_type, clamp_limit(args.get("limit", 50), 50, MAX_QUERY_LIMIT))

        cfg = args.get("config")
        assessment_rules = args.get("assessment_rules")
        if isinstance(cfg, dict):
            assessment_rules = (cfg.get("assessment_rules") or {}).get(dataset_type)
        if not isinstance(assessment_rules, list):
            assessment_rules = get_rules(dataset_type, user_id)

        payload = {
            "dataset_id": dataset_id,
            "dataset_type": dataset_type,
            "provider": provider,
            "records": rows,
            "rules": to_jsonable(assessment_rules),
        }
        async with httpx.AsyncClient(timeout=90) as client:
            response = await client.post(f"{DQ_ENGINE_URL}/assess", json=payload)
            response.raise_for_status()
            result = response.json()
        result["simulation"] = True
        return {"result": result}

    if tool == "canary_assessment":
        if AUTH_REQUIRED and not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        dataset_type = args.get("dataset_type", "customer_profile")
        enforce_team_scope(user, request, dataset_type=dataset_type)
        provider = args.get("provider", "BANK_A")
        dataset_id = args.get("dataset_id", f"{dataset_type}-canary")
        limit = clamp_limit(args.get("limit", 200), 200, MAX_QUERY_LIMIT)
        rows = query_dataset(dataset_type, limit)
        if not rows:
            return {"result": {"dataset_id": dataset_id, "canary": True, "sample_size": 0, "message": "No records"}}
        sample_percent = float(args.get("sample_percent", 20))
        sample_size = int(args.get("sample_size", max(1, int(len(rows) * sample_percent / 100.0))))
        sample_size = max(1, min(sample_size, len(rows)))
        sample_rows = random.sample(rows, sample_size) if sample_size < len(rows) else rows
        payload = {
            "dataset_id": dataset_id,
            "dataset_type": dataset_type,
            "provider": provider,
            "records": sample_rows,
            "rules": get_rules(dataset_type, user_id),
        }
        async with httpx.AsyncClient(timeout=90) as client:
            response = await client.post(f"{DQ_ENGINE_URL}/assess", json=payload)
            response.raise_for_status()
            result = response.json()
        result["canary"] = True
        result["sample_size"] = sample_size
        result["sample_ratio"] = round(sample_size / len(rows), 4)
        return {"result": result}

    if tool == "refresh_drift_baseline":
        if AUTH_REQUIRED and not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        dataset_type = args.get("dataset_type", "customer_profile")
        enforce_team_scope(user, request, dataset_type=dataset_type)
        provider = args.get("provider", "BANK_A")
        rows = query_dataset(dataset_type, clamp_limit(args.get("limit", 200), 200, MAX_QUERY_LIMIT))
        baseline = save_drift_baseline(user_id, provider, dataset_type, rows)
        return {"result": baseline}

    if tool == "get_workflow_runs":
        if AUTH_REQUIRED and not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        include_all = bool(args.get("include_all", False)) and user is not None and user.get("role") == "admin"
        with engine.begin() as conn:
            if include_all:
                rows = conn.execute(
                    text(
                        """
                        SELECT run_id, dataset_id, dataset_type, provider, process_type, status, created_at
                        FROM workflow_runs
                        ORDER BY id DESC
                        LIMIT :limit
                        """
                    ),
                    {"limit": clamp_limit(args.get("limit", 25), 25, MAX_LIST_LIMIT)},
                ).mappings().all()
            else:
                if user_id is None:
                    rows = conn.execute(
                        text(
                            """
                            SELECT run_id, dataset_id, dataset_type, provider, process_type, status, created_at
                            FROM workflow_runs
                            WHERE owner_user_id IS NULL
                            ORDER BY id DESC
                            LIMIT :limit
                            """
                        ),
                        {"limit": clamp_limit(args.get("limit", 25), 25, MAX_LIST_LIMIT)},
                    ).mappings().all()
                else:
                    rows = conn.execute(
                        text(
                            """
                            SELECT run_id, dataset_id, dataset_type, provider, process_type, status, created_at
                            FROM workflow_runs
                            WHERE owner_user_id = :uid
                            ORDER BY id DESC
                            LIMIT :limit
                            """
                        ),
                        {"limit": clamp_limit(args.get("limit", 25), 25, MAX_LIST_LIMIT), "uid": user_id},
                    ).mappings().all()
        data = []
        for r in rows:
            item = dict(r)
            item["created_at"] = item["created_at"].isoformat() if item.get("created_at") else None
            data.append(item)
        return {"result": data}

    if tool == "get_workflow_run_detail":
        if AUTH_REQUIRED and not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        run_id = args.get("run_id", "")
        if not isinstance(run_id, str) or not run_id.strip():
            raise HTTPException(status_code=400, detail="run_id is required")
        with engine.begin() as conn:
            row = conn.execute(
                text(
                    """
                    SELECT run_id, dataset_id, dataset_type, provider, process_type, status, created_at, result, owner_user_id
                    FROM workflow_runs
                    WHERE run_id = :run_id
                    LIMIT 1
                    """
                ),
                {"run_id": run_id},
            ).mappings().first()
        if not row:
            raise HTTPException(status_code=404, detail="Workflow run not found")
        owner_uid = row.get("owner_user_id")
        if user and user.get("role") == "admin":
            pass
        elif user_id is None:
            if owner_uid is not None:
                raise HTTPException(status_code=403, detail="Access denied for this workflow run")
        elif owner_uid != user_id:
            raise HTTPException(status_code=403, detail="Access denied for this workflow run")
        item = dict(row)
        item["created_at"] = item["created_at"].isoformat() if item.get("created_at") else None
        item["result"] = to_jsonable(item.get("result"))
        item.pop("owner_user_id", None)
        return {"result": item}

    if tool == "trace_lineage":
        if AUTH_REQUIRED and not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        run_id = str(args.get("run_id", "")).strip()
        if not run_id:
            raise HTTPException(status_code=400, detail="run_id is required")
        with engine.begin() as conn:
            row = conn.execute(
                text(
                    """
                    SELECT run_id, dataset_id, dataset_type, provider, process_type, status, created_at, result, owner_user_id
                    FROM workflow_runs
                    WHERE run_id = :run_id
                    LIMIT 1
                    """
                ),
                {"run_id": run_id},
            ).mappings().first()
        if not row:
            raise HTTPException(status_code=404, detail="Workflow run not found")
        owner_uid = row.get("owner_user_id")
        if user and user.get("role") == "admin":
            pass
        elif user_id is None:
            if owner_uid is not None:
                raise HTTPException(status_code=403, detail="Access denied for this workflow run")
        elif owner_uid != user_id:
            raise HTTPException(status_code=403, detail="Access denied for this workflow run")
        return {"result": build_lineage(dict(row), owner_uid)}

    if tool == "export_audit_pack":
        if AUTH_REQUIRED and not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        run_id = str(args.get("run_id", "")).strip()
        if not run_id:
            raise HTTPException(status_code=400, detail="run_id is required")
        fmt = str(args.get("format", "both")).lower()
        if fmt not in {"csv", "pdf", "both"}:
            raise HTTPException(status_code=400, detail="format must be csv|pdf|both")
        with engine.begin() as conn:
            row = conn.execute(
                text(
                    """
                    SELECT run_id, dataset_id, dataset_type, provider, process_type, status, created_at, result, owner_user_id
                    FROM workflow_runs
                    WHERE run_id = :run_id
                    LIMIT 1
                    """
                ),
                {"run_id": run_id},
            ).mappings().first()
        if not row:
            raise HTTPException(status_code=404, detail="Workflow run not found")
        owner_uid = row.get("owner_user_id")
        if user and user.get("role") == "admin":
            pass
        elif user_id is None:
            if owner_uid is not None:
                raise HTTPException(status_code=403, detail="Access denied for this workflow run")
        elif owner_uid != user_id:
            raise HTTPException(status_code=403, detail="Access denied for this workflow run")
        return {"result": export_audit_pack(dict(row), owner_uid, fmt)}

    if tool == "get_rules_yaml":
        return {"result": {"yaml_text": rules_config_as_yaml_for_user(user_id)}}

    if tool == "save_rules_yaml":
        enforce_authenticated_write(user)
        yaml_text = args.get("yaml_text", "")
        if not isinstance(yaml_text, str) or not yaml_text.strip():
            raise HTTPException(status_code=400, detail="yaml_text is required")
        save_rules_yaml_for_user(user_id, yaml_text)
        return {"result": {"message": "Rules saved successfully"}}

    if tool == "get_rules_config":
        return {"result": {"config": to_jsonable(load_rules_config_for_user(user_id))}}

    if tool == "save_rules_config":
        enforce_authenticated_write(user)
        config = args.get("config")
        if not isinstance(config, dict):
            raise HTTPException(status_code=400, detail="config object is required")
        validate_rules_config(config)
        if user_id is None:
            save_yaml(RULES_CONFIG_PATH, config)
        else:
            upsert_user_rules_config(user_id, config)
        create_rule_version(user_id, config, "save_rules_config")
        return {"result": {"message": "Rules config saved successfully"}}

    if tool == "list_rule_versions":
        if AUTH_REQUIRED and not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        return {"result": list_rule_versions(user_id, limit=clamp_limit(args.get("limit", 25), 25, MAX_LIST_LIMIT))}

    if tool == "get_rule_version":
        if AUTH_REQUIRED and not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        version_id = str(args.get("version_id", "")).strip()
        if not version_id:
            raise HTTPException(status_code=400, detail="version_id is required")
        item = get_rule_version(user_id, version_id)
        if not item:
            raise HTTPException(status_code=404, detail="Rule version not found")
        return {"result": item}

    if tool == "diff_rule_versions":
        if AUTH_REQUIRED and not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        from_version_id = str(args.get("from_version_id", "")).strip()
        to_version_id = str(args.get("to_version_id", "")).strip()
        if not from_version_id or not to_version_id:
            raise HTTPException(status_code=400, detail="from_version_id and to_version_id are required")
        return {"result": {"diff_text": diff_rule_versions(user_id, from_version_id, to_version_id)}}

    if tool == "rollback_rule_version":
        enforce_authenticated_write(user)
        version_id = str(args.get("version_id", "")).strip()
        if not version_id:
            raise HTTPException(status_code=400, detail="version_id is required")
        item = get_rule_version(user_id, version_id)
        if not item:
            raise HTTPException(status_code=404, detail="Rule version not found")
        config = item.get("rules_config")
        validate_rules_config(config)
        if user_id is None:
            save_yaml(RULES_CONFIG_PATH, config)
        else:
            upsert_user_rules_config(user_id, config)
        new_version_id = create_rule_version(user_id, config, f"rollback:{version_id}")
        return {"result": {"message": "Rollback completed", "rolled_back_to": version_id, "new_version_id": new_version_id}}

    if tool == "get_llm_yaml":
        return {"result": {"yaml_text": llm_config_as_yaml()}}

    if tool == "save_llm_yaml":
        enforce_authenticated_write(user)
        if AUTH_MODE == "production":
            raise HTTPException(status_code=403, detail="LLM config updates are file-only in production mode")
        yaml_text = args.get("yaml_text", "")
        if not isinstance(yaml_text, str) or not yaml_text.strip():
            raise HTTPException(status_code=400, detail="yaml_text is required")
        save_llm_yaml(yaml_text)
        return {"result": {"message": "LLM config saved successfully"}}

    if tool == "suggest_rules":
        dataset_type = args.get("dataset_type", "customer_profile")
        rows = query_dataset(dataset_type, clamp_limit(args.get("limit", 50), 50, MAX_QUERY_LIMIT))
        suggestions = generate_rule_suggestions(dataset_type, rows, user_id)
        return {"result": {"suggestions": suggestions, "llm_enabled": llm_enabled()}}

    if tool == "approve_suggestion":
        enforce_authenticated_write(user)
        if AUTH_REQUIRED and not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        suggestion_id = args.get("suggestion_id", "")
        if not suggestion_id:
            raise HTTPException(status_code=400, detail="suggestion_id is required")
        return {"result": approve_suggestion(suggestion_id, user)}

    if tool == "decline_suggestion":
        enforce_authenticated_write(user)
        if AUTH_REQUIRED and not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        suggestion_id = args.get("suggestion_id", "")
        if not suggestion_id:
            raise HTTPException(status_code=400, detail="suggestion_id is required")
        return {"result": decline_suggestion(suggestion_id, user)}

    if tool == "get_suggestion_decisions":
        if AUTH_REQUIRED and not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        include_all = bool(args.get("include_all", False)) and user is not None and user.get("role") == "admin"
        return {
            "result": get_suggestion_decisions(
                limit=clamp_limit(args.get("limit", 100), 100, MAX_LIST_LIMIT),
                user_id=user_id,
                include_all=include_all,
            )
        }

    if tool == "list_alerts":
        if AUTH_REQUIRED and not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        include_all = bool(args.get("include_all", False)) and user is not None and user.get("role") == "admin"
        return {"result": get_alerts(user_id, limit=clamp_limit(args.get("limit", 100), 100, MAX_LIST_LIMIT), include_all=include_all)}

    if tool == "create_workflow_job":
        enforce_authenticated_write(user)
        dataset_type = str(args.get("dataset_type", "customer_profile"))
        enforce_team_scope(user, request, dataset_type=dataset_type)
        provider = str(args.get("provider", "BANK_A"))
        dataset_id = str(args.get("dataset_id", f"{dataset_type}-job"))
        process_type = str(args.get("process_type", "assessment"))
        if process_type not in {"assessment", "correction", "both"}:
            raise HTTPException(status_code=400, detail="process_type must be assessment|correction|both")
        interval_minutes = int(args.get("interval_minutes", 60))
        if interval_minutes < 1:
            raise HTTPException(status_code=400, detail="interval_minutes must be >= 1")
        sla_min_quality = args.get("sla_min_quality")
        job_id = safe_id("job")
        now = utcnow()
        with engine.begin() as conn:
            conn.execute(
                workflow_jobs.insert().values(
                    job_id=job_id,
                    owner_user_id=user_id,
                    name=str(args.get("name", f"{dataset_type}-{process_type}"))[:128],
                    provider=provider,
                    dataset_type=dataset_type,
                    dataset_id=dataset_id,
                    process_type=process_type,
                    interval_minutes=interval_minutes,
                    sla_min_quality=int(sla_min_quality) if sla_min_quality is not None else None,
                    is_active=True,
                    next_run_at=now + timedelta(minutes=interval_minutes),
                    last_run_at=None,
                    last_status=None,
                    last_message=None,
                    claimed_until=None,
                    claimed_by=None,
                    created_at=now,
                    updated_at=now,
                )
            )
        return {"result": {"job_id": job_id, "message": "Workflow job created"}}

    if tool == "list_workflow_jobs":
        if AUTH_REQUIRED and not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        include_all = bool(args.get("include_all", False)) and user is not None and user.get("role") == "admin"
        with engine.begin() as conn:
            if include_all:
                rows = conn.execute(
                    text("SELECT * FROM workflow_jobs ORDER BY id DESC LIMIT :limit"),
                    {"limit": clamp_limit(args.get("limit", 100), 100, MAX_LIST_LIMIT)},
                ).mappings().all()
            elif user_id is None:
                rows = conn.execute(
                    text("SELECT * FROM workflow_jobs WHERE owner_user_id IS NULL ORDER BY id DESC LIMIT :limit"),
                    {"limit": clamp_limit(args.get("limit", 100), 100, MAX_LIST_LIMIT)},
                ).mappings().all()
            else:
                rows = conn.execute(
                    text("SELECT * FROM workflow_jobs WHERE owner_user_id = :uid ORDER BY id DESC LIMIT :limit"),
                    {"uid": user_id, "limit": clamp_limit(args.get("limit", 100), 100, MAX_LIST_LIMIT)},
                ).mappings().all()
        jobs = []
        for row in rows:
            item = dict(row)
            for dt_key in ["next_run_at", "last_run_at", "claimed_until", "created_at", "updated_at"]:
                item[dt_key] = item[dt_key].isoformat() if item.get(dt_key) else None
            jobs.append(to_jsonable(item))
        return {"result": jobs}

    if tool == "toggle_workflow_job":
        enforce_authenticated_write(user)
        job_id = str(args.get("job_id", "")).strip()
        is_active = bool(args.get("is_active", True))
        if not job_id:
            raise HTTPException(status_code=400, detail="job_id is required")
        with engine.begin() as conn:
            row = conn.execute(text("SELECT owner_user_id FROM workflow_jobs WHERE job_id = :job_id LIMIT 1"), {"job_id": job_id}).mappings().first()
            if not row:
                raise HTTPException(status_code=404, detail="Workflow job not found")
            owner_uid = row.get("owner_user_id")
            if not (user and user.get("role") == "admin") and owner_uid != user_id:
                raise HTTPException(status_code=403, detail="Access denied for this workflow job")
            conn.execute(
                text("UPDATE workflow_jobs SET is_active = :is_active, updated_at = :updated_at WHERE job_id = :job_id"),
                {"is_active": is_active, "updated_at": utcnow(), "job_id": job_id},
            )
        return {"result": {"job_id": job_id, "is_active": is_active}}

    if tool == "run_due_workflow_jobs":
        enforce_authenticated_write(user)
        include_all = bool(args.get("include_all", False)) and user is not None and user.get("role") == "admin"
        job_limit = int(args.get("limit", 20) or 20)
        row_limit = int(args.get("row_limit", 50) or 50)
        res = await execute_due_workflow_jobs(include_all=include_all, owner_user_id=None if include_all else user_id, job_limit=job_limit, row_limit=row_limit)
        return {"result": res}

    if tool == "create_ticket_from_run":
        enforce_authenticated_write(user)
        run_id = str(args.get("run_id", "")).strip()
        if not run_id:
            raise HTTPException(status_code=400, detail="run_id is required")
        with engine.begin() as conn:
            row = conn.execute(
                text(
                    """
                    SELECT run_id, dataset_id, dataset_type, provider, process_type, status, created_at, result, owner_user_id
                    FROM workflow_runs
                    WHERE run_id = :run_id
                    LIMIT 1
                    """
                ),
                {"run_id": run_id},
            ).mappings().first()
        if not row:
            raise HTTPException(status_code=404, detail="Workflow run not found")
        owner_uid = row.get("owner_user_id")
        if not (user and user.get("role") == "admin") and owner_uid != user_id:
            raise HTTPException(status_code=403, detail="Access denied for this workflow run")
        result = to_jsonable(row.get("result")) or {}
        payload = {
            "system": str(args.get("system", "generic")),
            "summary": f"IDQE issue: {row.get('dataset_type')} / {row.get('process_type')} / {row.get('run_id')}",
            "description": {
                "dataset_id": row.get("dataset_id"),
                "dataset_type": row.get("dataset_type"),
                "provider": row.get("provider"),
                "process_type": row.get("process_type"),
                "status": row.get("status"),
                "quality_index": result.get("quality_index"),
                "failed_checks": result.get("failed_checks"),
                "violations": (result.get("violations") or [])[:20],
            },
            "project_key": args.get("project_key"),
        }
        delivered = False
        if TICKET_WEBHOOK_URL:
            try:
                async with httpx.AsyncClient(timeout=8) as client:
                    resp = await client.post(TICKET_WEBHOOK_URL, json=payload)
                    delivered = 200 <= resp.status_code < 300
            except Exception:
                delivered = False
        return {"result": {"delivered": delivered, "ticket_webhook_configured": bool(TICKET_WEBHOOK_URL), "payload": payload}}

    if tool == "admin_set_team_policy":
        enforce_authenticated_write(user)
        require_admin(user)
        team = str(args.get("team", "")).strip()
        if not team:
            raise HTTPException(status_code=400, detail="team is required")
        dataset_types = args.get("allowed_dataset_types") or []
        server_urls = args.get("allowed_server_urls") or []
        if not isinstance(dataset_types, list) or not isinstance(server_urls, list):
            raise HTTPException(status_code=400, detail="allowed_dataset_types and allowed_server_urls must be arrays")
        create_or_update_team_policy(
            team,
            [str(x) for x in dataset_types if str(x).strip()],
            [str(x).rstrip("/") for x in server_urls if str(x).strip()],
            bool(args.get("scoped_admin", False)),
        )
        if user:
            audit_admin_action(
                int(user["id"]),
                "admin_set_team_policy",
                "team_policy",
                team,
                f"Updated team policy for {team}",
                {
                    "allowed_dataset_types": [str(x) for x in dataset_types if str(x).strip()],
                    "allowed_server_urls": [str(x).rstrip("/") for x in server_urls if str(x).strip()],
                    "scoped_admin": bool(args.get("scoped_admin", False)),
                },
            )
        return {"result": {"message": "Team policy saved", "team": team}}

    if tool == "admin_list_team_policies":
        require_admin(user)
        return {"result": list_team_policies()}

    if tool == "admin_list_audit_logs":
        require_admin(user)
        return {"result": list_admin_audit_logs(limit=clamp_limit(args.get("limit", 200), 200, MAX_LIST_LIMIT))}

    if tool == "admin_access_review":
        require_admin(user)
        return {
            "result": build_admin_access_review_report(
                stale_days=clamp_limit(args.get("stale_days", 90), 90, 3650),
                audit_limit=clamp_limit(args.get("audit_limit", 200), 200, MAX_LIST_LIMIT),
            )
        }

    if tool == "admin_rule_governance":
        require_admin(user)
        return {"result": build_admin_rule_governance_report(days=clamp_limit(args.get("days", 30), 30, 3650))}

    if tool == "admin_compliance_report":
        require_admin(user)
        return {"result": build_admin_compliance_report(days=clamp_limit(args.get("days", 30), 30, 3650))}

    if tool == "get_integration_status":
        if AUTH_REQUIRED and not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        return {
            "result": {
                "event_webhook_configured": bool(EVENT_WEBHOOK_URL),
                "ticket_webhook_configured": bool(TICKET_WEBHOOK_URL),
                "alert_quality_threshold": ALERT_QUALITY_THRESHOLD,
            }
        }

    if tool == "send_test_event":
        enforce_authenticated_write(user)
        event_type = str(args.get("event_type", "idqe_test_event")).strip() or "idqe_test_event"
        payload = args.get("payload") if isinstance(args.get("payload"), dict) else {"message": "IDQE test event"}
        await send_event(event_type, payload)
        return {"result": {"event_type": event_type, "sent": bool(EVENT_WEBHOOK_URL), "payload": to_jsonable(payload)}}

    raise HTTPException(status_code=404, detail=f"Unknown tool: {tool}")
