from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

import httpx
import yaml
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import JSON, Boolean, Column, DateTime, Integer, MetaData, String, Table, create_engine, text

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+psycopg2://dq:dq@postgres:5432/dq")
DQ_ENGINE_URL = os.getenv("DQ_ENGINE_URL", "http://dq-engine:8001")
RULES_CONFIG_PATH = os.getenv("RULES_CONFIG_PATH", "/app/config/rules.yaml")
LLM_CONFIG_PATH = os.getenv("LLM_CONFIG_PATH", "/app/config/llm.yaml")
MCP_SERVER_NAME = os.getenv("MCP_SERVER_NAME", "dq-workflow-mcp")

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
    Column("is_active", Boolean, nullable=False),
    Column("created_at", DateTime, nullable=False),
    Column("last_login_at", DateTime, nullable=True),
)
user_settings = Table(
    "user_settings",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("user_id", Integer, nullable=False, unique=True),
    Column("rules_config", JSON, nullable=True),
    Column("mcp_servers", JSON, nullable=True),
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


def make_token(user_id: int, role: str) -> str:
    now = utcnow()
    payload = {
        "uid": user_id,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TOKEN_TTL_MINUTES)).timestamp()),
    }
    payload_raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    body = b64url(payload_raw)
    sig = b64url(hmac.new(AUTH_SECRET.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).digest())
    return f"{body}.{sig}"


def parse_token(token: str) -> dict[str, Any] | None:
    try:
        body, sig = token.split(".", 1)
        expected = b64url(hmac.new(AUTH_SECRET.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(b64url_decode(body).decode("utf-8"))
        if int(payload.get("exp", 0)) < int(utcnow().timestamp()):
            return None
        return payload
    except Exception:
        return None


def get_current_user(request: Request, allow_anonymous: bool = False) -> dict[str, Any] | None:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        if allow_anonymous:
            return None
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = auth[7:]
    payload = parse_token(token)
    if not payload:
        if allow_anonymous:
            return None
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT id, email, name, role, is_active FROM users WHERE id = :id LIMIT 1"),
            {"id": int(payload.get("uid", 0))},
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
            text("SELECT rules_config, mcp_servers FROM user_settings WHERE user_id = :uid LIMIT 1"),
            {"uid": user_id},
        ).mappings().first()
    if not row:
        return {"rules_config": None, "mcp_servers": []}
    return {
        "rules_config": to_jsonable(row.get("rules_config")),
        "mcp_servers": to_jsonable(row.get("mcp_servers")) or [],
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
                    mcp_servers=[],
                    created_at=now,
                    updated_at=now,
                )
            )


def upsert_user_mcp_servers(user_id: int, servers: list[dict[str, Any]]) -> None:
    now = utcnow()
    servers_json = json.dumps(to_jsonable(servers))
    with engine.begin() as conn:
        existing = conn.execute(text("SELECT id FROM user_settings WHERE user_id = :uid LIMIT 1"), {"uid": user_id}).mappings().first()
        if existing:
            conn.execute(
                text("UPDATE user_settings SET mcp_servers = :servers, updated_at = :upd WHERE user_id = :uid"),
                {"servers": servers_json, "upd": now, "uid": user_id},
            )
        else:
            conn.execute(
                user_settings.insert().values(
                    user_id=user_id,
                    rules_config=None,
                    mcp_servers=to_jsonable(servers),
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


def get_user_mcp_servers(user_id: int | None) -> list[dict[str, Any]]:
    if user_id is None:
        return []
    settings = get_user_settings(user_id)
    raw = settings.get("mcp_servers", [])
    if not isinstance(raw, list):
        return []
    return sanitize_mcp_server_entries(raw, require_active_flag=False)


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


def list_available_mcp_servers(user_id: int | None) -> list[dict[str, Any]]:
    user_servers = get_user_mcp_servers(user_id)
    shared_servers = get_shared_mcp_servers(include_inactive=False)
    seen: set[str] = set()
    merged: list[dict[str, Any]] = []

    for item in user_servers:
        url = item.get("base_url")
        if not isinstance(url, str) or not url or url in seen:
            continue
        seen.add(url)
        merged.append({"name": item.get("name", "my-server"), "base_url": url, "source": "user", "is_active": True})

    for item in shared_servers:
        url = str(item.get("base_url") or "")
        if not url or url in seen:
            continue
        seen.add(url)
        merged.append(
            {
                "name": item.get("name", "shared-server"),
                "base_url": url,
                "source": "shared",
                "is_active": bool(item.get("is_active", True)),
            }
        )
    return merged


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


# ---------- data/model ----------
def query_dataset(dataset_type: str, limit: int = 50) -> list[dict[str, Any]]:
    table_map = {
        "customer_profile": "customer_profile",
        "credit_facility": "credit_facility",
    }
    table = table_map.get(dataset_type)
    if not table:
        raise HTTPException(status_code=400, detail=f"Unsupported dataset_type: {dataset_type}")
    stmt = text(f"SELECT * FROM {table} LIMIT :limit")
    with engine.begin() as conn:
        rows = conn.execute(stmt, {"limit": limit}).mappings().all()
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


def approve_suggestion(suggestion_id: str, user_id: int | None) -> dict[str, Any]:
    suggestion = get_pending_suggestion(suggestion_id)
    if not suggestion:
        raise HTTPException(status_code=404, detail="Suggestion not found or expired")
    if suggestion.get("owner_user_id") != user_id:
        raise HTTPException(status_code=403, detail="Suggestion belongs to another user")

    dataset_type = suggestion["dataset_type"]
    cfg = load_rules_config_for_user(user_id)
    cfg["assessment_rules"].setdefault(dataset_type, [])
    cfg["correction_rules"].setdefault(dataset_type, [])

    if suggestion.get("assessment_rule"):
        cfg["assessment_rules"][dataset_type].append(suggestion["assessment_rule"])
    if suggestion.get("correction_rule"):
        cfg["correction_rules"][dataset_type].append(suggestion["correction_rule"])

    validate_rules_config(cfg)
    if user_id is None:
        save_yaml(RULES_CONFIG_PATH, cfg)
    else:
        upsert_user_rules_config(user_id, cfg)

    mark_pending_suggestion_decided(suggestion_id, "approved")
    record_suggestion_decision(suggestion_id, dataset_type, "approved", suggestion, user_id)
    return {"message": "Suggestion approved and saved", "dataset_type": dataset_type}


def decline_suggestion(suggestion_id: str, user_id: int | None) -> dict[str, Any]:
    suggestion = get_pending_suggestion(suggestion_id)
    if not suggestion:
        raise HTTPException(status_code=404, detail="Suggestion not found or expired")
    if suggestion.get("owner_user_id") != user_id:
        raise HTTPException(status_code=403, detail="Suggestion belongs to another user")
    mark_pending_suggestion_decided(suggestion_id, "declined")
    record_suggestion_decision(suggestion_id, str(suggestion.get("dataset_type", "")), "declined", suggestion, user_id)
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


# ---------- lifecycle ----------
def ensure_tables() -> None:
    metadata.create_all(engine)


def ensure_schema_evolution() -> None:
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE workflow_runs ADD COLUMN IF NOT EXISTS owner_user_id INTEGER"))
        conn.execute(text("ALTER TABLE suggestion_decisions ADD COLUMN IF NOT EXISTS owner_user_id INTEGER"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_workflow_runs_owner_created ON workflow_runs(owner_user_id, created_at DESC)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_suggestion_decisions_owner_created ON suggestion_decisions(owner_user_id, created_at DESC)"))
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


@app.on_event("startup")
def startup() -> None:
    ensure_security_defaults()
    ensure_tables()
    ensure_schema_evolution()
    cleanup_suggestion_store()
    ensure_demo_admin()
    ensure_demo_shared_servers()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


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
            {"name": "auth_me", "description": "Get current user profile"},
            {"name": "admin_list_users", "description": "Admin: list users"},
            {"name": "admin_update_user", "description": "Admin: update role/active state"},
            {"name": "get_user_mcp_servers", "description": "Get current user's saved MCP servers"},
            {"name": "save_user_mcp_servers", "description": "Save current user's MCP servers"},
            {"name": "list_available_mcp_servers", "description": "List available MCP servers (personal + shared active)"},
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
            {"name": "get_workflow_runs", "description": "Return workflow execution history"},
            {"name": "get_workflow_run_detail", "description": "Return one workflow run including full result payload"},
            {"name": "get_rules_yaml", "description": "Get DQ rule configuration as YAML text"},
            {"name": "save_rules_yaml", "description": "Save DQ rule configuration from YAML text"},
            {"name": "get_rules_config", "description": "Get DQ rule configuration as structured object"},
            {"name": "save_rules_config", "description": "Save DQ rule configuration as structured object"},
            {"name": "get_llm_yaml", "description": "Get LLM configuration as YAML text"},
            {"name": "save_llm_yaml", "description": "Save LLM configuration from YAML text"},
            {"name": "suggest_rules", "description": "Generate LLM-based new DQ rule suggestions"},
            {"name": "approve_suggestion", "description": "Approve and store suggested rule"},
            {"name": "decline_suggestion", "description": "Decline suggested rule"},
            {"name": "get_suggestion_decisions", "description": "List accepted and declined suggested rules"},
        ]
    }


def get_request_user_for_tool(request: Request, tool: str) -> dict[str, Any] | None:
    public_tools = {"auth_register", "auth_login", "auth_me"}
    if tool in public_tools:
        return get_current_user(request, allow_anonymous=True)
    if not AUTH_REQUIRED:
        return get_current_user(request, allow_anonymous=True)
    return get_current_user(request)


@app.post("/mcp/call")
async def call_tool(call: MCPCall, request: Request) -> dict[str, Any]:
    tool = call.tool
    args = call.arguments
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
            raise HTTPException(status_code=429, detail="Too many failed login attempts. Try again later.")
        with engine.begin() as conn:
            row = conn.execute(
                text("SELECT id, email, name, role, is_active, password_hash FROM users WHERE email = :email LIMIT 1"),
                {"email": email},
            ).mappings().first()
            if not row or not verify_password(password, str(row.get("password_hash", ""))):
                login_record_failure(key)
                raise HTTPException(status_code=401, detail="Invalid credentials")
            if not row.get("is_active"):
                login_record_failure(key)
                raise HTTPException(status_code=403, detail="User is inactive")
            conn.execute(text("UPDATE users SET last_login_at = :ts WHERE id = :id"), {"ts": utcnow(), "id": row["id"]})
        login_record_success(key)
        token = make_token(int(row["id"]), str(row["role"]))
        return {
            "result": {
                "access_token": token,
                "token_type": "bearer",
                "user": {
                    "id": row["id"],
                    "email": row["email"],
                    "name": row["name"],
                    "role": row["role"],
                },
            }
        }

    if tool == "auth_me":
        if not user:
            return {"result": {"authenticated": False}}
        return {"result": {"authenticated": True, "user": user}}

    # below requires authenticated user in required mode
    if AUTH_REQUIRED and not user:
        raise HTTPException(status_code=401, detail="Authentication required")

    if tool == "admin_list_users":
        require_admin(user)
        with engine.begin() as conn:
            rows = conn.execute(
                text("SELECT id, email, name, role, is_active, created_at, last_login_at FROM users ORDER BY id ASC")
            ).mappings().all()
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
        target_user_id = int(args.get("user_id", 0))
        role = args.get("role")
        is_active = args.get("is_active")
        if target_user_id <= 0:
            raise HTTPException(status_code=400, detail="user_id is required")
        updates = []
        params: dict[str, Any] = {"id": target_user_id}
        if role is not None:
            if role not in {"admin", "user"}:
                raise HTTPException(status_code=400, detail="role must be admin or user")
            updates.append("role = :role")
            params["role"] = role
        if is_active is not None:
            updates.append("is_active = :is_active")
            params["is_active"] = bool(is_active)
        if not updates:
            raise HTTPException(status_code=400, detail="No update fields provided")
        with engine.begin() as conn:
            conn.execute(text(f"UPDATE users SET {', '.join(updates)} WHERE id = :id"), params)
        return {"result": {"message": "User updated"}}

    if tool == "get_user_mcp_servers":
        if user_id is None:
            raise HTTPException(status_code=401, detail="Authentication required")
        return {"result": {"servers": get_user_mcp_servers(user_id)}}

    if tool == "save_user_mcp_servers":
        enforce_authenticated_write(user)
        if user_id is None:
            raise HTTPException(status_code=401, detail="Authentication required")
        servers = args.get("servers", [])
        if not isinstance(servers, list):
            raise HTTPException(status_code=400, detail="servers must be a list")
        upsert_user_mcp_servers(user_id, sanitize_mcp_server_entries(servers, require_active_flag=False))
        return {"result": {"message": "MCP servers saved"}}

    if tool == "list_available_mcp_servers":
        if user_id is None:
            raise HTTPException(status_code=401, detail="Authentication required")
        return {"result": {"servers": list_available_mcp_servers(user_id)}}

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
        return {"result": {"message": "Shared MCP servers saved"}}

    if tool == "list_data_sources":
        cfg = load_rules_config_for_user(user_id)
        return {"result": to_jsonable(cfg["data_sources"])}

    if tool == "show_data_model":
        return {"result": get_data_model()}

    if tool == "show_dataset":
        dataset_type = args.get("dataset_type", "customer_profile")
        limit = int(args.get("limit", 50))
        return {"result": query_dataset(dataset_type, limit)}

    if tool == "show_foreign_key_relations":
        return {"result": get_foreign_key_relations()}

    if tool == "preview_dataset":
        dataset_type = args.get("dataset_type", "customer_profile")
        limit = int(args.get("limit", 20))
        return {"result": query_dataset(dataset_type, limit)}

    if tool == "run_dq_assessment":
        if AUTH_REQUIRED and not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        dataset_type = args.get("dataset_type", "customer_profile")
        dataset_id = args.get("dataset_id", f"{dataset_type}-{utcnow().strftime('%Y%m%d%H%M%S')}")
        provider = args.get("provider", "BANK_A")
        rows = query_dataset(dataset_type, int(args.get("limit", 50)))

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

        result["suggestions"] = generate_rule_suggestions(dataset_type, rows, user_id)
        run_id = insert_run(dataset_id, dataset_type, provider, "assessment", "completed", result, user_id)
        return {"run_id": run_id, "result": result}

    if tool == "run_correction":
        if AUTH_REQUIRED and not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        dataset_type = args.get("dataset_type", "customer_profile")
        dataset_id = args.get("dataset_id", f"{dataset_type}-{utcnow().strftime('%Y%m%d%H%M%S')}")
        provider = args.get("provider", "BANK_A")
        rows = query_dataset(dataset_type, int(args.get("limit", 50)))

        payload = {
            "dataset_id": dataset_id,
            "records": rows,
            "corrections": get_correction_rules(dataset_type, user_id),
        }

        async with httpx.AsyncClient(timeout=90) as client:
            response = await client.post(f"{DQ_ENGINE_URL}/correct", json=payload)
            response.raise_for_status()
            result = response.json()

        run_id = insert_run(dataset_id, dataset_type, provider, "correction", "completed", result, user_id)
        return {"run_id": run_id, "result": result}

    if tool == "simulate_rules":
        if AUTH_REQUIRED and not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        dataset_type = args.get("dataset_type", "customer_profile")
        dataset_id = args.get("dataset_id", f"{dataset_type}-simulation")
        provider = args.get("provider", "BANK_A")
        rows = query_dataset(dataset_type, int(args.get("limit", 50)))

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
                    {"limit": int(args.get("limit", 25))},
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
                        {"limit": int(args.get("limit", 25))},
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
                        {"limit": int(args.get("limit", 25)), "uid": user_id},
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
        return {"result": {"message": "Rules config saved successfully"}}

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
        rows = query_dataset(dataset_type, int(args.get("limit", 50)))
        suggestions = generate_rule_suggestions(dataset_type, rows, user_id)
        return {"result": {"suggestions": suggestions, "llm_enabled": llm_enabled()}}

    if tool == "approve_suggestion":
        enforce_authenticated_write(user)
        if AUTH_REQUIRED and not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        suggestion_id = args.get("suggestion_id", "")
        if not suggestion_id:
            raise HTTPException(status_code=400, detail="suggestion_id is required")
        return {"result": approve_suggestion(suggestion_id, user_id)}

    if tool == "decline_suggestion":
        enforce_authenticated_write(user)
        if AUTH_REQUIRED and not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        suggestion_id = args.get("suggestion_id", "")
        if not suggestion_id:
            raise HTTPException(status_code=400, detail="suggestion_id is required")
        return {"result": decline_suggestion(suggestion_id, user_id)}

    if tool == "get_suggestion_decisions":
        if AUTH_REQUIRED and not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        include_all = bool(args.get("include_all", False)) and user is not None and user.get("role") == "admin"
        return {"result": get_suggestion_decisions(limit=int(args.get("limit", 100)), user_id=user_id, include_all=include_all)}

    raise HTTPException(status_code=404, detail=f"Unknown tool: {tool}")
