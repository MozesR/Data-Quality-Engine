"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-02-09
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("email", sa.String(length=320), nullable=False, unique=True),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("password_hash", sa.String(length=512), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("team", sa.String(length=64), nullable=False, server_default="default"),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_login_at", sa.DateTime(), nullable=True),
    )

    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("token_id", sa.String(length=64), nullable=False, unique=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(length=128), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("idx_refresh_tokens_user_exp", "refresh_tokens", ["user_id", "expires_at"])
    op.create_index("idx_refresh_tokens_revoked", "refresh_tokens", ["revoked_at"])

    op.create_table(
        "revoked_tokens",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("jti", sa.String(length=64), nullable=False, unique=True),
        sa.Column("token_type", sa.String(length=16), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("idx_revoked_tokens_exp", "revoked_tokens", ["expires_at"])

    op.create_table(
        "user_settings",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.Integer(), nullable=False, unique=True),
        sa.Column("rules_config", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )

    op.create_table(
        "shared_mcp_servers",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("base_url", sa.String(length=512), nullable=False, unique=True),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )

    op.create_table(
        "workflow_runs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("run_id", sa.String(length=64), nullable=False, unique=True),
        sa.Column("dataset_id", sa.String(length=128), nullable=False),
        sa.Column("dataset_type", sa.String(length=64), nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("process_type", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.Column("owner_user_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("idx_workflow_runs_owner_created", "workflow_runs", ["owner_user_id", "created_at"])

    op.create_table(
        "suggestion_decisions",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("suggestion_id", sa.String(length=64), nullable=False),
        sa.Column("dataset_type", sa.String(length=64), nullable=False),
        sa.Column("decision", sa.String(length=32), nullable=False),
        sa.Column("suggestion", sa.JSON(), nullable=False),
        sa.Column("owner_user_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("idx_suggestion_decisions_owner_created", "suggestion_decisions", ["owner_user_id", "created_at"])

    op.create_table(
        "pending_suggestions_store",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("suggestion_id", sa.String(length=64), nullable=False, unique=True),
        sa.Column("dataset_type", sa.String(length=64), nullable=False),
        sa.Column("suggestion", sa.JSON(), nullable=False),
        sa.Column("owner_user_id", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index(
        "idx_pending_suggestions_status_owner_created",
        "pending_suggestions_store",
        ["status", "owner_user_id", "created_at"],
    )

    op.create_table(
        "rule_versions",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("version_id", sa.String(length=64), nullable=False, unique=True),
        sa.Column("owner_user_id", sa.Integer(), nullable=True),
        sa.Column("note", sa.String(length=256), nullable=False),
        sa.Column("rules_config", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("idx_rule_versions_owner_created", "rule_versions", ["owner_user_id", "created_at"])

    op.create_table(
        "workflow_jobs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("job_id", sa.String(length=64), nullable=False, unique=True),
        sa.Column("owner_user_id", sa.Integer(), nullable=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("dataset_type", sa.String(length=64), nullable=False),
        sa.Column("dataset_id", sa.String(length=128), nullable=False),
        sa.Column("process_type", sa.String(length=32), nullable=False),
        sa.Column("interval_minutes", sa.Integer(), nullable=False),
        sa.Column("sla_min_quality", sa.Integer(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("next_run_at", sa.DateTime(), nullable=False),
        sa.Column("last_run_at", sa.DateTime(), nullable=True),
        sa.Column("last_status", sa.String(length=32), nullable=True),
        sa.Column("last_message", sa.String(length=512), nullable=True),
        sa.Column("claimed_until", sa.DateTime(), nullable=True),
        sa.Column("claimed_by", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("idx_jobs_owner_next", "workflow_jobs", ["owner_user_id", "next_run_at"])
    op.create_index("idx_jobs_claimed_until", "workflow_jobs", ["claimed_until"])

    op.create_table(
        "drift_baselines",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("baseline_id", sa.String(length=64), nullable=False, unique=True),
        sa.Column("owner_user_id", sa.Integer(), nullable=True),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("dataset_type", sa.String(length=64), nullable=False),
        sa.Column("profile", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("idx_drift_owner_dataset_created", "drift_baselines", ["owner_user_id", "dataset_type", "created_at"])

    op.create_table(
        "alerts_store",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("alert_id", sa.String(length=64), nullable=False, unique=True),
        sa.Column("owner_user_id", sa.Integer(), nullable=True),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("message", sa.String(length=512), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("idx_alerts_owner_created", "alerts_store", ["owner_user_id", "created_at"])

    op.create_table(
        "suggestion_approvals",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("suggestion_id", sa.String(length=64), nullable=False),
        sa.Column("approver_user_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("suggestion_id", "approver_user_id", name="ux_suggestion_approvals_sid_uid"),
    )

    op.create_table(
        "team_policies",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("team", sa.String(length=64), nullable=False, unique=True),
        sa.Column("allowed_dataset_types", sa.JSON(), nullable=True),
        sa.Column("allowed_server_urls", sa.JSON(), nullable=True),
        sa.Column("scoped_admin", sa.Boolean(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )

    op.create_table(
        "admin_audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("event_id", sa.String(length=64), nullable=False, unique=True),
        sa.Column("admin_user_id", sa.Integer(), nullable=False),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("target_type", sa.String(length=64), nullable=False),
        sa.Column("target_id", sa.String(length=128), nullable=True),
        sa.Column("summary", sa.String(length=512), nullable=False),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("idx_admin_audit_created", "admin_audit_logs", ["created_at"])


def downgrade() -> None:
    op.drop_index("idx_admin_audit_created", table_name="admin_audit_logs")
    op.drop_table("admin_audit_logs")
    op.drop_table("team_policies")
    op.drop_table("suggestion_approvals")
    op.drop_index("idx_alerts_owner_created", table_name="alerts_store")
    op.drop_table("alerts_store")
    op.drop_index("idx_drift_owner_dataset_created", table_name="drift_baselines")
    op.drop_table("drift_baselines")
    op.drop_index("idx_jobs_claimed_until", table_name="workflow_jobs")
    op.drop_index("idx_jobs_owner_next", table_name="workflow_jobs")
    op.drop_table("workflow_jobs")
    op.drop_index("idx_rule_versions_owner_created", table_name="rule_versions")
    op.drop_table("rule_versions")
    op.drop_index("idx_pending_suggestions_status_owner_created", table_name="pending_suggestions_store")
    op.drop_table("pending_suggestions_store")
    op.drop_index("idx_suggestion_decisions_owner_created", table_name="suggestion_decisions")
    op.drop_table("suggestion_decisions")
    op.drop_index("idx_workflow_runs_owner_created", table_name="workflow_runs")
    op.drop_table("workflow_runs")
    op.drop_table("shared_mcp_servers")
    op.drop_table("user_settings")
    op.drop_index("idx_revoked_tokens_exp", table_name="revoked_tokens")
    op.drop_table("revoked_tokens")
    op.drop_index("idx_refresh_tokens_revoked", table_name="refresh_tokens")
    op.drop_index("idx_refresh_tokens_user_exp", table_name="refresh_tokens")
    op.drop_table("refresh_tokens")
    op.drop_table("users")

