from __future__ import annotations

import asyncio
import os

from app.main import (
    AUTH_MODE,
    cleanup_auth_tokens,
    cleanup_suggestion_store,
    configure_logging,
    ensure_demo_admin,
    ensure_demo_shared_servers,
    ensure_schema_evolution,
    ensure_security_defaults,
    ensure_tables,
    execute_due_workflow_jobs,
    logger,
)


async def worker_loop() -> None:
    interval = int(os.getenv("WORKER_INTERVAL_SECONDS", "30"))
    include_all = os.getenv("WORKER_INCLUDE_ALL", "true").lower() == "true"
    job_limit = int(os.getenv("WORKER_JOB_LIMIT", "20"))
    row_limit = int(os.getenv("WORKER_ROW_LIMIT", "50"))

    logger.info(
        "worker_started",
        extra={
            "mode": AUTH_MODE,
            "include_all": include_all,
            "interval_seconds": interval,
            "job_limit": job_limit,
            "row_limit": row_limit,
        },
    )

    while True:
        try:
            res = await execute_due_workflow_jobs(
                include_all=include_all,
                owner_user_id=None,
                job_limit=job_limit,
                row_limit=row_limit,
            )
            if (res or {}).get("count", 0):
                logger.info("worker_executed_jobs", extra=res)
        except Exception as exc:
            logger.error("worker_error", extra={"error": str(exc)})
        await asyncio.sleep(max(5, interval))


def main() -> None:
    configure_logging()
    ensure_security_defaults()
    ensure_tables()
    ensure_schema_evolution()
    cleanup_suggestion_store()
    cleanup_auth_tokens()
    # Demo helpers are harmless in production because they are guarded by mode.
    ensure_demo_admin()
    ensure_demo_shared_servers()
    asyncio.run(worker_loop())


if __name__ == "__main__":
    main()

