"""CYBERGUARD API entrypoint.

Refactored with:
- Async SQLAlchemy database engine and session management.
- Multi-tenancy: Single-User personal workspaces & Organization-based RBAC.
- Unified error handlers for database and validation errors.
- Async endpoints across all modules.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import (
    routes_actions,
    routes_alerts,
    routes_analysis,
    routes_assistant,
    routes_audit,
    routes_auth,
    routes_dashboard,
    routes_connectors,
    routes_dlq,
    routes_gmail_webhook,
    routes_enforcement,
    routes_db,
    routes_security_history,
    routes_settings,
    routes_gmail,
    routes_events,
    routes_health,
    routes_notifications,
    routes_incidents,
    routes_integrations,
    routes_public_gateway,
    routes_orgs,
    routes_policies,
    routes_response,
)
from app.ai.key_rotator import get_key_rotator
from app.core.config import get_settings
from app.core.errors import register_error_handlers
from app.core.logging_config import configure_structured_logging
from app.core.request_context import ClientContextMiddleware
from app.db.session import init_db

logger = logging.getLogger("cyberguard")
configure_structured_logging()

settings = get_settings()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Application lifespan: initialize database schema, seed data, and start background workers."""
    import asyncio
    logger.info("Starting CYBERGUARD backend...")
    await init_db()
    rotator = get_key_rotator()
    rotator.log_startup_summary()
    rotator.start_background_task()
    from app.services.scheduler import start_scheduler

    start_scheduler()

    # Start embedded ARQ background worker so email ingestion and threat analysis jobs process automatically
    embedded_worker = None
    worker_task = None
    try:
        from arq.worker import create_worker
        from app.workers.email_worker import WorkerSettings as EmailWorkerSettings

        embedded_worker = create_worker(EmailWorkerSettings)
        worker_task = asyncio.create_task(embedded_worker.async_run())
        logger.info("Embedded ARQ background worker started for email ingestion & threat analysis.")
    except Exception as exc:
        logger.warning("Could not start embedded ARQ worker (external worker can still be used): %s", exc)

    yield
    logger.info("Shutting down CYBERGUARD backend...")
    rotator.stop_background_task()
    from app.services.scheduler import stop_scheduler

    stop_scheduler()

    if embedded_worker:
        try:
            await embedded_worker.close()
        except Exception:
            pass
    if worker_task:
        worker_task.cancel()


app = FastAPI(
    title=settings.APP_TITLE,
    version=settings.APP_VERSION,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(ClientContextMiddleware)

# Health, readiness, and metrics probes (root & API prefix)
app.include_router(routes_health.router)

# Register API routers under /api/v1
app.include_router(routes_health.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_notifications.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_auth.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_public_gateway.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_orgs.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_db.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_events.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_analysis.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_alerts.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_actions.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_policies.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_incidents.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_integrations.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_response.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_dashboard.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_audit.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_assistant.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_connectors.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_settings.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_security_history.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_security_history.review_router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_enforcement.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_gmail_webhook.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_gmail.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_gmail.router)
app.include_router(routes_connectors.router)
app.include_router(routes_dlq.router, prefix=settings.API_V1_PREFIX)

# Register unified exception handlers
register_error_handlers(app)
