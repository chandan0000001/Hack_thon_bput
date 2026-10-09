"""Application settings loaded from environment variables / .env file."""

from functools import lru_cache
from typing import Self

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Environment-driven configuration for the CYBERGUARD backend."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    SUPABASE_URL: str
    SUPABASE_ANON_KEY: str
    SUPABASE_SERVICE_ROLE_KEY: str
    API_V1_PREFIX: str = "/api/v1"
    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:3000"
    # EXT-P1: browser-extension origins allowed to call the API from
    # extension pages (popup). Comma-separated; the Chromium dev ID is pinned
    # by browser-extension/build.mjs, the moz-extension UUID varies per
    # Firefox install (see browser-extension/README.md).
    EXT_CORS_ORIGINS: str = ""

    DATABASE_URL: str = ""
    # Service-role DSN used by Alembic migrations (bypasses RLS).
    # Falls back to DATABASE_URL when empty.
    MIGRATION_DATABASE_URL: str = ""

    # Password for the local NOBYPASSRLS app role (cyberguard_api). Single
    # source of truth for the startup bootstrap (which creates/syncs the
    # role) and the RLS verification harness — never hardcode it in test
    # files. Dev default matches the bootstrap-created role.
    APP_ROLE_PASSWORD: str = "cyberguard_api"

    # Strict Test Mode Configuration (Enabled by default)
    TEST_MODE: bool = True
    TEST_DATABASE_URL: str = ""
    TEST_MIGRATION_DATABASE_URL: str = ""
    TEST_REDIS_URL: str = ""
    TEST_ARQ_QUEUE_NAME: str = "cyberguard_email_test"

    @model_validator(mode="after")
    def _validate_and_apply_urls(self) -> Self:
        """Enforce strict database, Redis, and queue configuration with fail-fast validation."""
        # 1. Database URL Strict Enforcement
        if self.TEST_MODE:
            if not self.TEST_DATABASE_URL or not self.TEST_DATABASE_URL.strip():
                raise ValueError(
                    "CRITICAL CONFIGURATION ERROR: TEST_MODE=True is enabled, "
                    "but TEST_DATABASE_URL is missing or empty. SQLite fallback is disabled "
                    "because SQLite does not support PostgreSQL Row-Level Security (RLS). "
                    "Please define TEST_DATABASE_URL (e.g. postgresql+asyncpg://...) in your environment or .env."
                )
            self.DATABASE_URL = self.TEST_DATABASE_URL.strip()
            if self.TEST_MIGRATION_DATABASE_URL and self.TEST_MIGRATION_DATABASE_URL.strip():
                self.MIGRATION_DATABASE_URL = self.TEST_MIGRATION_DATABASE_URL.strip()
            else:
                self.MIGRATION_DATABASE_URL = self.DATABASE_URL
        else:
            if not self.DATABASE_URL or not self.DATABASE_URL.strip():
                raise ValueError(
                    "CRITICAL CONFIGURATION ERROR: TEST_MODE=False (Main Database Mode), "
                    "but DATABASE_URL is missing or empty. SQLite fallback is disabled "
                    "to enforce PostgreSQL Row-Level Security (RLS). "
                    "Please define DATABASE_URL in your environment or .env."
                )
            self.DATABASE_URL = self.DATABASE_URL.strip()
            if self.MIGRATION_DATABASE_URL and self.MIGRATION_DATABASE_URL.strip():
                self.MIGRATION_DATABASE_URL = self.MIGRATION_DATABASE_URL.strip()
            else:
                self.MIGRATION_DATABASE_URL = self.DATABASE_URL

        # 2. Redis URL Strict Enforcement
        if self.TEST_MODE:
            if not self.TEST_REDIS_URL or not self.TEST_REDIS_URL.strip():
                raise ValueError(
                    "CRITICAL CONFIGURATION ERROR: TEST_MODE=True is enabled, "
                    "but TEST_REDIS_URL is missing or empty. "
                    "Please define TEST_REDIS_URL (e.g. redis://localhost:6379/1) in your environment or .env."
                )
            self.REDIS_URL = self.TEST_REDIS_URL.strip()
            if self.TEST_ARQ_QUEUE_NAME and self.TEST_ARQ_QUEUE_NAME.strip():
                self.ARQ_QUEUE_NAME = self.TEST_ARQ_QUEUE_NAME.strip()
        else:
            if not self.REDIS_URL or not self.REDIS_URL.strip():
                raise ValueError(
                    "CRITICAL CONFIGURATION ERROR: TEST_MODE=False (Main Redis Mode), "
                    "but REDIS_URL is missing or empty. "
                    "Please define REDIS_URL (e.g. redis://localhost:6379/0) in your environment or .env."
                )
            self.REDIS_URL = self.REDIS_URL.strip()

        # 3. Worker & Queue Parameter Validation
        if self.ARQ_MAX_JOBS <= 0:
            raise ValueError(f"ARQ_MAX_JOBS must be greater than 0, got {self.ARQ_MAX_JOBS}")
        if self.ARQ_JOB_TIMEOUT <= 0:
            raise ValueError(f"ARQ_JOB_TIMEOUT must be greater than 0, got {self.ARQ_JOB_TIMEOUT}")
        if self.WORKER_CONCURRENCY <= 0:
            raise ValueError(f"WORKER_CONCURRENCY must be greater than 0, got {self.WORKER_CONCURRENCY}")

        return self

    # Organization accounts are frozen ("coming soon") until the Orgs Phase.
    ORG_ENABLED: bool = False

    # Real-time pipeline infrastructure (RT-1 / RT-3)
    REDIS_URL: str = ""
    ARQ_QUEUE_NAME: str = "cyberguard_email"
    ARQ_MAX_JOBS: int = 10
    ARQ_JOB_TIMEOUT: int = 300
    WORKER_CONCURRENCY: int = 4
    GOOGLE_PUBSUB_VERIFICATION_TOKEN: str = ""  # set via env; webhook validates this
    GMAIL_PUBSUB_TOPIC: str = "projects/<your-project>/topics/cyberguard-gmail"
    GMAIL_PUBSUB_AUDIENCE: str | None = None  # optional JWT audience

    # Retry and backoff tuning (RT-10)
    RETRY_BASE_DELAY_S: int = 5
    RETRY_MAX_RETRIES: int = 5
    RETRY_JITTER_ENABLED: bool = True

    # --- AUTH-VERIFY: independent SPF/DKIM/DMARC verification ---
    AUTH_VERIFY_ENABLED: bool = True
    DNS_TIMEOUT_S: int = 3
    DNS_CACHE_MAX: int = 512
    # Offline mode: independent verification fails fast with zero network I/O
    # (used by the test harness and air-gapped deployments).
    DNS_OFFLINE: bool = False
    SPF_MAX_DNS_LOOKUPS: int = 10
    # Per-domain circuit breaker for the DNS layer.
    DNS_CB_FAILURE_THRESHOLD: int = 5
    DNS_CB_WINDOW_S: int = 60
    DNS_CB_OPEN_S: int = 120

    # --- SE-HARDENING: social-engineering narrative patterns ---
    SE_PATTERN_ENABLED: bool = True


    # --- Email connectors (Phase 1-2): Gmail only; own Google OAuth client ---
    GOOGLE_GMAIL_CLIENT_ID: str = ""
    GOOGLE_GMAIL_CLIENT_SECRET: str = ""
    GOOGLE_GMAIL_REDIRECT_URI: str = "http://localhost:8000/api/v1/connectors/gmail/callback"
    # Where the Gmail OAuth callback redirects the browser afterwards.
    FRONTEND_CONNECTORS_URL: str = "http://localhost:5173/email-connectors"
    # Fernet key encrypting provider tokens at rest. Generate with:
    #   uv run python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    CONNECTOR_TOKEN_KEY: str = ""
    CONNECTOR_OAUTH_STATE_TTL_SECONDS: int = 600
    GMAIL_CONNECTOR_ENABLED: bool = True

    # --- Event email notifications (Phase 7) ---
    # Empty SMTP host = DB-logged delivery backend (hackathon-demo safe):
    # the email is rendered and persisted to notification_logs.
    # When set, SMTP delivery is attempted best-effort and falls back to
    # DB logging on any failure so the demo never crashes.
    NOTIFICATION_SMTP_HOST: str = ""
    NOTIFICATION_SMTP_PORT: int = 587
    NOTIFICATION_FROM_ADDRESS: str = "cyberguard-alerts@localhost"
    NOTIFICATION_SMTP_USERNAME: str = ""
    NOTIFICATION_SMTP_PASSWORD: str = ""

    # --- Member invitation emails (MEMBER-INVITE-P3) ---
    # Empty SMTP_HOST = dev mode: the invitation email (with the raw accept
    # link) is logged to the console instead of sent, so developers can
    # complete the flow without a mail server.
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASS: str = ""
    FROM_EMAIL: str = "invites@cyberguard.local"
    # Frontend origin used to build invitation accept links:
    #   {FRONTEND_URL}/auth/accept-invite?token=...
    FRONTEND_URL: str = "http://localhost:5173"

    # Multi-Provider Orchestration (Groq, Gemini, OpenRouter)
    LLM_PROVIDERS: str = "groq,gemini,openrouter"
    LLM_COOLDOWN_SECONDS: int = 60
    LLM_HEALTH_CHECK_INTERVAL_SECONDS: int = 30
    LLM_TIMEOUT_SECONDS: float = 20.0
    LLM_REQUEST_TIMEOUT_SECONDS: float = 10.0

    # OpenRouter
    OPENROUTER_API_KEY: str = ""
    OPENROUTER_API_KEYS: str = ""
    OPENROUTER_MAX_KEYS: int = 10
    OPENROUTER_KEY_COOLDOWN_SECONDS: int = 60
    OPENROUTER_HEALTH_CHECK_INTERVAL_SECONDS: int = 30
    OPENROUTER_MODEL: str = "liquid/lfm-2.5-2.6b:free"
    OPENROUTER_FALLBACK_MODELS: str = "liquid/lfm-2.5-2.6b:free,google/gemma-4-26b-a4b-it:free,nvidia/nemotron-3.5-lightning:free,nex-agi/nex-n2.5-mini:free"

    # Groq (Ultra-low latency inference: OpenAI GPT-OSS, Qwen, Llama)
    GROQ_API_KEY: str = ""
    GROQ_API_KEYS: str = ""
    GROQ_MAX_KEYS: int = 10
    GROQ_KEY_COOLDOWN_SECONDS: int = 60
    GROQ_HEALTH_CHECK_INTERVAL_SECONDS: int = 30
    GROQ_MODEL: str = "openai/gpt-oss-120b"
    GROQ_FALLBACK_MODELS: str = "openai/gpt-oss-120b,openai/gpt-oss-20b,qwen/qwen3.8-27b,llama-3.3-70b-versatile,llama-3.1-8b-instant"

    # Gemini (Google GenAI: Gemini 2.0 Flash, Gemini 1.5 Flash)
    GEMINI_API_KEY: str = ""
    GEMINI_API_KEYS: str = ""
    GEMINI_MAX_KEYS: int = 10
    GEMINI_KEY_COOLDOWN_SECONDS: int = 60
    GEMINI_HEALTH_CHECK_INTERVAL_SECONDS: int = 30
    GEMINI_MODEL: str = "gemini-2.0-flash"
    GEMINI_FALLBACK_MODELS: str = "gemini-2.0-flash,gemini-1.5-flash"

    # --- Firecrawl live page intelligence (optional URL enrichment) ---
    # Missing key => live enrichment cleanly disabled; the URL pipeline runs
    # heuristics-only (see app/services/firecrawl_client.py).
    FIRECRAWL_API_KEY: str = ""
    FIRECRAWL_BASE_URL: str = "https://api.firecrawl.dev"
    FIRECRAWL_ENABLED: bool = True
    FIRECRAWL_TIMEOUT_SECONDS: int = 10
    FIRECRAWL_CACHE_TTL_SECONDS: int = 3600
    FIRECRAWL_MAX_CONCURRENCY: int = 4
    FIRECRAWL_SKIP_INTERNAL_URLS: bool = True

    ML_ENABLED: bool = True
    ML_MODELS_DIR: str = "ml/models"

    # Strict loopback/localhost allowlist toggle (URL-LOOPBACK-ALLOWLIST)
    ALLOW_LOOPBACK_URLS: bool = False

    # --- Deepfake secondary detector (Model B: Lynote Sentry ConvNeXt Small) ---
    # Model B is an OPTIONAL independent verification signal behind a
    # confidence gate — never a default second pass, never a probability
    # average. Initial threshold values; calibrate on the evaluation dataset.
    DEEPFAKE_SECONDARY_ENABLED: bool = True
    DEEPFAKE_SECONDARY_BACKEND: str = "sentry-convnext-small"
    # Model A probability band treated as uncertain (gate runs Model B inside it).
    DEEPFAKE_SECONDARY_LOW_CONFIDENCE: float = 0.35
    DEEPFAKE_SECONDARY_HIGH_CONFIDENCE: float = 0.65
    # |A - B| above this is flagged as model disagreement evidence.
    DEEPFAKE_MODEL_DISAGREEMENT_THRESHOLD: float = 0.35
    # Hard wall-clock cap for one Model B inference.
    DEEPFAKE_SECONDARY_TIMEOUT_SECONDS: int = 30
    # Inference device (dev machine is CPU-only: i5 13th-gen U-series).
    DEEPFAKE_SECONDARY_DEVICE: str = "cpu"
    # Optional local path to the Sentry ConvNeXt Small checkpoint
    # (epoch_15.pth); empty = download once from the Hugging Face hub and
    # cache it via huggingface_hub.
    DEEPFAKE_SECONDARY_WEIGHT_PATH: str = ""
    DEEPFAKE_SECONDARY_HF_REPO: str = "InfImagine/Sentry_image_models"

    APP_TITLE: str = "CYBERGUARD API"
    APP_VERSION: str = "0.2.0"
    @model_validator(mode="after")
    def _validadte_and_set_API_KEYS(self) -> Self:
        """Enforce the api keys to null for faster testing and reduce"""
        if self.TEST_MODE:
            self.OPENROUTER_API_KEY = ""
            self.OPENROUTER_API_KEYS = ""
            self.GROQ_API_KEY = ""
            self.GROQ_API_KEYS = ""
            self.GEMINI_API_KEY = ""
            self.GEMINI_API_KEYS = ""
            # Live page scraping is external side-effecting: disabled in TEST_MODE.
            self.FIRECRAWL_API_KEY = ""
        return self
    @property
    def async_database_url(self) -> str:
        """Ensure standard postgresql:// URLs are translated to asyncpg."""
        url = self.DATABASE_URL.strip() if self.DATABASE_URL else "sqlite+aiosqlite:///./cyberguard.db"
        if url.startswith("postgres://"):
            return url.replace("postgres://", "postgresql+asyncpg://", 1)
        if url.startswith("postgresql://") and not url.startswith("postgresql+asyncpg://"):
            return url.replace("postgresql://", "postgresql+asyncpg://", 1)
        return url

    @property
    def fallback_models_list(self) -> list[str]:
        return [m.strip() for m in self.OPENROUTER_FALLBACK_MODELS.split(",") if m.strip()]

    @property
    def openrouter_keys_list(self) -> list[str]:
        """Collect and deduplicate OpenRouter API keys up to OPENROUTER_MAX_KEYS."""
        import os

        keys: list[str] = []
        # 1. Comma/newline-separated list
        if self.OPENROUTER_API_KEYS:
            for k in self.OPENROUTER_API_KEYS.replace("\n", ",").split(","):
                cleaned = k.strip()
                if cleaned and cleaned not in keys:
                    keys.append(cleaned)

        # 2. Check environment variables OPENROUTER_API_KEY_1 .. OPENROUTER_API_KEY_N
        for i in range(1, self.OPENROUTER_MAX_KEYS + 1):
            env_val = os.environ.get(f"OPENROUTER_API_KEY_{i}", "").strip()
            if env_val and env_val not in keys:
                keys.append(env_val)

        # 3. Fallback to single primary key
        if self.OPENROUTER_API_KEY:
            cleaned = self.OPENROUTER_API_KEY.strip()
            if cleaned and cleaned not in keys:
                keys.append(cleaned)

        return keys[: max(1, self.OPENROUTER_MAX_KEYS)]

    @property
    def groq_keys_list(self) -> list[str]:
        """Collect and deduplicate Groq API keys up to GROQ_MAX_KEYS."""
        import os

        keys: list[str] = []
        if self.GROQ_API_KEYS:
            for k in self.GROQ_API_KEYS.replace("\n", ",").split(","):
                cleaned = k.strip()
                if cleaned and cleaned not in keys:
                    keys.append(cleaned)

        for i in range(1, max(1, self.GROQ_MAX_KEYS) + 1):
            env_val = os.environ.get(f"GROQ_API_KEY_{i}", "").strip()
            if env_val and env_val not in keys:
                keys.append(env_val)

        if self.GROQ_API_KEY:
            cleaned = self.GROQ_API_KEY.strip()
            if cleaned and cleaned not in keys:
                keys.append(cleaned)

        return keys[: max(1, self.GROQ_MAX_KEYS)]

    @property
    def gemini_keys_list(self) -> list[str]:
        """Collect and deduplicate Gemini API keys up to GEMINI_MAX_KEYS."""
        import os

        keys: list[str] = []
        if self.GEMINI_API_KEYS:
            for k in self.GEMINI_API_KEYS.replace("\n", ",").split(","):
                cleaned = k.strip()
                if cleaned and cleaned not in keys:
                    keys.append(cleaned)

        for i in range(1, max(1, self.GEMINI_MAX_KEYS) + 1):
            env_val = os.environ.get(f"GEMINI_API_KEY_{i}", "").strip()
            if env_val and env_val not in keys:
                keys.append(env_val)

        if self.GEMINI_API_KEY:
            cleaned = self.GEMINI_API_KEY.strip()
            if cleaned and cleaned not in keys:
                keys.append(cleaned)

        # Fallback to standard GOOGLE_API_KEY if present
        google_env = os.environ.get("GOOGLE_API_KEY", "").strip()
        if google_env and google_env not in keys:
            keys.append(google_env)

        return keys[: max(1, self.GEMINI_MAX_KEYS)]

    @property
    def groq_fallback_models_list(self) -> list[str]:
        return [m.strip() for m in self.GROQ_FALLBACK_MODELS.split(",") if m.strip()]

    @property
    def gemini_fallback_models_list(self) -> list[str]:
        return [m.strip() for m in self.GEMINI_FALLBACK_MODELS.split(",") if m.strip()]

    @property
    def llm_providers_list(self) -> list[str]:
        return [p.strip().lower() for p in self.LLM_PROVIDERS.split(",") if p.strip()]

    @property
    def cors_origins_list(self) -> list[str]:
        """Parse CORS_ORIGINS + EXT_CORS_ORIGINS into one allow list."""
        combined = f"{self.CORS_ORIGINS},{self.EXT_CORS_ORIGINS}"
        return [origin.strip() for origin in combined.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    """Return the cached singleton Settings instance."""
    return Settings()
