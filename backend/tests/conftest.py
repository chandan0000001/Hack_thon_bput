"""Pytest evaluation harness configuration (backend/tests).

Sets up an isolated temp SQLite database BEFORE the app imports, seeds an
evaluation user through the REAL demo-token auth path (no dependency overrides
that skip security), and provides the HTTP client + metrics report writer.
"""

import pytest

import asyncio
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

# Isolated database for the harness: must be set before app.db.session imports.
_DB_FD, _DB_PATH = tempfile.mkstemp(suffix=".db", prefix="cg_eval_")
os.close(_DB_FD)
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_DB_PATH}"
# Deterministic, offline-first harness: no external LLM calls during scoring.
for _key in (
    "OPENROUTER_API_KEY", "OPENROUTER_API_KEYS", "GROQ_API_KEY", "GROQ_API_KEYS",
    "GEMINI_API_KEY", "GEMINI_API_KEYS", "GOOGLE_API_KEY",
):
    os.environ.setdefault(_key, "")
# AUTH-VERIFY: keep DNS verification fully offline in the harness (zero
# network I/O; independent checks degrade to "unavailable" + mx_parsed
# fallback). Individual auth tests override with injected fake resolvers.
os.environ.setdefault("DNS_OFFLINE", "true")

EVAL_USER_TOKEN = "demo-eval@cyberguard.local"
EVAL_USER_EMAIL = "eval@cyberguard.local"

REPORTS_DIR = Path(__file__).resolve().parent / "reports"
DATA_DIR = Path(__file__).resolve().parent / "data"


# ---------------------------------------------------------------------------
# CLI options
# ---------------------------------------------------------------------------

def pytest_addoption(parser):
    group = parser.getgroup("eval-harness")
    group.addoption("--scale", type=int, default=500,
                    help="Per-engine evaluation case count (default 500).")
    group.addoption("--full", action="store_true",
                    help="Run at 5x the default scale.")
    group.addoption("--fetch", action="store_true",
                    help="Force re-download of online datasets (ignores cache).")
    group.addoption("--offline", action="store_true",
                    help="Synthetic data only — never touch the network.")


def scale_n(request, default_n: int, maximum: int | None = None) -> int:
    """Effective dataset size: generators have their own default sizes
    (emails 1000, urls 2000, images 400, audio 400, auth 2000, flows 2000).
    --scale=N rescales proportionally to the 500 default; --full multiplies
    by 5."""
    factor = (request.config.getoption("--scale") or 500) / 500
    if request.config.getoption("--full"):
        factor *= 5
    n = int(default_n * factor)
    if maximum:
        n = min(n, maximum)
    return max(10, n)


# ---------------------------------------------------------------------------
# Session-scoped app + DB
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def initialized_db():
    """Create the schema + seed the response catalog on the temp DB."""
    from app.db.session import init_db

    asyncio.run(init_db())
    yield
    try:
        os.unlink(_DB_PATH)
    except OSError:
        pass


@pytest.fixture(scope="session")
def eval_user(initialized_db):
    """Seed the evaluation user through the REAL demo-token auth path, so
    get_current_user's JIT upsert, tenant resolution, and RLS GUC wiring all
    flow naturally — no dependency overrides that skip security."""
    from app.core.security import get_current_user
    from app.db.session import async_session_maker

    async def _seed():
        async with async_session_maker() as db:
            user = await get_current_user(
                credentials=__import__("fastapi.security", fromlist=["HTTPAuthorizationCredentials"]).HTTPAuthorizationCredentials(
                    scheme="Bearer", credentials=EVAL_USER_TOKEN
                ),
                db=db,
            )
            return user

    return asyncio.run(_seed())


@pytest.fixture
async def client(initialized_db, eval_user):
    """ASGI HTTP client authenticated as the eval user (function scope so the
    client lives on the test's own event loop)."""
    from httpx import ASGITransport, AsyncClient

    from app.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
        headers={"Authorization": f"Bearer {EVAL_USER_TOKEN}"},
        timeout=60,
    ) as c:
        yield c


# ---------------------------------------------------------------------------
# Metrics report writer
# ---------------------------------------------------------------------------

class EvalReport:
    """Collects per-engine metrics during the session; written to
    backend/tests/reports/eval_report.{md,json} at session end."""

    def __init__(self):
        self.engines: dict[str, dict] = {}
        self.properties: dict[str, dict] = {}
        self.http: dict = {}
        self.findings: list[str] = []
        self.provenance: list[dict] = []
        self.meta: dict = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def record_engine(self, name: str, **metrics):
        self.engines.setdefault(name, {}).update(metrics)

    def record_property(self, name: str, **kv):
        """Property-test results (no precision/recall table row)."""
        self.properties.setdefault(name, {}).update(kv)

    def record_finding(self, text: str):
        self.findings.append(text)

    def record_provenance(self, **kwargs):
        self.provenance.append(kwargs)

    def write(self):
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)

        def _fmt(value, nd=4):
            if isinstance(value, float):
                return f"{value:.{nd}f}"
            return str(value)

        lines = [
            "# CYBERGUARD Evaluation Harness Report",
            "",
            f"- Generated: {self.meta.get('generated_at')}",
            f"- Git tip: {self.meta.get('git_tip', 'unknown')}",
            f"- Scale option: {self.meta.get('scale_desc', 'default')}",
            f"- Data mode: {self.meta.get('data_mode', 'auto')}",
            "",
            "## Per-engine metrics",
            "",
            "| Engine | Cases | Positives | Precision | Recall | F1 | AUC | Malicious mean | Benign mean | Band gap | MW p-value |",
            "|---|---|---|---|---|---|---|---|---|---|---|",
        ]
        for name, m in self.engines.items():
            lines.append(
                f"| {name} | {m.get('cases', 0)} | {m.get('positives', 0)} "
                f"| {_fmt(m.get('precision', float('nan')))} | {_fmt(m.get('recall', float('nan')))} "
                f"| {_fmt(m.get('f1', float('nan')))} | {_fmt(m.get('auc', float('nan')))} "
                f"| {_fmt(m.get('mal_mean', float('nan')), 2)} | {_fmt(m.get('ben_mean', float('nan')), 2)} "
                f"| {_fmt(m.get('band_gap', float('nan')), 2)} | {_fmt(m.get('mw_p', float('nan')))} |"
            )

        lines += ["", "## Property tests", ""]
        for name, m in self.properties.items():
            lines.append(f"- {name}: " + ", ".join(f"{k}={v}" for k, v in m.items()))

        lines += ["", "## HTTP latency (sampled analysis requests)", ""]
        if self.http:
            for endpoint, stats in self.http.items():
                lines.append(
                    f"- `{endpoint}`: n={stats.get('n')} "
                    f"p50={stats.get('p50', 0):.1f}ms p95={stats.get('p95', 0):.1f}ms p99={stats.get('p99', 0):.1f}ms"
                )
        else:
            lines.append("- (no HTTP samples recorded)")

        lines += ["", "## Data provenance", "",
                  "| Source | Mode | Rows | SHA256 | Fetched at |", "|---|---|---|---|---|"]
        for p in self.provenance:
            lines.append(
                f"| {p.get('name')} | {p.get('mode')} | {p.get('rows')} | {(p.get('sha256') or '—')[:16]}… | {p.get('fetched_at', '—')} |"
            )

        lines += ["", "## Findings (bugs discovered by the harness — NOT fixed)", ""]
        if self.findings:
            lines += [f"- {f}" for f in self.findings]
        else:
            lines.append("- None recorded this run.")

        (REPORTS_DIR / "eval_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
        (REPORTS_DIR / "eval_report.json").write_text(
            json.dumps(
                {
                    "meta": self.meta,
                    "engines": self.engines,
                    "properties": self.properties,
                    "http": self.http,
                    "provenance": self.provenance,
                    "findings": self.findings,
                },
                indent=2,
                default=str,
            ),
            encoding="utf-8",
        )
        return REPORTS_DIR / "eval_report.md"


_report = EvalReport()


@pytest.fixture(scope="session")
def eval_report():
    return _report


@pytest.fixture(scope="session", autouse=True)
def _wire_datakit_report(eval_report):
    """Route datakit provenance records into the session report."""
    from tests import datakit

    datakit.set_report_hook(eval_report.record_provenance)
    yield


def pytest_sessionfinish(session, exitstatus):
    import subprocess

    try:
        tip = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, cwd=str(BACKEND_ROOT),
        ).stdout.strip()
        _report.meta["git_tip"] = tip
    except Exception:  # noqa: BLE001
        pass
    path = _report.write()
    print(f"\n📊 Evaluation report written to {path}")
