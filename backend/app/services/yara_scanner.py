"""YARA engine — signature/rule-based pattern detection for attachments.

yara-python is an OPTIONAL dependency: if it is not installed, or the rules
directory is missing/empty/uncompilable, the scanner reports itself
unavailable and the pipeline continues without it. Rules live in
backend/app/yara_rules/*.yar and are compiled once at construction.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger("cyberguard.attachment.yara")

# Default rules directory: backend/app/yara_rules, resolved package-relative
# so it works regardless of the process working directory.
DEFAULT_RULES_DIR = Path(__file__).resolve().parent.parent / "yara_rules"

MATCH_TIMEOUT_S = 10
YARA_RISK_PER_MATCH = 15
YARA_RISK_CAP = 60


class YaraScanner:
    """Compiles a rules directory once and matches files against it."""

    def __init__(self, rules_dir: Optional[Path] = None):
        self.rules_dir = Path(rules_dir) if rules_dir else DEFAULT_RULES_DIR
        self._rules = None
        self.available = self._compile_rules()

    def _compile_rules(self) -> bool:
        """Compile every *.yar/*.yara file in the rules dir; False on any failure."""
        try:
            import yara
        except ImportError:
            logger.info("yara-python not installed; YARA scanning disabled")
            return False

        rule_files = sorted(p for p in self.rules_dir.glob("*.yara")) + sorted(
            p for p in self.rules_dir.glob("*.yar")
        )
        if not rule_files:
            logger.info("No YARA rules found in %s; YARA scanning disabled", self.rules_dir)
            return False

        try:
            # yara.compile(dirpath=...) was removed in yara-python 4.5; compile
            # each file as a named source instead (also lets one bad rule be
            # identified by file name in the traceback).
            sources = {p.name: p.read_text(encoding="utf-8") for p in rule_files}
            self._rules = yara.compile(sources=sources)
            return True
        except Exception as exc:
            logger.warning("YARA rule compilation failed for %s: %s", self.rules_dir, exc)
            self._rules = None
            return False

    def scan_file(self, file_path: str) -> dict:
        """Match a file against the rule set.

        Returns {engine, available, matches, match_count, risk_score} where
        each match is {rule, tags, description}. risk_score = 15 per match,
        capped at 60 — YARA hits are strong signals but rules are
        intentionally conservative, so they weigh less than a ClamAV hit.
        """
        if not self.available or self._rules is None:
            return {"engine": "yara", "available": False, "matches": [], "match_count": 0, "risk_score": 0}

        raw_matches = self._rules.match(filepath=file_path, timeout=MATCH_TIMEOUT_S)

        matches = []
        for match in raw_matches:
            meta = getattr(match, "meta", {}) or {}
            matches.append(
                {
                    "rule": match.rule,
                    "tags": list(getattr(match, "tags", []) or []),
                    "description": meta.get("description"),
                }
            )

        risk_score = min(YARA_RISK_CAP, YARA_RISK_PER_MATCH * len(matches))
        return {
            "engine": "yara",
            "available": True,
            "matches": matches,
            "match_count": len(matches),
            "risk_score": risk_score,
        }
