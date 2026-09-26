"""Scenario template loader for the traffic generator.

scenarios/ holds JSON files per category, each a list of templates:
    {"action": "analyze_network", "data": {...},
     "metadata": {"source": "...", "description": "..."}}

Only `action` + `data` are shipped; `metadata` documents the scenario and
the verified trigger rule it exercises.

Mix groups (as accepted by the generator's `--mix`):
    net      -> network_critical.json
    ato      -> ato_critical.json
    benign   -> alternates network_benign + ato_benign
Aliases: net_critical, ato_critical, net_benign, ato_benign.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from pathlib import Path

SCENARIOS_DIR = Path(__file__).resolve().parent.parent / "scenarios"

CATEGORY_FILES = {
    "net_critical": "network_critical.json",
    "net_benign": "network_benign.json",
    "ato_critical": "ato_critical.json",
    "ato_benign": "ato_benign.json",
}

# Mix keys -> scenario categories. `benign` alternates both benign files.
MIX_GROUPS: dict[str, tuple[str, ...]] = {
    "net": ("net_critical",),
    "ato": ("ato_critical",),
    "benign": ("net_benign", "ato_benign"),
    # explicit aliases
    "net_critical": ("net_critical",),
    "ato_critical": ("ato_critical",),
    "net_benign": ("net_benign",),
    "ato_benign": ("ato_benign",),
}

DEFAULT_MIX = {"net": 15, "ato": 15, "benign": 70}


class ScenarioError(RuntimeError):
    pass


@dataclass(frozen=True)
class Template:
    category: str
    action: str
    data: dict
    metadata: dict


def load_category(category: str, scenarios_dir: Path | None = None) -> list[Template]:
    path = (scenarios_dir or SCENARIOS_DIR) / CATEGORY_FILES[category]
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ScenarioError(f"scenario file missing: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ScenarioError(f"scenario file invalid JSON: {path}: {exc}") from exc

    templates: list[Template] = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict) or "action" not in item or "data" not in item:
            raise ScenarioError(f"{path.name}[{i}] must be an object with 'action' and 'data'")
        templates.append(
            Template(
                category=category,
                action=str(item["action"]),
                data=item["data"],
                metadata=item.get("metadata", {}),
            )
        )
    if not templates:
        raise ScenarioError(f"{path.name} contains no templates")
    return templates


class ScenarioBook:
    """All categories loaded once; picks templates per mix group."""

    def __init__(self, scenarios_dir: Path | None = None, rng: random.Random | None = None) -> None:
        self.rng = rng or random.Random()
        self._by_category = {
            cat: load_category(cat, scenarios_dir) for cat in CATEGORY_FILES
        }
        # round-robin cursors so benign alternates deterministically
        self._cursors: dict[str, int] = {}

    def categories_for_group(self, group: str) -> tuple[str, ...]:
        if group not in MIX_GROUPS:
            known = ", ".join(sorted(set(MIX_GROUPS) - set(CATEGORY_FILES)))
            raise ScenarioError(f"unknown mix group {group!r}; known groups: {known}")
        return MIX_GROUPS[group]

    def pick(self, group: str) -> Template:
        """Pick a template from the group, rotating across its categories."""
        cats = self.categories_for_group(group)
        cursor = self._cursors.get(group, 0)
        self._cursors[group] = cursor + 1
        category = cats[cursor % len(cats)]
        templates = self._by_category[category]
        return self.rng.choice(templates)


def parse_mix(raw: str | None) -> dict[str, float]:
    """Parse 'net=30,ato=20,benign=50' into group->percent dict.

    Percent must sum to ~100 (±1 tolerance). Returns DEFAULT_MIX when raw
    is empty/None.
    """
    if not raw or not raw.strip():
        return dict(DEFAULT_MIX)
    out: dict[str, float] = {}
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            raise ScenarioError(f"mix entry {part!r} must look like 'net=30'")
        key, _, val = part.partition("=")
        try:
            pct = float(val)
        except ValueError as exc:
            raise ScenarioError(f"mix percent for {key!r} is not a number: {val!r}") from exc
        if pct < 0:
            raise ScenarioError(f"mix percent for {key!r} must be >= 0")
        out[key.strip()] = pct
    if not out:
        return dict(DEFAULT_MIX)
    total = sum(out.values())
    if abs(total - 100.0) > 1.0:
        raise ScenarioError(f"mix percentages must sum to 100 (got {total:g})")
    return out
