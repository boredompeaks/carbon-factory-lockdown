"""Resolve an optional product lane to an absolute repo root.

``files/policies/worktree-map.json`` is the single source of truth
(lane name -> absolute worktree path). The factory root is derived from
that map's directory chain, never hardcoded:

    <factory>/files/policies/worktree-map.json
                          ^parent ^parent ^parent = <factory>

An omitted lane returns the factory root (backward compatible) unless
the process runs with ``CARBON_WORKSPACE`` set: a workspace session
must name its lane explicitly, so an omitted lane is
``REJECT_AMBIGUOUS_LANE`` rather than a silent factory fallback. An
unknown lane, a missing/invalid map, or a missing lane path fails
closed with ``REJECT_PRECONDITION`` so a tool can never silently fall
back to the factory for a product session.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from ..core.validate import Reject

LANE_PATTERN = r"^(lane/[a-z0-9_-]+|spec-comp)$"
_LANE_RE = re.compile(LANE_PATTERN)

_POLICIES_DIR = Path(__file__).resolve().parents[3] / "policies"
_MAP_PATH = _POLICIES_DIR / "worktree-map.json"
_FACTORY_ROOT = _MAP_PATH.parent.parent.parent


def is_lane_name(value: object) -> bool:
    """True for a syntactically valid lane key."""
    return isinstance(value, str) and _LANE_RE.fullmatch(value) is not None


def factory_root() -> Path:
    """Factory repo root, derived from the map path (no hardcode)."""
    return _FACTORY_ROOT


def _load_map() -> dict:
    try:
        data = json.loads(_MAP_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise Reject(
            "REJECT_PRECONDITION",
            f"worktree-map unavailable at {_MAP_PATH}: {exc}",
        ) from exc
    if not isinstance(data, dict) or not data:
        raise Reject("REJECT_PRECONDITION", f"worktree-map invalid at {_MAP_PATH}")
    return data


def resolve_repo_root(lane: str | None) -> Path:
    """Resolve ``lane`` to an absolute existing repo root.

    ``None`` -> factory root. Unknown lane / map missing / path missing
    raise ``REJECT_PRECONDITION`` (fail closed).
    """
    if lane is None:
        return _FACTORY_ROOT
    if not is_lane_name(lane):
        raise Reject("REJECT_PRECONDITION", f"unknown lane: {lane!r}")
    mapping = _load_map()
    raw = mapping.get(lane)
    if not isinstance(raw, str) or not raw.strip():
        raise Reject("REJECT_PRECONDITION", f"unknown lane: {lane!r}")
    path = Path(raw)
    if not path.is_absolute():
        raise Reject(
            "REJECT_PRECONDITION",
            f"lane {lane!r} path is not absolute: {raw!r}",
        )
    try:
        root = path.resolve()
    except OSError as exc:
        raise Reject(
            "REJECT_PRECONDITION",
            f"lane {lane!r} path cannot be resolved: {raw!r}: {exc}",
        ) from exc
    if not root.is_dir():
        raise Reject(
            "REJECT_PRECONDITION",
            f"lane {lane!r} path missing: {root}",
        )
    return root


def resolve_required_lane(lane: str | None, factory_root: Path) -> Path:
    """Resolve a lane without an implicit factory fallback in a workspace.

    - explicit ``lane`` -> worktree-map.json (same checks as
      :func:`resolve_repo_root`);
    - no lane + ``CARBON_WORKSPACE`` set -> ``REJECT_AMBIGUOUS_LANE``;
    - no lane + no workspace -> ``factory_root`` (backward compatible).
    """
    if lane is not None:
        return resolve_repo_root(lane)
    if os.environ.get("CARBON_WORKSPACE"):
        raise Reject(
            "REJECT_AMBIGUOUS_LANE",
            "pass lane=<lane/a|lane/b|spec-comp>",
        )
    return Path(factory_root)
