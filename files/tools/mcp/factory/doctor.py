"""Read-only factory doctor.

``doctor(factory_root, workspace)`` inspects the harness and its lane
worktrees and returns ``{ok, blockers, facts}``. It is evidence-only: it
never writes, never repairs, and never reads ledger record bodies,
secrets, or ``.opencode`` agent content. Ledger evidence is the
capability tip hash obtained via ``ledger.store.tip_for``; plugin and
policy checks use presence/shape only.

Stable blocker codes:

- ``LANE_MISSING`` / ``LANE_NO_HEAD`` -- worktree-map lane absent or its
  git HEAD cannot be resolved.
- ``LEDGER_EMPTY`` / ``LEDGER_UNREADABLE`` -- capability chain has no
  records or its tip is malformed.
- ``DOCKER_DOWN`` -- ``docker info`` failed.
- ``IMAGE_MISSING`` -- ``k1-app:latest`` absent.
- ``RUNTIME_MISSING`` -- a lane lacks what ``check.run`` SUITE/BOOTTEST
  needs (``backend/manage.py``, settings module, importable Django).
- ``ENV_MISSING`` / ``ENV_MISMATCH`` -- ``CARBON_HARNESS`` /
  ``CARBON_WORKSPACE`` unset or pointing elsewhere.
- ``AGT_MISSING`` / ``AGT_INVALID`` -- ``.agt/policy.json`` absent or
  unparseable/unsound.
- ``PLUGIN_MISSING`` -- a pinned ``.opencode/plugins`` entry is absent.
- ``POLICY_MISSING`` / ``WORKSPACE_MISSING`` -- worktree-map or the
  supplied workspace root is unusable.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
from pathlib import Path

from ..core.validate import Reject
from ..ledger.store import GENESIS, list_records, tip_for

_IMAGE = "k1-app:latest"
_LANE_RE = re.compile(r"^(lane/[a-z0-9_-]+|spec-comp)$")
_HEAD_RE = re.compile(r"^[0-9a-f]{40}$")
_PLUGINS = ("agt.js", "authz.js")
_AGT_REQUIRED = ("mode", "denyOnPolicyError", "toolPolicies")


def _run(argv: list[str], timeout: int) -> tuple[int, str]:
    """Run argv-only (no shell), returning ``(exit_code, output)``."""
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, str(exc)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _blocker(code: str, detail: str, fix: str) -> dict:
    return {"code": code, "detail": detail, "fix": fix}


def _git_head(lane_path: Path) -> str | None:
    code, out = _run(["git", "-C", str(lane_path), "rev-parse", "HEAD"], timeout=15)
    head = out.strip().splitlines()[0] if out.strip() else ""
    if code != 0 or not _HEAD_RE.fullmatch(head):
        return None
    return head


def _check_lanes(factory: Path, blockers: list[dict]) -> dict:
    map_path = factory / "files" / "policies" / "worktree-map.json"
    facts: dict = {"map": str(map_path), "lanes": {}}
    try:
        mapping = json.loads(map_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        blockers.append(
            _blocker(
                "POLICY_MISSING",
                f"worktree-map unreadable at {map_path}: {exc}",
                "restore files/policies/worktree-map.json with lane -> absolute path entries",
            )
        )
        return facts
    if not isinstance(mapping, dict) or not mapping:
        blockers.append(
            _blocker(
                "POLICY_MISSING",
                f"worktree-map has no lanes at {map_path}",
                "add lane/a, lane/b and spec-comp entries to files/policies/worktree-map.json",
            )
        )
        return facts

    for lane, raw in sorted(mapping.items()):
        entry: dict = {"path": raw if isinstance(raw, str) else None}
        facts["lanes"][lane] = entry
        if not _LANE_RE.fullmatch(str(lane)) or not isinstance(raw, str) or not raw.strip():
            blockers.append(
                _blocker(
                    "POLICY_MISSING",
                    f"worktree-map entry {lane!r} is not a valid lane -> absolute path",
                    "use lane/<name> or spec-comp keys with absolute worktree paths",
                )
            )
            continue
        lane_path = Path(raw).expanduser()
        if not lane_path.is_absolute():
            blockers.append(
                _blocker(
                    "POLICY_MISSING",
                    f"lane {lane!r} path is not absolute: {raw}",
                    "store an absolute worktree path in files/policies/worktree-map.json",
                )
            )
            continue
        entry["path"] = str(lane_path)
        if not lane_path.is_dir():
            entry["exists"] = False
            blockers.append(
                _blocker(
                    "LANE_MISSING",
                    f"lane {lane!r} worktree is absent: {lane_path}",
                    f"create or restore the worktree at {lane_path}",
                )
            )
            continue
        entry["exists"] = True
        head = _git_head(lane_path)
        entry["head"] = head
        if head is None:
            blockers.append(
                _blocker(
                    "LANE_NO_HEAD",
                    f"lane {lane!r} git HEAD cannot be resolved at {lane_path}",
                    f"repair the git checkout at {lane_path} (rev-parse HEAD)",
                )
            )
    return facts


def _check_ledger(factory: Path, blockers: list[dict]) -> dict:
    root = factory / "files" / "quality" / "ledger"
    facts: dict = {"root": str(root), "record_type": "capability", "tip": None, "records": 0}
    try:
        records = list_records("capability", root)
        facts["records"] = len(records)
        tip = tip_for("capability", root)
    except Reject as exc:
        blockers.append(
            _blocker(
                "LEDGER_UNREADABLE",
                f"capability tip unreadable under {root}: {exc.detail}",
                "repair the newest capability ledger record or restore it from backup",
            )
        )
        return facts
    except OSError as exc:
        blockers.append(
            _blocker(
                "LEDGER_UNREADABLE",
                f"capability ledger unreadable under {root}: {exc}",
                "restore read access to files/quality/ledger/capability",
            )
        )
        return facts
    facts["tip"] = tip
    if tip == GENESIS or facts["records"] == 0:
        blockers.append(
            _blocker(
                "LEDGER_EMPTY",
                f"capability chain is empty at {root / 'capability'}",
                "append one orchestrator capability record before dispatching lanes",
            )
        )
    return facts


def _check_docker(blockers: list[dict]) -> dict:
    facts: dict = {"engine": False, "image": _IMAGE, "image_present": False, "image_id": None}
    code, out = _run(["docker", "info"], timeout=20)
    if code != 0:
        blockers.append(
            _blocker(
                "DOCKER_DOWN",
                f"docker info failed (exit {code}): {out.strip()[:300]}",
                "start the Docker engine (or run the harness docker.ensure prerequisite)",
            )
        )
        return facts
    facts["engine"] = True
    code, out = _run(
        ["docker", "image", "inspect", _IMAGE, "--format", "{{.Id}}"], timeout=20
    )
    if code != 0:
        blockers.append(
            _blocker(
                "IMAGE_MISSING",
                f"image {_IMAGE} is not present locally",
                f"build {_IMAGE} locally; the harness never pulls or builds implicitly",
            )
        )
        return facts
    facts["image_present"] = True
    facts["image_id"] = out.strip().splitlines()[0] if out.strip() else None
    return facts


def _check_runtime(lanes: dict, blockers: list[dict]) -> dict:
    django = importlib.util.find_spec("django") is not None
    facts: dict = {"django": django, "lanes": {}}
    for lane, entry in lanes.items():
        if not entry.get("exists"):
            facts["lanes"][lane] = {"checked": False}
            continue
        lane_path = Path(entry["path"])
        backend = lane_path / "backend"
        marker = {
            "checked": True,
            "manage": (backend / "manage.py").is_file(),
            "settings": (backend / "config" / "settings.py").is_file(),
            "django": django,
        }
        facts["lanes"][lane] = marker
        missing = []
        if not marker["manage"]:
            missing.append("backend/manage.py")
        if not marker["settings"]:
            missing.append("backend/config/settings.py")
        if not django:
            missing.append("importable Django")
        if missing:
            blockers.append(
                _blocker(
                    "RUNTIME_MISSING",
                    f"lane {lane!r} cannot run SUITE/BOOTTEST: missing {', '.join(missing)}",
                    "provide backend/manage.py + config/settings.py and a Django-bearing interpreter",
                )
            )
    return facts


def _check_env(factory: Path, workspace: Path, blockers: list[dict]) -> dict:
    facts: dict = {
        "CARBON_HARNESS": os.environ.get("CARBON_HARNESS"),
        "CARBON_WORKSPACE": os.environ.get("CARBON_WORKSPACE"),
        "expected_harness": str(factory),
        "expected_workspace": str(workspace),
    }
    for name, expected in (
        ("CARBON_HARNESS", str(factory)),
        ("CARBON_WORKSPACE", str(workspace)),
    ):
        raw = facts[name]
        if not raw:
            blockers.append(
                _blocker(
                    "ENV_MISSING",
                    f"{name} is not set",
                    f"export {name}={expected} for the session/server process",
                )
            )
            continue
        try:
            actual = Path(raw).expanduser().resolve()
        except OSError:
            actual = Path(raw)
        if actual != Path(expected):
            blockers.append(
                _blocker(
                    "ENV_MISMATCH",
                    f"{name} points to {raw}, expected {expected}",
                    f"set {name}={expected} for the session/server process",
                )
            )
    return facts


def _check_agt(factory: Path, blockers: list[dict]) -> dict:
    policy_path = factory / ".agt" / "policy.json"
    facts: dict = {"path": str(policy_path), "loaded": False, "mode": None,
                   "version": None, "deny_on_policy_error": None}
    try:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
    except OSError as exc:
        blockers.append(
            _blocker(
                "AGT_MISSING",
                f"AGT policy unavailable at {policy_path}: {exc}",
                "restore .agt/policy.json (fail-closed policy is required)",
            )
        )
        return facts
    except ValueError as exc:
        blockers.append(
            _blocker(
                "AGT_INVALID",
                f"AGT policy is not valid JSON at {policy_path}: {exc}",
                "repair .agt/policy.json so it parses and keeps denyOnPolicyError=true",
            )
        )
        return facts
    if not isinstance(policy, dict) or any(k not in policy for k in _AGT_REQUIRED):
        blockers.append(
            _blocker(
                "AGT_INVALID",
                f"AGT policy at {policy_path} lacks required keys: {', '.join(_AGT_REQUIRED)}",
                "restore the required AGT policy top-level keys",
            )
        )
        return facts
    facts["loaded"] = True
    facts["mode"] = policy.get("mode")
    facts["version"] = policy.get("version")
    facts["deny_on_policy_error"] = policy.get("denyOnPolicyError")
    if policy.get("denyOnPolicyError") is not True:
        blockers.append(
            _blocker(
                "AGT_INVALID",
                f"AGT policy at {policy_path} has denyOnPolicyError={policy.get('denyOnPolicyError')!r}",
                "set denyOnPolicyError=true so policy errors fail closed",
            )
        )
    return facts


def _check_plugins(factory: Path, blockers: list[dict]) -> dict:
    root = factory / ".opencode" / "plugins"
    present = {name: (root / name).is_file() for name in _PLUGINS}
    for name, ok in present.items():
        if not ok:
            blockers.append(
                _blocker(
                    "PLUGIN_MISSING",
                    f"plugin file absent: {root / name}",
                    "restore the pinned plugin file (contents are not inspected)",
                )
            )
    return {"root": str(root), "files": present}


def doctor(factory_root: str, workspace: str) -> dict:
    """Return read-only health evidence for the harness and its lanes."""
    factory = Path(factory_root).expanduser().resolve() if factory_root else (
        Path(__file__).resolve().parents[4]
    )
    workspace_path = Path(workspace).expanduser().resolve() if workspace else factory

    blockers: list[dict] = []
    if not factory.is_dir():
        blockers.append(
            _blocker(
                "POLICY_MISSING",
                f"factory root does not exist: {factory}",
                "pass the harness checkout as factory_root",
            )
        )
    if not workspace_path.is_dir():
        blockers.append(
            _blocker(
                "WORKSPACE_MISSING",
                f"workspace root does not exist: {workspace_path}",
                "pass an existing session workspace directory",
            )
        )

    lanes = _check_lanes(factory, blockers)
    facts: dict = {
        "factory_root": str(factory),
        "workspace": str(workspace_path),
        "lanes": lanes["lanes"],
        "worktree_map": lanes["map"],
        "ledger": _check_ledger(factory, blockers),
        "docker": _check_docker(blockers),
        "runtime": _check_runtime(lanes["lanes"], blockers),
        "env": _check_env(factory, workspace_path, blockers),
        "agt": _check_agt(factory, blockers),
        "plugins": _check_plugins(factory, blockers),
    }
    return {"ok": not blockers, "blockers": blockers, "facts": facts}
