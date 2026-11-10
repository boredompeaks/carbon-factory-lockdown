#!/usr/bin/env python3
"""Generate per-host opencode.json (Ubuntu / Windows cross-compatible).

opencode.json is gitignored (it embeds host paths), so it must be generated
per machine. Run this script from the harness root::

    python scripts/gen_opencode_config.py           # write opencode.json
    python scripts/gen_opencode_config.py --print   # stdout only, no write
    python scripts/gen_opencode_config.py --check   # exit 1 on drift (CI)

Resolution rules:
  * Python interpreter: ``CARBON_PYTHON`` env when absolute and present
    -> factory venv ``~/.local/share/factory-venv/bin/python`` when present
    (POSIX only) -> ``sys.executable`` when it is a stable path (absolute
    and an existing file) -> else ``python3`` on POSIX / ``python`` on
    Windows. A bare ``python`` breaks on Ubuntu >=22.04 (no ``python``,
    only ``python3``), so the generated config carries an interpreter that
    exists on *this* host. Preferring the factory venv keeps ``--check``
    byte-stable whether it is invoked by the venv or by system
    ``python3`` (``verify_workspace.sh``).
  * ``basemind``: ``BASEMIND_BIN`` env -> ``shutil.which("basemind")``
    -> Windows default ``%LOCALAPPDATA%\\basemind\\bin\\basemind.exe``
    (only when that file exists). When nothing is found the server is
    omitted and a warning is printed; a dead path is never emitted.
  * ``fe-bridge``: ``FE_BRIDGE_ROOT`` env -> repo-relative
    ``.opencode-web/fe-bridge`` (requires its ``mcp.js`` to be present).
    When nothing is found the server is omitted and a warning is
    printed; a dead path is never emitted.

Workspace mode (``--workspace <dir>``) emits ``<dir>/opencode.json`` for a
session root: absolute plugin/carbon paths pinned to this harness, absolute
``cwd``, ``CARBON_HARNESS`` for the authz plugin, and one ``basemind-*``
server per lane in ``files/policies/worktree-map.json`` rooted at that lane's
absolute path. Globally-provided servers (playwright/chrome-devtools/context7)
are intentionally not duplicated.

Warnings go to stderr so ``--print`` stdout stays pure JSON.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

HARNESS_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = HARNESS_ROOT / "opencode.json"
WORKTREE_MAP = HARNESS_ROOT / "files" / "policies" / "worktree-map.json"

SCHEMA = "https://opencode.ai/config.json"
CARBON_ROLES = ("orchestrator", "builder", "auditor", "hacker", "compliance", "release-engineer", "crouton")
CARBON_ENTRY = "files/tools/mcp/__main__.py"
CARBON_TIMEOUT = {"startup": 60000, "catalog": 30000, "execution": 300000}
BASEMIND_TIMEOUT = {"startup": 120000, "catalog": 30000, "execution": 120000}
# V2 config key is the singular ``plugin`` array; ``.opencode/plugins/*`` is
# auto-discovered, but explicit entries pin load order and host parity.
PLUGIN = [
    "./.opencode/plugins/agt.js",
    "./.opencode/plugins/authz.js",
]
# Globally configured servers that a workspace config must not duplicate.
GLOBAL_SERVERS = ("playwright", "chrome-devtools", "context7")


def resolve_python() -> str:
    """Return the interpreter that generated configs must pin.

    Order (deterministic regardless of which Python runs the generator):

    1. ``CARBON_PYTHON`` when it is absolute and an existing file.
    2. The factory venv ``~/.local/share/factory-venv/bin/python`` when it
       exists (POSIX only; absent paths are skipped, so Windows is
       unaffected).
    3. ``sys.executable`` when it is absolute and an existing file.
    4. The bare name that exists on that platform: ``python3`` on POSIX,
       ``python`` on Windows.

    Pinning the factory venv keeps ``--check`` stable across callers
    (factory venv vs. system ``python3`` in ``verify_workspace.sh``).
    """
    env = os.environ.get("CARBON_PYTHON", "").strip()
    if env and os.path.isabs(env) and os.path.isfile(env):
        return env
    if not sys.platform.startswith("win"):
        venv = Path.home() / ".local" / "share" / "factory-venv" / "bin" / "python"
        if venv.is_file():
            return str(venv)
    exe = sys.executable or ""
    if exe and os.path.isabs(exe) and os.path.isfile(exe):
        return exe
    return "python" if sys.platform.startswith("win") else "python3"


def resolve_basemind() -> str | None:
    """Return the basemind binary, or None when it cannot be found."""
    env = os.environ.get("BASEMIND_BIN", "").strip()
    if env:
        return env
    found = shutil.which("basemind")
    if found:
        return found
    if sys.platform.startswith("win"):
        local = os.environ.get("LOCALAPPDATA", "").strip() or str(Path.home() / "AppData" / "Local")
        candidate = Path(local) / "basemind" / "bin" / "basemind.exe"
        if candidate.is_file():
            return str(candidate)
    return None


def resolve_fe_bridge_root() -> str | None:
    """Return the fe-bridge root directory, or None when it cannot be found.

    A repo-relative candidate counts as present only when its ``mcp.js``
    entrypoint exists, so a stray empty directory never yields a dead
    ``node <dir>/mcp.js`` command.
    """
    env = os.environ.get("FE_BRIDGE_ROOT", "").strip()
    if env:
        return env
    candidate = HARNESS_ROOT / ".opencode-web" / "fe-bridge"
    if (candidate / "mcp.js").is_file():
        return str(candidate)
    return None


def build_config() -> tuple[dict, list[str]]:
    """Build the opencode.json dict and the list of omission warnings."""
    python = resolve_python()
    warnings: list[str] = []

    servers: dict[str, dict] = {}
    for role in CARBON_ROLES:
        servers[f"carbon-{role}"] = {
            "type": "local",
            "command": [python, CARBON_ENTRY],
            "cwd": ".",
            "disabled": False,
            "codemode": False,
            "environment": {"CARBON_ROLE": role},
            "timeout": dict(CARBON_TIMEOUT),
        }

    basemind_bin = resolve_basemind()
    if basemind_bin:
        servers["basemind"] = {
            "type": "local",
            "command": [basemind_bin, "serve"],
            "cwd": ".",
            "disabled": False,
            "codemode": False,
            "timeout": dict(BASEMIND_TIMEOUT),
        }
    else:
        warnings.append(
            "warning: basemind not found (BASEMIND_BIN unset, not on PATH, "
            "no Windows default); omitting the basemind server"
        )

    fe_root = resolve_fe_bridge_root()
    if fe_root:
        fe_root_str = str(Path(fe_root))
        servers["fe-bridge"] = {
            "type": "local",
            "command": ["node", str(Path(fe_root_str) / "mcp.js")],
            "disabled": False,
            "environment": {"FE_BRIDGE_ROOT": fe_root_str},
        }
    else:
        warnings.append(
            "warning: fe-bridge not found (FE_BRIDGE_ROOT unset, no "
            ".opencode-web/fe-bridge/mcp.js); omitting the fe-bridge server"
        )

    servers["playwright"] = {
        "type": "local",
        "command": ["playwright-mcp", "--allow-unrestricted-file-access"],
        "disabled": False,
    }
    servers["chrome-devtools"] = {
        "type": "local",
        "command": ["chrome-devtools-mcp", "--isolated", "--viewport", "1280x720"],
        "disabled": False,
    }
    servers["context7"] = {
        "type": "remote",
        "url": "https://mcp.context7.com/mcp",
        "disabled": False,
    }

    config = {
        "$schema": SCHEMA,
        "default_agent": "orchestrator",
        "mcp": {"servers": servers},
        "plugin": list(PLUGIN),
    }
    return config, warnings


def load_worktree_map() -> dict[str, str]:
    """Return {lane: absolute worktree path} from the policy map.

    Lanes are read from ``files/policies/worktree-map.json``; nothing is
    hardcoded here. Relative lane paths are resolved against the harness
    root so the emitted server argv is always absolute.
    """
    data = json.loads(WORKTREE_MAP.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not data:
        raise ValueError(f"worktree map must be a non-empty object: {WORKTREE_MAP}")
    lanes: dict[str, str] = {}
    for lane, raw in data.items():
        if not isinstance(raw, str) or not raw.strip():
            raise ValueError(f"worktree map lane {lane!r} must be a non-empty path string")
        path = Path(raw)
        if not path.is_absolute():
            path = HARNESS_ROOT / path
        lanes[lane] = str(path.resolve())
    return lanes


def lane_slug(lane: str) -> str:
    """Sanitize a lane key into an opencode server-name suffix."""
    slug = "".join(ch if ch.isalnum() else "-" for ch in lane.lower())
    return "-".join(part for part in slug.split("-") if part)


def build_workspace_config(workspace: Path) -> tuple[dict, list[str]]:
    """Build the session-root config with absolute factory/lane paths."""
    python = resolve_python()
    factory = HARNESS_ROOT
    warnings: list[str] = []
    servers: dict[str, dict] = {}

    for role in CARBON_ROLES:
        servers[f"carbon-{role}"] = {
            "type": "local",
            "command": [python, str(factory / CARBON_ENTRY)],
            "cwd": str(workspace),
            "disabled": False,
            "codemode": False,
            "environment": {"CARBON_ROLE": role, "CARBON_HARNESS": str(factory)},
            "timeout": dict(CARBON_TIMEOUT),
        }

    basemind_bin = resolve_basemind()
    if not basemind_bin:
        basemind_bin = "basemind"
        warnings.append(
            "warning: basemind not found (BASEMIND_BIN unset, not on PATH, "
            "no Windows default); emitting bare 'basemind' in workspace config"
        )

    for lane, lane_path in load_worktree_map().items():
        servers[f"basemind-{lane_slug(lane)}"] = {
            "type": "local",
            "command": [basemind_bin, "serve", "--root", lane_path],
            "cwd": str(workspace),
            "disabled": False,
            "codemode": False,
            "timeout": dict(BASEMIND_TIMEOUT),
        }

    for name in GLOBAL_SERVERS:
        servers.pop(name, None)

    config = {
        "$schema": SCHEMA,
        "default_agent": "orchestrator",
        "mcp": {"servers": servers},
        "plugin": [str(factory / p) for p in PLUGIN],
    }
    return config, warnings


def serialize(config: dict) -> str:
    return json.dumps(config, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate per-host opencode.json (fail-safe: omit, never emit a dead path).")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--print", action="store_true", help="print generated JSON to stdout, do not write")
    mode.add_argument("--check", action="store_true", help="exit 1 when on-disk opencode.json differs from generated (CI drift assert)")
    mode.add_argument("--write", action="store_true", help="write opencode.json (default behaviour)")
    parser.add_argument("--out", default=None, help="output path (default: <harness root>/opencode.json)")
    parser.add_argument(
        "--workspace",
        default=None,
        help="emit a session-root config for this dir (default output <workspace>/opencode.json)",
    )
    args = parser.parse_args()

    if args.workspace:
        workspace = Path(args.workspace).expanduser().resolve()
        out_path = Path(args.out) if args.out else workspace / "opencode.json"
        try:
            config, warnings = build_workspace_config(workspace)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: cannot build workspace config: {exc}", file=sys.stderr)
            return 2
    else:
        out_path = Path(args.out) if args.out else DEFAULT_OUT
        config, warnings = build_config()
    for warning in warnings:
        print(warning, file=sys.stderr)
    text = serialize(config)

    if args.print:
        sys.stdout.write(text)
        return 0

    if args.check:
        try:
            on_disk = json.loads(out_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            print(f"check: {out_path} is missing; run python scripts/gen_opencode_config.py", file=sys.stderr)
            return 1
        except json.JSONDecodeError as exc:
            print(f"check: {out_path} is invalid JSON: {exc}", file=sys.stderr)
            return 1
        if on_disk != config:
            print(
                f"check: {out_path} differs from generated config; "
                "run python scripts/gen_opencode_config.py to regenerate",
                file=sys.stderr,
            )
            return 1
        print(f"check: {out_path} matches generated config (in sync)")
        return 0

    # default (no mode flag) and explicit --write both write opencode.json
    out_path.write_text(text, encoding="utf-8")
    print(f"wrote {out_path} ({len(config['mcp']['servers'])} servers)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
