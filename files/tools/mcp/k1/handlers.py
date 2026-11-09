"""K1 execution. 6B-3 + phase7 P3c (real docker).

Lifecycle (argv-only, shell=False, 180s cap):
- docker.ensure -> scripts/ensure_docker.ps1 -EngineOnly
- k1.up -> scripts/k1_up.ps1 -RunId -Base -Head; creates the in-memory
  TTL lease; lease expiry is the reaper (leases.reap_expired_leases).
- k1.status -> docker inspect -f "{{.State.Status}}" k1-<id>-app +
  docker ps --filter name=k1-<id>-
- k1.exec -> direct docker exec argv (no sh -c) for a fixed action
  allowlist. Direct exec is used deliberately: scripts/k1_exec.ps1
  still exposes only a free -Command string (executed inside the
  container via /bin/sh -c); this handler never passes caller or
  spec text through that string. Once the script grows -Argv
  support (argv array -> docker exec <ctr> <argv...>, no sh -c),
  k1.exec may route through it without changing the allowlist.
- k1.down -> scripts/k1_down.ps1 -RunId; reaped is a real
  before/after docker existence check, never ``existed or True``.

All real executions return executed=True plus
evidence{argv, exit_code, stdout_sha256}. A missing powershell,
docker or script is REJECT_PRECONDITION ("runtime unavailable: ...").
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from ..core.validate import Reject
from .leases import _TTL_SECONDS, reap_expired_leases

_TIMEOUT = 180
_HARNESS_ROOT = Path(__file__).resolve().parents[4]
_SCRIPTS = _HARNESS_ROOT / "scripts"
_RUN_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_SHA_RE = re.compile(r"^[a-f0-9]{40}$")

# Registry (registry.json) actions and the task brief's action names
# both map to fixed argv. Anything else is REJECT_ENUM. Inner argv
# runs inside the app container (uid/workdir per row); no sh -c.
_BACKEND_CWD = "/repo/head/backend"
_WORK_CWD = "/work"
_HEALTH_PY = "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8081/health')"

# action -> (inner argv template, workdir). pg_ping needs the run id
# for the pg hostname and is built dynamically in _inner_argv.
_ACTION_ROWS: dict[str, tuple[list[str], str]] = {
    "health_probe": (["python", "-c", _HEALTH_PY], _WORK_CWD),
    "http_get": (["python", "-c", _HEALTH_PY], _WORK_CWD),
    "run_pytest_subset": (
        ["python", "-m", "pytest", "-q", "/repo/head/backend"],
        _WORK_CWD,
    ),
    "run_migrate": (
        ["python", "manage.py", "migrate", "--noinput"],
        _BACKEND_CWD,
    ),
    "makemigrations_check": (
        ["python", "manage.py", "makemigrations", "--check", "--dry-run"],
        _BACKEND_CWD,
    ),
    # Registry enum (registry.json k1.exec.action).
    "django test": (["python", "manage.py", "test", "--verbosity", "2"], _BACKEND_CWD),
    "migrate": (["python", "manage.py", "migrate", "--noinput"], _BACKEND_CWD),
    "makemigrations check": (
        ["python", "manage.py", "makemigrations", "--check", "--dry-run"],
        _BACKEND_CWD,
    ),
    "boot test": (["python", "-c", _HEALTH_PY], _WORK_CWD),
}


def _sha(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _trunc(text: str, limit: int = 4000) -> str:
    text = text or ""
    return text if len(text) <= limit else text[:limit] + "\n[TRUNCATED]"


def _powershell() -> str:
    for name in ("powershell.exe", "powershell", "pwsh.exe", "pwsh"):
        found = shutil.which(name)
        if found:
            return found
    raise Reject("REJECT_PRECONDITION", "runtime unavailable: powershell not found on PATH")


def _docker() -> str:
    for name in ("docker.exe", "docker"):
        found = shutil.which(name)
        if found:
            return found
    raise Reject("REJECT_PRECONDITION", "runtime unavailable: docker not found on PATH")


def _script(name: str) -> Path:
    path = _SCRIPTS / name
    if not path.is_file():
        raise Reject("REJECT_PRECONDITION", f"runtime unavailable: script missing: {path}")
    return path


def _child_env() -> dict[str, str]:
    # Minimal non-secret env for powershell/docker children. PATH and
    # SystemRoot are required (the .ps1 scripts spawn docker/git/tar
    # via PATH); LOCALAPPDATA is required (k1_up/k1_down run dirs).
    # Secret-bearing keys never pass through.
    keep = (
        "PATH",
        "SystemRoot",
        "SYSTEMROOT",
        "PATHEXT",
        "TEMP",
        "TMP",
        "LOCALAPPDATA",
        "USERPROFILE",
        "LANG",
        "LC_ALL",
        "PYTHONNOUSERSITE",
    )
    env = {k: os.environ[k] for k in keep if k in os.environ}
    env.setdefault("PYTHONNOUSERSITE", "1")
    return env


def _run(argv: list[str], timeout: int = _TIMEOUT) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            argv,
            shell=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=_child_env(),
            cwd=str(_HARNESS_ROOT),
        )
    except FileNotFoundError as exc:
        raise Reject(
            "REJECT_PRECONDITION",
            f"runtime unavailable: executable not found: {argv[0] if argv else ''}: {exc}",
        ) from exc
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, (bytes, bytearray)) else (exc.stdout or "")
        partial = f"; partial stdout sha256={_sha(out)}" if out else ""
        raise Reject(
            "REJECT_PRECONDITION",
            f"runtime unavailable: command timed out after {timeout}s: {argv[0] if argv else ''}{partial}",
        ) from exc
    except OSError as exc:
        raise Reject(
            "REJECT_PRECONDITION",
            f"runtime unavailable: failed to spawn {argv[0] if argv else ''}: {exc}",
        ) from exc


def _evidence(argv: list[str], proc: subprocess.CompletedProcess) -> dict:
    return {
        "argv": list(argv),
        "exit_code": proc.returncode,
        "stdout_sha256": _sha(proc.stdout or ""),
        "stderr_sha256": _sha(proc.stderr or ""),
    }


def _check_run_id(run_id: str) -> str:
    if not isinstance(run_id, str) or not _RUN_ID_RE.fullmatch(run_id):
        raise Reject("REJECT_PATTERN", f"run_id {run_id!r} does not match ^[a-z0-9][a-z0-9_-]{{0,63}}$")
    return run_id


def _check_sha(value: str, field: str) -> str:
    if not isinstance(value, str) or not _SHA_RE.fullmatch(value):
        raise Reject("REJECT_PATTERN", f"{field} must be a 40-hex commit id")
    return value


def _leases(server) -> dict:
    leases = getattr(server, "_k1_leases", None)
    if leases is None:
        leases = {}
        try:
            server._k1_leases = leases  # type: ignore[attr-defined]
        except Exception:
            pass
    return leases


def _run_dir(run_id: str) -> Path | None:
    root = os.environ.get("LOCALAPPDATA")
    if not root:
        return None
    return Path(root) / "Temp" / "opencode" / "k1" / run_id


def _docker_exists(docker: str, kind: str, name: str) -> bool:
    # best-effort existence; missing docker counts as absent here
    # (callers that need a hard runtime check reject earlier).
    try:
        if kind == "network":
            argv = [docker, "network", "inspect", name]
        else:
            argv = [docker, "inspect", name]
        proc = subprocess.run(
            argv, shell=False, capture_output=True, text=True,
            timeout=30, env=_child_env(), cwd=str(_HARNESS_ROOT),
        )
        return proc.returncode == 0
    except Exception:
        return False


def _any_exists(server, run_id: str) -> bool:
    if run_id in _leases(server):
        return True
    app = f"k1-{run_id}-app"
    pg = f"k1-{run_id}-pg"
    net = f"k1-{run_id}-net"
    try:
        docker = _docker()
    except Reject:
        docker = None  # type: ignore[assignment]
    if docker is not None:
        if _docker_exists(docker, "container", app):
            return True
        if _docker_exists(docker, "container", pg):
            return True
        if _docker_exists(docker, "network", net):
            return True
    run_dir = _run_dir(run_id)
    return bool(run_dir is not None and run_dir.exists())


def _container_id(docker: str, name: str) -> str | None:
    try:
        proc = subprocess.run(
            [docker, "inspect", "-f", "{{.Id}}", name],
            shell=False, capture_output=True, text=True,
            timeout=30, env=_child_env(), cwd=str(_HARNESS_ROOT),
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    except Exception:
        return None
    return None


def _inner_argv(action: str, run_id: str, node: str | None) -> tuple[list[str], str]:
    if action == "pg_ping":
        pg = f"k1-{run_id}-pg"
        code = f"import socket;socket.create_connection(('{pg}',5432),timeout=5);print('pg ok')"
        return ["python", "-c", code], _WORK_CWD
    row = _ACTION_ROWS.get(action)
    if row is None:
        raise Reject("REJECT_ENUM", f"action {action!r} not in k1.exec allowlist")
    argv, workdir = row
    argv = list(argv)
    # node is the optional Django test label (registry pattern).
    if action == "django test" and node:
        argv = ["python", "manage.py", "test", str(node), "--verbosity", "2"]
    return argv, workdir


def _ensure(server, tool: str, args: dict) -> dict:
    script = _script("ensure_docker.ps1")
    ps = _powershell()
    argv = [ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), "-EngineOnly"]
    proc = _run(argv)
    if proc.returncode != 0:
        detail = _trunc((proc.stderr or proc.stdout or "").strip(), 500)
        raise Reject("REJECT_PRECONDITION", f"docker ensure failed (exit {proc.returncode}): {detail}")
    return {
        "tool": tool,
        "action": args.get("action", "ensure"),
        "executed": True,
        "stdout": _trunc(proc.stdout or ""),
        "stderr": _trunc(proc.stderr or ""),
        "evidence": _evidence(argv, proc),
    }


def _up(server, tool: str, args: dict) -> dict:
    run_id = _check_run_id(str(args.get("run_id", "")))
    base = _check_sha(str(args.get("base", "")), "base")
    head = _check_sha(str(args.get("head", "")), "head")
    script = _script("k1_up.ps1")
    ps = _powershell()
    argv = [ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script),
            "-RunId", run_id, "-Base", base, "-Head", head]
    proc = _run(argv)
    if proc.returncode != 0:
        detail = _trunc((proc.stderr or proc.stdout or "").strip(), 1000)
        raise Reject("REJECT_PRECONDITION", f"k1_up failed (exit {proc.returncode}): {detail}")
    out = proc.stdout or ""
    app = f"k1-{run_id}-app"
    pg = f"k1-{run_id}-pg"
    net = f"k1-{run_id}-net"
    for var, key in ((r"app=(\S+)", "app"), (r"pg=(\S+)", "pg"), (r"net=(\S+)", "net")):
        m = re.search(var, out)
        if m:
            if key == "app":
                app = m.group(1).strip()
            elif key == "pg":
                pg = m.group(1).strip()
            else:
                net = m.group(1).strip()
    docker = _docker()
    lease = {
        "base": base, "head": head,
        "created": time.time(), "expiry": time.time() + _TTL_SECONDS,
        "app": app, "pg": pg, "net": net,
        "app_id": _container_id(docker, app),
        "pg_id": _container_id(docker, pg),
    }
    _leases(server)[run_id] = lease
    return {
        "tool": tool, "run_id": run_id, "base": base, "head": head,
        "executed": True, "lease": True, "ttl_seconds": _TTL_SECONDS,
        "app": app, "pg": pg, "net": net,
        "app_id": lease["app_id"], "pg_id": lease["pg_id"],
        "stdout": _trunc(out), "stderr": _trunc(proc.stderr or ""),
        "evidence": _evidence(argv, proc),
    }


def _status(server, tool: str, args: dict) -> dict:
    reap_expired_leases(server)
    run_id = _check_run_id(str(args.get("run_id", "")))
    docker = _docker()
    app = f"k1-{run_id}-app"
    inspect_argv = [docker, "inspect", "-f", "{{.State.Status}}", app]
    proc = _run(inspect_argv, timeout=60)
    status = (proc.stdout or "").strip()
    if proc.returncode == 0 and status:
        state = "up" if status == "running" else status
    else:
        state = "reaped"
    ps_argv = [docker, "ps", "--filter", f"name=k1-{run_id}-", "--format", "{{.Names}}"]
    ps_proc = _run(ps_argv, timeout=60)
    containers = [ln.strip() for ln in (ps_proc.stdout or "").splitlines() if ln.strip()]
    return {
        "tool": tool, "run_id": run_id,
        "executed": True, "state": state, "container_status": status or None,
        "containers": containers, "lease": bool(_leases(server).get(run_id)),
        "ttl_seconds": _TTL_SECONDS,
        "app": app,
        "evidence": _evidence(inspect_argv, proc),
        "ps_evidence": _evidence(ps_argv, ps_proc),
        "stdout": _trunc(proc.stdout or ""), "stderr": _trunc(proc.stderr or ""),
    }


def _exec(server, tool: str, args: dict) -> dict:
    reap_expired_leases(server)
    run_id = _check_run_id(str(args.get("run_id", "")))
    lease = _leases(server).get(run_id)
    if not lease:
        raise Reject("REJECT_PRECONDITION", "no runtime")
    action = str(args.get("action", ""))
    node = args.get("node")
    if node is not None and not isinstance(node, str):
        raise Reject("REJECT_ARG", "node must be a string")
    inner, workdir = _inner_argv(action, run_id, node)
    docker = _docker()
    app = lease.get("app") or f"k1-{run_id}-app"
    argv = [docker, "exec", "-u", "10001", "-w", workdir, app, *inner]
    proc = _run(argv)
    return {
        "tool": tool, "run_id": run_id, "action": action, "node": node or None,
        "executed": True, "state": "up",
        "exit_code": proc.returncode,
        "stdout": _trunc(proc.stdout or ""), "stderr": _trunc(proc.stderr or ""),
        "evidence": _evidence(argv, proc),
    }


def _down(server, tool: str, args: dict) -> dict:
    run_id = _check_run_id(str(args.get("run_id", "")))
    script = _script("k1_down.ps1")
    ps = _powershell()
    before = _any_exists(server, run_id)
    argv = [ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script),
            "-RunId", run_id]
    proc = _run(argv)
    if proc.returncode != 0:
        detail = _trunc((proc.stderr or proc.stdout or "").strip(), 1000)
        raise Reject("REJECT_PRECONDITION", f"k1_down failed (exit {proc.returncode}): {detail}")
    _leases(server).pop(run_id, None)
    after = _any_exists(server, run_id)
    reaped = bool(before) and not after
    return {
        "tool": tool, "run_id": run_id,
        "executed": True, "reaped": reaped, "lease": False,
        "before": bool(before), "after": bool(after),
        "stdout": _trunc(proc.stdout or ""), "stderr": _trunc(proc.stderr or ""),
        "evidence": _evidence(argv, proc),
    }


def execute(server, tool: str, role: str, args: dict) -> dict | None:
    if tool == "docker.ensure":
        return _ensure(server, tool, args)
    if tool == "k1.up":
        return _up(server, tool, args)
    if tool == "k1.down":
        return _down(server, tool, args)
    if tool == "k1.status":
        return _status(server, tool, args)
    if tool == "k1.exec":
        return _exec(server, tool, args)
    return None
