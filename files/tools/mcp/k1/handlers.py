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

U3 cross-platform routing: Windows default keeps the PowerShell scripts
(``IS_WINDOWS and POWERSHELL and not CARBON_K1_NATIVE``). POSIX, or
``CARBON_K1_NATIVE=1``, uses the native ``docker`` CLI path in this module
(no .ps1, no Docker Desktop / Start-Service). ``k1.status``/``k1.exec``
are already native and shared by both paths.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import tarfile
import time
from pathlib import Path

from ..core import platform as _platform
from ..core.validate import Reject
from .leases import _TTL_SECONDS, k1_run_dir, reap_expired_leases

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


def _run_dir(run_id: str) -> Path:
    # U3 cross-platform: core.platform.run_dir() is identical to the old
    # %LOCALAPPDATA%\Temp\opencode\k1 path on Windows and XDG/tempdir on
    # POSIX, so TTL reaping finds runs on both OSes.
    return k1_run_dir(run_id)


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
    return bool(run_dir.exists())


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


def _powershell_available() -> bool:
    try:
        _powershell()
    except Reject:
        return False
    return True


def _use_native() -> bool:
    """Native docker CLI path when POSIX, CARBON_K1_NATIVE=1, or Windows
    without resolvable PowerShell. Default Windows keeps the .ps1 path."""
    if os.environ.get("CARBON_K1_NATIVE", "") == "1":
        return True
    if not _platform.IS_WINDOWS:
        return True
    if not _powershell_available():
        return True
    return False


def _try_run(argv: list[str], timeout: int = 60) -> "subprocess.CompletedProcess | None":
    """Best-effort _run: None on spawn/timeout (callers treat as absent)."""
    try:
        return _run(argv, timeout=timeout)
    except Reject:
        return None


def _run_bytes(argv: list[str], timeout: int = 120) -> "subprocess.CompletedProcess[bytes]":
    """Binary _run (no text) for tar streaming. Same reject mapping."""
    try:
        return subprocess.run(
            argv,
            shell=False,
            capture_output=True,
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
        raise Reject(
            "REJECT_PRECONDITION",
            f"runtime unavailable: command timed out after {timeout}s: {argv[0] if argv else ''}",
        ) from exc
    except OSError as exc:
        raise Reject(
            "REJECT_PRECONDITION",
            f"runtime unavailable: failed to spawn {argv[0] if argv else ''}: {exc}",
        ) from exc


def _app_image_ref() -> str:
    # Local build tag (no pull, no build); the app image's base pin lives
    # in image-pins.json (python:3.14-slim) but the runnable image is the tag.
    return "k1-app:latest"


def _pg_image_ref() -> str:
    """Postgres pinned digest from files/docker/k1/image-pins.json."""
    pins_path = _HARNESS_ROOT / "files" / "docker" / "k1" / "image-pins.json"
    try:
        data = json.loads(pins_path.read_text(encoding="utf-8"))
        digest = data["pins"]["postgres:17-alpine"]
    except Exception as exc:
        raise Reject(
            "REJECT_PRECONDITION",
            f"runtime unavailable: image pins unreadable: {pins_path}: {exc}",
        ) from exc
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise Reject(
            "REJECT_PRECONDITION",
            "runtime unavailable: postgres pin missing in image-pins.json",
        )
    return f"postgres:17-alpine@{digest}"


def _docker_running(docker: str, name: str) -> bool:
    proc = _try_run([docker, "inspect", "-f", "{{.State.Running}}", name], timeout=30)
    return proc is not None and proc.returncode == 0 and (proc.stdout or "").strip() == "true"


def _docker_logs_tail(docker: str, name: str, lines: int = 20) -> str:
    proc = _try_run([docker, "logs", "--tail", str(lines), name], timeout=30)
    if proc is None:
        return ""
    return (proc.stdout or "") + (proc.stderr or "")


def _wait_until(docker: str, name: str, probe_argv: list[str], what: str, seconds: int = 60) -> None:
    """Poll probe_argv until exit 0 (fail fast on container exit)."""
    deadline = time.time() + seconds
    while time.time() < deadline:
        proc = _run(probe_argv, timeout=30)
        if proc.returncode == 0:
            return
        running = _run([docker, "inspect", "-f", "{{.State.Running}}", name], timeout=30)
        if running.returncode != 0 or (running.stdout or "").strip() != "true":
            detail = _trunc(_docker_logs_tail(docker, name, 20).strip(), 1000)
            raise Reject(
                "REJECT_PRECONDITION",
                f"{name} exited during startup ({what}): {detail}",
            )
        time.sleep(2)
    detail = _trunc(_docker_logs_tail(docker, name, 30).strip(), 1000)
    raise Reject(
        "REJECT_PRECONDITION",
        f"{what} timed out after {seconds}s: {detail}",
    )


def _remove_excluded(root: Path) -> int:
    """Mirror k1_up.ps1 Remove-Excluded (no venv/quality/.env* into runs)."""
    removed = 0

    def _rm(path: Path) -> None:
        nonlocal removed
        try:
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path, ignore_errors=True)
                removed += 1
            elif path.exists() or path.is_symlink():
                try:
                    path.unlink()
                    removed += 1
                except OSError:
                    pass
        except OSError:
            pass

    for rel in ("backend/venv", "backend/.venv", "quality"):
        _rm(root / rel)
    if not root.is_dir():
        return removed
    all_paths = sorted(root.rglob("*"), key=lambda p: (-len(p.parts), str(p)))
    for path in all_paths:
        if path.name.startswith(".env"):
            _rm(path)
    for path in all_paths:
        if path.name == "venv":
            _rm(path)
    for path in all_paths:
        if path.name == "quality":
            _rm(path)
    return removed


def _archive_checkout(git: str, repo: Path, sha: str, dest: Path, tar_path: Path) -> int:
    """git archive backend@sha -> dest; returns excluded count."""
    argv = [git, "-C", str(repo), "archive", "--format=tar", f"--output={tar_path}", sha, "backend"]
    proc = _run(argv)
    if proc.returncode != 0:
        detail = _trunc((proc.stderr or proc.stdout or "").strip(), 500)
        raise Reject("REJECT_PRECONDITION", f"git archive failed (exit {proc.returncode}): {detail}")
    try:
        with tarfile.open(tar_path, "r") as tf:
            try:
                tf.extractall(dest, filter="data")
            except TypeError:
                # Older Python without PEP 706 filter kwarg.
                tf.extractall(dest)  # noqa: S202
    except (tarfile.TarError, OSError) as exc:
        raise Reject("REJECT_PRECONDITION", f"tar extract failed: {exc}") from exc
    try:
        tar_path.unlink()
    except OSError:
        pass
    return _remove_excluded(dest)


def _ensure_native(server, tool: str, args: dict) -> dict:
    """``docker info`` engine check; optional ``docker start`` pg2a/pg2b."""
    docker = _docker()
    argv = [docker, "info"]
    proc = _run(argv, timeout=60)
    if proc.returncode != 0:
        detail = _trunc((proc.stderr or proc.stdout or "").strip(), 500)
        raise Reject("REJECT_PRECONDITION", f"docker ensure failed (exit {proc.returncode}): {detail}")
    lines = ["docker engine: ready"]
    ver = _try_run([docker, "info", "--format", "{{.ServerVersion}}"], timeout=30)
    if ver is not None and ver.returncode == 0 and (ver.stdout or "").strip():
        lines = [f"docker engine: ready {ver.stdout.strip()}"]
    for name in ("pg2a", "pg2b"):
        insp = _try_run([docker, "inspect", "-f", "{{.State.Running}}", name], timeout=30)
        if insp is None or insp.returncode != 0:
            continue  # not present by default (ok); never created here
        if (insp.stdout or "").strip() == "true":
            lines.append(f"container {name}: running")
            continue
        start = _try_run([docker, "start", name], timeout=60)
        if start is None or start.returncode != 0:
            code = start.returncode if start is not None else -1
            detail = ""
            if start is not None:
                detail = _trunc((start.stderr or start.stdout or "").strip(), 500)
            raise Reject("REJECT_PRECONDITION", f"docker start {name} failed (exit {code}): {detail}")
        lines.append(f"container {name}: started")
    return {
        "tool": tool,
        "action": args.get("action", "ensure"),
        "executed": True,
        "stdout": _trunc("\n".join(lines)),
        "stderr": _trunc(proc.stderr or ""),
        "evidence": _evidence(argv, proc),
    }


def _up_native(server, tool: str, args: dict) -> dict:
    """Native ``k1_up.ps1`` equivalent (same limits, pins, run dir)."""
    run_id = _check_run_id(str(args.get("run_id", "")))
    base = _check_sha(str(args.get("base", "")), "base")
    head = _check_sha(str(args.get("head", "")), "head")
    docker = _docker()
    git = _platform.git_binary()
    # Discover the worktree (mirror k1_up.ps1: git rev-parse --show-toplevel).
    repo = _HARNESS_ROOT
    disc = _try_run([git, "-C", str(_HARNESS_ROOT), "rev-parse", "--show-toplevel"], timeout=30)
    if disc is not None and disc.returncode == 0 and (disc.stdout or "").strip():
        repo = Path(disc.stdout.strip())
    if not repo.is_dir():
        raise Reject("REJECT_PRECONDITION", f"repository not found: {repo}")
    for sha in (base, head):
        chk = _try_run([git, "-C", str(repo), "cat-file", "-e", f"{sha}^{{commit}}"], timeout=30)
        if chk is None or chk.returncode != 0:
            raise Reject("REJECT_PRECONDITION", f"commit {sha} not found in {repo}")
    app_ref = _app_image_ref()
    pg_ref = _pg_image_ref()
    for ref in (app_ref, pg_ref):
        insp = _try_run([docker, "image", "inspect", ref], timeout=30)
        if insp is None or insp.returncode != 0:
            hint = (
                "; build it first (owner/FDE only): docker build --pull=false -t "
                f"{app_ref} files/docker/k1"
                if ref == app_ref
                else ""
            )
            raise Reject(
                "REJECT_PRECONDITION",
                f"k1_up: refused: IMAGE_MISSING: {ref} is not present locally (not pulling){hint}",
            )
    app = f"k1-{run_id}-app"
    pg = f"k1-{run_id}-pg"
    net = f"k1-{run_id}-net"
    for name in (net, pg, app):
        kind = "network" if name == net else "container"
        if _docker_exists(docker, kind, name):
            raise Reject("REJECT_PRECONDITION", f"{name} already exists; run k1.down first")
    run_dir = _run_dir(run_id)
    if run_dir.exists():
        raise Reject("REJECT_PRECONDITION", f"run dir {run_dir} already exists; run k1.down first")
    pg_pass = secrets.token_hex(12)
    created = {"run_dir": False, "net": False, "pg": False, "app": False}
    out_lines: list[str] = []
    app_run_argv: list[str] | None = None
    app_run_proc = None
    try:
        base_dir = run_dir / "repo-base"
        head_dir = run_dir / "repo-head"
        base_dir.mkdir(parents=True)
        head_dir.mkdir(parents=True)
        created["run_dir"] = True
        out_lines.append(f"run dir: {run_dir}")
        for sha, dest, tar_name, label in (
            (base, base_dir, "base.tar", "base"),
            (head, head_dir, "head.tar", "head"),
        ):
            excluded = _archive_checkout(git, repo, sha, dest, run_dir / tar_name)
            out_lines.append(f"archive: {label} {sha} -> {dest} (excluded={excluded})")
        # --- network ---
        net_argv = [docker, "network", "create", "--internal", net]
        net_proc = _run(net_argv)
        if _docker_exists(docker, "network", net):
            created["net"] = True
        if net_proc.returncode != 0:
            detail = _trunc((net_proc.stderr or net_proc.stdout or "").strip(), 500)
            raise Reject(
                "REJECT_PRECONDITION",
                f"docker network create {net} failed (exit {net_proc.returncode}): {detail}",
            )
        out_lines.append(f"network: {net} (internal)")
        # --- postgres (pinned digest, tmpfs 96m, cap-drop ALL, no port) ---
        pg_argv = [
            docker, "run", "-d", "--name", pg, "--network", net,
            "--tmpfs", "/var/lib/postgresql/data:rw,nosuid,nodev,size=96m",
            "--memory", "256m", "--cpus", "0.5", "--shm-size", "32m",
            "--cap-drop", "ALL",
            "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER",
            "--cap-add", "SETGID", "--cap-add", "SETUID",
            "--security-opt", "no-new-privileges",
            "-e", f"POSTGRES_PASSWORD={pg_pass}", "-e", "POSTGRES_DB=k1", pg_ref,
        ]
        pg_proc = _run(pg_argv)
        if _docker_exists(docker, "container", pg):
            created["pg"] = True
        if pg_proc.returncode != 0:
            detail = _trunc((pg_proc.stderr or pg_proc.stdout or "").strip(), 500)
            raise Reject("REJECT_PRECONDITION", f"docker run {pg} failed (exit {pg_proc.returncode}): {detail}")
        _wait_until(docker, pg, [docker, "exec", pg, "pg_isready", "-U", "postgres", "-d", "k1"], "pg_isready")
        out_lines.append(f"pg: {pg} ready ({pg_ref}, tmpfs /var/lib/postgresql/data)")
        # --- app (read-only, user 10001, tmpfs /tmp,/run,/work,/home/k1) ---
        app_run_argv = [
            docker, "run", "-d", "--name", app, "--network", net,
            "--read-only", "--user", "10001:10001",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--memory", "384m", "--memory-swap", "384m", "--cpus", "1", "--pids-limit", "256",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=32m,uid=10001,gid=10001,mode=1777",
            "--tmpfs", "/run:rw,noexec,nosuid,nodev,size=8m",
            "--tmpfs", "/work:rw,exec,nosuid,nodev,size=64m,uid=10001,gid=10001,mode=0755",
            "--tmpfs", "/home/k1:rw,noexec,nosuid,nodev,size=8m,uid=10001,gid=10001,mode=0755",
            "-v", f"{base_dir}:/repo/base:ro",
            "-v", f"{head_dir}:/repo/head:ro",
            "-e", f"DATABASE_URL=postgresql://postgres:{pg_pass}@{pg}:5432/k1",
            "-e", "FAKE_PROVIDER_URL=http://127.0.0.1:8081",
            "--log-driver", "local", "--log-opt", "max-size=1m", "--log-opt", "max-file=1",
            "--log-opt", "compress=false",
            app_ref,
        ]
        app_run_proc = _run(app_run_argv)
        if _docker_exists(docker, "container", app):
            created["app"] = True
        if app_run_proc.returncode != 0:
            detail = _trunc((app_run_proc.stderr or app_run_proc.stdout or "").strip(), 500)
            raise Reject("REJECT_PRECONDITION", f"docker run {app} failed (exit {app_run_proc.returncode}): {detail}")
        _wait_until(docker, app, [docker, "exec", app, "python", "-c", _HEALTH_PY], "app /health")
        out_lines.append(f"app: {app} healthy (fake provider http://127.0.0.1:8081)")
        out_lines.append(f"k1 up: {run_id} app={app} pg={pg} net={net}")
    except Reject:
        # Rollback (mirror k1_up.ps1 catch): remove created resources only.
        if created["app"]:
            _try_run([docker, "rm", "-f", app], timeout=60)
        if created["pg"]:
            _try_run([docker, "rm", "-f", pg], timeout=60)
        if created["net"]:
            _try_run([docker, "network", "rm", net], timeout=60)
        if created["run_dir"]:
            try:
                shutil.rmtree(run_dir, ignore_errors=True)
            except OSError:
                pass
        raise
    if app_run_argv is None or app_run_proc is None:  # unreachable; guards evidence typing
        raise Reject("REJECT_PRECONDITION", "k1 up failed: app argv missing")
    out = "\n".join(out_lines)
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
        "stdout": _trunc(out), "stderr": "",
        "evidence": _evidence(app_run_argv, app_run_proc),
    }


def _copy_artifacts_native(docker: str, app: str, run_dir: Path) -> tuple[str, str]:
    """Best-effort /work/artifacts copy. Returns (status, message) where
    status is copied/none/failed (docker cp first, tmpfs tar fallback)."""
    cp_argv = [docker, "cp", f"{app}:/work/artifacts", str(run_dir / "artifacts")]
    cp_proc = _try_run(cp_argv, timeout=120)
    if cp_proc is not None and cp_proc.returncode == 0:
        return "copied", ""
    cp_text = ""
    if cp_proc is not None:
        cp_text = ((cp_proc.stderr or "") + (cp_proc.stdout or ""))
    lower = cp_text.lower()
    is_missing = any(s in lower for s in ("no such file", "not found", "could not find"))
    if not is_missing:
        return "failed", cp_text.strip()[:200]
    if not _docker_running(docker, app):
        return "none", ""
    try:
        tar_proc = _run_bytes(
            [docker, "exec", app, "tar", "-C", "/work", "-cf", "-", "artifacts"], timeout=120
        )
    except Reject as exc:
        return "failed", str(exc)[:200]
    if tar_proc.returncode != 0:
        err = (tar_proc.stderr or b"").decode("utf-8", "replace")
        el = err.lower()
        if "no such file" in el or "not found" in el:
            return "none", ""
        return "failed", err.strip()[:200]
    try:
        run_dir.mkdir(parents=True, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(tar_proc.stdout), mode="r") as tf:
            try:
                tf.extractall(run_dir, filter="data")
            except TypeError:
                tf.extractall(run_dir)  # noqa: S202
    except (tarfile.TarError, OSError) as exc:
        return "failed", str(exc)[:200]
    return "copied", ""


def _down_native(server, tool: str, args: dict) -> dict:
    """Native ``k1_down.ps1`` equivalent (artifacts, rm -f, net, run dir)."""
    run_id = _check_run_id(str(args.get("run_id", "")))
    docker = _docker()
    keep_artifacts = bool(args.get("keep_artifacts", False))
    before = _any_exists(server, run_id)
    app = f"k1-{run_id}-app"
    pg = f"k1-{run_id}-pg"
    net = f"k1-{run_id}-net"
    run_dir = _run_dir(run_id)
    lines: list[str] = []
    last_argv: list[str] | None = None
    last_proc = None
    # Artifacts before the container goes away (best-effort, like .ps1).
    if _docker_exists(docker, "container", app):
        try:
            run_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
        status, msg = _copy_artifacts_native(docker, app, run_dir)
        if status == "copied":
            lines.append(f"artifacts: copied to {run_dir / 'artifacts'}")
        elif status == "none":
            lines.append(f"artifacts: none in {app} (ok)")
        else:
            lines.append(f"artifacts: copy failed (continuing): {msg}")
    else:
        lines.append(f"app container {app}: not found (ok)")
    for name in (app, pg):
        if _docker_exists(docker, "container", name):
            argv = [docker, "rm", "-f", name]
            proc = _run(argv, timeout=120)
            last_argv, last_proc = argv, proc
            lines.append(
                f"container {name}: removed" if proc.returncode == 0
                else f"container {name}: remove failed (continuing)"
            )
        else:
            lines.append(f"container {name}: not found (ok)")
    if _docker_exists(docker, "network", net):
        argv = [docker, "network", "rm", net]
        proc = _run(argv, timeout=60)
        last_argv, last_proc = argv, proc
        lines.append(
            f"network {net}: removed" if proc.returncode == 0
            else f"network {net}: remove failed (continuing)"
        )
    else:
        lines.append(f"network {net}: not found (ok)")
    if run_dir.exists():
        if keep_artifacts:
            lines.append(f"run dir: kept {run_dir} (-KeepArtifacts)")
        else:
            try:
                shutil.rmtree(run_dir, ignore_errors=True)
            except OSError:
                pass
            lines.append(f"run dir: removed {run_dir}")
    else:
        lines.append(f"run dir: not found (ok) {run_dir}")
    _leases(server).pop(run_id, None)
    after = _any_exists(server, run_id)
    if last_argv is None or last_proc is None:
        # Nothing to remove: still report a real executed argv as evidence.
        last_argv = [docker, "inspect", app]
        probe_proc = _run(last_argv, timeout=30)
        last_proc = probe_proc
    reaped = bool(before) and not after
    return {
        "tool": tool, "run_id": run_id,
        "executed": True, "reaped": reaped, "lease": False,
        "before": bool(before), "after": bool(after),
        "stdout": _trunc("\n".join(lines)), "stderr": "",
        "evidence": _evidence(last_argv, last_proc),
    }


def _ensure(server, tool: str, args: dict) -> dict:
    if _use_native():
        return _ensure_native(server, tool, args)
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
    if _use_native():
        return _up_native(server, tool, args)
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
    if _use_native():
        return _down_native(server, tool, args)
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
