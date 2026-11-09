"""U1 platform abstraction layer: cross-compatible platform helpers.

Windows and POSIX share one API built only on ``os``, ``sys``, ``shutil``,
``tempfile`` and ``pathlib`` -- no absolute host prefixes are hardcoded.
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

IS_WINDOWS: bool = os.name == "nt"

PYTHON: str = sys.executable

# ``None`` on POSIX regardless of what is on PATH; on Windows probe in
# preference order pwsh -> powershell -> powershell.exe.
if IS_WINDOWS:
    POWERSHELL: str | None = (
        shutil.which("pwsh")
        or shutil.which("powershell")
        or shutil.which("powershell.exe")
    )
else:
    POWERSHELL = None


def run_dir() -> Path:
    """Scratch dir for k1 runs. Pure Path return; creation is lazy.

    Windows: ``%LOCALAPPDATA%\\Temp\\opencode\\k1``.
    POSIX: ``$XDG_CACHE_HOME/opencode/k1`` or ``<tmpdir>/opencode/k1``.
    """
    if IS_WINDOWS:
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            base = Path(local_app_data)
            if base.is_absolute():
                return base / "Temp" / "opencode" / "k1"
        return Path(tempfile.gettempdir()) / "opencode" / "k1"
    xdg_cache_home = os.environ.get("XDG_CACHE_HOME")
    if xdg_cache_home:
        base = Path(xdg_cache_home)
        if base.is_absolute():
            return base / "opencode" / "k1"
    return Path(tempfile.gettempdir()) / "opencode" / "k1"


def venv_python(repo: Path) -> Path | None:
    """Return the venv interpreter under ``repo`` if one exists.

    Probes ``backend/venv`` then ``.venv`` with platform layouts
    (``Scripts/python.exe`` on Windows, ``bin/python`` on POSIX).
    Returns ``None`` when no candidate is a file.
    """
    root = Path(repo)
    if IS_WINDOWS:
        candidates = [
            root / "backend" / "venv" / "Scripts" / "python.exe",
            root / ".venv" / "Scripts" / "python.exe",
        ]
    else:
        candidates = [
            root / "backend" / "venv" / "bin" / "python",
            root / ".venv" / "bin" / "python",
        ]
    for candidate in candidates:
        try:
            if candidate.is_file():
                return candidate
        except OSError:
            continue
    return None


def tool_binary(name: str, env_var: str | None = None) -> str | None:
    """Resolve a tool binary cross-platform.

    Order: ``env_var`` override -> ``shutil.which(name)`` ->
    ``shutil.which(name + ".exe")`` (Windows only) -> ``None``.
    """
    if env_var:
        override = os.environ.get(env_var)
        if override:
            return override
    found = shutil.which(name)
    if found:
        return found
    if IS_WINDOWS:
        exe_found = shutil.which(name + ".exe")
        if exe_found:
            return exe_found
    return None


def harness_root() -> Path:
    # platform.py -> core -> mcp -> tools -> files -> <harness root>.
    # parents[3] would be files/ so the verified repo root is parents[4],
    # matching Server._harness_root (see server.py).
    return Path(__file__).resolve().parents[4]


def git_binary() -> str:
    """Resolved git binary, falling back to the bare name ``"git"``."""
    return tool_binary("git") or "git"


__all__ = [
    "IS_WINDOWS",
    "PYTHON",
    "POWERSHELL",
    "run_dir",
    "venv_python",
    "tool_binary",
    "harness_root",
    "git_binary",
]
