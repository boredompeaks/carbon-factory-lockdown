"""Exec core config: absolute executables, scrubbed env, caps. 6B-0.

Rules (from Block 6B spec):
 - role binding is harness-injected (server instance), never a caller arg
 - spawn with shell=False and an absolute executable from config
   (no PATH lookup, reject .cmd, .bat, .ps1)
 - scrubbed environment; timeout, memory and output caps
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

_REJECTED_SUFFIXES = (".cmd", ".bat", ".ps1")

# Env keys allowlisted for child processes. Anything else is scrubbed.
_ENV_ALLOWLIST = frozenset({
    "PATH_SYSTEM",
    "SYSTEM_ROOT",
    "TEMP",
    "TMP",
    "LANG",
    "LC_ALL",
    "PYTHONPATH",
})

# Keys that must never pass through if present in parent env.
_ENV_BLOCKLIST = frozenset({
    "DATABASE_URL",
    "POSTGRES_PASSWORD",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "HF_TOKEN",
    "PYTHONPATH",
    "LD_PRELOAD",
    "DYLD_INSERT_LIBRARIES",
})


@dataclass
class ExecConfig:
    """Per-server exec config. Executables are absolute paths from config."""

    executables: dict[str, str] = field(default_factory=dict)
    timeout_seconds: int = 30
    memory_limit_mb: int = 512
    output_cap_bytes: int = 65536
    max_arg_bytes: int = 262144

    def register_executable(self, name: str, absolute_path: str) -> None:
        validate_executable(absolute_path)
        self.executables[name] = absolute_path

    def resolve(self, name: str) -> str:
        if name not in self.executables:
            raise ValueError(f"unknown executable slot: {name!r}")
        return self.executables[name]


def validate_executable(absolute_path: str) -> str:
    """Reject PATH lookups and script wrappers; require absolute path."""
    if not isinstance(absolute_path, str) or not absolute_path:
        raise ValueError("executable must be a non-empty absolute path")
    lower = absolute_path.lower()
    for suf in _REJECTED_SUFFIXES:
        if lower.endswith(suf):
            raise ValueError(f"wrapper executable rejected: {absolute_path!r}")
    if absolute_path.startswith("-"):
        raise ValueError("executable must not start with a dash")
    if os.path.isabs(absolute_path):
        return absolute_path
    # On Windows, os.path.isabs handles C:/...; also accept drive-letter form.
    if len(absolute_path) >= 3 and absolute_path[1] == ":" and absolute_path[2] in ("\\", "/"):
        return absolute_path
    raise ValueError(f"executable must be absolute (no PATH lookup): {absolute_path!r}")


def scrub_environment(parent: dict | None = None) -> dict:
    """Return a minimal scrubbed env for children. No secrets pass through."""
    src = parent if parent is not None else dict(os.environ)
    out: dict[str, str] = {}
    for key, val in src.items():
        if key in _ENV_BLOCKLIST:
            continue
        if key in _ENV_ALLOWLIST:
            out[key] = val
    # PATH is intentionally NOT inherited (children use absolute execs).
    out.setdefault("PYTHONNOUSERSITE", "1")
    return out


def enforce_output_cap(text: str, cap: int) -> str:
    if len(text.encode("utf-8", errors="replace")) > cap:
        return text[: max(0, cap // 2)] + "\n[OUTPUT_TRUNCATED]"
    return text
