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

# Env keys allowlisted for child processes (toolchain context only, V1/F3).
# Comparison is case-insensitive (upper-case names below); anything else is
# scrubbed. RUFF_* is handled by prefix in _is_allowlisted().
_ENV_ALLOWLIST = frozenset({
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "COMSPEC",
    "TEMP",
    "TMP",
    "HOME",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONNOUSERSITE",
    "GITLEAKS_BIN",
    # Legacy locale essentials (test_core asserts LANG survives).
    "LANG",
    "LC_ALL",
})

# Keys that must never pass through if present in parent env.
# PYTHONPATH is intentionally NOT here (V1/F3: it is toolchain context).
_ENV_BLOCKLIST = frozenset({
    "DATABASE_URL",
    "POSTGRES_PASSWORD",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "HF_TOKEN",
    "LD_PRELOAD",
    "DYLD_INSERT_LIBRARIES",
})

# Secret-looking name shapes (V1/F3). Checked case-insensitively and the
# secret test wins over the allowlist: e.g. RUFF_API_KEY still strips.
_SECRET_SUBSTRINGS = ("KEY", "TOKEN", "SECRET", "PASSWORD")
_SECRET_PREFIXES = ("AWS_", "NOUS_")


def _is_secret_name(upper_name: str) -> bool:
    """True iff a scrubbed-env key looks like a secret / injection vector."""
    if upper_name in _ENV_BLOCKLIST:
        return True
    if upper_name.startswith(_SECRET_PREFIXES):
        return True
    if upper_name == "GITHUB_TOKEN":
        return True
    return any(sub in upper_name for sub in _SECRET_SUBSTRINGS)


def _is_allowlisted(upper_name: str) -> bool:
    """True iff a (non-secret) key is toolchain/child-safe."""
    if upper_name in _ENV_ALLOWLIST:
        return True
    if upper_name.startswith("RUFF_"):
        return True
    return False


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
        upper = str(key).upper()
        if _is_secret_name(upper):
            continue
        if _is_allowlisted(upper):
            out[key] = val
    # PYTHONNOUSERSITE is allowlisted but guaranteed even if parent lacks it.
    out.setdefault("PYTHONNOUSERSITE", "1")
    return out


def scrub_self_test() -> None:
    """V1/F3 unit assertion: toolchain survives, secrets do not.

    Run: python -m files.tools.mcp.core.config  (or import + call).
    """
    env = scrub_environment({
        "GITLEAKS_BIN": "C:/tools/gitleaks/gitleaks.exe",
        "NOUS_API_KEY": "sk-live-EXAMPLE",
        "HOME": "C:/Users/Test",
        "RUFF_CACHE_DIR": "C:/tmp/ruff",
        "AWS_SECRET_ACCESS_KEY": "EXAMPLE",
        "MY_SECRET_THING": "x",
    })
    assert env.get("GITLEAKS_BIN") == "C:/tools/gitleaks/gitleaks.exe", env
    assert "NOUS_API_KEY" not in env, env
    assert env.get("HOME") == "C:/Users/Test", env
    assert env.get("RUFF_CACHE_DIR") == "C:/tmp/ruff", env
    assert not any(k.upper() in ("AWS_SECRET_ACCESS_KEY", "MY_SECRET_THING") for k in env), env


if __name__ == "__main__":
    scrub_self_test()
    print("scrub_self_test: GITLEAKS_BIN survives, NOUS_API_KEY stripped (PASS)")


def enforce_output_cap(text: str, cap: int) -> str:
    if len(text.encode("utf-8", errors="replace")) > cap:
        return text[: max(0, cap // 2)] + "\n[OUTPUT_TRUNCATED]"
    return text
