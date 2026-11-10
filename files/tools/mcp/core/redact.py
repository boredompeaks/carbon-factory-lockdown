"""Output-boundary redaction. 6B-0.

Order: secret patterns, then PII patterns, then high-entropy fallback
with the 6A-4 fixture allowlist. Fail closed (raise) on unredactable
residue when fail_on_unredactable is true.

Git output rule: hex 32/40/64 object ids are allowed (40/64 standalone,
32 only with index/From/labelled context); recognised git diff header
lines may carry slash/filename path tokens. Random 32-char alphanumeric
tokens and named secrets still redact or fail closed.

Source of patterns: files/policies/redaction.json (version 2).
The runner contract pinned there is implemented here.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path

_POLICY_PATH = Path(__file__).resolve().parents[2] / ".." / "policies" / "redaction.json"


def _load_policy() -> dict:
    try:
        return json.loads(_POLICY_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


_POLICY = _load_policy()
_SECRET_PATTERNS = _POLICY.get("secret_patterns", [])
_PII_PATTERNS = _POLICY.get("pii_patterns", [])
_ALLOW = _POLICY.get("fixture_allowlist", {})
_EXACT_STRINGS = _ALLOW.get("exact_strings", [])
_ANCHORED = _ALLOW.get("anchored_patterns", [])

# Fallback to the well-known fixtures if policy file is unreachable.
if not _SECRET_PATTERNS:
    _SECRET_PATTERNS = [
        {"name": "generic_secret_assignment", "regex": "(?i)(api[_-]?key|secret|token|password)\\s*[:=]\\s*['\"]?[A-Za-z0-9_./+=-]{8,}",
         "replacement": "[REDACTED:SECRET:generic_secret_assignment]"},
    ]
if not _PII_PATTERNS:
    _PII_PATTERNS = [
        {"name": "email", "regex": "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}",
         "replacement": "[REDACTED:PII:email]"},
    ]
if not _EXACT_STRINGS:
    _EXACT_STRINGS = ["127.0.0.1:8081", "http://127.0.0.1:8081/health", "127.0.0.1", "k1-fake-provider/1.0",
                      "/health", "postgres:17-alpine", "python:3.14-slim"]
if not _ANCHORED:
    _ANCHORED = ["^pay_[0-9a-f]{16}$", "^ref_[0-9a-f]{16}$", "^/work/", "^/repo/"]

_ENTROPY_RE = re.compile(r"[A-Za-z0-9+/=_-]{20,}")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_SHA_RE = re.compile(r"^[a-f0-9]{40,64}$")
_ENTROPY_THRESHOLD = 4.5

# Git output rules. Hex object ids: 40/64 are safe standalone; any 7-64 hex
# is safe inside index/From/labelled context; bare 32-hex still fails closed.
# Recognised git header lines may carry path tokens (slash + filename/ext).
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_HEX_STANDALONE_LENGTHS = frozenset({40, 64})
_GIT_HEX_CONTEXT_RE = re.compile(
    r"(?i)(?:"
    r"\bindex\s+[0-9a-f]{7,64}\.\.[0-9a-f]{7,64}\b"
    r"|\bFrom\s+[0-9a-f]{7,64}\b"
    r"|\b(?:commit|tree|parent|base|head|rev|sha|hash)\b[\"']?\s*(?::|=|\s)\s*[\"']?[0-9a-f]{7,64}\b"
    r")"
)
_GIT_HEADER_RE = re.compile(
    r"(?:^diff --git a/.* b/.*"
    r"|^--- "
    r"|^\+\+\+ "
    r"|^rename from "
    r"|^rename to "
    r"|^index "
    r"|^new file mode "
    r"|^deleted file mode "
    r"|^similarity index "
    r"|^Binary files )"
)
_PATH_EXT_RE = re.compile(r"\.[A-Za-z0-9]{1,8}(?![A-Za-z0-9])")
_PATH_BASENAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._~@%+=-]*$")


class UnredactableSecret(Exception):
    """Raised when residue cannot be safely redacted; no artifact is emitted."""


def _compile(pat: dict) -> re.Pattern:
    flags = 0
    text = pat.get("regex", "")
    # Inline (?i) already carries case-insensitive; strip nothing.
    if pat.get("flags") == "i":
        flags = re.IGNORECASE
    elif "i" in str(pat.get("flags", "")):
        flags = re.IGNORECASE
    return re.compile(text, flags)


_COMPILED_SECRET = [_compile(p) for p in _SECRET_PATTERNS]
_COMPILED_PII = [_compile(p) for p in _PII_PATTERNS]
SecretNames = [p.get("name") for p in _SECRET_PATTERNS]
PiiNames = [p.get("name") for p in _PII_PATTERNS]


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_allowlisted(token: str) -> bool:
    if token in _EXACT_STRINGS:
        return True
    if _UUID_RE.match(token) or _SHA_RE.match(token):
        return True
    for pat in _ANCHORED:
        try:
            if re.match(pat, token):
                return True
        except re.error:
            continue
    return False


def _is_git_hex_allowlisted(token: str, line: str, offset: int) -> bool:
    """Allow pure hex object ids without opening the door to bare 32-hex."""
    if not _HEX_RE.match(token):
        return False
    if len(token) in _HEX_STANDALONE_LENGTHS:
        return True
    if 7 <= len(token) <= 64:
        for ctx in _GIT_HEX_CONTEXT_RE.finditer(line):
            if ctx.start() <= offset < ctx.end():
                return True
    return False


def _is_git_header_path_token(token: str, line: str, offset: int) -> bool:
    """Allow path tokens on git header lines (never on content lines)."""
    if "/" not in token or not _GIT_HEADER_RE.match(line):
        return False
    basename = token.rsplit("/", 1)[-1]
    if not _PATH_BASENAME_RE.match(basename):
        return False
    # The extension is outside the token because '.' is not a token char.
    if _PATH_EXT_RE.match(line[offset + len(token):]):
        return True
    # Header paths may also be extensionless files (Dockerfile, Makefile).
    return len(basename) >= 2


def _protect_allowlist(text: str) -> tuple[str, dict[str, str]]:
    """Replace allowlisted fixtures with placeholders before redaction."""
    protected: dict[str, str] = {}
    out = text
    # Longest first so 127.0.0.1:8081 protects before 127.0.0.1 alone.
    for i, s in enumerate(sorted(_EXACT_STRINGS, key=len, reverse=True)):
        if s and s in out:
            ph = f"\x00ALLOW_{i}\x00"
            protected[ph] = s
            out = out.replace(s, ph)
    return out, protected


def _restore_allowlist(text: str, protected: dict[str, str]) -> str:
    out = text
    for ph, s in protected.items():
        out = out.replace(ph, s)
    return out


def redact_text(text: str, *, fail_on_unredactable: bool = True) -> str:
    """Redact secrets then PII, then entropy fallback. Fail closed.

    Returns the redacted string, or raises UnredactableSecret when a
    high-entropy token matches no named pattern and is not allowlisted.
    """
    if not isinstance(text, str):
        text = json.dumps(text, ensure_ascii=False, sort_keys=True)
    protected_text, protected = _protect_allowlist(text)
    out = protected_text
    for pat, compiled in zip(_SECRET_PATTERNS, _COMPILED_SECRET):
        out = compiled.sub(pat.get("replacement", "[REDACTED]"), out)
    for pat, compiled in zip(_PII_PATTERNS, _COMPILED_PII):
        out = compiled.sub(pat.get("replacement", "[REDACTED]"), out)
    # High-entropy fallback over residue.
    for m in _ENTROPY_RE.finditer(out):
        token = m.group(0)
        line_start = out.rfind("\n", 0, m.start()) + 1
        line_end = out.find("\n", m.end())
        if line_end < 0:
            line_end = len(out)
        line = out[line_start:line_end]
        if _is_allowlisted(token):
            continue
        if _is_git_hex_allowlisted(token, line, m.start() - line_start):
            continue
        if _is_git_header_path_token(token, line, m.start() - line_start):
            continue
        if _shannon(token) >= _ENTROPY_THRESHOLD:
            if fail_on_unredactable:
                raise UnredactableSecret(
                    f"unredactable high-entropy token (len={len(token)})"
                )
            # else: fall through and emit residue (never used by server).
    return _restore_allowlist(out, protected)


def redact_value(value, *, fail_on_unredactable: bool = True):
    """Deep-redact an arbitrary tool result (strings inside structures)."""
    if isinstance(value, str):
        return redact_text(value, fail_on_unredactable=fail_on_unredactable)
    if isinstance(value, list):
        return [redact_value(v, fail_on_unredactable=fail_on_unredactable) for v in value]
    if isinstance(value, dict):
        return {k: redact_value(v, fail_on_unredactable=fail_on_unredactable) for k, v in value.items()}
    return value


def cache_key(tree: str, check_id: str | None, check_impl_sha: str, engine: str) -> str:
    """Sealing cache key: sha256 of the joined tuple."""
    joined = f"{tree}|{check_id or ''}|{check_impl_sha}|{engine or ''}"
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()
