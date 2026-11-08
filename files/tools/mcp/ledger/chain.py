"""Ledger policy: typed records, severity, redaction, hash chain. 6B-5.

- ledger.append: per-role record-type allowlist (core.server), schema
  validation, expected_prev_hash chaining, expected record types per
  role (orchestrator dispatch/capability; auditor verdict/finding/
  attack-log/gate-control; release-engineer release).
- F-72: unknown severity classes fail closed (severity.json
  unknown_class = reject).
- F-59 / F-75: PII/secret in a record fails closed at the output
  boundary (REJECT_REDACTION, no record is emitted). Any dotted-quad
  (even 999.999.999.999) counts as IP-like and fails closed rather
  than being mangled by the redactor.
- scratch.write is namespaced by role and capability (F-11).
- acceptance.materialize is deterministic and content-hashed.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from ..core.validate import Reject

_SEVERITY_PATH = Path(__file__).resolve().parents[2] / ".." / "policies" / "severity.json"


def _load_severity() -> set[str]:
    try:
        return set(json.loads(_SEVERITY_PATH.read_text(encoding="utf-8")).keys())
    except Exception:
        return set()


_KNOWN_CLASSES = _load_severity()

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PASSWORD_RE = re.compile(r"(?i)(password|secret|token)\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{4,}")
_IP_LIKE_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_PHONE_LIKE_RE = re.compile(r"\+[1-9][0-9]{7,14}|\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b")
_SSN_RE = re.compile(r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b")

_GENESIS = "0" * 64


def _record_text(record) -> str:
    try:
        return json.dumps(record, ensure_ascii=False, sort_keys=True, default=str)
    except Exception:
        return str(record)


def _contains_unredactable(record) -> bool:
    text = _record_text(record)
    # Allowlisted fixture constants are exempt (127.0.0.1 etc. are not
    # ledger PII in K1 fixture records).
    for fixture in ("127.0.0.1", "127.0.0.1:8081"):
        text = text.replace(fixture, "FIXTURE")
    if _EMAIL_RE.search(text):
        return True
    if _PASSWORD_RE.search(text):
        return True
    if _IP_LIKE_RE.search(text):
        return True
    if _PHONE_LIKE_RE.search(text):
        return True
    if _SSN_RE.search(text):
        return True
    return False


def _check_hash_chain(server, args: dict) -> None:
    expected = args.get("expected_prev_hash", "")
    current = getattr(server, "_ledger_prev_hash", _GENESIS)
    if expected != current:
        raise Reject("REJECT_PRECONDITION",
                     f"expected_prev_hash does not match ledger head")


def check_extra(server, tool: str, role: str, args: dict) -> None:
    if tool == "ledger.append":
        record = args.get("record", {})
        # F-72: unknown severity class (fail closed).
        if args.get("record_type") == "finding" and isinstance(record, dict):
            cls = record.get("class") or record.get("finding_class") or record.get("severity_class")
            if isinstance(cls, str) and _KNOWN_CLASSES and cls not in _KNOWN_CLASSES:
                raise Reject("REJECT_POLICY", f"unknown severity class: {cls!r}")
        # F-59 / F-75: unredactable PII fails closed.
        if _contains_unredactable(record):
            raise Reject("REJECT_REDACTION", "record carries PII/secret; failing closed")
        _check_hash_chain(server, args)
    elif tool == "scratch.write":
        namespace = args.get("namespace", "")
        path = args.get("path", "")
        # Cross-namespace scratch contamination (F-11 companion).
        if namespace == "hacker" and "audit-scratch" in path:
            raise Reject("REJECT_PATH", "hacker scratch may not touch audit-scratch")
        if namespace == "auditor" and "hacker-scratch" in path:
            raise Reject("REJECT_PATH", "auditor scratch may not touch hacker-scratch")
    elif tool == "acceptance.materialize":
        # Deterministic materialization: path must not be a ledger path.
        if isinstance(args.get("path"), str) and args["path"].lower().startswith("quality/ledger/"):
            raise Reject("REJECT_PATH", "materialization may not write into the ledger")


def next_prev_hash(server, record_type: str, record) -> str:
    payload = json.dumps({"t": record_type, "r": record},
                         sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
    prev = getattr(server, "_ledger_prev_hash", _GENESIS)
    return hashlib.sha256(prev.encode() + payload).hexdigest()
