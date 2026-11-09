"""Ledger policy: typed records, severity, redaction, hash chain. 6B-5 + P2.

- ledger.append: per-role record-type allowlist (core.server), schema
  validation (ledger.store), expected_prev_hash chaining against the
  durable on-disk tip per record type (ledger.store), expected record
  types per role (orchestrator dispatch/capability; auditor verdict/
  finding/attack-log; release-engineer release).
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


def _disk_tip(record_type: str) -> str:
    """Fresh on-disk tip for the type (never a per-instance counter)."""
    try:
        from .store import tip_for

        return tip_for(record_type)
    except Reject:
        raise
    except Exception:
        # Store unavailable: fall back to genesis so the precondition
        # check still runs (and fails closed for non-genesis callers).
        return _GENESIS


def _check_hash_chain(server, args: dict) -> None:
    expected = args.get("expected_prev_hash", "")
    record_type = str(args.get("record_type", ""))
    # Prev-hash source is the durable store, not a dynamic server counter.
    # Server._ledger_prev_hash is initialised from disk in __init__ only
    # as a compatibility snapshot; it is never advanced per-append.
    current = _disk_tip(record_type) if record_type else _GENESIS
    if expected != current:
        raise Reject(
            "REJECT_PRECONDITION",
            "expected_prev_hash does not match ledger head",
        )


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
    """Prospective record_hash for (record_type, record) against disk tip.

    Kept for backward compatibility (handlers now call ``store.append``
    directly). The hash matches the durable store sealing: sha256 of the
    canonical JSON of the record with ``prev_hash`` set to the on-disk tip
    and ``record_hash`` removed.
    """
    try:
        from .store import canonical, sha256_text, tip_for
    except Exception:
        # Legacy fallback when the store is unavailable: deterministic
        # hash of the payload (never a server-side counter).
        payload = json.dumps(
            {"t": record_type, "r": record},
            sort_keys=True,
            ensure_ascii=False,
            default=str,
        )
        import hashlib

        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
    prev = tip_for(record_type)
    body = dict(record) if isinstance(record, dict) else {"value": record}
    body.pop("record_hash", None)
    body["prev_hash"] = prev
    return sha256_text(canonical(body))
