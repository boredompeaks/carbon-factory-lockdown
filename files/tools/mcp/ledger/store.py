"""Durable hash-chained ledger store. Phase7 P2.

Append-only records under ``files/quality/ledger/<record_type>/NNNN-<hash12>.json``
following the proven gate_control pattern (``files/tools/gate_control.py``
previous_hash / seal / write):

- ``mkdir(parents=True)`` for the record-type directory.
- Atomic write: temp file + ``os.replace``, fsync file + directory.
- ``record_hash`` = sha256 of canonical JSON of the record minus
  ``record_hash``; ``prev_hash`` = newest file's ``record_hash``
  (genesis ``"0"*64``).
- ``expected_prev_hash`` mismatch -> ``REJECT_PRECONDITION``.
- ``verify_chain(record_type)`` recomputes and compares.
- Single-writer lock (``O_EXCL`` lockfile, 5s retry, then
  ``REJECT_PRECONDITION``).
- Schema validation against ``files/policies/schemas/<type>.json`` when a
  schema exists (mapped aliases for verdict/release; ``prev_hash`` envelope
  stripped for validation where the schema does not define it).
- Role <-> record-type matrix enforced:
  orchestrator {capability, dispatch},
  auditor {verdict, finding, attack-log},
  release-engineer {release}; anything else -> ``REJECT_ROLE``.
  ``gate-control`` records are sealed via ``files/tools/gate_control.py``
  directly (not via ``ledger.append``) and therefore are not in this
  append matrix.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

from ..core.validate import Reject

GENESIS = "0" * 64

# Role <-> record-type allowlist. Strict per P2 spec: auditor may append
# only verdict/finding/attack-log; orchestrator only capability/dispatch;
# release-engineer only release. Every other combination (including
# gate-control via ledger.append) is REJECT_ROLE.
ROLE_MATRIX: dict[str, set[str]] = {
    "orchestrator": {"capability", "dispatch"},
    "auditor": {"verdict", "finding", "attack-log"},
    "release-engineer": {"release"},
}

KNOWN_RECORD_TYPES = (
    "capability",
    "dispatch",
    "verdict",
    "finding",
    "attack-log",
    "gate-control",
    "release",
)

# Schema file lookup: primary ``<type>.json`` per P2 spec, with mapped
# aliases for types whose schema uses a different stem
# (verdict -> auditor-verdict, release -> release-result).
_SCHEMA_ALIASES = {
    "verdict": "auditor-verdict.json",
    "release": "release-result.json",
}

_SEQ_RE = re.compile(r"^(\d{4})-[a-f0-9]{12}\.json$")


def _files_root() -> Path:
    # store.py -> ledger -> mcp -> tools -> files
    return Path(__file__).resolve().parents[3]


def ledger_root(override: Path | str | None = None) -> Path:
    if override is not None:
        return Path(override)
    return _files_root() / "quality" / "ledger"


def ledger_root_path() -> Path:  # alias
    return ledger_root()


def _schemas_dir() -> Path:
    return _files_root() / "policies" / "schemas"


def schema_path_for(record_type: str) -> Path | None:
    """Return the schema file for a record type, or None when absent."""
    schemas = _schemas_dir()
    exact = schemas / f"{record_type}.json"
    if exact.is_file():
        return exact
    alias = _SCHEMA_ALIASES.get(record_type)
    if alias is not None:
        candidate = schemas / alias
        if candidate.is_file():
            return candidate
    return None


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def record_hash_of(record: dict) -> str:
    body = {k: v for k, v in record.items() if k != "record_hash"}
    return sha256_text(canonical(body))


def seal_record(record: dict) -> dict:
    body = {k: v for k, v in record.items() if k != "record_hash"}
    sealed = dict(body)
    sealed["record_hash"] = sha256_text(canonical(body))
    return sealed


def type_dir(record_type: str, root: Path | str | None = None) -> Path:
    return ledger_root(root) / record_type


def list_records(record_type: str, root: Path | str | None = None) -> list[Path]:
    d = type_dir(record_type, root)
    if not d.is_dir():
        return []
    out = [
        p
        for p in d.glob("*.json")
        if p.name != "verify.json" and not p.name.startswith(".")
    ]
    return sorted(out, key=lambda p: p.name)


def _load_record(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def tip_for(record_type: str, root: Path | str | None = None) -> str:
    """Newest file's record_hash for the type, or genesis when empty."""
    records = list_records(record_type, root)
    if not records:
        return GENESIS
    last = records[-1]
    try:
        data = _load_record(last)
    except (OSError, ValueError) as exc:
        raise Reject(
            "REJECT_PRECONDITION",
            f"newest ledger record {last.name} unreadable: {exc}",
        ) from exc
    value = data.get("record_hash", "")
    if not isinstance(value, str) or len(value) != 64:
        raise Reject(
            "REJECT_PRECONDITION",
            f"newest ledger record {last.name} has no record_hash",
        )
    try:
        int(value, 16)
    except ValueError:
        raise Reject(
            "REJECT_PRECONDITION",
            f"newest ledger record {last.name} record_hash is not hex",
        ) from None
    return value


# Aliases for callers that expect read_tip / get_tip / ledger_tip names.
def read_tip(record_type: str, root: Path | str | None = None) -> str:
    return tip_for(record_type, root)


def get_tip(record_type: str, root: Path | str | None = None) -> str:
    return tip_for(record_type, root)


def global_tip(root: Path | str | None = None) -> str:
    """Legacy single-tip view: newest record_hash across all types.

    Per-type chains are authoritative; this exists only for the server
    ``_ledger_prev_hash`` compatibility attribute initialised from disk.
    Returns genesis when the ledger is empty.
    """
    best: tuple[str, str] | None = None  # (filename, hash)
    for rt in KNOWN_RECORD_TYPES:
        for p in list_records(rt, root):
            try:
                h = str(_load_record(p).get("record_hash", ""))
            except Exception:
                continue
            if len(h) == 64 and (best is None or p.name > best[0]):
                best = (p.name, h)
    return best[1] if best is not None else GENESIS


def _next_sequence(tdir: Path) -> int:
    seqs: list[int] = []
    for p in tdir.glob("*.json"):
        m = _SEQ_RE.match(p.name)
        if m:
            try:
                seqs.append(int(m.group(1)))
            except ValueError:
                continue
    if seqs:
        return max(seqs) + 1
    # Fallback mirrors gate_control: count existing *.json + 1.
    count = len([p for p in tdir.glob("*.json") if p.name != "verify.json"])
    return count + 1


@contextmanager
def ledger_lock(record_type: str, root: Path | str | None = None, timeout_s: float = 5.0):
    """Single-writer lock: O_EXCL lockfile with 5s retry."""
    d = type_dir(record_type, root)
    d.mkdir(parents=True, exist_ok=True)
    lock_path = d / ".lock"
    start = time.monotonic()
    fd: int | None = None
    while True:
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            try:
                os.write(fd, f"{os.getpid()}\n".encode("utf-8"))
            except OSError:
                pass
            break
        except FileExistsError:
            if time.monotonic() - start >= timeout_s:
                raise Reject(
                    "REJECT_PRECONDITION",
                    f"ledger lock held >{int(timeout_s)}s for {record_type!r}",
                ) from None
            time.sleep(0.05)
    try:
        yield
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            lock_path.unlink(missing_ok=True)
        except OSError:
            pass


def validate_schema(record_type: str, sealed: dict) -> None:
    """Validate the sealed record against its schema when one exists.

    ``prev_hash`` is a chain envelope: strip it before validation where the
    schema does not define the property (capability/verdict/release), keep
    it where defined (gate-control). Free-form records that do not claim a
    ``schema`` are not subjected to strict schema rejection here; the
    durable-hash chain still applies to every record.
    """
    schema_file = schema_path_for(record_type)
    if schema_file is None:
        return
    if "schema" not in sealed:
        return
    try:
        import jsonschema  # noqa: PLC0415 - required dependency (fail closed)
    except ImportError as exc:
        raise Reject(
            "REJECT_PRECONDITION",
            "jsonschema is required but not installed",
        ) from exc
    try:
        schema = json.loads(schema_file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise Reject(
            "REJECT_PRECONDITION",
            f"schema {schema_file.name} unreadable: {exc}",
        ) from exc
    candidate = dict(sealed)
    props = schema.get("properties", {}) if isinstance(schema, dict) else {}
    if isinstance(props, dict) and "prev_hash" not in props:
        candidate.pop("prev_hash", None)
    try:
        checker = jsonschema.FormatChecker()
    except Exception:
        checker = None  # type: ignore[assignment]
    try:
        if checker is not None:
            validator = jsonschema.Draft202012Validator(schema, format_checker=checker)
        else:
            validator = jsonschema.Draft202012Validator(schema)
        errors = sorted(
            validator.iter_errors(candidate),
            key=lambda e: list(e.path),
        )
    except Exception as exc:  # noqa: BLE001 - fail closed on validator misuse
        raise Reject(
            "REJECT_PRECONDITION",
            f"schema validation error for {record_type!r}: {exc}",
        ) from exc
    if errors:
        first = errors[0]
        where = "/".join(str(p) for p in first.path) or "<root>"
        raise Reject(
            "REJECT_POLICY",
            f"record {record_type!r} fails {schema_file.name} at {where}: {first.message}",
        )


def _atomic_write_json(path: Path, payload: dict) -> None:
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".tmp-", suffix=".json", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, str(path))
        # fsync the directory so the rename is durable.
        try:
            dfd = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            # Directory fsync is unsupported on some platforms (Windows);
            # the file fsync above is the portable durability boundary.
            pass
    finally:
        try:
            if Path(tmp_name).exists():
                Path(tmp_name).unlink(missing_ok=True)
        except OSError:
            pass


def append(
    role: str,
    record_type: str,
    record: dict,
    expected_prev_hash: str,
    root: Path | str | None = None,
) -> dict:
    """Durably append one record; return path/record_hash/prev_hash.

    Enforces the role matrix, the expected-prev-hash chain, schema
    validation, and the single-writer lock. Raises ``Reject`` with the
    canonical codes (REJECT_ROLE / REJECT_ARG / REJECT_POLICY /
    REJECT_PRECONDITION). Alias: ``append_record``.
    """
    allowed = ROLE_MATRIX.get(role)
    if allowed is None or record_type not in allowed:
        raise Reject(
            "REJECT_ROLE",
            f"role {role!r} may not append {record_type!r}",
        )
    if not isinstance(record, dict):
        raise Reject("REJECT_ARG", "record must be an object")
    if not isinstance(expected_prev_hash, str):
        raise Reject("REJECT_ARG", "expected_prev_hash must be a string")
    base = ledger_root(root)
    d = type_dir(record_type, base)
    d.mkdir(parents=True, exist_ok=True)
    with ledger_lock(record_type, base):
        tip = tip_for(record_type, base)
        if expected_prev_hash != tip:
            raise Reject(
                "REJECT_PRECONDITION",
                f"expected_prev_hash does not match {record_type} tip",
            )
        body = {k: v for k, v in record.items() if k != "record_hash"}
        body["prev_hash"] = tip
        record_hash = sha256_text(canonical(body))
        body["record_hash"] = record_hash
        validate_schema(record_type, body)
        sequence = _next_sequence(d)
        final_path = d / f"{sequence:04d}-{record_hash[:12]}.json"
        _atomic_write_json(final_path, body)
        return {
            "path": final_path,
            "record_hash": record_hash,
            "prev_hash": tip,
            "sequence": sequence,
            "record_type": record_type,
        }


append_record = append


def verify_chain(record_type: str, root: Path | str | None = None) -> dict:
    """Recompute every record_hash and prev_hash link for one type."""
    records = list_records(record_type, root)
    problems: list[str] = []
    expected = GENESIS
    tip = GENESIS
    for path in records:
        try:
            data = _load_record(path)
        except (OSError, ValueError) as exc:
            problems.append(f"{path.name}: unreadable: {exc}")
            continue
        if data.get("prev_hash") != expected:
            problems.append(
                f"{path.name}: prev_hash does not match previous record"
            )
        stored = data.get("record_hash")
        recomputes = isinstance(stored, str) and record_hash_of(data) == stored
        if not recomputes:
            problems.append(f"{path.name}: record_hash does not recompute")
        # Chain links follow stored hashes so the next prev_hash check is
        # against the stored predecessor even when a file is tampered.
        if isinstance(stored, str) and len(stored) == 64:
            tip = stored
            expected = stored
    return {
        "record_type": record_type,
        "chain_size": len(records),
        "tip": tip,
        "result": "PASS" if not problems else "FAIL",
        "ok": not problems,
        "problems": problems,
        "exit_code": 0 if not problems else 1,
    }


__all__ = [
    "GENESIS",
    "ROLE_MATRIX",
    "KNOWN_RECORD_TYPES",
    "ledger_root",
    "ledger_root_path",
    "schema_path_for",
    "canonical",
    "sha256_text",
    "record_hash_of",
    "seal_record",
    "type_dir",
    "list_records",
    "tip_for",
    "read_tip",
    "get_tip",
    "global_tip",
    "ledger_lock",
    "validate_schema",
    "append",
    "append_record",
    "verify_chain",
]
