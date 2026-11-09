#!/usr/bin/env python3
"""Deterministic Semgrep runner for the factory gate.

Runs the semgrep.yml ruleset when the semgrep binary is available. Default is
STRICT: exit 2 (BLOCKED) when the semgrep binary is absent (engine !=
"semgrep"); the local AST matcher (regex assisted) implementing the same seven
rules from ONE single-source list (MONEY_MODELS, WATERMARK_FIELDS,
GATEWAY_PREFIXES, GATEWAY_CALL_NAMES) runs only with --allow-fallback.
control_envelopes asserts semgrep.yml == fallback (AST probes + regex probes
+ engine parity, fail-closed when the binary is absent). Only added lines in
a unified diff are reported; pre-existing hits are counted in the envelope
as preexisting_suppressed.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

TOOL = "semgrep_runner"
VERSION = "1.0.0"
SCHEMA = "factory-tool/1"
HERE = Path(__file__).resolve().parent
DEFAULT_CONFIG = HERE.parent / "policies" / "semgrep.yml"

RULE_META = {
    "gateway-call-inside-atomic": ("GATEWAY_IN_ATOMIC", "high"),
    "lock-held-across-network-call": ("LOCK_ACROSS_NETWORK", "high"),
    "missing-idempotency-key": ("MISSING_IDEMPOTENCY", "high"),
    "mutable-default-argument": ("MUTABLE_DEFAULT", "high"),
    "bare-except": ("BARE_EXCEPT", "high"),
    "read-modify-write-without-select-for-update": ("UNSAFE_RMW", "high"),
    "non-atomic-watermark-update": ("NONATOMIC_WATERMARK", "high"),
}
CLASS_TO_RULE = {v[0]: k for k, v in RULE_META.items()}
# Single source of truth for semgrep.yml <-> fallback parity. Semgrep.yml is
# hand-written to mirror these literals; control_envelopes asserts the mirror.
MONEY_MODELS = {
    "refund",
    "payment",
    "payout",
    "ledgerentry",
    "wallettransaction",
    "moneytransfer",
    "invoice",
    "charge",
}
WATERMARK_FIELDS = {"last_used_counter", "watermark", "last_seq", "last_processed_id"}
WATERMARK_FIELD = "last_used_counter"  # kept for backward compat; use WATERMARK_FIELDS
GATEWAY_PREFIXES = (
    "requests.",
    "httpx.",
    "aiohttp.",
    "stripe.",
    "http.client.",
    "urllib.",
    "razorpay.",
)
# Bare-call family: explicit names plus any *refund*/*charge*/*capture* name.
GATEWAY_CALL_NAMES = {
    "refund_payment",
    "create_refund",
    "refund_create",
    "capture_payment",
    "create_payment",
    "create_charge",
    "capture_charge",
    "gateway_refund",
    "process_refund",
    "issue_refund",
    "refund",
    "charge",
    "capture",
}
GATEWAY_FAMILY_SUBSTRINGS = ("refund", "charge", "capture")
GATEWAY_CLIENT_CALLS = (
    ".refund.create",
    ".refunds.create",
    ".refund",
    ".charge",
    ".capture",
    ".payments.create",
    ".payouts.create",
)
NETWORK_ATTRS = {"get", "post", "put", "patch", "delete", "request", "urlopen"}


class ToolError(RuntimeError):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message):  # pragma: no cover - exercised through CLI
        raise ToolError(message)


@dataclass
class Hunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: list = field(default_factory=list)


@dataclass
class FileDiff:
    path: str
    added: dict = field(default_factory=dict)
    context: dict = field(default_factory=dict)
    removed: dict = field(default_factory=dict)
    hunks: list = field(default_factory=list)


@dataclass
class Source:
    path: str
    text: str
    lines: list
    added: set
    actual: bool = True


def fingerprint(cls: str, path: str, symbol: str, code: str) -> str:
    normalized = re.sub(r"\s+", " ", f"{symbol}|{code}").strip()
    return hashlib.sha256(f"{cls}|{path}|{normalized}".encode("utf-8")).hexdigest()[:16]


def clean_path(value: str) -> str:
    value = value.strip().split("\t")[0].strip()
    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    if value.startswith("a/") or value.startswith("b/"):
        value = value[2:]
    return value.replace("\\", "/")


def parse_diff(text: str) -> list[FileDiff]:
    files: list[FileDiff] = []
    current: FileDiff | None = None
    in_hunk = False
    old_line = new_line = 0
    old_path = ""

    for raw in text.splitlines():
        if raw.startswith("diff --git "):
            current = None
            in_hunk = False
            continue
        if raw.startswith("--- "):
            old_path = clean_path(raw[4:])
            continue
        if raw.startswith("+++ "):
            new_path = clean_path(raw[4:])
            if new_path == "/dev/null":
                current = None
                in_hunk = False
                continue
            current = FileDiff(path=new_path or old_path)
            files.append(current)
            in_hunk = False
            continue
        match = re.match(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", raw)
        if match and current is not None:
            old_line = int(match.group(1))
            old_count = int(match.group(2) or "1")
            new_line = int(match.group(3))
            new_count = int(match.group(4) or "1")
            current.hunks.append(Hunk(old_line, old_count, new_line, new_count))
            in_hunk = True
            continue
        if current is None or not in_hunk:
            continue
        if raw.startswith("\\"):
            continue
        tag = raw[:1] if raw else " "
        body = raw[1:] if raw else ""
        if tag == "+":
            current.added[new_line] = body
            new_line += 1
        elif tag == "-":
            current.removed[old_line] = body
            old_line += 1
        elif tag == " " or raw == "":
            current.context[new_line] = body
            old_line += 1
            new_line += 1
    return files


def reconstruct(fd: FileDiff, side: str) -> str:
    if side == "head":
        mapping = dict(fd.context)
        mapping.update(fd.added)
    else:
        mapping = dict(fd.context)
        mapping.update(fd.removed)
    if not mapping:
        return ""
    limit = max(mapping)
    lines = [""] * limit
    for number, content in mapping.items():
        if 1 <= number <= limit:
            lines[number - 1] = content
    return "\n".join(lines) + "\n"


def dotted(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return dotted(node.func)
    return ""


def is_gateway(call: ast.Call) -> str | None:
    name = dotted(call.func)
    if not name:
        return None
    if name.startswith(GATEWAY_PREFIXES):
        return name
    if "urlopen" in name:
        return name
    if "razorpay" in name:
        return name
    if any(name.endswith(suffix) for suffix in GATEWAY_CLIENT_CALLS):
        return name
    # The project's own seam. A gateway call wrapped by the repository is still
    # a network call; the earlier version only saw the SDK and missed
    # ``refund_payment(...)`` on the exact refund finding this tool exists for.
    # Single-source with semgrep.yml: explicit names plus the
    # *refund*/*charge*/*capture* family (substring match mirrors the yml
    # metavariable-regex family).
    leaf = name.split(".")[-1].lower()
    if leaf in GATEWAY_CALL_NAMES:
        return name
    if any(token in leaf for token in GATEWAY_FAMILY_SUBSTRINGS):
        return name
    return None


def is_select_for_update(call: ast.Call) -> bool:
    return dotted(call.func).endswith("select_for_update")


def is_atomic_with(node: ast.With) -> bool:
    for item in node.items:
        context = getattr(item, "context_expr", None)
        if context is None:
            continue
        name = dotted(context)
        if name.endswith("atomic") or name.endswith(".atomic"):
            return True
    return False


def is_mutable_default(node) -> bool:
    if isinstance(node, (ast.List, ast.Dict, ast.Set)):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        return node.func.id in {"set", "list", "dict"} and not node.args and not node.keywords
    return False


def build_symbol_map(tree: ast.AST) -> dict:
    symbols: dict[int, str] = {}

    def walk(node, prefix: str = ""):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qual = prefix + child.name
                end = getattr(child, "end_lineno", child.lineno) or child.lineno
                for line in range(child.lineno, end + 1):
                    symbols[line] = qual
                walk(child, qual + ".")
            elif isinstance(child, ast.ClassDef):
                qual = prefix + child.name
                end = getattr(child, "end_lineno", child.lineno) or child.lineno
                for line in range(child.lineno, end + 1):
                    symbols.setdefault(line, qual)
                walk(child, qual + ".")
            else:
                walk(child, prefix)

    walk(tree)
    return symbols


def nearest_function(node, parents):
    parent = parents.get(node)
    while parent is not None:
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return parent
        parent = parents.get(parent)
    return None


def enclosing_atomic(node, parents) -> bool:
    parent = parents.get(node)
    while parent is not None:
        if isinstance(parent, ast.With) and is_atomic_with(parent):
            return True
        parent = parents.get(parent)
    return False


def ast_analyze(src: Source) -> tuple[list, int]:
    try:
        tree = ast.parse(src.text)
    except SyntaxError:
        return regex_analyze(src)

    parents = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    symbols = build_symbol_map(tree)
    hits: dict[tuple, dict] = {}
    preexisting: set[tuple] = set()

    def add(cls: str, line: int, message: str, evidence: str):
        symbol = symbols.get(line, "<module>")
        key = (cls, line, symbol)
        if line not in src.added:
            preexisting.add(key)
            return
        if key in hits:
            return
        hits[key] = {
            "rule_id": CLASS_TO_RULE[cls],
            "class": cls,
            "tier": "high",
            "path": src.path,
            "line": line,
            "symbol": symbol,
            "severity": "ERROR",
            "message": message,
            "evidence": evidence.strip()[:160],
            "fingerprint": fingerprint(cls, src.path, symbol, evidence),
        }

    def source_line(line: int) -> str:
        return src.lines[line - 1] if 0 < line <= len(src.lines) else ""

    functions = [
        n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    function_select = {
        id(fn): any(isinstance(n, ast.Call) and is_select_for_update(n) for n in ast.walk(fn))
        for fn in functions
    }

    # Rule 4: mutable default arguments.
    for fn in functions:
        args = fn.args
        defaults = args.defaults
        positional = args.args
        if not defaults:
            continue
        for arg, default in zip(positional[-len(defaults):], defaults):
            if is_mutable_default(default):
                evidence = source_line(default.lineno)
                add(
                    "MUTABLE_DEFAULT",
                    fn.lineno,
                    f"Mutable default argument '{arg.arg}' is shared across calls.",
                    evidence,
                )

    # Rule 5: bare except.
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            add(
                "BARE_EXCEPT",
                node.lineno,
                "Bare except catches every exception and hides failures.",
                source_line(node.lineno),
            )

    # Rule 3: missing idempotency key on money-model writes.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute):
            continue
        if func.attr in {"create", "update_or_create", "get_or_create", "bulk_create"}:
            if not isinstance(func.value, ast.Attribute) or func.value.attr != "objects":
                continue
            model = dotted(func.value.value).split(".")[-1].lower()
            if model not in MONEY_MODELS:
                continue
            keywords = {kw.arg for kw in node.keywords if kw.arg}
            if "idempotency_key" not in keywords:
                add(
                    "MISSING_IDEMPOTENCY",
                    node.lineno,
                    f"{model} write has no idempotency_key; retries can double-write.",
                    source_line(node.lineno),
                )

    # Rule 1 and 2: network calls inside atomic / while a row lock is held.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        gateway = is_gateway(node)
        if not gateway:
            continue
        if enclosing_atomic(node, parents):
            add(
                "GATEWAY_IN_ATOMIC",
                node.lineno,
                f"Gateway call {gateway}() runs inside transaction.atomic().",
                source_line(node.lineno),
            )
        parent = parents.get(node)
        while parent is not None:
            if isinstance(parent, (ast.With, ast.FunctionDef, ast.AsyncFunctionDef)):
                select_calls = [
                    n
                    for n in ast.walk(parent)
                    if isinstance(n, ast.Call) and is_select_for_update(n)
                ]
                if select_calls and node.lineno > min(n.lineno for n in select_calls):
                    add(
                        "LOCK_ACROSS_NETWORK",
                        node.lineno,
                        f"Gateway call {gateway}() runs while select_for_update() holds a lock.",
                        source_line(node.lineno),
                    )
                    break
            parent = parents.get(parent)

    # Rule 6: read-modify-write without select_for_update.
    save_calls = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "save"
        ):
            fn = nearest_function(node, parents)
            receiver = dotted(node.func.value)
            if fn is not None and receiver:
                save_calls.append((fn, receiver, node.lineno))

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets = node.targets
            value = node.value
        elif isinstance(node, ast.AugAssign):
            targets = [node.target]
            value = node.value
        else:
            continue
        if len(targets) != 1 or not isinstance(targets[0], ast.Attribute):
            continue
        target = targets[0]
        base = dotted(target.value)
        if not base:
            continue
        repeated = any(
            isinstance(n, ast.Attribute) and dotted(n) == dotted(target)
            for n in ast.walk(value)
        )
        if not repeated:
            continue
        fn = nearest_function(node, parents)
        if fn is None or function_select.get(id(fn), False):
            continue
        saves = [s for s in save_calls if s[0] is fn and s[1] == base and s[2] > node.lineno]
        if saves:
            save_line = min(s[2] for s in saves)
            report_line = save_line if save_line in src.added else node.lineno
            add(
                "UNSAFE_RMW",
                report_line,
                f"Read-modify-write of {base}.{target.attr} saved without select_for_update().",
                f"{source_line(node.lineno).strip()} -> {source_line(save_line).strip()}",
            )

    # Rule 7: non-atomic watermark update. Single-source fields with
    # semgrep.yml: last_used_counter + watermark/last_seq/last_processed_id,
    # plus update()/F() writes.
    def _is_f_call(n) -> bool:
        if not isinstance(n, ast.Call):
            return False
        return dotted(n.func) == "F" or dotted(n.func).endswith(".F")

    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Attribute) or target.attr not in WATERMARK_FIELDS:
            continue
        base = dotted(target.value)
        field = target.attr
        if not base:
            continue
        # update()/F() write: assignment whose RHS is/contain F(...) mirrors
        # yml `$DEVICE.<field> = F(...)`.
        if any(_is_f_call(n) for n in ast.walk(node.value)):
            add(
                "NONATOMIC_WATERMARK",
                node.lineno,
                f"{base}.{field} is updated with F() outside an atomic compare-and-swap.",
                source_line(node.lineno),
            )
            continue
        fn = nearest_function(node, parents)
        if fn is None:
            continue
        for call in ast.walk(fn):
            if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
                continue
            if call.func.attr != "save" or dotted(call.func.value) != base:
                continue
            keywords = {kw.arg for kw in call.keywords if kw.arg}
            if "update_fields" not in keywords or call.lineno <= node.lineno:
                continue
            if enclosing_atomic(call, parents):
                continue
            report_line = call.lineno if call.lineno in src.added else node.lineno
            add(
                "NONATOMIC_WATERMARK",
                report_line,
                f"{base}.{field} is updated outside an atomic compare-and-swap.",
                f"{source_line(node.lineno).strip()} -> {source_line(call.lineno).strip()}",
            )
            break

    # update() writes: $MODEL.objects.filter(...).update(<watermark_field>=...)
    # or $QS.update(<watermark_field>=...), including F(...) values. Mirrors
    # yml `.update(<field>=...)` / `.update(<field>=F(...))`.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "update":
            continue
        fields = {kw.arg for kw in node.keywords if kw.arg}
        hit = fields & WATERMARK_FIELDS
        if hit:
            add(
                "NONATOMIC_WATERMARK",
                node.lineno,
                f"update() writes watermark field {sorted(hit)[0]} outside an atomic compare-and-swap.",
                source_line(node.lineno),
            )

    findings = sorted(
        hits.values(),
        key=lambda f: (f["path"], f["line"], f["rule_id"], f["fingerprint"]),
    )
    return findings, len(preexisting)


def regex_analyze(src: Source) -> tuple[list, int]:
    lines = src.lines
    hits: dict[tuple, dict] = {}
    preexisting: set[tuple] = set()

    def symbol_at(line: int) -> str:
        current = lines[line - 1]
        current_def = re.match(r"^\s*(?:async\s+)?def\s+(\w+)", current)
        if current_def:
            return current_def.group(1)
        name = "<module>"
        indent = len(current) - len(current.lstrip())
        for index in range(line - 1, -1, -1):
            text = lines[index]
            match = re.match(r"^(\s*)(?:async\s+)?def\s+(\w+)", text)
            if match and len(match.group(1)) < indent:
                name = match.group(2)
                break
        return name

    def add(cls: str, line: int, message: str, evidence: str):
        symbol = symbol_at(line)
        key = (cls, line, symbol)
        if line not in src.added:
            preexisting.add(key)
            return
        if key in hits:
            return
        hits[key] = {
            "rule_id": CLASS_TO_RULE[cls],
            "class": cls,
            "tier": "high",
            "path": src.path,
            "line": line,
            "symbol": symbol,
            "severity": "ERROR",
            "message": message,
            "evidence": evidence.strip()[:160],
            "fingerprint": fingerprint(cls, src.path, symbol, evidence),
        }

    atomic_stack: list[tuple[int, int]] = []
    def_ranges = []
    stack = []
    for index, text in enumerate(lines, start=1):
        if not text.strip():
            continue
        indent = len(text) - len(text.lstrip())
        match = re.match(r"^\s*(?:async\s+)?def\s+(\w+)", text)
        if match:
            while stack and indent <= stack[-1][1]:
                start, _, name = stack.pop()
                def_ranges.append((start, index - 1, name))
            stack.append((index, indent, match.group(1)))
    while stack:
        start, _, name = stack.pop()
        def_ranges.append((start, len(lines), name))

    for index, text in enumerate(lines, start=1):
        stripped = text.strip()
        indent = len(text) - len(text.lstrip())
        while atomic_stack and stripped and indent <= atomic_stack[-1][0]:
            atomic_stack.pop()
        if re.match(r"^\s*with\s+.*atomic\s*\(", text):
            atomic_stack.append((indent, index))
            continue
        if atomic_stack and not stripped.startswith(("def ", "async def ")):
            gateway_re = (
                r"\b(?:requests|httpx|aiohttp|stripe|http\.client|urllib|razorpay)\.\w+\s*\("
                r"|\burlopen\s*\("
                r"|[\w.]+\.(?:refund|charge|capture)(?:\.create)?\s*\("
                r"|[\w.]+\.payments\.create\s*\("
                r"|[\w.]+\.payouts\.create\s*\("
                r"|\b\w*(?:refund|charge|capture)\w*\s*\("
            )
            if re.search(gateway_re, text, re.IGNORECASE):
                add(
                    "GATEWAY_IN_ATOMIC",
                    index,
                    "Gateway call runs inside transaction.atomic().",
                    text,
                )

        mutable = re.match(
            r"^\s*(?:async\s+)?def\s+\w+\s*\([^)]*=\s*(\[\]|\{\}|set\(\))", text
        )
        if mutable:
            add(
                "MUTABLE_DEFAULT",
                index,
                "Mutable default argument is shared across calls.",
                text,
            )
        if re.match(r"^\s*except\s*:", text):
            add("BARE_EXCEPT", index, "Bare except catches every exception.", text)

        write = re.search(
            r"([A-Za-z_]\w*)\.objects\.(create|update_or_create|get_or_create|bulk_create)\s*\(",
            text,
        )
        if write and write.group(1).lower() in MONEY_MODELS:
            chunk = text
            depth = text.count("(") - text.count(")")
            look = index
            while depth > 0 and look < len(lines) and look - index < 15:
                chunk += "\n" + lines[look]
                depth += lines[look].count("(") - lines[look].count(")")
                look += 1
            if "idempotency_key" not in chunk:
                add(
                    "MISSING_IDEMPOTENCY",
                    index,
                    f"{write.group(1).lower()} write has no idempotency_key.",
                    text,
                )

        save_write = None  # save() is a state transition, not a new money write.

        rmw = re.match(
            r"^\s*([A-Za-z_][\w.]*)\.(\w+)\s*=\s*\1\.\2\s*\+", text
        )
        if rmw:
            base = rmw.group(1)
            save_line = None
            for look in range(index, min(index + 10, len(lines) + 1)):
                if re.match(rf"^\s*{re.escape(base)}\.save\s*\(", lines[look - 1]):
                    save_line = look
                    break
            block = next(
                ((a, b) for a, b, _ in def_ranges if a <= index <= b), (index, index)
            )
            block_text = "\n".join(lines[block[0] - 1:block[1]])
            if save_line and "select_for_update" not in block_text:
                report_line = save_line if save_line in src.added else index
                add(
                    "UNSAFE_RMW",
                    report_line,
                    f"Read-modify-write of {base}.{rmw.group(2)} saved without select_for_update().",
                    f"{stripped} -> {lines[save_line - 1].strip()}",
                )

        watermark = re.match(
            r"^\s*([A-Za-z_][\w.]*)\.(last_used_counter|watermark|last_seq|last_processed_id)\s*=",
            text,
        )
        if watermark:
            base = watermark.group(1)
            field = watermark.group(2)
            # F() write: `$OBJ.<field> = F(...)` mirrors yml standalone.
            if re.search(r"=\s*F\s*\(", text):
                add(
                    "NONATOMIC_WATERMARK",
                    index,
                    f"{base}.{field} is updated with F() outside an atomic compare-and-swap.",
                    text,
                )
            else:
                for look in range(index + 1, min(index + 8, len(lines) + 1)):
                    if re.match(
                        rf"^\s*{re.escape(base)}\.save\s*\(.*update_fields", lines[look - 1]
                    ):
                        report_line = look if look in src.added else index
                        add(
                            "NONATOMIC_WATERMARK",
                            report_line,
                            f"{base}.{field} is updated outside an atomic compare-and-swap.",
                            f"{stripped} -> {lines[look - 1].strip()}",
                        )
                        break

        # update() writes: `.update(<watermark_field>=...)` mirrors yml.
        if re.search(
            r"\.update\s*\([^)]*\b(last_used_counter|watermark|last_seq|last_processed_id)\s*=",
            text,
        ):
            add(
                "NONATOMIC_WATERMARK",
                index,
                "update() writes a watermark field outside an atomic compare-and-swap.",
                text,
            )

    for start, end, name in def_ranges:
        select_line = None
        for index in range(start, end + 1):
            if "select_for_update" in lines[index - 1]:
                select_line = index
                break
        if select_line is None:
            continue
        for index in range(select_line + 1, end + 1):
            lock_candidate = lines[index - 1]
            lock_stripped = lock_candidate.strip()
            if lock_stripped.startswith(("def ", "async def ")):
                continue
            lock_re = (
                r"\b(?:requests|httpx|aiohttp|stripe|http\.client|urllib|razorpay)\.\w+\s*\("
                r"|\burlopen\s*\("
                r"|[\w.]+\.(?:refund|charge|capture)(?:\.create)?\s*\("
                r"|[\w.]+\.payments\.create\s*\("
                r"|[\w.]+\.payouts\.create\s*\("
                r"|\b\w*(?:refund|charge|capture)\w*\s*\("
            )
            if re.search(lock_re, lock_candidate, re.IGNORECASE):
                add(
                    "LOCK_ACROSS_NETWORK",
                    index,
                    "Gateway call runs while select_for_update() holds a lock.",
                    lines[index - 1],
                )
                break

    findings = sorted(
        hits.values(),
        key=lambda f: (f["path"], f["line"], f["rule_id"], f["fingerprint"]),
    )
    return findings, len(preexisting)


def semgrep_symbol(path: Path, line: int) -> str:
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        return build_symbol_map(tree).get(line, "<module>")
    except Exception:
        return "<module>"


def run_semgrep(resolved_paths: list[Path], config: Path) -> list[dict]:
    binary = shutil.which("semgrep")
    if not binary:
        return []
    cmd = [
        binary,
        "--config",
        str(config),
        "--json",
        "--severity",
        "ERROR",
        "--quiet",
        *[str(p) for p in resolved_paths],
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=600,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ToolError(f"semgrep failed to run: {exc}") from exc
    if proc.returncode not in (0, 1):
        raise ToolError(f"semgrep exited {proc.returncode}: {proc.stderr.strip()[:300]}")
    try:
        payload = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise ToolError(f"semgrep returned invalid JSON: {exc}") from exc
    return payload.get("results", [])


def build_finding(
    cls: str,
    rule_id: str,
    path: str,
    line: int,
    symbol: str,
    message: str,
    evidence: str,
) -> dict:
    return {
        "rule_id": rule_id,
        "class": cls,
        "tier": "high",
        "path": path,
        "line": line,
        "symbol": symbol,
        "severity": "ERROR",
        "message": message.strip(),
        "evidence": evidence.strip()[:160],
        "fingerprint": fingerprint(cls, path, symbol, evidence),
    }


def map_semgrep_results(
    results: list[dict], display_by_real: dict, sources: dict, engine_limited: bool
) -> tuple[list, int]:
    findings = []
    preexisting = 0
    for result in results:
        raw_path = result.get("path", "")
        real = str(Path(raw_path).resolve())
        display = display_by_real.get(real, raw_path.replace("\\", "/"))
        source = sources.get(display)
        check_id = result.get("check_id", "")
        short = check_id.rsplit(".", 1)[-1]
        metadata = (result.get("extra") or {}).get("metadata") or {}
        cls = metadata.get("class") or RULE_META.get(short, (short.upper(), "high"))[0]
        tier = metadata.get("tier") or "high"
        line = int((result.get("start") or {}).get("line", 0) or 0)
        if source is not None and line not in source.added and engine_limited:
            preexisting += 1
            continue
        if source is not None:
            symbol = build_symbol_map(ast.parse(source.text)).get(line, "<module>") if _parses(source.text) else "<module>"
            evidence = source.lines[line - 1] if 0 < line <= len(source.lines) else ""
        else:
            symbol = semgrep_symbol(Path(raw_path), line)
            evidence = ((result.get("extra") or {}).get("lines") or "").strip()
        message = (result.get("extra") or {}).get("message") or short
        finding = build_finding(cls, short, display, line, symbol, message, evidence)
        finding["tier"] = tier
        findings.append(finding)
    return findings, preexisting


def _parses(text: str) -> bool:
    try:
        ast.parse(text)
        return True
    except SyntaxError:
        return False


def collect(
    diff_text: str | None,
    path_args: list[str],
    repo: str | None,
    config: Path,
    allow_fallback: bool = False,
) -> tuple[list, int, int, str, dict]:
    """Return findings, preexisting count, files scanned, engine, extra stats."""
    binary = shutil.which("semgrep")
    engine = "semgrep" if binary else "fallback"
    if engine != "semgrep" and not allow_fallback:
        raise ToolError(
            "BLOCKED: semgrep binary not found on PATH; engine != semgrep "
            "(fallback) is forbidden without --allow-fallback"
        )
    repo_root = Path(repo).resolve() if repo else Path.cwd()
    sources: dict[str, Source] = {}
    display_by_real: dict[str, str] = {}
    fd_by_path: dict[str, FileDiff] = {}

    if diff_text is not None:
        for fd in parse_diff(diff_text):
            fd_by_path[fd.path] = fd
        if not fd_by_path:
            # Empty diff fails closed (PASS=False): it is BLOCKED
            # (exit 2), never a PASS. Documented strict behavior.
            raise ToolError("no file changes found in diff (empty diff fails closed; PASS=False)")
        for path, fd in fd_by_path.items():
            candidate = (repo_root / path).resolve()
            if candidate.is_file():
                text = candidate.read_text(encoding="utf-8-sig", errors="replace")
                actual = True
            else:
                text = reconstruct(fd, "head")
                actual = False
            if not text:
                continue
            src = Source(
                path=path,
                text=text,
                lines=text.splitlines(),
                added=set(fd.added),
                actual=actual,
            )
            sources[path] = src
            if actual:
                display_by_real[str(candidate)] = path
        mode = "diff"
    else:
        if not path_args:
            raise ToolError("either --diff or --paths is required")
        for raw in path_args:
            candidate = Path(raw)
            if not candidate.is_absolute():
                joined = repo_root / raw
                candidate = joined if joined.exists() else candidate
            candidate = candidate.resolve()
            if not candidate.is_file():
                raise ToolError(f"file not found: {raw}")
            text = candidate.read_text(encoding="utf-8-sig", errors="replace")
            display = clean_path(raw)
            if Path(raw).is_absolute():
                display = str(raw).replace("\\", "/")
            source = Source(
                path=display,
                text=text,
                lines=text.splitlines(),
                added=set(range(1, len(text.splitlines()) + 1)),
                actual=True,
            )
            sources[display] = source
            display_by_real[str(candidate)] = display
        mode = "paths"

    findings: list[dict] = []
    preexisting = 0
    if engine == "semgrep":
        resolved = [Path(real) for real in display_by_real]
        results: list[dict] = []
        if diff_text is not None:
            # Files absent from disk are materialised in a temp tree for semgrep.
            missing = [s for s in sources.values() if not s.actual]
            if missing:
                with tempfile.TemporaryDirectory(prefix="factory-semgrep-") as tmp:
                    tmp_root = Path(tmp)
                    for source in missing:
                        target = tmp_root / source.path
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_text(source.text, encoding="utf-8")
                        resolved.append(target)
                        display_by_real[str(target.resolve())] = source.path
                    results = run_semgrep(resolved, config)
            else:
                results = run_semgrep(resolved, config)
        else:
            results = run_semgrep(resolved, config)
        findings, preexisting = map_semgrep_results(
            results, display_by_real, sources, engine_limited=True
        )
    else:
        for source in sources.values():
            hits, suppressed = ast_analyze(source)
            findings.extend(hits)
            preexisting += suppressed

    # Syntax warnings: files that do not parse as Python are analyzed
    # via the regex fallback (fail-closed parity), but the syntax
    # failure is recorded as a warning instead of passing silently.
    syntax_warnings = sum(1 for src in sources.values() if not _parses(src.text))
    findings.sort(key=lambda f: (f["path"], f["line"], f["rule_id"], f["fingerprint"]))
    stats = {"mode": mode, "files": len(sources), "syntax_warnings": syntax_warnings}
    return findings, preexisting, len(sources), engine, stats


def _probe_classes(code: str) -> set:
    source = Source(
        path="probe.py",
        text=code,
        lines=code.splitlines(),
        added=set(range(1, len(code.splitlines()) + 1)),
    )
    findings, _ = ast_analyze(source)
    return {f["class"] for f in findings}


def _probe_classes_regex(code: str) -> set:
    """Probe through regex_analyze alone (the SyntaxError fallback path)."""
    source = Source(
        path="probe.py",
        text=code,
        lines=code.splitlines(),
        added=set(range(1, len(code.splitlines()) + 1)),
    )
    findings, _ = regex_analyze(source)
    return {f["class"] for f in findings}


def control_envelopes(config: Path) -> dict:
    fixtures = HERE / "fixtures" / "semgrep"
    bad = fixtures / "bad.py"
    clean = fixtures / "clean.py"
    cases = []
    bad_findings, _, _, bad_engine, _ = collect(None, [str(bad)], None, config, allow_fallback=True)
    clean_findings, _, _, _, _ = collect(None, [str(clean)], None, config, allow_fallback=True)
    bad_classes = sorted({f["class"] for f in bad_findings})
    clean_classes = sorted({f["class"] for f in clean_findings})
    bad_passed = len(bad_findings) >= 2 and {
        "GATEWAY_IN_ATOMIC",
        "BARE_EXCEPT",
    }.issubset(bad_classes)
    clean_passed = len(clean_findings) == 0
    cases.append(
        {
            "name": "semgrep/bad.py",
            "passed": bad_passed,
            "expected": ">=2 findings incl. GATEWAY_IN_ATOMIC and BARE_EXCEPT",
            "actual": {"findings": len(bad_findings), "classes": bad_classes},
        }
    )
    cases.append(
        {
            "name": "semgrep/clean.py",
            "passed": clean_passed,
            "expected": "0 findings",
            "actual": {"findings": len(clean_findings), "classes": clean_classes},
        }
    )
    # Parity: semgrep.yml == fallback. Static token mirror plus fallback probes;
    # engine comparison when the semgrep binary is present (otherwise
    # documented fallback-only parity).
    try:
        yml_text = config.read_text(encoding="utf-8")
    except OSError:
        yml_text = ""
    yml_lower = yml_text.lower()
    required_tokens = [
        "charge", "invoice", "bulk_create",
        "last_used_counter", "watermark", "last_seq", "last_processed_id",
        "httpx.", "aiohttp.", "stripe.", "http.client",
        "gateway_refund", "process_refund", "issue_refund",
        "$client.refund", "$client.charge", "$client.capture",
        "refund|charge|capture",
    ]
    missing_tokens = [t for t in required_tokens if t not in yml_lower]
    probes = [
        ("probe/charge-idempotency", "def f():\n    Charge.objects.create(amount=1)\n", "MISSING_IDEMPOTENCY"),
        ("probe/invoice-bulk-create", "def f():\n    Invoice.objects.bulk_create([])\n", "MISSING_IDEMPOTENCY"),
        ("probe/watermark-save", "def f(obj):\n    obj.watermark = 5\n    obj.save(update_fields=[\"watermark\"])\n", "NONATOMIC_WATERMARK"),
        ("probe/watermark-update", "def f():\n    Device.objects.filter(id=1).update(last_seq=5)\n", "NONATOMIC_WATERMARK"),
        ("probe/watermark-F", "def f(obj):\n    obj.last_seq = F(\"last_seq\") + 1\n", "NONATOMIC_WATERMARK"),
        ("probe/gateway-httpx", "from django.db import transaction\ndef f():\n    with transaction.atomic():\n        httpx.post(\"https://example.com\")\n", "GATEWAY_IN_ATOMIC"),
        # Phase 5 P1: the three classes previously probe-less (executor
        # parity asserted only 6 of the 7 rules).
        ("probe/lock-across-network", "def f():\n    obj = Book.objects.select_for_update().get(id=1)\n    requests.post(\"https://example.com\")\n", "LOCK_ACROSS_NETWORK"),
        ("probe/mutable-default", "def f(x=[]):\n    return x\n", "MUTABLE_DEFAULT"),
        ("probe/unsafe-rmw", "def f(obj):\n    obj.count = obj.count + 1\n    obj.save()\n", "UNSAFE_RMW"),
    ]
    probe_results = []
    probes_passed = True
    for name, code, want in probes:
        got = _probe_classes(code)
        ok = want in got
        probes_passed = probes_passed and ok
        probe_results.append({"name": name, "passed": ok, "expected": want, "actual": sorted(got)})
    # Regex fallback parity: same probes through regex_analyze (no AST), so
    # the SyntaxError fallback path cannot pass by note.
    regex_results = []
    regex_passed = True
    for name, code, want in probes:
        got = _probe_classes_regex(code)
        ok = want in got
        regex_passed = regex_passed and ok
        regex_results.append({"name": name, "passed": ok, "expected": want, "actual": sorted(got)})
    cases.append(
        {
            "name": "semgrep/parity-yml-tokens",
            "passed": not missing_tokens,
            "expected": "yml contains charge/invoice/bulk_create, all watermark fields, httpx/aiohttp/stripe/http.client, gateway_refund/process_refund/issue_refund, client refund/charge/capture, refund|charge|capture family",
            "actual": {"missing": missing_tokens},
        }
    )
    cases.append(
        {
            "name": "semgrep/parity-fallback-probes",
            "passed": probes_passed,
            "expected": "AST fallback flags charge/invoice/bulk_create, watermark save/update/F, httpx gateway, lock-across-network, mutable-default, unsafe-rmw",
            "actual": {"probes": probe_results},
        }
    )
    cases.append(
        {
            "name": "semgrep/parity-regex-probes",
            "passed": regex_passed,
            "expected": "regex fallback flags charge/invoice/bulk_create, watermark save/update/F, httpx gateway, lock-across-network, mutable-default, unsafe-rmw",
            "actual": {"probes": regex_results},
        }
    )
    binary = shutil.which("semgrep")
    if binary:
        # Engine parity: run semgrep binary on the same probes and compare.
        engine_results = []
        engine_ok = True
        with tempfile.TemporaryDirectory(prefix="factory-semgrep-parity-") as tmp:
            for idx, (name, code, want) in enumerate(probes):
                target = Path(tmp) / f"probe{idx}.py"
                target.write_text(code, encoding="utf-8")
                try:
                    raw = run_semgrep([target], config)
                    found = {((r.get("extra") or {}).get("metadata") or {}).get("class") for r in raw}
                    found = {c for c in found if c}
                except ToolError:
                    found = set()
                ok = want in found
                engine_ok = engine_ok and ok
                engine_results.append({"name": name, "passed": ok, "expected": want, "actual": sorted(found)})
        cases.append(
            {
                "name": "semgrep/parity-engines",
                "passed": engine_ok,
                "expected": "semgrep binary flags same probes as fallback",
                "actual": {"probes": engine_results},
            }
        )
    else:
        cases.append(
            {
                "name": "semgrep/parity-engines",
                "passed": False,
                "expected": "semgrep binary flags same probes as fallback",
                "actual": {"note": "semgrep binary absent; parity check failed closed (no pass-by-note)"},
            }
        )
    return {
        "ran": True,
        "passed": all(case["passed"] for case in cases),
        "cases": cases,
    }


def envelope(result_type: str, findings: list, control: dict, exit_code: int, extras: dict) -> dict:
    doc = {
        "schema": SCHEMA,
        "tool": TOOL,
        "version": VERSION,
        "interpreter": sys.executable,
        "result_type": result_type,
        "findings": findings,
        "control": control,
        "exit_code": exit_code,
    }
    doc.update(extras)
    return doc


def maybe_reexec(repo: str | None) -> None:
    if not repo or os.environ.get("FACTORY_REEXEC") == "1":
        return
    venv = Path(repo) / "backend" / "venv" / "Scripts" / "python.exe"
    if not venv.is_file():
        return
    current = Path(sys.executable).resolve()
    if current == venv.resolve():
        return
    os.environ["FACTORY_REEXEC"] = "1"
    try:
        os.execv(str(venv), [str(venv), str(Path(__file__).resolve()), *sys.argv[1:]])
    except OSError:
        pass


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    repo_hint = None
    for i, arg in enumerate(argv):
        if arg == "--repo" and i + 1 < len(argv):
            repo_hint = argv[i + 1]
        elif arg.startswith("--repo="):
            repo_hint = arg.split("=", 1)[1]
    maybe_reexec(repo_hint)

    parser = Parser(description="Run factory Semgrep rules over a diff or paths.")
    parser.add_argument("--diff")
    parser.add_argument("--paths", nargs="+")
    parser.add_argument("--repo")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    parser.add_argument("--control", action="store_true")
    parser.add_argument(
        "--allow-fallback",
        action="store_true",
        help="permit the local AST/regex fallback when the semgrep binary is absent "
        "(default strict: exit 2 BLOCKED when engine != semgrep)",
    )
    try:
        args = parser.parse_args(argv)
        if args.control:
            control = control_envelopes(Path(args.config))
            result_type = "RESULT" if control["passed"] else "CONTROL_FAIL"
            code = 0 if control["passed"] else 1
            doc = envelope(
                result_type,
                [],
                control,
                code,
                {"preexisting_suppressed": 0, "engine": "semgrep" if shutil.which("semgrep") else "fallback"},
            )
            sys.stdout.write(json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n")
            return code
        if args.diff is None and not args.paths:
            raise ToolError("provide --diff <file> or --paths <paths...>")
        diff_text = None
        if args.diff is not None:
            if args.diff == "-":
                diff_text = sys.stdin.read()
            elif Path(args.diff).is_file():
                diff_text = Path(args.diff).read_text(encoding="utf-8-sig", errors="replace")
            else:
                diff_text = args.diff
        config = Path(args.config)
        if not config.is_absolute() and not config.exists():
            config = HERE / config
        if not config.is_file():
            raise ToolError(f"config not found: {config}")
        findings, preexisting, files, engine, stats = collect(
            diff_text, args.paths or [], args.repo, config,
            allow_fallback=args.allow_fallback,
        )
        control = {"ran": False, "passed": True, "cases": []}
        result_type = "RESULT"
        code = 1 if findings else 0
        doc = envelope(
            result_type,
            findings,
            control,
            code,
            {
                "preexisting_suppressed": preexisting,
                "engine": engine,
                "files_scanned": files,
                "mode": stats["mode"],
                "syntax_warnings": stats.get("syntax_warnings", 0),
                "warning": (
                    "syntax warnings indicate files that did not parse as Python; "
                    "analyzed via regex fallback, recorded for visibility"
                    if stats.get("syntax_warnings", 0)
                    else None
                ),
            },
        )
        sys.stdout.write(json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n")
        return code
    except ToolError as exc:
        doc = envelope(
            "ERROR",
            [],
            {"ran": False, "passed": False, "cases": []},
            2,
            {"error": str(exc)},
        )
        sys.stdout.write(json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n")
        return 2
    except Exception as exc:  # noqa: BLE001 - tool boundary must stay JSON
        doc = envelope(
            "ERROR",
            [],
            {"ran": False, "passed": False, "cases": []},
            2,
            {"error": f"{type(exc).__name__}: {exc}"},
        )
        sys.stdout.write(json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
