#!/usr/bin/env python3
"""Test smells on added test lines plus delta-only code smells.

Code smells (function length, cyclomatic complexity, duplicated blocks) are
reported only when the head value is larger than the base value for the same
function/file. A pre-existing smell that did not increase is never reported.
Python uses radon for complexity when importable, otherwise a keyword/AST
heuristic. TypeScript uses a brace-matching keyword heuristic.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

TOOL = "smell"
VERSION = "1.0.0"
SCHEMA = "factory-tool/1"
HERE = Path(__file__).resolve().parent
DUP_WINDOW = 4
NUM_EXEMPT = {0, 1, -1}
TEST_CLASSES = {
    "ASSERTION_FREE",
    "SLEEP",
    "BROAD_EXCEPT",
    "MAGIC_NUMBER",
    "MOCK_ONLY",
    "DUPLICATE_TEST_NAME",
}
CODE_CLASSES = {
    "FUNCTION_LENGTH_DELTA",
    "COMPLEXITY_DELTA",
    "DUPLICATED_BLOCK_DELTA",
}


class ToolError(RuntimeError):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ToolError(message)


@dataclass
class Hunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    raw: list = field(default_factory=list)


@dataclass
class FileDiff:
    path: str
    added: dict = field(default_factory=dict)
    context: dict = field(default_factory=dict)
    context_old: dict = field(default_factory=dict)
    removed: dict = field(default_factory=dict)
    hunks: list = field(default_factory=list)


def fingerprint(cls: str, path: str, symbol: str, evidence: str) -> str:
    normalized = re.sub(r"\s+", " ", f"{symbol}|{evidence}").strip()
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
    hunk: Hunk | None = None
    in_hunk = False
    old_line = new_line = 0
    for raw in text.splitlines():
        if raw.startswith("diff --git "):
            current = None
            hunk = None
            in_hunk = False
            continue
        if raw.startswith("--- "):
            continue
        if raw.startswith("+++ "):
            path = clean_path(raw[4:])
            if path == "/dev/null":
                current = None
                in_hunk = False
                continue
            current = FileDiff(path=path)
            files.append(current)
            in_hunk = False
            continue
        match = re.match(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", raw)
        if match and current is not None:
            old_line = int(match.group(1))
            new_line = int(match.group(3))
            hunk = Hunk(
                old_line,
                int(match.group(2) or "1"),
                new_line,
                int(match.group(4) or "1"),
            )
            current.hunks.append(hunk)
            in_hunk = True
            continue
        if current is None or not in_hunk or raw.startswith("\\"):
            continue
        tag = raw[:1] if raw else " "
        body = raw[1:] if raw else ""
        if hunk is not None:
            hunk.raw.append((tag, body))
        if tag == "+":
            current.added[new_line] = body
            new_line += 1
        elif tag == "-":
            current.removed[old_line] = body
            old_line += 1
        elif tag == " " or raw == "":
            current.context[new_line] = body
            current.context_old[old_line] = body
            old_line += 1
            new_line += 1
    return files


def reconstruct(fd: FileDiff, side: str) -> str:
    if side == "head":
        mapping = dict(fd.context)
        mapping.update(fd.added)
    else:
        mapping = dict(fd.context_old)
        mapping.update(fd.removed)
    if not mapping:
        return ""
    limit = max(mapping)
    lines = [""] * limit
    for number, content in mapping.items():
        if 1 <= number <= limit:
            lines[number - 1] = content
    return "\n".join(lines) + "\n"


def reverse_apply(head_text: str, fd: FileDiff) -> str:
    lines = head_text.splitlines()
    for hunk in reversed(fd.hunks):
        old_block = [body for tag, body in hunk.raw if tag in {" ", "-"}]
        start = max(0, hunk.new_start - 1)
        lines[start:start + hunk.new_count] = old_block
    return "\n".join(lines) + "\n"


def parse_added_lines(spec: str) -> set[int]:
    result: set[int] = set()
    for chunk in (spec or "").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start, end = chunk.split("-", 1)
            a, b = int(start), int(end)
            if a > b:
                a, b = b, a
            result.update(range(a, b + 1))
        else:
            result.add(int(chunk))
    return result


def dotted(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return dotted(node.func)
    return ""


def is_test_path(path: str) -> bool:
    p = path.replace("\\", "/").lower()
    name = p.rsplit("/", 1)[-1]
    return (
        name.startswith("test_")
        or name.endswith("_test.py")
        or name.endswith("_test.ts")
        or ".test.ts" in name
        or ".spec.ts" in name
        or ".test.tsx" in name
        or ".spec.tsx" in name
        or "/tests/" in p
        or "/__tests__/" in p
    )


def finding(cls: str, path: str, line: int, symbol: str, delta: str, evidence: str) -> dict:
    return {
        "class": cls,
        "path": path,
        "line": line,
        "symbol": symbol,
        "delta": delta,
        "evidence": evidence.strip()[:160],
        "fingerprint": fingerprint(cls, path, symbol, evidence),
    }


def node_line(node, added: set[int]) -> int | None:
    line = getattr(node, "lineno", None)
    if line is None:
        return None
    if line in added:
        return line
    end = getattr(node, "end_lineno", line) or line
    for candidate in range(line, end + 1):
        if candidate in added:
            return candidate
    return None


def exact_line(node, added: set[int]) -> int | None:
    line = getattr(node, "lineno", None)
    return line if line in added else None


def source_line(lines: list[str], number: int) -> str:
    return lines[number - 1].strip() if 0 < number <= len(lines) else ""


# ---------------------------------------------------------------------------
# Python test smells
# ---------------------------------------------------------------------------


def py_test_functions(tree: ast.AST) -> list[tuple[str, ast.AST]]:
    tests: list[tuple[str, ast.AST]] = []

    def walk(node, prefix: str = ""):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                walk(child, prefix + child.name + ".")
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qual = prefix + child.name
                if child.name.startswith("test"):
                    tests.append((qual, child))
                walk(child, qual + ".")
            else:
                walk(child, prefix)

    walk(tree)
    return tests


def assertion_nodes(fn) -> list:
    found = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Assert):
            found.append(node)
        elif isinstance(node, ast.Call):
            short = dotted(node.func).split(".")[-1]
            if short.startswith("assert") or short in {"fail", "raises", "warns", "expect"}:
                found.append(node)
    return found


def has_assertion(fn) -> bool:
    return bool(assertion_nodes(fn))


def mock_vars_in(fn) -> set[str]:
    names = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Attribute) and target.attr in {"return_value", "side_effect"}:
                    base = dotted(target.value).split(".")[0]
                    if base:
                        names.add(base)
            if isinstance(node.value, ast.Call):
                short = dotted(node.value.func).split(".")[-1]
                if short in {"Mock", "MagicMock", "patch", "mock"} or "patch" in dotted(node.value.func):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            names.add(target.id)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if "patch" in dotted(item.context_expr) and item.optional_vars is not None:
                    if isinstance(item.optional_vars, ast.Name):
                        names.add(item.optional_vars.id)
        elif isinstance(node, ast.Call):
            short = dotted(node.func).split(".")[-1]
            if short.startswith("assert_") and isinstance(node.func, ast.Attribute):
                base = dotted(node.func.value).split(".")[0]
                if base:
                    names.add(base)
    return names


def references_mock(node, mock_vars: set[str]) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in mock_vars:
            return True
        if isinstance(child, ast.Attribute):
            root = dotted(child)
            if any(root == name or root.startswith(name + ".") for name in mock_vars):
                return True
    return False


def is_mock_assertion(node, mock_vars: set[str]) -> bool:
    if not mock_vars:
        return False
    if isinstance(node, ast.Assert):
        test = node.test
        if isinstance(test, ast.Attribute) and test.attr in {"called", "call_count"}:
            return references_mock(test, mock_vars)
        if isinstance(test, ast.Call) and dotted(test.func) in mock_vars:
            return True
        if isinstance(test, ast.Compare):
            return any(references_mock(side, mock_vars) for side in [test.left, *test.comparators])
        return references_mock(test, mock_vars)
    if isinstance(node, ast.Call):
        short = dotted(node.func).split(".")[-1]
        if short.startswith("assert_") and references_mock(node.func, mock_vars):
            return True
        if short in {"assertTrue", "assertFalse"} and node.args:
            return references_mock(node.args[0], mock_vars)
    return False


def magic_number_line(node, added: set[int]) -> tuple[int, str] | None:
    for child in ast.walk(node):
        if not isinstance(child, ast.Compare):
            continue
        for comparator in child.comparators:
            if (
                isinstance(comparator, ast.Constant)
                and isinstance(comparator.value, (int, float))
                and not isinstance(comparator.value, bool)
                and comparator.value not in NUM_EXEMPT
            ):
                line = exact_line(child, added)
                if line is not None:
                    return line, f"threshold literal {comparator.value}"
    return None


def py_test_smells(path: str, text: str, added: set[int]) -> tuple[list, str]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return py_test_regex(path, text, added), "regex"
    lines = text.splitlines()
    findings = []
    seen: set[tuple] = set()

    def add(cls: str, line: int | None, symbol: str, evidence: str):
        if line is None:
            return
        key = (cls, line, symbol)
        if key in seen:
            return
        seen.add(key)
        findings.append(finding(cls, path, line, symbol, "0->1", evidence))

    tests = py_test_functions(tree) if is_test_path(path) else []
    name_counts: dict[str, int] = {}
    for qual, fn in tests:
        name_counts[qual] = name_counts.get(qual, 0) + 1
        if name_counts[qual] > 1:
            line = node_line(fn, added)
            add("DUPLICATE_TEST_NAME", line, qual, f"duplicate test name {qual.rsplit('.', 1)[-1]}")

        assertions = assertion_nodes(fn)
        if not assertions:
            line = node_line(fn, added)
            add("ASSERTION_FREE", line, qual, "test has no assertion")

        for node in ast.walk(fn):
            if isinstance(node, ast.Call) and dotted(node.func).split(".")[-1] == "sleep":
                line = exact_line(node, added)
                add("SLEEP", line, qual, source_line(lines, line) if line else "sleep()")
            elif isinstance(node, ast.ExceptHandler):
                broad = node.type is None or (
                    isinstance(node.type, ast.Name) and node.type.id in {"Exception", "BaseException"}
                )
                if broad:
                    line = exact_line(node, added)
                    add("BROAD_EXCEPT", line, qual, source_line(lines, line) if line else "broad except")

        for assertion in assertions:
            magic = magic_number_line(assertion, added)
            if magic:
                line, evidence = magic
                add("MAGIC_NUMBER", line, qual, evidence)

        mocks = mock_vars_in(fn)
        if assertions and mocks and all(is_mock_assertion(a, mocks) for a in assertions):
            line = node_line(fn, added)
            add("MOCK_ONLY", line, qual, "test asserts only mock interactions/returns")

    findings.sort(key=lambda f: (f["path"], f["line"], f["class"], f["fingerprint"]))
    return findings, "ast"


def py_test_regex(path: str, text: str, added: set[int]) -> list:
    if not is_test_path(path):
        return []
    lines = text.splitlines()
    findings = []
    blocks = []
    current = None
    for index, line in enumerate(lines, start=1):
        match = re.match(r"^(\s*)(?:async\s+)?def\s+(test\w+)\s*\(", line)
        if match:
            if current:
                blocks.append(current)
            current = [match.group(2), index, len(match.group(1)), index]
        elif current and line.strip():
            indent = len(line) - len(line.lstrip())
            if indent <= current[2]:
                blocks.append(current)
                current = None
    if current:
        blocks.append(current)

    names = [block[0] for block in blocks]
    for position, (name, start, def_indent, _initial_end) in enumerate(blocks):
        end = start
        for index in range(start + 1, len(lines) + 1):
            line = lines[index - 1]
            if not line.strip():
                continue
            indent = len(line) - len(line.lstrip())
            if indent <= def_indent:
                end = index - 1
                break
            end = index
        body = "\n".join(lines[start - 1:end])
        has_assert = bool(re.search(r"\bassert\b|self\.assert|pytest\.raises|\bexpect\s*\(", body))
        target = start if start in added else next((i for i in range(start, end + 1) if i in added), None)
        if target is None:
            continue
        if not has_assert:
            findings.append(finding("ASSERTION_FREE", path, target, name, "0->1", "test has no assertion"))
        if names.count(name) > 1 and position > names.index(name):
            findings.append(finding("DUPLICATE_TEST_NAME", path, target, name, "0->1", f"duplicate test name {name}"))
        for index in range(start, end + 1):
            if index not in added:
                continue
            stripped = lines[index - 1].strip()
            if re.search(r"\bsleep\s*\(", stripped):
                findings.append(finding("SLEEP", path, index, name, "0->1", stripped))
            if re.match(r"^except\s*:", stripped):
                findings.append(finding("BROAD_EXCEPT", path, index, name, "0->1", stripped))
            if re.match(r"^assert\b.*[<>]=?\s*\d+", stripped) and not re.search(r"[<>]=?\s*[01]\b", stripped):
                findings.append(finding("MAGIC_NUMBER", path, index, name, "0->1", stripped))
    findings.sort(key=lambda f: (f["path"], f["line"], f["class"], f["fingerprint"]))
    return findings


# ---------------------------------------------------------------------------
# TypeScript test smells (line/brace heuristic)
# ---------------------------------------------------------------------------


def ts_block_at(text: str, open_pos: int) -> int:
    depth = 0
    index = open_pos
    quote = ""
    while index < len(text):
        char = text[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = ""
        elif char in {"'", '"', "`"}:
            quote = char
        elif char == "/" and index + 1 < len(text) and text[index + 1] == "/":
            index = text.find("\n", index)
            if index == -1:
                return len(text)
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return len(text)


def ts_line_of(text: str, position: int) -> int:
    return text.count("\n", 0, position) + 1


def ts_test_smells(path: str, text: str, added: set[int]) -> list:
    if not is_test_path(path):
        return []
    lines = text.splitlines()
    findings = []
    names: list[str] = []
    pattern = re.compile(r"(?m)\b(?:test|it)\s*\(\s*(['\"`])(.+?)\1\s*,")
    for match in pattern.finditer(text):
        name = match.group(2)
        open_brace = text.find("{", match.end())
        if open_brace == -1:
            continue
        close_brace = ts_block_at(text, open_brace)
        start = ts_line_of(text, match.start())
        end = ts_line_of(text, close_brace)
        block = text[match.start():close_brace + 1]
        names.append(name)
        target = start if start in added else next((i for i in range(start, end + 1) if i in added), None)
        if target is None:
            continue
        has_assert = bool(re.search(r"\bexpect\s*\(|\bassert\b|\.should\b", block))
        if not has_assert:
            findings.append(finding("ASSERTION_FREE", path, target, name, "0->1", "test has no assertion"))
        if names.count(name) > 1 and names.index(name) != len(names) - 1:
            findings.append(finding("DUPLICATE_TEST_NAME", path, target, name, "0->1", f"duplicate test name {name}"))
        for index in range(start, end + 1):
            if index not in added:
                continue
            stripped = lines[index - 1].strip()
            if re.search(r"\b(?:sleep|setTimeout)\s*\(", stripped):
                findings.append(finding("SLEEP", path, index, name, "0->1", stripped))
            magic = re.search(
                r"\.(?:toBe|toEqual|toStrictEqual|toBeGreaterThan|toBeLessThan|toBeGreaterThanOrEqual|toBeLessThanOrEqual)\(\s*(-?\d+(?:\.\d+)?)\s*\)",
                stripped,
            )
            if magic and float(magic.group(1)) not in NUM_EXEMPT:
                findings.append(finding("MAGIC_NUMBER", path, index, name, "0->1", stripped))
        for catch in re.finditer(r"\bcatch\s*(?:\([^)]*\))?\s*\{([^{}]*)\}", block, re.S):
            inner = catch.group(1)
            meaningful = [
                line
                for line in inner.splitlines()
                if line.strip() and not line.strip().startswith(("//", "/*", "*"))
            ]
            if meaningful:
                continue
            catch_line = ts_line_of(text, match.start() + catch.start())
            if catch_line in added:
                findings.append(
                    finding("BROAD_EXCEPT", path, catch_line, name, "0->1", lines[catch_line - 1].strip())
                )
        mock_vars = re.findall(
            r"(?:const|let|var)\s+(\w+)\s*=\s*(?:jest|vi|sinon)\.(?:fn|spyOn|stub)", block
        )
        expect_args = re.findall(r"expect\s*\(([^)]*)\)", block)
        if expect_args and mock_vars and all(
            any(re.search(rf"\b{re.escape(mock)}\b", arg) for mock in mock_vars) for arg in expect_args
        ):
            findings.append(finding("MOCK_ONLY", path, target, name, "0->1", "test asserts only mocks"))
    findings.sort(key=lambda f: (f["path"], f["line"], f["class"], f["fingerprint"]))
    return findings


# ---------------------------------------------------------------------------
# Code metrics
# ---------------------------------------------------------------------------


def ast_functions(tree: ast.AST) -> dict:
    functions: dict[str, ast.AST] = {}

    def walk(node, prefix: str = ""):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qual = prefix + child.name
                functions[qual] = child
                walk(child, qual + ".")
            elif isinstance(child, ast.ClassDef):
                walk(child, prefix + child.name + ".")
            else:
                walk(child, prefix)

    walk(tree)
    return functions


def ast_complexity(fn) -> int:
    score = 1
    for node in ast.walk(fn):
        if isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler)):
            score += 1
        elif isinstance(node, ast.BoolOp):
            score += max(0, len(node.values) - 1)
        elif isinstance(node, ast.IfExp):
            score += 1
        elif isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            score += len(node.generators)
    return score


def radon_complexity(text: str) -> dict[str, int]:
    try:
        from radon.complexity import cc_visit
    except Exception:
        return {}
    try:
        blocks = cc_visit(text)
    except Exception:
        return {}
    result: dict[str, int] = {}
    for block in blocks:
        classname = getattr(block, "classname", None)
        qual = f"{classname}.{block.name}" if classname else block.name
        result[qual] = int(block.complexity)
    return result


def py_code_metrics(text: str) -> dict:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return {}
    functions = ast_functions(tree)
    radon = radon_complexity(text)
    metrics = {}
    for qual, fn in functions.items():
        end = getattr(fn, "end_lineno", fn.lineno) or fn.lineno
        complexity = radon.get(qual)
        if complexity is None:
            complexity = radon.get(qual.rsplit(".", 1)[-1], ast_complexity(fn))
        metrics[qual] = {
            "line": fn.lineno,
            "length": end - fn.lineno + 1,
            "complexity": complexity,
        }
    return metrics


def brace_end(text: str, open_pos: int) -> int:
    return ts_block_at(text, open_pos)


def ts_code_metrics(text: str) -> dict:
    pattern = re.compile(
        r"(?m)^[ \t]*(?:export\s+)?(?:async\s+)?(?:"
        r"function\s+(\w+)\s*\([^)]*\)"
        r"|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?(?:function\s*)?\([^)]*\)\s*=>"
        r")"
    )
    metrics = {}
    for match in pattern.finditer(text):
        name = match.group(1) or match.group(2)
        open_brace = text.find("{", match.end())
        if open_brace == -1:
            continue
        close_brace = brace_end(text, open_brace)
        body = text[open_brace:close_brace + 1]
        start_line = ts_line_of(text, match.start())
        end_line = ts_line_of(text, close_brace)
        complexity = 1
        complexity += len(re.findall(r"\b(?:if|for|while|case|catch)\b", body))
        complexity += len(re.findall(r"&&|\|\|", body))
        complexity += len(re.findall(r"\?(?![.?])", body))
        metrics[name] = {
            "line": start_line,
            "length": end_line - start_line + 1,
            "complexity": complexity,
        }
    return metrics


def duplicate_score(lines: list[str]) -> tuple[int, Counter, dict]:
    normalized = []
    for number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", "/*", "*", "*/")):
            continue
        normalized.append((number, re.sub(r"\s+", " ", stripped)))
    windows = Counter()
    positions: dict[tuple, list[list[int]]] = {}
    for index in range(len(normalized) - DUP_WINDOW + 1):
        chunk = normalized[index:index + DUP_WINDOW]
        key = tuple(text for _, text in chunk)
        windows[key] += 1
        positions.setdefault(key, []).append([number for number, _ in chunk])
    score = sum(count - 1 for count in windows.values() if count > 1)
    return score, windows, positions


def code_smell_findings(
    path: str,
    base_text: str,
    head_text: str,
    added: set[int],
    lang: str,
) -> list:
    if not base_text.strip() or not head_text.strip():
        return []
    if lang == "py":
        base = py_code_metrics(base_text)
        head = py_code_metrics(head_text)
    else:
        base = ts_code_metrics(base_text)
        head = ts_code_metrics(head_text)
    if not base or not head:
        return []

    lines = head_text.splitlines()
    findings = []
    for qual, head_metric in head.items():
        base_metric = base.get(qual)
        if base_metric is None:
            continue
        length_delta = head_metric["length"] - base_metric["length"]
        if length_delta > 0:
            findings.append(
                finding(
                    "FUNCTION_LENGTH_DELTA",
                    path,
                    head_metric["line"],
                    qual,
                    f"{base_metric['length']}->{head_metric['length']}",
                    f"function length +{length_delta} lines",
                )
            )
        complexity_delta = head_metric["complexity"] - base_metric["complexity"]
        if complexity_delta > 0:
            findings.append(
                finding(
                    "COMPLEXITY_DELTA",
                    path,
                    head_metric["line"],
                    qual,
                    f"{base_metric['complexity']}->{head_metric['complexity']}",
                    f"cyclomatic complexity +{complexity_delta}",
                )
            )

    base_score, _, _ = duplicate_score(base_text.splitlines())
    head_score, windows, positions = duplicate_score(lines)
    if head_score > base_score:
        added_line = None
        for key, count in windows.items():
            if count < 2:
                continue
            for window_lines in positions.get(key, []):
                for number in window_lines:
                    if number in added and (added_line is None or number < added_line):
                        added_line = number
        if added_line is not None:
            findings.append(
                finding(
                    "DUPLICATED_BLOCK_DELTA",
                    path,
                    added_line,
                    "<file>",
                    f"{base_score}->{head_score}",
                    f"duplicated {DUP_WINDOW}-line blocks +{head_score - base_score}",
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def analyze_file(path: str, text: str, added: set[int], lang: str) -> tuple[list, str]:
    if lang == "py":
        test_findings, engine = py_test_smells(path, text, added)
    else:
        test_findings, engine = ts_test_smells(path, text, added), "heuristic"
    findings = list(test_findings)
    findings.sort(key=lambda f: (f["path"], f["line"], f["class"], f["fingerprint"]))
    return findings, engine


def control() -> dict:
    fixtures = HERE / "fixtures" / "smell"
    bad = fixtures / "bad_test.py"
    clean = fixtures / "clean_test.py"
    bad_text = bad.read_text(encoding="utf-8")
    clean_text = clean.read_text(encoding="utf-8")
    bad_added = set(range(1, len(bad_text.splitlines()) + 1))
    clean_added = set(range(1, len(clean_text.splitlines()) + 1))
    bad_findings, _ = analyze_file(str(bad), bad_text, bad_added, "py")
    clean_findings, _ = analyze_file(str(clean), clean_text, clean_added, "py")
    bad_classes = sorted({f["class"] for f in bad_findings})
    clean_classes = sorted({f["class"] for f in clean_findings})
    # Diff-mode probes: delta-only code smells. Each probe asserts an exact
    # class set, so a stray extra finding fails the control.
    func_base = "def foo(x):\n    return x\n"
    func_head = (
        "def foo(x):\n"
        "    if x:\n"
        "        y = 1\n"
        "    if y:\n"
        "        y = 2\n"
        "    if x > 1:\n"
        "        y = 3\n"
        "    return y + x\n"
    )
    func_added = set(range(1, len(func_head.splitlines()) + 1))
    func_findings = code_smell_findings("probe_function.py", func_base, func_head, func_added, "py")
    func_classes = sorted({f["class"] for f in func_findings})
    dup_base = (
        "def foo(a):\n"
        "    x = a + 1\n"
        "    y = x + 2\n"
        "    z = y + 3\n"
        "    w = z + 4\n"
        "    p = a + 11\n"
        "    q = p + 12\n"
        "    r = q + 13\n"
        "    s = r + 14\n"
        "    return w + s\n"
    )
    dup_head = (
        "def foo(a):\n"
        "    x = a + 1\n"
        "    y = x + 2\n"
        "    z = y + 3\n"
        "    w = z + 4\n"
        "    x = a + 1\n"
        "    y = x + 2\n"
        "    z = y + 3\n"
        "    w = z + 4\n"
        "    return w + w\n"
    )
    dup_added = set(range(1, len(dup_head.splitlines()) + 1))
    dup_findings = code_smell_findings("probe_duplicated.py", dup_base, dup_head, dup_added, "py")
    dup_classes = sorted({f["class"] for f in dup_findings})
    steady_added = set(range(1, len(dup_base.splitlines()) + 1))
    steady_findings = code_smell_findings("probe_steady.py", dup_base, dup_base, steady_added, "py")
    steady_classes = sorted({f["class"] for f in steady_findings})
    cases = [
        {
            "name": "smell/bad_test.py",
            "passed": set(bad_classes) == TEST_CLASSES,
            "expected": f"exact classes {sorted(TEST_CLASSES)}",
            "actual": {"findings": len(bad_findings), "classes": bad_classes},
        },
        {
            "name": "smell/clean_test.py",
            "passed": len(clean_findings) == 0,
            "expected": "0 findings",
            "actual": {"findings": len(clean_findings), "classes": clean_classes},
        },
        {
            "name": "smell/diff/function_complexity.py",
            "passed": set(func_classes) == {"FUNCTION_LENGTH_DELTA", "COMPLEXITY_DELTA"},
            "expected": "exact classes ['COMPLEXITY_DELTA', 'FUNCTION_LENGTH_DELTA']",
            "actual": {"findings": len(func_findings), "classes": func_classes},
        },
        {
            "name": "smell/diff/duplicated.py",
            "passed": set(dup_classes) == {"DUPLICATED_BLOCK_DELTA"},
            "expected": "exact classes ['DUPLICATED_BLOCK_DELTA']",
            "actual": {"findings": len(dup_findings), "classes": dup_classes},
        },
        {
            "name": "smell/diff/no_delta.py",
            "passed": len(steady_findings) == 0,
            "expected": "0 findings (pre-existing metrics unchanged)",
            "actual": {"findings": len(steady_findings), "classes": steady_classes},
        },
    ]
    return {"ran": True, "passed": all(case["passed"] for case in cases), "cases": cases}


def envelope(result_type: str, findings: list, control_doc: dict, exit_code: int, extras: dict) -> dict:
    doc = {
        "schema": SCHEMA,
        "tool": TOOL,
        "version": VERSION,
        "interpreter": sys.executable,
        "result_type": result_type,
        "findings": findings,
        "control": control_doc,
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
    if Path(sys.executable).resolve() == venv.resolve():
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

    parser = Parser(description="Test smells on added lines and delta-only code smells.")
    parser.add_argument("--diff")
    parser.add_argument("--file")
    parser.add_argument("--added-lines")
    parser.add_argument("--lang", choices=["py", "ts"], default="py")
    parser.add_argument("--repo")
    parser.add_argument("--control", action="store_true")
    try:
        args = parser.parse_args(argv)
        if args.control:
            control_doc = control()
            result_type = "RESULT" if control_doc["passed"] else "CONTROL_FAIL"
            code = 0 if control_doc["passed"] else 1
            doc = envelope(result_type, [], control_doc, code, {"lang": args.lang})
            sys.stdout.write(json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n")
            return code

        findings = []
        engine = "ast" if args.lang == "py" else "heuristic"
        files = 0
        if args.diff:
            diff_arg = args.diff
            if diff_arg == "-":
                diff_text = sys.stdin.read()
            elif Path(diff_arg).is_file():
                diff_text = Path(diff_arg).read_text(encoding="utf-8-sig", errors="replace")
            else:
                diff_text = diff_arg
            file_diffs = parse_diff(diff_text)
            if not file_diffs:
                raise ToolError("no file changes found in diff")
            repo_root = Path(args.repo).resolve() if args.repo else Path.cwd()
            for fd in file_diffs:
                if args.lang == "py" and not fd.path.endswith(".py"):
                    continue
                if args.lang == "ts" and not re.search(r"\.(?:ts|tsx)$", fd.path):
                    continue
                candidate = (repo_root / fd.path).resolve()
                if candidate.is_file():
                    head_text = candidate.read_text(encoding="utf-8-sig", errors="replace")
                    base_text = reverse_apply(head_text, fd)
                else:
                    head_text = reconstruct(fd, "head")
                    base_text = reconstruct(fd, "base")
                if not head_text:
                    continue
                files += 1
                hits, used = analyze_file(fd.path, head_text, set(fd.added), args.lang)
                findings.extend(hits)
                if used != "ast":
                    engine = used
                findings.extend(
                    code_smell_findings(fd.path, base_text, head_text, set(fd.added), args.lang)
                )
        elif args.file:
            path = Path(args.file)
            if not path.is_file():
                raise ToolError(f"file not found: {args.file}")
            text = path.read_text(encoding="utf-8-sig", errors="replace")
            if args.added_lines:
                added = parse_added_lines(args.added_lines)
            else:
                added = set(range(1, len(text.splitlines()) + 1))
            files = 1
            hits, engine = analyze_file(args.file.replace("\\", "/"), text, added, args.lang)
            findings.extend(hits)
        else:
            raise ToolError("provide --diff <file> or --file <path> --added-lines <ranges>")

        findings.sort(key=lambda f: (f["path"], f["line"], f["class"], f["fingerprint"]))
        code = 1 if findings else 0
        doc = envelope(
            "RESULT",
            findings,
            {"ran": False, "passed": True, "cases": []},
            code,
            {"lang": args.lang, "engine": engine, "files_scanned": files},
        )
        sys.stdout.write(json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n")
        return code
    except ToolError as exc:
        doc = envelope("ERROR", [], {"ran": False, "passed": False, "cases": []}, 2, {"error": str(exc)})
        sys.stdout.write(json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n")
        return 2
    except Exception as exc:  # noqa: BLE001
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
