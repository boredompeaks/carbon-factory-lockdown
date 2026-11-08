#!/usr/bin/env python3
"""Detect tautological or implementation-copied test oracles.

Classes:
  SELF_COMPARE    both sides of == normalize to the same expression
  ORACLE_BY_COPY  expected constant or expression appears in the added
                  implementation lines, or the assertion is the same call
                  on both sides (f(x) == f(x) / assigned-call equality)
  MOCK_ECHO       asserts a value configured on a mock - not a call count,
                  not a test-owned list

AST based. In diff mode only assertions touching added lines are reported.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

TOOL = "oracle_provenance"
VERSION = "1.0.0"
SCHEMA = "factory-tool/1"
HERE = Path(__file__).resolve().parent
CLASSES = {"SELF_COMPARE", "ORACLE_BY_COPY", "MOCK_ECHO"}


class ToolError(RuntimeError):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ToolError(message)


@dataclass
class FileDiff:
    path: str
    added: dict
    context: dict
    removed: dict


@dataclass
class Assertion:
    line: int
    lhs: ast.AST
    rhs: ast.AST
    kind: str
    node: ast.AST


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
    current = None
    in_hunk = False
    old_line = new_line = 0
    for raw in text.splitlines():
        if raw.startswith("diff --git "):
            current = None
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
            current = FileDiff(path, {}, {}, {})
            files.append(current)
            in_hunk = False
            continue
        match = re.match(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", raw)
        if match and current is not None:
            old_line = int(match.group(1))
            new_line = int(match.group(3))
            in_hunk = True
            continue
        if current is None or not in_hunk or raw.startswith("\\"):
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


def reconstruct(fd: FileDiff) -> str:
    mapping = dict(fd.context)
    mapping.update(fd.added)
    if not mapping:
        return ""
    limit = max(mapping)
    lines = [""] * limit
    for number, content in mapping.items():
        if 1 <= number <= limit:
            lines[number - 1] = content
    return "\n".join(lines) + "\n"


def parse_added_lines(spec: str) -> set[int]:
    if not spec:
        return set()
    result: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start, end = chunk.split("-", 1)
            start_i, end_i = int(start), int(end)
            if start_i > end_i:
                start_i, end_i = end_i, start_i
            result.update(range(start_i, end_i + 1))
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


def dump(node) -> str:
    return ast.dump(node, annotate_fields=True, include_attributes=False)


def nearest_function(node, parents):
    parent = parents.get(node)
    while parent is not None:
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return parent
        parent = parents.get(parent)
    return None


def function_symbol(node, parents) -> str:
    fn = nearest_function(node, parents)
    return fn.name if fn is not None else "<module>"


ASSERT_METHODS = {
    "assertEqual",
    "assertTrue",
    "assertFalse",
    "assertIs",
    "assertIn",
    "assertNotEqual",
}


def extract_assertions(tree: ast.AST) -> list[Assertion]:
    assertions: list[Assertion] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assert):
            test = node.test
            if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq):
                assertions.append(
                    Assertion(node.lineno, test.left, test.comparators[0], "assert", node)
                )
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            call = node.value
            name = dotted(call.func).split(".")[-1]
            if name not in ASSERT_METHODS:
                continue
            if name == "assertEqual" and len(call.args) >= 2:
                assertions.append(
                    Assertion(node.lineno, call.args[0], call.args[1], "unittest", node)
                )
            elif name == "assertTrue" and len(call.args) >= 1:
                arg = call.args[0]
                if isinstance(arg, ast.Compare) and len(arg.ops) == 1 and isinstance(arg.ops[0], ast.Eq):
                    assertions.append(
                        Assertion(node.lineno, arg.left, arg.comparators[0], "assertTrue", node)
                    )
    assertions.sort(key=lambda a: (a.line, a.kind))
    return assertions


def collect_context(fn, parents) -> tuple[dict, dict, set, set]:
    assigned_calls: dict[str, tuple[int, str]] = {}
    mock_values: dict[str, list[tuple[int, str]]] = {}
    mock_containers: set[str] = set()
    input_literals: set[str] = set()
    trivial = {"'0'", "'1'", "'-1'", "'None'", "'True'", "'False'"}

    def literal(node):
        if isinstance(node, ast.Constant):
            return repr(node.value)
        if (
            isinstance(node, ast.Call)
            and dotted(node.func) in {"Decimal", "str", "int", "float"}
            and len(node.args) == 1
        ):
            return literal(node.args[0])
        return None

    def assertion_call(node) -> bool:
        name = dotted(node.func).split(".")[-1]
        return name.startswith("assert") or name in {"fail", "failUnless", "failIf"}

    def collect_literals(root) -> None:
        for node in ast.walk(root):
            if not isinstance(node, ast.Call) or assertion_call(node):
                continue
            for argument in list(node.args) + [keyword.value for keyword in node.keywords]:
                value = literal(argument)
                if value is not None and value not in trivial:
                    input_literals.add(value)

    for node in sorted(ast.walk(fn), key=lambda n: getattr(n, "lineno", 0)):
        if nearest_function(node, parents) is not fn:
            continue
        line = getattr(node, "lineno", 0)
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and isinstance(node.value, ast.Call):
                assigned_calls[target.id] = (line, dump(node.value))
            if isinstance(target, ast.Attribute) and target.attr in {"return_value", "side_effect"}:
                base = dotted(target.value)
                if not base:
                    continue
                values = mock_values.setdefault(base, [])
                if isinstance(node.value, (ast.List, ast.Tuple)):
                    for element in node.value.elts:
                        values.append((line, dump(element)))
                else:
                    values.append((line, dump(node.value)))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if isinstance(node.value, ast.Call):
                assigned_calls[node.target.id] = (line, dump(node.value))
        if isinstance(node, ast.Call):
            if not assertion_call(node):
                for argument in list(node.args) + [keyword.value for keyword in node.keywords]:
                    value = literal(argument)
                    if value is not None and value not in trivial:
                        input_literals.add(value)

    # The test's own helpers (attempt(), slow_gateway()) carry the input
    # literals and the mock container mutations. Walk them separately: the
    # main loop's nearest_function guard deliberately skips nested bodies.
    for helper in ast.walk(fn):
        if isinstance(helper, (ast.FunctionDef, ast.AsyncFunctionDef)) and helper is not fn:
            collect_literals(helper)

    # A side_effect can be a function (assigned or passed as a keyword). A list
    # that function appends to is a mock container: asserting len(list) == 1
    # is an assertion on the mock, not on the product.
    side_effect_funcs: set[str] = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if (
                isinstance(target, ast.Attribute)
                and target.attr == "side_effect"
                and isinstance(node.value, ast.Name)
            ):
                side_effect_funcs.add(node.value.id)
        if isinstance(node, ast.Call):
            for keyword in node.keywords:
                if keyword.arg == "side_effect" and isinstance(keyword.value, ast.Name):
                    side_effect_funcs.add(keyword.value.id)
    for node in ast.walk(fn):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in side_effect_funcs:
            for child in ast.walk(node):
                if (
                    isinstance(child, ast.Call)
                    and isinstance(child.func, ast.Attribute)
                    and child.func.attr in {"append", "extend", "add", "update"}
                    and isinstance(child.func.value, ast.Name)
                ):
                    mock_containers.add(child.func.value.id)

    return assigned_calls, mock_values, mock_containers, input_literals


def implementation_constants(tree: ast.AST) -> tuple[set[str], set[str]]:
    module_values: dict[str, str] = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    module_values[target.id] = dump(stmt.value)
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            module_values[stmt.target.id] = dump(stmt.value) if stmt.value else ""

    names: set[str] = set()
    values: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("test"):
            for child in ast.walk(node):
                if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                    if child.id in module_values:
                        names.add(child.id)
                        values.add(module_values[child.id])
                elif isinstance(child, ast.Assign):
                    for target in child.targets:
                        if isinstance(target, ast.Name) and (
                            target.id.isupper() or isinstance(child.value, ast.Constant)
                        ):
                            if target.id.isupper():
                                names.add(target.id)
                                values.add(dump(child.value))
        elif isinstance(node, ast.ClassDef) and not node.name.startswith("Test"):
            for child in ast.walk(node):
                if isinstance(child, ast.Assign):
                    for target in child.targets:
                        if isinstance(target, ast.Name) and (
                            target.id.isupper() or isinstance(child.value, ast.Constant)
                        ):
                            if target.id.isupper():
                                names.add(target.id)
                                values.add(dump(child.value))
    return names, values


def is_mock_echo(lhs, rhs, mock_values: dict, mock_containers: set) -> bool:
    for side, other in ((lhs, rhs), (rhs, lhs)):
        if isinstance(side, ast.Call):
            base = dotted(side.func)
            if base in mock_values and dump(other) in mock_values[base]:
                return True
        if isinstance(side, ast.Attribute) and side.attr == "return_value":
            base = dotted(side.value)
            if base in mock_values and dump(other) in mock_values[base]:
                return True
    return False


def is_oracle_by_copy(
    lhs,
    rhs,
    assigned_calls: dict,
    impl_constants: set[str],
    impl_values: set[str],
    input_literals: set[str],
) -> bool:
    if isinstance(lhs, ast.Call) and isinstance(rhs, ast.Call) and dump(lhs) == dump(rhs):
        return True
    for name_side, expr_side in ((lhs, rhs), (rhs, lhs)):
        if isinstance(name_side, ast.Name) and isinstance(expr_side, ast.Call):
            if assigned_calls.get(name_side.id) == dump(expr_side):
                return True

    trivial = {dump(ast.Constant(0)), dump(ast.Constant(1)), dump(ast.Constant(-1)), dump(ast.Constant(None)), dump(ast.Constant(True)), dump(ast.Constant(False))}
    for side in (rhs, lhs):
        if isinstance(side, ast.Name) and side.id in impl_constants:
            return True
        if dump(side) in impl_values and dump(side) not in trivial:
            return True
    return False


def is_self_compare(lhs, rhs) -> bool:
    if isinstance(lhs, ast.Call) and isinstance(rhs, ast.Call):
        return False
    return dump(lhs) == dump(rhs)


def classify(
    assertion: Assertion,
    assigned_calls: dict,
    mock_values: dict,
    mock_containers: set,
    input_literals: set,
    impl_constants: set[str],
    impl_values: set[str],
) -> str | None:
    if is_mock_echo(assertion.lhs, assertion.rhs, mock_values, mock_containers):
        return "MOCK_ECHO"
    if is_oracle_by_copy(
        assertion.lhs,
        assertion.rhs,
        assigned_calls,
        impl_constants,
        impl_values,
        input_literals,
    ):
        return "ORACLE_BY_COPY"
    if is_self_compare(assertion.lhs, assertion.rhs):
        return "SELF_COMPARE"
    return None


def find_line(assertion: Assertion, added: set[int], lines: list[str]) -> int | None:
    end = getattr(assertion.node, "end_lineno", assertion.line) or assertion.line
    if assertion.line in added:
        return assertion.line
    for line in range(assertion.line, end + 1):
        if line in added:
            return line
    return None


def evidence_for(assertion: Assertion, lines: list[str], line: int) -> str:
    end = getattr(assertion.node, "end_lineno", assertion.line) or assertion.line
    start = max(1, assertion.line)
    parts = [lines[i - 1].strip() for i in range(start, min(end, len(lines)) + 1) if i - 1 < len(lines)]
    evidence = re.sub(r"\s+", " ", " ".join(parts)).strip() or lines[line - 1].strip()
    return evidence[:117] + "..." if len(evidence) > 120 else evidence[:120]


def analyze_ast(
    path: str,
    text: str,
    added: set[int],
    rejection: list[str],
) -> tuple[list, int]:
    tree = ast.parse(text)
    lines = text.splitlines()
    parents = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    impl_constants, impl_values = implementation_constants(tree)
    assertions = extract_assertions(tree)

    function_context = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function_context[id(node)] = collect_context(node, parents)
    module_context = ({}, {}, set(), set())

    findings = []
    scanned = 0
    for assertion in assertions:
        line = find_line(assertion, added, lines)
        if line is None:
            continue
        scanned += 1
        fn = nearest_function(assertion.node, parents)
        raw_assigned, raw_mock, mock_containers, input_literals = (
            function_context.get(id(fn), module_context) if fn else module_context
        )
        assigned_calls = {
            name: value for name, (assigned_line, value) in raw_assigned.items()
            if assigned_line < assertion.line
        }
        mock_values = {
            base: {value for assigned_line, value in values if assigned_line < assertion.line}
            for base, values in raw_mock.items()
        }
        mock_values = {base: values for base, values in mock_values.items() if values}
        cls = classify(
            assertion,
            assigned_calls,
            mock_values,
            mock_containers,
            input_literals,
            impl_constants,
            impl_values,
        )
        if cls is None:
            continue
        symbol = fn.name if fn is not None else "<module>"
        evidence = evidence_for(assertion, lines, line)
        findings.append(
            {
                "class": cls,
                "path": path,
                "line": line,
                "symbol": symbol,
                "locus": f"{path}:{symbol}",
                "evidence": evidence,
                "fingerprint": fingerprint(cls, path, symbol, evidence),
            }
        )
    return findings, scanned


def regex_fallback(path: str, text: str, added: set[int], lines: list[str]) -> tuple[list, int]:
    """Parse only assertion lines when the reconstructed head is not valid Python."""
    findings = []
    scanned = 0
    mock_values: dict[str, set[str]] = {}
    assigned_calls: dict[str, str] = {}
    for number, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if number not in added:
            continue
        mock_assign = re.match(
            r"^([A-Za-z_][\w.]*)\.(return_value|side_effect)\s*=\s*(.+)$", stripped
        )
        if mock_assign:
            value = mock_assign.group(3).strip().rstrip(";")
            mock_values.setdefault(mock_assign.group(1), set()).add(value)
            continue
        call_assign = re.match(r"^([A-Za-z_]\w*)\s*=\s*(.+\(.*\))\s*$", stripped)
        if call_assign:
            assigned_calls[call_assign.group(1)] = re.sub(r"\s+", "", call_assign.group(2))
            continue
        match = re.match(r"^assert\s+(.+?)\s*==\s*(.+?)(?:\s*#.*)?$", stripped)
        if not match:
            continue
        scanned += 1
        left, right = match.group(1).strip(), match.group(2).strip()
        cls = None
        left_norm, right_norm = re.sub(r"\s+", "", left), re.sub(r"\s+", "", right)
        for side, other in ((left_norm, right_norm), (right_norm, left_norm)):
            call = re.match(r"^([A-Za-z_][\w.]*)\(.*\)$", side)
            if call and call.group(1) in mock_values and other in mock_values[call.group(1)]:
                cls = "MOCK_ECHO"
        if cls is None:
            if left_norm == right_norm:
                cls = "ORACLE_BY_COPY" if "(" in left_norm else "SELF_COMPARE"
            elif left_norm in assigned_calls and assigned_calls[left_norm] == right_norm:
                cls = "ORACLE_BY_COPY"
            elif right_norm in assigned_calls and assigned_calls[right_norm] == left_norm:
                cls = "ORACLE_BY_COPY"
        if cls is None:
            continue
        evidence = stripped[:120]
        symbol = "<module>"
        for index in range(number - 1, -1, -1):
            fn = re.match(r"^\s*def\s+(\w+)", lines[index])
            if fn:
                symbol = fn.group(1)
                break
        findings.append(
            {
                "class": cls,
                "path": path,
                "line": number,
                "symbol": symbol,
                "locus": f"{path}:{symbol}",
                "evidence": evidence,
                "fingerprint": fingerprint(cls, path, symbol, evidence),
            }
        )
    return findings, scanned


def analyze_file(path: str, text: str, added: set[int]) -> tuple[list, int, str]:
    try:
        findings, scanned = analyze_ast(path, text, added, [])
        engine = "ast"
    except SyntaxError:
        findings, scanned = regex_fallback(path, text, added, text.splitlines())
        engine = "regex-fallback"
    findings.sort(key=lambda f: (f["path"], f["line"], f["class"], f["fingerprint"]))
    return findings, scanned, engine


def load_diff(arg: str) -> str:
    if arg == "-":
        return sys.stdin.read()
    if Path(arg).is_file():
        return Path(arg).read_text(encoding="utf-8-sig", errors="replace")
    return arg


def control() -> dict:
    fixtures = HERE / "fixtures" / "oracle"
    bad = fixtures / "bad_test.py"
    clean = fixtures / "clean_test.py"
    bad_text = bad.read_text(encoding="utf-8")
    clean_text = clean.read_text(encoding="utf-8")
    bad_added = set(range(1, len(bad_text.splitlines()) + 1))
    clean_added = set(range(1, len(clean_text.splitlines()) + 1))
    bad_findings, _, _ = analyze_file(str(bad), bad_text, bad_added)
    clean_findings, _, _ = analyze_file(str(clean), clean_text, clean_added)
    impl_const = fixtures / "impl_constant_test.py"
    mirror = fixtures / "mirror_refund_race.py"
    mirror_text = mirror.read_text(encoding="utf-8")
    mirror_added = set(range(1, len(mirror_text.splitlines()) + 1))
    mirror_findings, _, _ = analyze_file(str(mirror), mirror_text, mirror_added)
    impl_text = impl_const.read_text(encoding="utf-8")
    impl_added = set(range(1, len(impl_text.splitlines()) + 1))
    impl_findings, _, _ = analyze_file(str(impl_const), impl_text, impl_added)
    counter = fixtures / "call_count_test.py"
    counter_text = counter.read_text(encoding="utf-8")
    counter_added = set(range(1, len(counter_text.splitlines()) + 1))
    counter_findings, _, _ = analyze_file(str(counter), counter_text, counter_added)
    bad_classes = sorted({f["class"] for f in bad_findings})
    clean_classes = sorted({f["class"] for f in clean_findings})
    mirror_classes = sorted({f["class"] for f in mirror_findings})
    counter_classes = sorted({f["class"] for f in counter_findings})
    cases = [
        {
            "name": "oracle/bad_test.py",
            "passed": CLASSES.issubset(set(bad_classes)),
            "expected": "at least SELF_COMPARE, ORACLE_BY_COPY, MOCK_ECHO",
            "actual": {"findings": len(bad_findings), "classes": bad_classes},
        },
        {
            "name": "oracle/clean_test.py",
            "passed": len(clean_findings) == 0,
            "expected": "0 findings",
            "actual": {"findings": len(clean_findings), "classes": clean_classes},
        },
        {
            "name": "oracle/mirror_refund_race.py",
            "passed": {"MOCK_ECHO"}.issubset(set(mirror_classes)),
            "expected": "at least MOCK_ECHO",
            "actual": {"findings": len(mirror_findings), "classes": mirror_classes},
        },
        {
            "name": "oracle/call_count_test.py",
            "passed": len(counter_findings) == 0,
            "expected": "0 findings",
            "actual": {"findings": len(counter_findings), "classes": counter_classes},
        },
        {
            "name": "oracle/impl_constant_test.py",
            "passed": {"ORACLE_BY_COPY"}.issubset({f["class"] for f in impl_findings}),
            "expected": "at least ORACLE_BY_COPY (expected is a file constant)",
            "actual": {
                "findings": len(impl_findings),
                "classes": sorted({f["class"] for f in impl_findings}),
            },
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

    parser = Parser(description="Detect copied or self-referential test oracles.")
    parser.add_argument("--diff")
    parser.add_argument("--file")
    parser.add_argument("--added-lines")
    parser.add_argument("--repo")
    parser.add_argument("--control", action="store_true")
    try:
        args = parser.parse_args(argv)
        if args.control:
            control_doc = control()
            result_type = "RESULT" if control_doc["passed"] else "CONTROL_FAIL"
            code = 0 if control_doc["passed"] else 1
            doc = envelope(result_type, [], control_doc, code, {})
            sys.stdout.write(json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n")
            return code

        findings = []
        scanned = 0
        engine = "ast"
        if args.diff:
            diff_text = load_diff(args.diff)
            file_diffs = parse_diff(diff_text)
            if not file_diffs:
                raise ToolError("no file changes found in diff")
            repo_root = Path(args.repo).resolve() if args.repo else Path.cwd()
            for fd in file_diffs:
                candidate = (repo_root / fd.path).resolve()
                if candidate.is_file():
                    text = candidate.read_text(encoding="utf-8-sig", errors="replace")
                else:
                    text = reconstruct(fd)
                if not text:
                    continue
                hits, seen, used_engine = analyze_file(fd.path, text, set(fd.added))
                findings.extend(hits)
                scanned += seen
                if used_engine != "ast":
                    engine = used_engine
        elif args.file:
            path = Path(args.file)
            if not path.is_file():
                raise ToolError(f"file not found: {args.file}")
            text = path.read_text(encoding="utf-8-sig", errors="replace")
            if args.added_lines:
                added = parse_added_lines(args.added_lines)
            else:
                added = set(range(1, len(text.splitlines()) + 1))
            hits, scanned, engine = analyze_file(args.file.replace("\\", "/"), text, added)
            findings.extend(hits)
        else:
            raise ToolError("provide --diff <file> or --file <py> --added-lines <ranges>")

        findings.sort(key=lambda f: (f["path"], f["line"], f["class"], f["fingerprint"]))
        control_doc = {"ran": False, "passed": True, "cases": []}
        code = 1 if findings else 0
        doc = envelope(
            "RESULT",
            findings,
            control_doc,
            code,
            {"assertions_scanned": scanned, "engine": engine},
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
