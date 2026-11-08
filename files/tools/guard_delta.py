#!/usr/bin/env python3
"""GUARD_DELTA -- fail a diff that deletes a control-flow guard on a risky path.

A removed guard line is only tolerated when a test added in the same diff is
shown to cover the changed hunk: either a covering-tests entry names a test
that is added at head, the coverage JSON marks the line executed while a test
was added, or an added test body names a symbol from the removed line.

Risk tiers come from the policy risk map (longest glob wins, default tier for
everything else).  Only tier high/max removals are findings; removals on tier
none paths are counted as skipped and never fail the diff.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

TOOL = "guard_delta"
VERSION = "1.0.0"
SCHEMA = "factory-tool/1"
HERE = Path(__file__).resolve().parent
DEFAULT_RISK_MAP = HERE.parent / "policies" / "risk-map.json"

GUARD_PATTERNS = (
    ("if", re.compile(r"^if\b")),
    ("elif", re.compile(r"^elif\b")),
    ("else", re.compile(r"^else\s*:")),
    ("try", re.compile(r"^try\s*:")),
    ("except", re.compile(r"^except\b")),
    ("raise", re.compile(r"^raise\b")),
    ("assert", re.compile(r"^assert\b")),
    ("return_none", re.compile(r"^return\s+None\b")),
    ("continue", re.compile(r"^continue\b")),
    ("break", re.compile(r"^break\b")),
    ("finally", re.compile(r"^finally\s*:")),
)

SYMBOL_STOP = {
    "if", "elif", "else", "try", "except", "raise", "assert", "return",
    "continue", "break", "finally", "none", "true", "false", "and", "or",
    "not", "in", "is", "lambda", "self", "cls", "pass", "from", "import",
}


class ToolError(RuntimeError):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ToolError(message)


def discover_repo() -> str | None:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    out = proc.stdout.strip()
    return out or None


def resolve_repo(explicit: str | None) -> str | None:
    if explicit:
        return explicit
    return discover_repo()


def require_repo(explicit: str | None) -> str:
    repo = resolve_repo(explicit)
    if not repo:
        raise ToolError("no repository: provide --repo or run inside a git worktree")
    return repo


@dataclass
class Hunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    section: str = ""
    raw: list = field(default_factory=list)


@dataclass
class FileDiff:
    path: str
    new_file: bool = False
    added: dict = field(default_factory=dict)
    removed: dict = field(default_factory=dict)
    hunks: list = field(default_factory=list)


def canonical_json(doc: dict) -> str:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"))


def fingerprint(cls: str, path: str, symbol: str) -> str:
    return hashlib.sha256(f"{cls}|{path}|{symbol}".encode("utf-8")).hexdigest()[:16]


def glob_regex(pattern: str) -> re.Pattern:
    out = ["^"]
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "*":
            if pattern[index:index + 2] == "**":
                index += 2
                if index < len(pattern) and pattern[index] == "/":
                    out.append("(?:.*/)?")
                    index += 1
                else:
                    out.append(".*")
            else:
                out.append("[^/]*")
                index += 1
        elif char == "?":
            out.append("[^/]")
            index += 1
        else:
            out.append(re.escape(char))
            index += 1
    out.append("$")
    return re.compile("".join(out))


class GlobMap:
    def __init__(self, mapping: dict):
        self.rules = []
        for glob, value in mapping.items():
            self.rules.append((len(glob), glob, glob_regex(glob), value))

    def best(self, path: str):
        hits = [rule for rule in self.rules if rule[2].match(path)]
        if not hits:
            return None
        hits.sort(key=lambda rule: (-rule[0], rule[1]))
        return hits[0][3]


def clean_diff_path(value: str) -> str:
    value = value.strip().split("\t")[0].strip()
    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    if value.startswith("a/") or value.startswith("b/"):
        value = value[2:]
    return value.replace("\\", "/")


def norm_path(value: str) -> str:
    value = value.strip()
    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    if value.startswith("a/") or value.startswith("b/"):
        value = value[2:]
    value = value.replace("\\", "/")
    while value.startswith("./"):
        value = value[2:]
    return value


def parse_diff(text: str) -> list[FileDiff]:
    files: list[FileDiff] = []
    current: FileDiff | None = None
    hunk: Hunk | None = None
    pending_new = False
    old_line = new_line = 0
    in_hunk = False
    for raw in text.splitlines():
        if raw.startswith("diff --git "):
            current = None
            hunk = None
            pending_new = False
            in_hunk = False
            continue
        if raw.startswith("new file mode"):
            pending_new = True
            continue
        if raw.startswith("--- "):
            if raw[4:].strip() == "/dev/null":
                pending_new = True
            continue
        if raw.startswith("+++ "):
            path = clean_diff_path(raw[4:])
            if path == "/dev/null":
                current = None
                continue
            current = FileDiff(path=path, new_file=pending_new)
            files.append(current)
            pending_new = False
            hunk = None
            in_hunk = False
            continue
        match = re.match(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$", raw)
        if match and current is not None:
            old_line = int(match.group(1))
            new_line = int(match.group(3))
            hunk = Hunk(
                old_line,
                int(match.group(2) if match.group(2) is not None else "1"),
                new_line,
                int(match.group(4) if match.group(4) is not None else "1"),
                match.group(5).strip(),
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
            current.removed[old_line] = (body, new_line)
            old_line += 1
        elif tag == " " or raw == "":
            old_line += 1
            new_line += 1
    return files


def guard_kind(line: str) -> str | None:
    text = line.strip()
    for name, pattern in GUARD_PATTERNS:
        if pattern.match(text):
            return name
    return None


def is_test_path(path: str) -> bool:
    p = path.replace("\\", "/").lower()
    name = p.rsplit("/", 1)[-1]
    return (
        name in {"tests.py", "test.py"}
        or name.startswith("test_")
        or name.startswith("tests_")
        or name.endswith("_test.py")
        or name.endswith("_test.ts")
        or ".test.ts" in name
        or ".spec.ts" in name
        or ".test.tsx" in name
        or ".spec.tsx" in name
        or "/tests/" in p
        or "/__tests__/" in p
    )


@dataclass
class TestBlock:
    file: str
    name: str
    line: int
    indent: int
    body: str


def module_prefixes(path: str) -> list[str]:
    p = path.replace("\\", "/")
    for suffix in (".py", ".ts", ".tsx", ".js", ".jsx"):
        if p.endswith(suffix):
            p = p[: -len(suffix)]
            break
    parts = [part for part in p.split("/") if part]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    prefixes = []
    for start in range(len(parts)):
        prefixes.append(".".join(parts[start:]))
    return prefixes


def test_evidence(files: list[FileDiff]) -> tuple[set, set, list[TestBlock]]:
    names: set[str] = set()
    ids: set[str] = set()
    blocks: list[TestBlock] = []
    for fd in files:
        if not is_test_path(fd.path):
            continue
        ordered = sorted(fd.added.items())
        for position, (line, body) in enumerate(ordered):
            py = re.match(r"^(\s*)(?:async\s+)?def\s+(test\w*)\s*\(", body)
            ts = re.match(r"^(\s*)(?:it|test)(?:\.\w+)?\s*\(\s*(['\"`])(.+?)\2", body)
            if not py and not ts:
                continue
            if py:
                indent = len(py.group(1))
                name = py.group(2)
            else:
                indent = len(ts.group(1))
                name = ts.group(3)
            names.add(name)
            for prefix in module_prefixes(fd.path):
                ids.add(f"{prefix}.{name}")
            ids.add(name)
            collected = []
            for later_line, later_body in ordered[position + 1:]:
                stripped = later_body.strip()
                if stripped:
                    later_indent = len(later_body) - len(later_body.lstrip())
                    if later_indent <= indent:
                        break
                collected.append(later_body)
            blocks.append(
                TestBlock(fd.path, name, line, indent, "\n".join(collected))
            )
    return names, ids, blocks


def test_is_added(test_id: str, names: set, ids: set) -> bool:
    value = (test_id or "").strip().rstrip("()")
    if not value:
        return False
    if value in ids or value in names:
        return True
    return value.split(".")[-1] in names


def line_in_hunk(fd: FileDiff, line: int) -> bool:
    for hunk in fd.hunks:
        if hunk.old_count > 0 and hunk.old_start <= line <= hunk.old_start + hunk.old_count - 1:
            return True
        if hunk.new_count > 0 and hunk.new_start <= line <= hunk.new_start + hunk.new_count - 1:
            return True
    return False


def removed_symbols(text: str) -> set[str]:
    found = set(re.findall(r"[A-Za-z_]\w*", text))
    return {name for name in found if len(name) > 1 and name.lower() not in SYMBOL_STOP}


def canon_for_compare(value: str) -> str:
    value = value.replace("\\", "/")
    while value.startswith("./"):
        value = value[2:]
    return value.lower() if sys.platform == "win32" else value


def same_path(key: str, path: str, repo: str | None) -> bool:
    key_clean = canon_for_compare(norm_path(key))
    path_clean = canon_for_compare(norm_path(path))
    if key_clean == path_clean or key_clean.endswith("/" + path_clean):
        return True
    if repo:
        try:
            root = Path(repo).resolve()
            key_path = Path(key.replace("\\", "/"))
            if not key_path.is_absolute():
                key_path = root / key_path
            if Path(key_path).resolve() == (root / path_clean).resolve():
                return True
        except OSError:
            return False
    return False


def coverage_lines(doc: dict, path: str, repo: str | None) -> set[int]:
    files = doc.get("files") or {}
    lines: set[int] = set()
    if not isinstance(files, dict):
        return lines
    for key, info in files.items():
        if not isinstance(info, dict) or not same_path(str(key), path, repo):
            continue
        for value in info.get("executed_lines") or []:
            try:
                lines.add(int(value))
            except (TypeError, ValueError):
                continue
    return lines


def load_json(path: str | Path, what: str):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise ToolError(f"cannot read {what}: {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ToolError(f"invalid JSON in {what}: {path}: {exc}") from exc


def load_covering(path: str | None) -> list[dict]:
    if not path:
        return []
    data = load_json(path, "covering-tests")
    if isinstance(data, dict):
        data = data.get("covering_tests") or data.get("tests") or []
    if not isinstance(data, list):
        raise ToolError("covering-tests must be a JSON list")
    entries = []
    for item in data:
        if not isinstance(item, dict):
            raise ToolError("covering-tests entries must be objects")
        if "path" not in item or "line" not in item or "test_id" not in item:
            raise ToolError("covering-tests entries need path, line, test_id")
        entries.append(item)
    return entries


def evaluate(
    diff_text: str,
    risk_map: dict,
    covering: list[dict],
    coverage: dict | None,
    repo: str | None = None,
) -> tuple[list[dict], dict]:
    files = parse_diff(diff_text)
    if not files:
        raise ToolError("no file changes found in diff")

    glob_map = GlobMap(risk_map.get("globs") or {})
    default_tier = (risk_map.get("default") or {}).get("tier", "none")
    names, ids, blocks = test_evidence(files)
    added_tests = bool(names or blocks)

    findings: list[dict] = []
    covered: list[dict] = []
    skipped = 0
    guard_removals = 0

    for fd in files:
        hit = glob_map.best(fd.path)
        tier = hit.get("tier", "none") if isinstance(hit, dict) else default_tier
        for old_line in sorted(fd.removed):
            body, head_line = fd.removed[old_line]
            if not guard_kind(body):
                continue
            if tier not in {"high", "max"}:
                skipped += 1
                continue
            guard_removals += 1
            covered_by = None

            for entry in covering:
                entry_path = norm_path(str(entry.get("path", "")))
                if entry_path != fd.path:
                    continue
                try:
                    entry_line = int(entry.get("line"))
                except (TypeError, ValueError):
                    continue
                if not line_in_hunk(fd, entry_line):
                    continue
                if test_is_added(str(entry.get("test_id", "")), names, ids):
                    covered_by = f"covering-test:{entry.get('test_id')}"
                    break

            if covered_by is None and coverage is not None and added_tests:
                executed = coverage_lines(coverage, fd.path, repo)
                if old_line in executed or head_line in executed:
                    covered_by = f"coverage:{fd.path}:{old_line}"

            if covered_by is None:
                symbols = removed_symbols(body)
                if symbols:
                    for block in blocks:
                        if any(
                            re.search(rf"\b{re.escape(symbol)}\b", block.body)
                            for symbol in symbols
                        ):
                            covered_by = f"diff-test:{block.file}:{block.name}"
                            break

            if covered_by is not None:
                covered.append(
                    {
                        "path": fd.path,
                        "line": old_line,
                        "removed": body.strip(),
                        "covered_by": covered_by,
                    }
                )
                continue

            removed = body.strip()
            findings.append(
                {
                    "class": "GUARD_REMOVED",
                    "path": fd.path,
                    "line": old_line,
                    "removed": removed,
                    "covered_by": None,
                    "tier": tier,
                    "symbol": removed,
                    "fingerprint": fingerprint("GUARD_REMOVED", fd.path, removed),
                }
            )

    findings.sort(key=lambda item: (item["path"], item["line"], item["class"], item["fingerprint"]))
    covered.sort(key=lambda item: (item["path"], item["line"]))
    extras = {
        "files_scanned": len(files),
        "guard_removals": guard_removals,
        "covered_count": len(covered),
        "covered": covered,
        "skipped_low_tier": skipped,
    }
    return findings, extras


def run_git_diff(repo: str, base: str, head: str) -> str:
    command = [
        "git", "-C", repo, "--no-pager", "diff", "--no-color", "-U0",
        f"{base}..{head}",
    ]
    try:
        proc = subprocess.run(command, capture_output=True, check=False)
    except OSError as exc:
        raise ToolError(f"cannot run git: {exc}") from exc
    if proc.returncode != 0:
        message = proc.stderr.decode("utf-8", "replace").strip()
        raise ToolError(f"git diff failed ({proc.returncode}): {message}")
    return proc.stdout.decode("utf-8", "replace")


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


def control_case(name: str, expected: str, findings: list, code: int, checks: dict) -> dict:
    return {
        "name": name,
        "passed": all(checks.values()),
        "expected": expected,
        "actual": {
            "exit_code": code,
            "findings": len(findings),
            "classes": sorted({item.get("class", "") for item in findings}),
            "tiers": sorted({item.get("tier", "") for item in findings if item.get("tier")}),
        },
    }


def control(risk_map: dict) -> dict:
    fixtures = HERE / "fixtures" / "guard_delta"
    bad_text = (fixtures / "bad.diff").read_text(encoding="utf-8-sig")
    good_text = (fixtures / "good.diff").read_text(encoding="utf-8-sig")
    covering = load_covering(str(fixtures / "covering-tests.json"))

    bad_findings, bad_extras = evaluate(bad_text, risk_map, [], None)
    bad_code = 1 if bad_findings else 0
    bad_case = control_case(
        "guard_delta/bad.diff",
        "exit 1, exactly 1 GUARD_REMOVED on tier max with no coverage",
        bad_findings,
        bad_code,
        {
            "exit": bad_code == 1,
            "count": len(bad_findings) == 1,
            "class": bool(bad_findings) and bad_findings[0]["class"] == "GUARD_REMOVED",
            "tier": bool(bad_findings) and bad_findings[0]["tier"] == "max",
            "uncovered": bool(bad_findings) and bad_findings[0]["covered_by"] is None,
        },
    )

    good_findings, good_extras = evaluate(good_text, risk_map, covering, None)
    good_code = 1 if good_findings else 0
    good_case = control_case(
        "guard_delta/good.diff",
        "exit 0, 0 findings, removal covered by an added test",
        good_findings,
        good_code,
        {
            "exit": good_code == 0,
            "count": len(good_findings) == 0,
            "covered": good_extras["covered_count"] == 1,
        },
    )

    return {
        "ran": True,
        "passed": bad_case["passed"] and good_case["passed"],
        "skipped_low_tier": bad_extras["skipped_low_tier"] + good_extras["skipped_low_tier"],
        "cases": [bad_case, good_case],
    }


def main(argv: list[str] | None = None) -> int:
    parser = Parser(description="Detect removed guards on high/max risk paths.")
    parser.add_argument("--repo", default=None, help="repo root (default: git root of cwd)")
    parser.add_argument("--base")
    parser.add_argument("--head")
    parser.add_argument("--diff-file")
    parser.add_argument("--risk-map", default=str(DEFAULT_RISK_MAP))
    parser.add_argument("--covering-tests")
    parser.add_argument("--coverage")
    parser.add_argument("--control", action="store_true")
    parser.add_argument("--out")
    try:
        args = parser.parse_args(None if argv is None else argv)
        risk_map = load_json(args.risk_map, "risk map")
        if not isinstance(risk_map, dict):
            raise ToolError("risk map must be a JSON object")

        if args.control:
            control_doc = control(risk_map)
            code = 0 if control_doc["passed"] else 1
            doc = envelope(
                "RESULT" if control_doc["passed"] else "CONTROL_FAIL",
                [],
                control_doc,
                code,
                {"risk_map": str(args.risk_map), "diff_source": "control",
                 "skipped_low_tier": control_doc.get("skipped_low_tier", 0)},
            )
            if args.out:
                Path(args.out).write_text(canonical_json(doc) + "\n", encoding="utf-8")
            sys.stdout.write(canonical_json(doc) + "\n")
            return code

        if args.diff_file:
            try:
                diff_text = Path(args.diff_file).read_text(encoding="utf-8-sig", errors="replace")
            except OSError as exc:
                raise ToolError(f"cannot read diff file: {args.diff_file}: {exc}") from exc
            source = "file"
            repo = resolve_repo(args.repo)
        else:
            if not args.base or not args.head:
                raise ToolError("provide --base and --head, or --diff-file")
            repo = require_repo(args.repo)
            diff_text = run_git_diff(repo, args.base, args.head)
            source = "git"

        covering = load_covering(args.covering_tests)
        coverage = None
        if args.coverage:
            coverage = load_json(args.coverage, "coverage")
            if not isinstance(coverage, dict):
                raise ToolError("coverage JSON must be an object")

        findings, extras = evaluate(diff_text, risk_map, covering, coverage, repo)
        code = 1 if findings else 0
        extras.update(
            {
                "base": args.base,
                "head": args.head,
                "diff_source": source,
                "risk_map": str(args.risk_map),
            }
        )
        doc = envelope("RESULT", findings, {"ran": False, "passed": True, "cases": []}, code, extras)
        if args.out:
            Path(args.out).write_text(canonical_json(doc) + "\n", encoding="utf-8")
        sys.stdout.write(canonical_json(doc) + "\n")
        return code
    except ToolError as exc:
        doc = envelope("ERROR", [], {"ran": False, "passed": False, "cases": []}, 2, {"error": str(exc)})
        sys.stdout.write(canonical_json(doc) + "\n")
        return 2
    except Exception as exc:  # noqa: BLE001
        doc = envelope(
            "ERROR",
            [],
            {"ran": False, "passed": False, "cases": []},
            2,
            {"error": f"{type(exc).__name__}: {exc}"},
        )
        sys.stdout.write(canonical_json(doc) + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
