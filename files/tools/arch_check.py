#!/usr/bin/env python3
"""ARCH_CHECK -- enforce the layer graph, manifests, public surface and owners.

Only added lines in the supplied diff are judged.  A Python/JS import creates
an edge between the source file's layer and the imported module's layer; the
edge must exist in layers.allowed_edges (self-edges are implicit).  Factory
paths (policies, .opencode, tools, .github/workflows) may not import into or
out of their tree at all.  Added dependency-manifest lines, new public-surface
files/exports and new modules without an owner are reported unless an
architecture_allow entry suppresses them.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import posixpath
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

TOOL = "arch_check"
VERSION = "1.0.0"
SCHEMA = "factory-tool/1"
HERE = Path(__file__).resolve().parent
DEFAULT_LAYERS = HERE.parent / "policies" / "layers.json"

PY_FROM = re.compile(r"^\s*from\s+([.\w]+)\s+import\b")
PY_IMPORT = re.compile(r"^\s*import\s+([.\w]+(?:\s*,\s*[.\w]+)*)")
JS_IMPORT = re.compile(r"""(?:\bfrom\s*|\brequire\s*\(\s*)['"]([^'"]+)['"]""")
JS_BARE = re.compile(r"""^\s*import\s*['"]([^'"]+)['"]""")
PY_DEF = re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(")
PY_CLASS = re.compile(r"^\s*class\s+([A-Za-z_]\w*)")
JS_EXPORT = re.compile(
    r"^\s*export\s+(?:default\s+)?(?:async\s+)?"
    r"(?:function|class|const|let|var|interface|type|enum)\s+([A-Za-z_$][\w$]*)"
)
JS_EXPORT_LIST = re.compile(r"^\s*export\s*\{")

SOURCE_SUFFIXES = (".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
NEW_MODULE_SUFFIXES = (".py", ".ts", ".tsx")


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


@dataclass
class FileDiff:
    path: str
    new_file: bool = False
    added: dict = field(default_factory=dict)
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


def norm_path(value: str, repo: str | None = None) -> str:
    value = value.strip()
    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    if value.startswith("a/") or value.startswith("b/"):
        value = value[2:]
    value = value.replace("\\", "/")
    if repo:
        try:
            root = Path(repo).resolve().as_posix().rstrip("/")
            if value.lower().startswith(root.lower() + "/"):
                value = value[len(root) + 1:]
        except OSError:
            pass
    while value.startswith("./"):
        value = value[2:]
    return value


def parse_diff(text: str) -> list[FileDiff]:
    files: list[FileDiff] = []
    current: FileDiff | None = None
    pending_new = False
    old_line = new_line = 0
    in_hunk = False
    for raw in text.splitlines():
        if raw.startswith("diff --git "):
            current = None
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
            in_hunk = False
            continue
        match = re.match(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$", raw)
        if match and current is not None:
            old_line = int(match.group(1))
            new_line = int(match.group(3))
            current.hunks.append(
                Hunk(
                    old_line,
                    int(match.group(2) if match.group(2) is not None else "1"),
                    new_line,
                    int(match.group(4) if match.group(4) is not None else "1"),
                    match.group(5).strip(),
                )
            )
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
            old_line += 1
        elif tag == " " or raw == "":
            old_line += 1
            new_line += 1
    return files


class LayerMap:
    def __init__(self, layers: dict):
        self.layers = layers
        mapping = {}
        for name, spec in (layers.get("layers") or {}).items():
            for glob in (spec or {}).get("globs") or []:
                mapping.setdefault(glob, name)
        self.glob_map = GlobMap(mapping)

    def layer_for(self, path: str) -> str | None:
        return self.glob_map.best(path)

    def allowed(self, source: str, target: str) -> bool:
        if source == target:
            return True
        for edge in self.layers.get("allowed_edges") or []:
            if edge.get("from") == source and edge.get("to") == target:
                return True
        return False

    def factory_globs(self) -> list[str]:
        return sorted((self.layers.get("factory_paths") or {}).keys())


def module_prefixes(path: str) -> list[str]:
    p = path.replace("\\", "/")
    for suffix in SOURCE_SUFFIXES:
        if p.endswith(suffix):
            p = p[: -len(suffix)]
            break
    parts = [part for part in p.split("/") if part]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return [".".join(parts[start:]) for start in range(len(parts))]


def py_module_candidates(module: str, source: str) -> list[str]:
    stems: list[str] = []
    if module.startswith("."):
        level = len(module) - len(module.lstrip("."))
        rest = module[level:]
        base = source.rsplit("/", 1)[0] if "/" in source else ""
        for _ in range(max(0, level - 1)):
            base = base.rsplit("/", 1)[0] if "/" in base else ""
        stem = f"{base}/{rest.replace('.', '/')}" if rest else base
        stems.append(stem)
    else:
        stems.append(module.replace(".", "/"))

    candidates: list[str] = []
    for stem in stems:
        stem = stem.strip("/")
        if not stem:
            continue
        prefixes = [""]
        if not stem.startswith("backend/"):
            prefixes.append("backend/")
        for prefix in prefixes:
            base = prefix + stem
            candidates.append(base + ".py")
            candidates.append(base + "/__init__.py")
    return candidates


def js_module_candidates(spec: str, source: str) -> list[str]:
    stems: list[str] = []
    if spec.startswith("@/"):
        stems.append("frontend/src/" + spec[2:])
    elif spec.startswith("."):
        base = source.rsplit("/", 1)[0] if "/" in source else ""
        stems.append(posixpath.normpath(posixpath.join(base, spec)))
    elif spec.startswith("frontend/") or spec.startswith("src/"):
        stems.append(spec if spec.startswith("frontend/") else "frontend/" + spec)
    else:
        return []

    candidates: list[str] = []
    for stem in stems:
        stem = stem.lstrip("./")
        if not stem:
            continue
        if re.search(r"\.(?:js|jsx|ts|tsx|mjs|cjs)$", stem):
            candidates.append(stem)
            continue
        for extension in (".ts", ".tsx", ".js", ".jsx"):
            candidates.append(stem + extension)
        for extension in (".ts", ".tsx", ".js", ".jsx"):
            candidates.append(f"{stem}/index{extension}")
    return candidates


def py_imports(line: str) -> list[str]:
    match = PY_FROM.match(line)
    if match:
        return [match.group(1)]
    match = PY_IMPORT.match(line)
    if match:
        return [part.strip() for part in match.group(1).split(",") if part.strip()]
    return []


def js_imports(line: str) -> list[str]:
    found = [match.group(1) for match in JS_IMPORT.finditer(line)]
    bare = JS_BARE.match(line)
    if bare:
        found.append(bare.group(1))
    return found


def dependency_name(line: str, path: str) -> str:
    if path.endswith(("requirements.txt", "requirements-dev.txt")) or "/requirements" in path:
        match = re.match(r"^([A-Za-z0-9][A-Za-z0-9_.\-]*)", line)
        if match:
            return match.group(1)
    if path.endswith("pyproject.toml"):
        match = re.match(r"^([A-Za-z0-9][A-Za-z0-9_.\-]*)\s*=", line)
        if match:
            return match.group(1)
    if path.endswith(".json"):
        match = re.match(r'^"([^"]+)"\s*:', line)
        if match:
            return match.group(1)
    return line


def load_json(path: str | Path, what: str):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise ToolError(f"cannot read {what}: {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ToolError(f"invalid JSON in {what}: {path}: {exc}") from exc


def load_allow(value: str | None) -> list[dict]:
    if not value:
        return []
    candidate = Path(value)
    if candidate.is_file():
        data = load_json(candidate, "architecture allow")
    else:
        try:
            data = json.loads(value)
        except json.JSONDecodeError:
            raise ToolError(f"--allow is neither a JSON file nor inline JSON: {value}")
    if isinstance(data, dict):
        data = data.get("architecture_allow") or data.get("allow") or []
    if not isinstance(data, list):
        raise ToolError("architecture_allow must be a JSON list")
    entries = []
    for item in data:
        if isinstance(item, dict) and item.get("kind"):
            entries.append(item)
    return entries


def field_matches(expected, actual: str) -> bool:
    if expected is None or expected == "":
        return True
    text = str(expected)
    if text == "*" or text == actual:
        return True
    if any(char in text for char in "*?["):
        return bool(glob_regex(text).match(actual))
    return False


def allow_matches(entry: dict, kind: str, from_: str, to: str, path: str) -> bool:
    if entry.get("kind") != kind:
        return False
    source = entry.get("from", entry.get("source"))
    target = entry.get("to", entry.get("target"))
    if not field_matches(source, from_):
        return False
    if not field_matches(target, to):
        return False
    if entry.get("path") is not None and not field_matches(entry.get("path"), path):
        return False
    return True


def evaluate(
    diff_text: str,
    layers: dict,
    allow: list[dict],
    repo: str | None = None,
) -> tuple[list[dict], dict]:
    files = parse_diff(diff_text)
    if not files:
        raise ToolError("no file changes found in diff")

    layer_map = LayerMap(layers)
    factory_map = GlobMap({glob: glob for glob in layer_map.factory_globs()})
    owner_map = GlobMap(layers.get("module_owners") or {})
    manifest_paths = {norm_path(str(item), repo) for item in layers.get("dependency_manifests") or []}
    public_globs = list(layers.get("public_surface") or [])
    for spec in (layers.get("layers") or {}).values():
        public_globs.extend((spec or {}).get("public_surface") or [])
    public_map = GlobMap({glob: glob for glob in dict.fromkeys(public_globs)})

    findings: list[dict] = []
    allowed: list[dict] = []
    imports_scanned = 0

    def emit(kind: str, path: str, line: int, from_: str, to: str, symbol: str, evidence: str):
        finding = {
            "class": "ARCH_VIOLATION",
            "kind": kind,
            "path": path,
            "line": line,
            "from": from_,
            "to": to,
            "symbol": symbol,
            "evidence": evidence.strip()[:160],
            "fingerprint": fingerprint("ARCH_VIOLATION", path, symbol),
        }
        for entry in allow:
            if allow_matches(entry, kind, from_, to, path):
                allowed.append(
                    {
                        "kind": kind,
                        "from": from_,
                        "to": to,
                        "path": path,
                        "line": line,
                        "allow": {key: entry[key] for key in ("kind", "from", "to", "path") if key in entry},
                    }
                )
                return
        for existing in findings:
            if (
                existing["kind"] == kind
                and existing["path"] == path
                and existing["line"] == line
                and existing["symbol"] == symbol
            ):
                return
        findings.append(finding)

    for fd in files:
        path = fd.path
        source_layer = layer_map.layer_for(path)
        source_factory = factory_map.best(path)
        ordered = sorted(fd.added.items())

        if path.endswith(".py"):
            for line, body in ordered:
                for module in py_imports(body):
                    imports_scanned += 1
                    target = None
                    for candidate in py_module_candidates(module, path):
                        layer = layer_map.layer_for(candidate)
                        if layer:
                            target = ("layer", layer, candidate)
                            break
                    if target is None:
                        for candidate in py_module_candidates(module, path):
                            factory = factory_map.best(candidate)
                            if factory:
                                target = ("factory", factory, candidate)
                                break
                    if target is None:
                        continue
                    target_kind, target_value, _candidate = target
                    if source_factory or target_kind == "factory":
                        if (
                            source_factory
                            and target_kind == "factory"
                            and source_factory == target_value
                        ):
                            continue
                        from_label = f"factory:{source_factory}" if source_factory else (source_layer or "")
                        to_label = (
                            f"factory:{target_value}" if target_kind == "factory" else target_value
                        )
                        emit(
                            "edge", path, line, from_label, to_label,
                            f"{from_label}->{to_label}", body,
                        )
                    elif source_layer and target_kind == "layer":
                        if layer_map.allowed(source_layer, target_value):
                            continue
                        emit(
                            "edge", path, line, source_layer, target_value,
                            f"{source_layer}->{target_value}", body,
                        )

        elif path.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")):
            for line, body in ordered:
                for spec in js_imports(body):
                    imports_scanned += 1
                    target = None
                    for candidate in js_module_candidates(spec, path):
                        layer = layer_map.layer_for(candidate)
                        if layer:
                            target = ("layer", layer, candidate)
                            break
                    if target is None:
                        for candidate in js_module_candidates(spec, path):
                            factory = factory_map.best(candidate)
                            if factory:
                                target = ("factory", factory, candidate)
                                break
                    if target is None:
                        continue
                    target_kind, target_value, _candidate = target
                    if source_factory or target_kind == "factory":
                        if (
                            source_factory
                            and target_kind == "factory"
                            and source_factory == target_value
                        ):
                            continue
                        from_label = f"factory:{source_factory}" if source_factory else (source_layer or "")
                        to_label = (
                            f"factory:{target_value}" if target_kind == "factory" else target_value
                        )
                        emit(
                            "edge", path, line, from_label, to_label,
                            f"{from_label}->{to_label}", body,
                        )
                    elif source_layer and target_kind == "layer":
                        if layer_map.allowed(source_layer, target_value):
                            continue
                        emit(
                            "edge", path, line, source_layer, target_value,
                            f"{source_layer}->{target_value}", body,
                        )

        if path in manifest_paths:
            for line, body in ordered:
                stripped = body.strip()
                if not stripped:
                    continue
                if stripped.startswith(("#", "//", "/*", "*", "<!--")):
                    continue
                dependency = dependency_name(stripped, path)
                emit(
                    "dependency", path, line, path, dependency,
                    f"dependency:{dependency}", stripped,
                )

        is_public = public_map.best(path) is not None
        if is_public:
            if fd.new_file:
                emit(
                    "public_surface", path, 1, source_layer or "", path,
                    f"public_surface:new:{path}", "new file under public_surface",
                )
            for line, body in ordered:
                names = []
                for pattern in (PY_DEF, PY_CLASS, JS_EXPORT):
                    match = pattern.match(body)
                    if match:
                        names.append(match.group(1))
                if JS_EXPORT_LIST.match(body):
                    names.append("export")
                for name in names:
                    emit(
                        "public_surface", path, line, source_layer or "", path,
                        f"public_surface:{path}:{name}", body,
                    )

        if fd.new_file and path.endswith(NEW_MODULE_SUFFIXES):
            if owner_map.best(path) is None:
                emit(
                    "unowned_module", path, 1, "", path,
                    f"unowned_module:{path}", "new module has no matching module_owners glob",
                )

    findings.sort(key=lambda item: (item["path"], item["line"], item["class"], item["fingerprint"]))
    allowed.sort(key=lambda item: (item["path"], item["line"], item["kind"], item["to"]))
    extras = {
        "files_scanned": len(files),
        "imports_scanned": imports_scanned,
        "allowed_count": len(allowed),
        "allowed": allowed,
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
            "kinds": sorted({item.get("kind", "") for item in findings}),
        },
    }


def control(layers: dict) -> dict:
    fixtures = HERE / "fixtures" / "arch_check"
    bad_text = (fixtures / "bad.diff").read_text(encoding="utf-8-sig")
    clean_text = (fixtures / "clean.diff").read_text(encoding="utf-8-sig")

    bad_findings, _ = evaluate(bad_text, layers, [])
    bad_code = 1 if bad_findings else 0
    bad_kinds = {item.get("kind") for item in bad_findings}
    bad_case = control_case(
        "arch_check/bad.diff",
        "exit 1, >=3 findings including edge, dependency and unowned_module",
        bad_findings,
        bad_code,
        {
            "exit": bad_code == 1,
            "count": len(bad_findings) >= 3,
            "edge": "edge" in bad_kinds,
            "dependency": "dependency" in bad_kinds,
            "unowned_module": "unowned_module" in bad_kinds,
        },
    )

    clean_findings, _ = evaluate(clean_text, layers, [])
    clean_code = 1 if clean_findings else 0
    clean_case = control_case(
        "arch_check/clean.diff",
        "exit 0, 0 findings (orders -> common is allowed)",
        clean_findings,
        clean_code,
        {"exit": clean_code == 0, "count": len(clean_findings) == 0},
    )

    return {
        "ran": True,
        "passed": bad_case["passed"] and clean_case["passed"],
        "cases": [bad_case, clean_case],
    }


def main(argv: list[str] | None = None) -> int:
    parser = Parser(description="Check layer edges, manifests, public surface and module owners.")
    parser.add_argument("--repo", default=None, help="repo root (default: git root of cwd)")
    parser.add_argument("--base")
    parser.add_argument("--head")
    parser.add_argument("--diff-file")
    parser.add_argument("--layers", default=str(DEFAULT_LAYERS))
    parser.add_argument("--allow")
    parser.add_argument("--control", action="store_true")
    parser.add_argument("--out")
    try:
        args = parser.parse_args(None if argv is None else argv)
        layers = load_json(args.layers, "layers policy")
        if not isinstance(layers, dict):
            raise ToolError("layers policy must be a JSON object")
        allow = load_allow(args.allow)

        if args.control:
            control_doc = control(layers)
            code = 0 if control_doc["passed"] else 1
            doc = envelope(
                "RESULT" if control_doc["passed"] else "CONTROL_FAIL",
                [],
                control_doc,
                code,
                {"layers": str(args.layers), "diff_source": "control"},
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

        findings, extras = evaluate(diff_text, layers, allow, repo)
        code = 1 if findings else 0
        extras.update(
            {
                "base": args.base,
                "head": args.head,
                "diff_source": source,
                "layers": str(args.layers),
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
