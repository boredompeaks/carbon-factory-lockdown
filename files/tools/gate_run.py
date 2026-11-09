#!/usr/bin/env python3
"""Deterministic checks that do not need a live application runtime.

`gate_run.py --check <ID> --input <json>` evaluates one check and exits
0 (accept), 1 (reject), or 2 (tool error). `--control` runs the check's
known-bad and known-good fixtures and returns the same envelope shape as the
other factory tools, so gate_control.py can admit the case as a negative
control.

Execution model: SECRETS and CONVENTION execute subprocesses (gitleaks and
ruff respectively); every other check is a recorded-evidence evaluator that
consumes evidence JSON and never executes the suite, boot, zizmor, or ZAP
itself. Where evidence JSON carries a SHA-256 claim beside an output string
or file path, the evaluators verify the hash against the actual bytes and
emit a finding on mismatch.

Checks implemented here: SCOPE, TEST_SET, TEST_INFRA, CHANGELOG, SECRETS,
CONVENTION, GATE_CONTROLS, plus the structured-evidence evaluators SUITE,
BASE_FAIL_HEAD_PASS, MUTATION, THREAD_RACE, SCHEMA_FUZZ, BOOTTEST, ZIZMOR,
and DAST_BASELINE.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from gate_run_doc_patch import check_doc_scope

TOOL = "gate_run"
VERSION = "1.0.0"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
POLICIES = Path(__file__).resolve().parent.parent / "policies"

CHECKS = (
    "SCOPE",
    "SUITE",
    "TEST_SET",
    "TEST_INFRA",
    "BASE_FAIL_HEAD_PASS",
    "MUTATION",
    "CHANGELOG",
    "SECRETS",
    "CONVENTION",
    "GATE_CONTROLS",
    "THREAD_RACE",
    "SCHEMA_FUZZ",
    "BOOTTEST",
    "ZIZMOR",
    "DAST_BASELINE",
    "DOC",
)


def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


def normalise(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def matches(path: str, globs: list[str]) -> bool:
    path = normalise(path)
    return any(fnmatch.fnmatchcase(path, normalise(glob)) for glob in globs)


def finding(kind: str, locus: str, detail: str) -> dict:
    return {"class": kind, "locus": locus, "detail": detail}


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


# Recorded-evidence checks verify embedded hashes; DOC is intentionally
# untouched, SECRETS/CONVENTION run subprocesses instead.
_EVIDENCE_CHECKS = frozenset({"SCOPE", "SUITE", "TEST_SET", "TEST_INFRA", "BASE_FAIL_HEAD_PASS", "MUTATION", "CHANGELOG", "GATE_CONTROLS", "THREAD_RACE", "SCHEMA_FUZZ", "BOOTTEST", "ZIZMOR", "DAST_BASELINE"})
_STRING_KEYS = ("output", "content", "text", "stdout", "stderr", "body", "data", "result")


def _evidence_hash_findings(node: object, locus: str = "evidence") -> list[dict]:
    """Verify embedded SHA-256 claims against strings/file bytes; mismatch -> finding.

    Fail-closed on missing bytes: a hash claim whose actual string/file
    cannot be read (missing path, missing output) emits
    EVIDENCE_HASH_MISSING instead of silently passing.
    """
    out: list[dict] = []
    if isinstance(node, dict):
        for key, value in node.items():
            k = str(key).strip().lower()
            if ("sha256" in k or k in ("hash", "digest")) and isinstance(value, str) and value.strip():
                expected = value.strip().lower()
                if expected.startswith("sha256:"):
                    expected = expected[len("sha256:") :]
                actual = None
                has_string = False
                for skey in _STRING_KEYS:
                    if isinstance(node.get(skey), str):
                        actual = hashlib.sha256(str(node[skey]).encode("utf-8")).hexdigest()
                        has_string = True
                        break
                if actual is None and isinstance(node.get("path"), str):
                    try:
                        actual = hashlib.sha256(Path(str(node["path"])).read_bytes()).hexdigest()
                    except OSError:
                        actual = None
                if actual is None:
                    out.append(finding("EVIDENCE_HASH_MISSING", f"{locus}.{key}", "sha256 claim present but the claimed bytes/output are missing"))
                elif actual != expected:
                    out.append(finding("EVIDENCE_HASH_MISMATCH", f"{locus}.{key}", "sha256 does not match actual bytes/output"))
            elif ("sha256" in k or k in ("hash", "digest")) and (value is None or (isinstance(value, str) and not value.strip())):
                # Explicit empty hash claim with claimed bytes present is
                # a missing hash (fail closed). Nodes without any claimed
                # bytes and without a hash key do not trigger here.
                if any(isinstance(node.get(skey), str) for skey in _STRING_KEYS) or isinstance(node.get("path"), str):
                    out.append(finding("EVIDENCE_HASH_MISSING", f"{locus}.{key}", "sha256 claim missing but bytes/output are present"))
        for key, value in node.items():
            out.extend(_evidence_hash_findings(value, f"{locus}.{key}"))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            out.extend(_evidence_hash_findings(value, f"{locus}[{index}]"))
    return out


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


def check_scope(data: dict) -> list[dict]:
    # Fail-closed on missing evidence: missing/empty scope or paths is
    # SCOPE_MISSING, never a vacuous PASS.
    if "scope" not in data or "paths" not in data:
        return [finding("SCOPE_MISSING", "evidence", "scope/paths evidence is missing")]
    scope = list(data.get("scope") or [])
    paths = list(data.get("paths") or [])
    if not scope:
        return [finding("SCOPE_MISSING", "scope", "scope is missing/empty")]
    if not paths:
        return [finding("SCOPE_MISSING", "paths", "paths is missing/empty")]
    return [
        finding("SCOPE_VIOLATION", str(path), "path is outside capability.scope")
        for path in data.get("paths") or []
        if not matches(str(path), scope)
    ]


def _test_map(items: list[dict]) -> dict[str, dict]:
    return {str(item["id"]): item for item in items}


def check_test_set(data: dict) -> list[dict]:
    # Fail-closed on missing evidence.
    if "base" not in data or "head" not in data:
        return [finding("TEST_SET_MISSING", "evidence", "base/head test evidence is missing")]
    if not data.get("base") and not data.get("head"):
        return [finding("TEST_SET_MISSING", "base/head", "base/head are missing/empty")]
    findings: list[dict] = []
    base = _test_map(list(data.get("base") or []))
    head = _test_map(list(data.get("head") or []))
    allowed = {
        str(item.get("test_id"))
        for item in data.get("allowed_removals") or []
    }
    for item in data.get("allowed_removals") or []:
        covered_by = item.get("covered_by") if isinstance(item, dict) else None
        if covered_by is None or (isinstance(covered_by, str) and not covered_by.strip()):
            findings.append(
                finding(
                    "TEST_REMOVAL_UNCOVERED",
                    str(item.get("test_id") or "allowed_removals"),
                    "allowed_removal covered_by is null, missing, or empty",
                )
            )
    for test_id in base:
        if test_id not in head and test_id not in allowed:
            findings.append(
                finding(
                    "TEST_REMOVAL_UNCOVERED",
                    test_id,
                    "test id present at base is absent at head without an allowance",
                )
            )
    for test_id, item in head.items():
        markers = {str(marker).lower() for marker in item.get("markers") or []}
        bad = markers & {"skip", "xfail", "expectedfailure", "skiptest"}
        if bad:
            findings.append(
                finding(
                    "TEST_REMOVAL_UNCOVERED",
                    test_id,
                    "added skip/xfail marker: " + ", ".join(sorted(bad)),
                )
            )
        previous = base.get(test_id)
        if previous is not None and int(item.get("assertions", 0)) < int(
            previous.get("assertions", 0)
        ):
            findings.append(
                finding(
                    "TAUTOLOGICAL_ASSERTION",
                    test_id,
                    "assertion count is lower than base",
                )
            )
    patterns = [re.compile(str(p)) for p in data.get("tautology_patterns") or []]
    for assertion in data.get("added_assertions") or []:
        if any(pattern.search(str(assertion)) for pattern in patterns):
            findings.append(
                finding(
                    "TAUTOLOGICAL_ASSERTION",
                    "added-assertion",
                    "assertion matches a tautology pattern",
                )
            )
    return findings


def check_test_infra(data: dict) -> list[dict]:
    if "paths" not in data or "scope" not in data or "test_infra_globs" not in data:
        return [finding("TEST_INFRA_MISSING", "evidence", "paths/scope/test_infra_globs evidence is missing")]
    if not data.get("paths"):
        return [finding("TEST_INFRA_MISSING", "paths", "paths is missing/empty")]
    if not data.get("scope"):
        return [finding("TEST_INFRA_MISSING", "scope", "scope is missing/empty")]
    if not data.get("test_infra_globs"):
        return [finding("TEST_INFRA_MISSING", "test_infra_globs", "test_infra_globs is missing/empty")]
    globs = list(data.get("test_infra_globs") or [])
    scope = list(data.get("scope") or [])
    findings: list[dict] = []
    for path in data.get("paths") or []:
        path = str(path)
        if matches(path, globs) and not matches(path, scope):
            findings.append(
                finding(
                    "TEST_INFRA_CHANGE",
                    normalise(path),
                    "test-infrastructure path is outside capability.scope",
                )
            )
    return findings


def check_changelog(data: dict) -> list[dict]:
    # Fail-closed on missing evidence.
    if "paths" not in data or "rows" not in data:
        return [finding("CHANGELOG_MISSING", "evidence", "paths/rows changelog evidence is missing")]
    if not data.get("paths"):
        return [finding("CHANGELOG_MISSING", "paths", "paths is missing/empty")]
    paths = {normalise(str(path)) for path in data.get("paths") or []}
    exempt = list(data.get("exempt") or [])
    findings: list[dict] = []
    covered: set[str] = set()
    cap = data.get("capability") if isinstance(data.get("capability"), dict) else {}
    cap_tier = cap.get("tier", data.get("capability_tier", data.get("tier")))
    cap_tier = str(cap_tier) if cap_tier is not None else None
    valid_classes: set[str] | None = None
    for row in data.get("rows") or []:
        row_paths = {normalise(str(path)) for path in row.get("paths") or []}
        outside = row_paths - paths
        if outside:
            findings.append(
                finding(
                    "CHANGELOG_GAP",
                    "row:" + ",".join(sorted(row_paths)),
                    "row names paths not present in the diff: "
                    + ", ".join(sorted(outside)),
                )
            )
        row_tier = row.get("tier")
        if cap_tier is not None and row_tier is not None and str(row_tier) != cap_tier:
            findings.append(finding("CHANGELOG_GAP", "tier", f"changelog tier {row_tier!r} != capability tier {cap_tier!r}"))
        attack = row.get("attack_class")
        if attack is not None:
            if valid_classes is None:
                try:
                    sev = load_json(POLICIES / "severity.json")
                    valid_classes = {k for k, v in sev.items() if isinstance(v, dict) and any(t in v for t in ("none", "high", "max"))}
                except Exception:
                    valid_classes = set()
            if str(attack) not in valid_classes:
                findings.append(finding("CHANGELOG_GAP", str(attack), f"attack_class {attack!r} is not a known severity class"))
        covered |= row_paths & paths
    for path in sorted(paths - covered):
        if not matches(path, exempt):
            findings.append(
                finding(
                    "CHANGELOG_GAP",
                    path,
                    "diff path is not named by any added changelog row",
                )
            )
    return findings


def _gitleaks_binary() -> str:
    """Resolve gitleaks fail-closed: GITLEAKS_BIN env override, else PATH."""
    override = os.environ.get("GITLEAKS_BIN")
    if override:
        return override
    found = shutil.which("gitleaks")
    if found:
        return found
    raise RuntimeError(
        "gitleaks binary not found: set GITLEAKS_BIN or put gitleaks on PATH"
    )


def _run_gitleaks(
    source: Path, report: Path, config: Path | None = None
) -> subprocess.CompletedProcess[str]:
    """Run gitleaks over an absolute source path; cwd is deliberately unset."""
    command = [
        _gitleaks_binary(),
        "detect",
        "--no-git",
        "--source",
        str(source),
        "--report-format",
        "json",
        "--report-path",
        str(report),
        "--no-banner",
    ]
    if config is not None:
        command.extend(["--config", str(config)])
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


def _gitleaks_findings(
    report: Path,
    process: subprocess.CompletedProcess[str],
    remap: dict[str, str] | None = None,
) -> list[dict]:
    if process.returncode not in (0, 1):
        output = (process.stderr or "") + (process.stdout or "")
        raise RuntimeError(
            f"gitleaks exited {process.returncode}: {output.strip() or 'no output'}"
        )
    if not report.is_file():
        if process.returncode == 0:
            return []
        raise RuntimeError("gitleaks reported leaks but wrote no report")
    try:
        leaks = json.loads(report.read_text(encoding="utf-8") or "[]")
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"cannot parse gitleaks report {report}: {exc}") from exc
    if not isinstance(leaks, list):
        raise RuntimeError("gitleaks report is not a JSON list")
    findings: list[dict] = []
    for leak in leaks:
        raw = str(leak.get("File", ""))
        original = remap.get(Path(raw).name, raw) if remap is not None else raw
        line = int(leak.get("StartLine") or 0)
        rule = str(leak.get("RuleID") or "unknown")
        findings.append(finding("SECRET_LEAK", f"{original}:{line}", f"{rule}:{line}"))
    if process.returncode == 1 and not findings:
        raise RuntimeError("gitleaks exited 1 but its report contains no leaks")
    return findings


def check_secrets(data: dict) -> list[dict]:
    # Fail-closed on missing evidence: missing/empty paths is FAIL,
    # never a vacuous PASS over an empty temp dir.
    if "paths" not in data or not data.get("paths"):
        return [finding("SECRETS_MISSING_PATHS", "paths", "paths is missing/empty")]
    paths = [Path(str(path)) for path in data.get("paths") or []]
    remap: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="gate-run-secrets-") as tmp:
        root = Path(tmp)
        for index, path in enumerate(paths):
            if not path.is_file():
                raise FileNotFoundError(
                    f"secrets input path is not a readable file: {path}"
                )
            target = root / f"{index:04d}-{path.name}"
            try:
                shutil.copyfile(path, target)
            except OSError as exc:
                raise OSError(f"cannot read secrets input {path}: {exc}") from exc
            remap[target.name] = str(path)
        report = root / "report.json"
        process = _run_gitleaks(root.resolve(), report.resolve())
        return _gitleaks_findings(report, process, remap)


def _scan_secrets_directory(directory: Path) -> list[dict]:
    """Control-mode scan of one fixture directory, honouring its allowlist."""
    config = directory / ".gitleaks.toml"
    with tempfile.TemporaryDirectory(prefix="gate-run-secrets-control-") as tmp:
        report = Path(tmp) / "report.json"
        process = _run_gitleaks(
            directory.resolve(),
            report.resolve(),
            config.resolve() if config.is_file() else None,
        )
        return _gitleaks_findings(report, process)


def _ruff_binary() -> str | None:
    return shutil.which("ruff")


def check_convention(data: dict) -> tuple[list[dict], str | None]:
    # Fail-closed on missing evidence: missing/empty files is FAIL,
    # never a vacuous PASS. The missing-files check runs before the
    # ruff-availability error so empty input is always FAIL.
    files = [str(path) for path in data.get("files") or []]
    if "files" not in data or not files:
        return [finding("CONVENTION_MISSING_FILES", "files", "files is missing/empty")], None
    ruff = _ruff_binary()
    if ruff is None:
        return [], "ruff is not on PATH"
    added = {
        normalise(str(path)): {int(line) for line in lines or []}
        for path, lines in (data.get("added_lines") or {}).items()
    }
    process = subprocess.run(
        [ruff, "check", "--output-format=json", *files],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    if process.returncode == 2:
        return [], process.stderr.strip() or "ruff failed"
    try:
        diagnostics = json.loads(process.stdout or "[]")
    except json.JSONDecodeError as exc:
        return [], f"ruff output is not JSON: {exc}"
    findings: list[dict] = []
    for diagnostic in diagnostics:
        path = normalise(str(diagnostic.get("filename", "")))
        row = diagnostic.get("location", {}).get("row")
        if added and path in added and row not in added[path]:
            continue
        code = diagnostic.get("code") or "RUFF"
        findings.append(
            finding(
                "CONVENTION_VIOLATION",
                f"{path}:{row}",
                str(code),
            )
        )
    return findings, None


def manifest_minima(manifest: dict) -> tuple[dict[str, int], int]:
    minima = {
        str(check): int(entry.get("min_count", 0))
        for check, entry in (manifest.get("controls") or {}).items()
    }
    return minima, int(manifest.get("known_bad_min", manifest.get("total_min", 0)))


def check_gate_controls(data: dict) -> list[dict]:
    record = data.get("record") or {}
    manifest = data.get("manifest") or {}
    minima, known_bad_min = manifest_minima(manifest)
    controls = list(record.get("controls") or [])
    bad = [item for item in controls if item.get("expected_outcome") == "FAIL"]
    rejected = [item for item in bad if item.get("rejected") is True]
    reported_total = int(record.get("controls_total", -1))
    reported_rejected = int(record.get("controls_rejected", -1))
    findings: list[dict] = []
    if reported_total != len(bad):
        findings.append(
            finding(
                "CONTROL_UNDERCOUNT",
                "controls_total",
                f"record says {reported_total}, controls array has {len(bad)} known-bad entries",
            )
        )
    if reported_total < known_bad_min:
        findings.append(
            finding(
                "CONTROL_UNDERCOUNT",
                "known_bad_min",
                f"controls_total {reported_total} is below known_bad_min {known_bad_min}",
            )
        )
    for check, minimum in minima.items():
        count = sum(1 for item in bad if item.get("check_id") == check)
        if count < minimum:
            findings.append(
                finding(
                    "CONTROL_UNDERCOUNT",
                    check,
                    f"{count} known-bad controls, minimum {minimum}",
                )
            )
    if reported_rejected != reported_total or len(rejected) != len(bad):
        findings.append(
            finding(
                "GATE_CONTROL_FAILURE",
                "controls_rejected",
                f"{reported_rejected}/{reported_total} rejected; array {len(rejected)}/{len(bad)}",
            )
        )
    if record.get("all_rejected") is not True:
        findings.append(
            finding("GATE_CONTROL_FAILURE", "all_rejected", "all_rejected is not true")
        )
    if record.get("result") != "PASS":
        findings.append(
            finding("GATE_CONTROL_FAILURE", "result", "record result is not PASS")
        )
    return findings


_DJANGO_RAN = re.compile(r"^Ran (\d+) tests? in \d+(?:\.\d+)?s\s*$", re.MULTILINE)
_DJANGO_OK = re.compile(r"^OK(?: \(.*\))?\s*$", re.MULTILINE)
_DJANGO_FAILED = re.compile(r"^FAILED\b.*$", re.MULTILINE)


def check_suite(data: dict) -> list[dict]:
    """SUITE: every configured engine must show a real Django pass summary."""
    engines = data.get("engines")
    if not isinstance(engines, dict) or not engines:
        return [
            finding(
                "SUITE_MISSING_ENGINE",
                "engines",
                "no engine results were supplied",
            )
        ]
    findings: list[dict] = []
    for engine in ("postgres", "sqlite"):
        entry = engines.get(engine)
        if not isinstance(entry, dict):
            findings.append(
                finding(
                    "SUITE_MISSING_ENGINE",
                    engine,
                    f"{engine} suite evidence is absent",
                )
            )
            continue
        output = str(entry.get("output") or "")
        ran = _DJANGO_RAN.search(output)
        ok = _DJANGO_OK.search(output)
        failed = _DJANGO_FAILED.search(output)
        if failed is not None:
            findings.append(
                finding(
                    "SUITE_FAILED",
                    engine,
                    "Django summary reports FAILED",
                )
            )
            continue
        if ran is None:
            findings.append(
                finding(
                    "SUITE_UNMEASURED",
                    engine,
                    "output has no 'Ran N tests in ...' summary; "
                    "an exit code alone is not evidence",
                )
            )
            continue
        count = int(ran.group(1))
        if count <= 0:
            findings.append(
                finding(
                    "SUITE_UNMEASURED",
                    engine,
                    f"Django summary reports Ran {count} tests",
                )
            )
            continue
        if ok is None:
            findings.append(
                finding(
                    "SUITE_UNMEASURED",
                    engine,
                    "Django summary has no OK verdict line",
                )
            )
            continue
        exit_code = entry.get("exit_code")
        if exit_code is not None and int(exit_code) != 0:
            findings.append(
                finding(
                    "SUITE_FAILED",
                    engine,
                    f"test process exited {int(exit_code)} with an OK summary",
                )
            )
    return findings


def check_base_fail_head_pass(data: dict) -> list[dict]:
    """BASE_FAIL_HEAD_PASS: added tests must be red on base and green on head."""
    # Fail-closed on missing evidence.
    if "added_tests" not in data or not data.get("added_tests"):
        return [finding("BASE_FAIL_HEAD_PASS_MISSING", "added_tests", "added_tests is missing/empty")]
    findings: list[dict] = []
    for index, test in enumerate(data.get("added_tests") or []):
        test_id = str(test.get("id") or f"added_tests[{index}]")
        base = str(test.get("base_outcome") or "").upper()
        head = str(test.get("head_outcome") or "").upper()
        characterization = bool(test.get("characterization"))
        fail_kind = str(test.get("fail_kind") or "").strip()
        reason = str(test.get("reason") or "").strip()
        if base == "OK":
            findings.append(
                finding(
                    "NON_FALSIFIABLE",
                    test_id,
                    "added test passes on base; it cannot demonstrate the change",
                )
            )
        elif base not in {"FAILED", "ERROR"}:
            findings.append(
                finding(
                    "INVALID",
                    test_id,
                    f"base_outcome {base or '<missing>'} is not FAILED|ERROR|OK",
                )
            )
        if head != "OK":
            findings.append(
                finding(
                    "INVALID",
                    test_id,
                    f"head_outcome {head or '<missing>'} is not OK",
                )
            )
        if not characterization and not fail_kind:
            findings.append(
                finding(
                    "INVALID",
                    test_id,
                    "non-characterization test has no fail_kind",
                )
            )
        if characterization and not reason:
            findings.append(
                finding(
                    "INVALID",
                    test_id,
                    "characterization test has an empty reason",
                )
            )
    return findings


def _locus(value: object) -> str:
    return normalise(str(value or ""))


def check_mutation(data: dict) -> list[dict]:
    """MUTATION: kill ratio above threshold and no survivor on a changed line."""
    # Fail-closed on missing evidence: MUTATION {} (or any missing
    # score/threshold) is MUTATION_MISSING, never a vacuous PASS.
    if data.get("score") is None or data.get("threshold") is None:
        return [finding("MUTATION_MISSING", "evidence", "score/threshold mutation evidence is missing")]
    findings: list[dict] = []
    score = float(data.get("score", 0.0) or 0.0)
    threshold = float(data.get("threshold", 0.0) or 0.0)
    total_mutatable = data.get("total_mutatable")
    total_generated = data.get("total_generated")
    if total_mutatable is not None and total_generated is not None and total_mutatable != total_generated:
        findings.append(finding("MUTATION_TRUNCATED", "mutants_truncated", f"total_mutatable {total_mutatable} != total_generated {total_generated}"))
    if total_generated == 0 or total_mutatable == 0:
        findings.append(finding("MUTATION_NO_MUTANTS", "mutants", "zero mutants generated"))
    changed = {_locus(item) for item in data.get("changed_lines") or []}
    if score < threshold:
        findings.append(
            finding(
                "MUTATION_SCORE",
                "score",
                f"mutation score {score:g} is below threshold {threshold:g}",
            )
        )
    for survivor in data.get("survivors") or []:
        locus = str(survivor.get("locus") or "")
        if _locus(locus) in changed:
            findings.append(
                finding(
                    "MUTATION_SURVIVOR",
                    locus or "survivor",
                    "surviving mutant lies on a changed line",
                )
            )
    return findings


def check_thread_race(data: dict) -> list[dict]:
    """THREAD_RACE: postgres repetitions must be complete, clean, and stable.

    Fail-closed: a postgres engine without workers/reps evidence is
    THREAD_RACE_MISSING, never a vacuous PASS.
    """
    engine = str(data.get("engine") or "").lower()
    if engine == "postgres":
        if data.get("workers") is None or data.get("required_workers") is None or data.get("reps") is None or data.get("required_reps") is None:
            return [finding("THREAD_RACE_MISSING", "evidence", "workers/reps evidence is missing for postgres")]
    if engine != "postgres":
        if engine == "sqlite":
            detail = (
                "NOT_APPLICABLE: sqlite does not exercise the protected "
                "concurrency property; only postgres repetitions count"
            )
        else:
            detail = (
                f"NOT_APPLICABLE: engine {engine or '<missing>'} is not postgres; "
                "only postgres repetitions count"
            )
        return [finding("THREAD_RACE_ENGINE", "engine", detail)]
    findings: list[dict] = []
    workers = int(data.get("workers") or 0)
    required_workers = int(data.get("required_workers") or 0)
    reps = int(data.get("reps") or 0)
    required_reps = int(data.get("required_reps") or 0)
    failures = int(data.get("failures") or 0)
    flaky = [str(item) for item in data.get("flaky") or []]
    if workers < required_workers:
        findings.append(
            finding(
                "THREAD_RACE_WORKERS",
                "workers",
                f"{workers} workers is below the required {required_workers}",
            )
        )
    if reps < required_reps:
        findings.append(
            finding(
                "THREAD_RACE_REPS",
                "reps",
                f"{reps} repetitions is below the required {required_reps}",
            )
        )
    if failures != 0:
        findings.append(
            finding(
                "THREAD_RACE_FAILURE",
                "failures",
                f"{failures} failing repetitions observed",
            )
        )
    for name in flaky:
        findings.append(
            finding(
                "THREAD_RACE_FLAKE",
                name or "flaky",
                "repetition was flaky",
            )
        )
    return findings


_SEVERITY_RANK = {
    "informational": 0,
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
}
_THRESHOLDS = ("high", "medium", "low")


def _threshold(value: object) -> tuple[str, bool]:
    """Return (threshold, valid); an invalid threshold fails closed at low."""
    raw = str(value or "").strip().lower()
    if raw in _THRESHOLDS:
        return raw, True
    return "low", False


def _at_or_above(severity: object, threshold: str) -> bool:
    """True when severity is at/above threshold; unknown severities fail closed."""
    rank = _SEVERITY_RANK.get(str(severity or "").strip().lower())
    floor = _SEVERITY_RANK[threshold]
    if rank is None:
        return True
    return rank >= floor


def check_schema_fuzz(data: dict) -> list[dict]:
    """SCHEMA_FUZZ: schemathesis must run cases and observe no failure or error."""
    # Fail-closed on missing spec.
    if not data.get("spec"):
        return [finding("SCHEMA_MISSING", "spec", "spec is missing")]
    findings: list[dict] = []
    engine = str(data.get("engine") or "")
    if engine != "schemathesis":
        findings.append(
            finding(
                "SCHEMA_ENGINE",
                "engine",
                f"engine {engine or '<missing>'} is not schemathesis",
            )
        )
    try:
        cases = int(data.get("cases") or 0)
    except (TypeError, ValueError):
        cases = 0
    if cases <= 0:
        findings.append(
            finding("SCHEMA_NO_CASES", "cases", "schemathesis generated no cases")
        )
    for index, failure in enumerate(data.get("failures") or []):
        endpoint = str(failure.get("endpoint") or f"failures[{index}]")
        status = failure.get("status")
        detail = str(failure.get("detail") or "schema violation")
        findings.append(
            finding(
                "SCHEMA_FAILURE",
                endpoint,
                f"status {status if status is not None else '<missing>'}: {detail}",
            )
        )
    for error in data.get("errors") or []:
        findings.append(finding("SCHEMA_FAILURE", "errors", str(error)))
    return findings


def check_boottest(data: dict) -> list[dict]:
    """BOOTTEST: every config boots and proves an allowed and a denied action."""
    configs = list(data.get("configs") or [])
    if not configs:
        return [
            finding("BOOT_LOAD", "configs", "no boot configurations were supplied")
        ]
    findings: list[dict] = []
    for index, config in enumerate(configs):
        name = str(config.get("name") or f"configs[{index}]")
        error = str(config.get("error") or "")
        if not bool(config.get("loads")) or error:
            findings.append(
                finding(
                    "BOOT_LOAD",
                    name,
                    error or "config did not boot with production settings",
                )
            )
        if not bool(config.get("allowed_probe")):
            findings.append(
                finding(
                    "BOOT_ALLOWED",
                    name,
                    "no allowed action was proven after boot",
                )
            )
        if not bool(config.get("denied_probe")):
            findings.append(
                finding(
                    "BOOT_DENIED",
                    name,
                    "no denied action was proven after boot",
                )
            )
    return findings


def check_zizmor(data: dict) -> list[dict]:
    """ZIZMOR: no workflow finding at or above the policy threshold."""
    if "findings" not in data:
        return [finding("ZIZMOR_MISSING", "findings", "findings evidence is missing")]
    threshold, valid = _threshold(data.get("threshold"))
    findings: list[dict] = []
    if not valid:
        findings.append(
            finding(
                "ZIZMOR_FINDING",
                "threshold",
                f"threshold {data.get('threshold')!r} is not high|medium|low; "
                "using low",
            )
        )
    for index, item in enumerate(data.get("findings") or []):
        severity = str(item.get("severity") or "")
        if not _at_or_above(severity, threshold):
            continue
        path = normalise(str(item.get("path") or ""))
        line = item.get("line")
        locus = f"{path}:{line}" if path else f"findings[{index}]"
        findings.append(
            finding(
                "ZIZMOR_FINDING",
                locus,
                f"{item.get('rule') or 'unknown'} severity "
                f"{severity or '<missing>'} is at/above {threshold}",
            )
        )
    return findings


def check_dast_baseline(data: dict) -> list[dict]:
    """DAST_BASELINE: docker + zap runtime, no alert at/above threshold."""
    if "alerts" not in data:
        return [finding("DAST_MISSING", "alerts", "alerts evidence is missing")]
    runtime = str(data.get("runtime") or "").strip().lower()
    if runtime == "none":
        return [
            finding(
                "BLOCKED_NO_RUNTIME",
                "runtime",
                "no container runtime is available; DAST_BASELINE cannot run",
            )
        ]
    findings: list[dict] = []
    if runtime != "docker":
        findings.append(
            finding(
                "DAST_RUNTIME",
                "runtime",
                f"runtime {runtime or '<missing>'} is not docker",
            )
        )
    engine = str(data.get("engine") or "").strip().lower()
    if engine != "zap":
        findings.append(
            finding(
                "DAST_RUNTIME",
                "engine",
                f"engine {engine or '<missing>'} is not zap",
            )
        )
    threshold, valid = _threshold(data.get("threshold"))
    if not valid:
        findings.append(
            finding(
                "DAST_RUNTIME",
                "threshold",
                f"threshold {data.get('threshold')!r} is not high|medium|low; "
                "using low",
            )
        )
    for index, alert in enumerate(data.get("alerts") or []):
        risk = str(alert.get("risk") or "")
        if not _at_or_above(risk, threshold):
            continue
        name = str(alert.get("name") or f"alerts[{index}]")
        findings.append(
            finding(
                "DAST_ALERT",
                name,
                f"risk {risk or '<missing>'} is at/above {threshold}",
            )
        )
    return findings


CHECK_FUNCTIONS = {
    "SCOPE": check_scope,
    "SUITE": check_suite,
    "TEST_SET": check_test_set,
    "TEST_INFRA": check_test_infra,
    "BASE_FAIL_HEAD_PASS": check_base_fail_head_pass,
    "MUTATION": check_mutation,
    "CHANGELOG": check_changelog,
    "SECRETS": check_secrets,
    "GATE_CONTROLS": check_gate_controls,
    "THREAD_RACE": check_thread_race,
    "SCHEMA_FUZZ": check_schema_fuzz,
    "BOOTTEST": check_boottest,
    "ZIZMOR": check_zizmor,
    "DAST_BASELINE": check_dast_baseline,
    "DOC": check_doc_scope,
}


# ---------------------------------------------------------------------------
# Control fixtures
# ---------------------------------------------------------------------------


def _fixture(name: str) -> dict:
    return load_json(FIXTURES / name)


def control_specs() -> dict[str, list[tuple[str, str, bool]]]:
    """check -> [(case name, fixture ref, expect_reject), ...]."""
    return {
        "SCOPE": [
            ("scope/bad.json", "tools/fixtures/scope/bad.json", True),
            ("scope/clean.json", "tools/fixtures/scope/clean.json", False),
        ],
        "SUITE": [
            ("suite/bad.json", "tools/fixtures/suite/bad.json", True),
            ("suite/clean.json", "tools/fixtures/suite/clean.json", False),
        ],
        "TEST_SET": [
            ("test_set/bad.json", "tools/fixtures/test_set/bad.json", True),
            ("test_set/clean.json", "tools/fixtures/test_set/clean.json", False),
        ],
        "TEST_INFRA": [
            ("test_infra/bad.json", "tools/fixtures/test_infra/bad.json", True),
            ("test_infra/clean.json", "tools/fixtures/test_infra/clean.json", False),
        ],
        "BASE_FAIL_HEAD_PASS": [
            (
                "base_fail_head_pass/bad.json",
                "tools/fixtures/base_fail_head_pass/bad.json",
                True,
            ),
            (
                "base_fail_head_pass/clean.json",
                "tools/fixtures/base_fail_head_pass/clean.json",
                False,
            ),
        ],
        "MUTATION": [
            ("mutation/bad.json", "tools/fixtures/mutation/bad.json", True),
            ("mutation/clean.json", "tools/fixtures/mutation/clean.json", False),
        ],
        "CHANGELOG": [
            ("changelog/bad.json", "tools/fixtures/changelog/bad.json", True),
            ("changelog/clean.json", "tools/fixtures/changelog/clean.json", False),
        ],
        "SECRETS": [
            (
                "secrets/bad/bad_key.py",
                "tools/fixtures/secrets/bad/bad_key.py",
                True,
            ),
            (
                "secrets/clean/clean.py",
                "tools/fixtures/secrets/clean/clean.py",
                False,
            ),
            (
                "secrets/baseline/bad_key.py",
                "tools/fixtures/secrets/baseline/bad_key.py",
                False,
            ),
        ],
        "CONVENTION": [
            ("convention/bad.py", "tools/fixtures/convention/bad.py", True),
            ("convention/clean.py", "tools/fixtures/convention/clean.py", False),
        ],
        "GATE_CONTROLS": [
            ("gate_controls/undercounted.json", "builtin://controls/gate-controls/undercounted.json", True),
            ("gate_controls/valid.json", "builtin://controls/gate-controls/valid.json", False),
        ],
        "THREAD_RACE": [
            (
                "thread_race/bad.json",
                "tools/fixtures/thread_race/bad.json",
                True,
            ),
            (
                "thread_race/clean.json",
                "tools/fixtures/thread_race/clean.json",
                False,
            ),
        ],
        "SCHEMA_FUZZ": [
            (
                "schema_fuzz/bad.json",
                "tools/fixtures/schema_fuzz/bad.json",
                True,
            ),
            (
                "schema_fuzz/clean.json",
                "tools/fixtures/schema_fuzz/clean.json",
                False,
            ),
        ],
        "BOOTTEST": [
            ("boottest/bad.json", "tools/fixtures/boottest/bad.json", True),
            ("boottest/clean.json", "tools/fixtures/boottest/clean.json", False),
        ],
        "ZIZMOR": [
            ("zizmor/bad.json", "tools/fixtures/zizmor/bad.json", True),
            ("zizmor/clean.json", "tools/fixtures/zizmor/clean.json", False),
        ],
        "DAST_BASELINE": [
            (
                "dast_baseline/bad.json",
                "tools/fixtures/dast_baseline/bad.json",
                True,
            ),
            (
                "dast_baseline/clean.json",
                "tools/fixtures/dast_baseline/clean.json",
                False,
            ),
        ],
    }


def synthetic_gate_controls() -> tuple[dict, dict]:
    """A manifest and a matching record; the bad copy undercounts."""
    manifest = {
        "total_min": 2,
        "known_bad_min": 2,
        "controls": {
            "SCOPE": {"min_count": 1},
            "SECRETS": {"min_count": 1},
        },
    }
    controls = [
        {
            "check_id": "SCOPE",
            "control_id": "S1",
            "expected_outcome": "FAIL",
            "observed_outcome": "FAIL",
            "rejected": True,
        },
        {
            "check_id": "SECRETS",
            "control_id": "K1",
            "expected_outcome": "FAIL",
            "observed_outcome": "FAIL",
            "rejected": True,
        },
    ]
    valid = {
        "controls_total": 2,
        "controls_rejected": 2,
        "all_rejected": True,
        "result": "PASS",
        "controls": controls,
    }
    undercounted = dict(valid, controls_total=1, controls_rejected=1)
    return manifest, {"undercounted.json": undercounted, "valid.json": valid}


def run_case(check_id: str, name: str) -> tuple[list[dict], str | None]:
    """Return (findings, error) for one control case."""
    if check_id == "GATE_CONTROLS":
        manifest, records = synthetic_gate_controls()
        record = records[Path(name).name]
        data = {"manifest": manifest, "record": record}
        return _evidence_hash_findings(data) + check_gate_controls(data), None
    if check_id == "CONVENTION":
        fixture = FIXTURES / "convention" / Path(name).name
        return check_convention(
            {"files": [str(fixture)], "added_lines": {}}
        )
    if check_id == "SECRETS":
        return _scan_secrets_directory(FIXTURES / Path(name).parent), None
    fixture = FIXTURES / name
    data = load_json(fixture)
    findings = CHECK_FUNCTIONS[check_id](data)
    if check_id in _EVIDENCE_CHECKS:
        findings = _evidence_hash_findings(data) + findings
    return findings, None


def run_control(check_id: str) -> dict:
    cases = []
    for name, fixture_ref, expect_reject in control_specs()[check_id]:
        findings, error = run_case(check_id, name)
        if error:
            cases.append(
                {
                    "name": name,
                    "expected": "REJECT" if expect_reject else "ACCEPT",
                    "actual": {"outcome": "ERROR", "findings": 0, "error": error},
                    "passed": False,
                }
            )
            continue
        outcome = "FAIL" if findings else "PASS"
        expected = "FAIL" if expect_reject else "PASS"
        cases.append(
            {
                "name": name,
                "expected": expected,
                "actual": {"outcome": outcome, "findings": len(findings)},
                "passed": outcome == expected,
            }
        )
    return {"ran": True, "passed": all(case["passed"] for case in cases), "cases": cases}


# ---------------------------------------------------------------------------
# Envelope / CLI
# ---------------------------------------------------------------------------


def envelope(check_id: str, findings: list[dict], control_doc: dict | None, code: int) -> dict:
    return {
        "schema": "factory-tool/1",
        "tool": TOOL,
        "version": VERSION,
        "interpreter": sys.executable,
        "check_id": check_id,
        "result_type": "RESULT" if code == 0 else ("CONTROL_FAIL" if control_doc else "REJECT"),
        "exit_code": code,
        "findings": findings,
        "control": control_doc,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", required=True, choices=CHECKS)
    parser.add_argument("--input", default=None, help="JSON input for the check")
    parser.add_argument("--control", action="store_true", help="run the check's control fixtures")
    args = parser.parse_args(argv)

    if args.control:
        try:
            control_doc = run_control(args.check)
        except Exception as exc:  # noqa: BLE001 - CLI boundary
            eprint(f"gate_run: tool error: {type(exc).__name__}: {exc}")
            return 2
        code = 0 if control_doc["passed"] else 1
        doc = envelope(args.check, [], control_doc, code)
        print(json.dumps(doc, sort_keys=True, separators=(",", ":")))
        return code

    if not args.input:
        eprint("gate_run: --input is required unless --control is used")
        return 2
    try:
        data = load_json(Path(args.input))
        if args.check == "CONVENTION":
            findings, error = check_convention(data)
            if error:
                raise RuntimeError(error)
        else:
            findings = CHECK_FUNCTIONS[args.check](data)
            if args.check in _EVIDENCE_CHECKS:
                findings = _evidence_hash_findings(data) + findings
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        eprint(f"gate_run: tool error: {type(exc).__name__}: {exc}")
        return 2
    code = 1 if findings else 0
    print(json.dumps(envelope(args.check, findings, None, code), sort_keys=True, separators=(",", ":")))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
