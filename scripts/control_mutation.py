#!/usr/bin/env python3
"""Gate 6c control-mutation harness.

Reads the live ``files/policies/negative-controls.json`` and
``files/policies/checks.json``, copies the live ``files/`` tree into
``%TEMP%\\opencode\\mutation\\<pid>\\run-<n>-<check>-<mutation>\\files``
(read-only wrt the live tree), applies ONE predicate mutation at a time via a
per-tool patch adapter, and observes each control entry with the copy's own
``gate_control.py`` observation logic (``observed_for`` / ``match_case`` /
``case_outcome`` imported from the copied module). The reporting layer
(``--control`` case builders and envelopes) is never patched.

Operator sets follow each check's ``predicate_kind`` in checks.json:
  aggregate   INVERT, ALWAYS_PASS, EMPTY
  collection  INVERT, ALWAYS_PASS, TRUNCATE

Mutation classes:
  INVERT      negate the check's decision: defects accepted, accepted flagged
  ALWAYS_PASS force the predicate to report no finding / accept unconditionally
  EMPTY       keep the tool running but return an empty detected-findings list
  TRUNCATE    make the comparison inspect only its first item

Every invocation owns ``%TEMP%\\opencode\\mutation\\<pid>``.  ``--all`` clears
only that per-process root, so two invocations cannot collide.

Modes: ``--all`` (every group) or ``--sample N`` (first N groups in manifest
order). Output: one table row per check group plus a survivor summary.
Exit codes: 0 no survivors, 1 at least one survivor, 2 fatal (baseline
mismatch or patch could not be applied).
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

HARNESS_ROOT = Path(__file__).resolve().parent.parent
FILES_ROOT = HARNESS_ROOT / "files"
CHECKS_PATH = FILES_ROOT / "policies" / "checks.json"
OPERATORS_BY_KIND = {
    "aggregate": ("INVERT", "ALWAYS_PASS", "EMPTY"),
    "collection": ("INVERT", "ALWAYS_PASS", "TRUNCATE"),
}

# check group -> tool file (relative to the copies' files/ root)
GROUP_TOOL = {
    "AUTHZ_MATRIX": "tools/authz_matrix.py",
    "SEMGREP": "tools/semgrep_runner.py",
    "ORACLE_PROVENANCE": "tools/oracle_provenance.py",
    "SMELL": "tools/smell.py",
    "GUARD_DELTA": "tools/guard_delta.py",
    "ARCH": "tools/arch_check.py",
    "SCOPE": "tools/gate_run.py",
    "SUITE": "tools/gate_run.py",
    "TEST_SET": "tools/gate_run.py",
    "TEST_INFRA": "tools/gate_run.py",
    "BASE_FAIL_HEAD_PASS": "tools/gate_run.py",
    "MUTATION": "tools/gate_run.py",
    "CHANGELOG": "tools/gate_run.py",
    "SECRETS": "tools/gate_run.py",
    "CONVENTION": "tools/gate_run.py",
    "GATE_CONTROLS": "tools/gate_run.py",
    "THREAD_RACE": "tools/gate_run.py",
    "SCHEMA_FUZZ": "tools/gate_run.py",
    "BOOTTEST": "tools/gate_run.py",
    "ZIZMOR": "tools/gate_run.py",
    "DAST_BASELINE": "tools/gate_run.py",
    "POLICY_DIGEST": "tools/policy_digest.py",
    "AGT_PARITY": "tools/agt_parity.py",
    "AGT_AUDIT": "tools/agt_audit.py",
}


# ---------------------------------------------------------------------------
# Patch adapters. Each adapter is a list of exact (old, new) text replacements
# applied to the fresh copy of the group's tool. The first occurrence of every
# ``old`` must exist exactly once in the source; the replacement carries a
# ``# MUTANT-<CLASS>`` marker used for evidence line numbers.
# ---------------------------------------------------------------------------

GR_INVERT_SCOPE_OLD = """    return [
        finding("SCOPE_VIOLATION", str(path), "path is outside capability.scope")
        for path in data.get("paths") or []
        if not matches(str(path), scope)
    ]"""


def gr_invert_scope_new(tag: str) -> str:
    assert tag == "INVERT"
    return """    original = [
        finding("SCOPE_VIOLATION", str(path), "path is outside capability.scope")
        for path in data.get("paths") or []
        if not matches(str(path), scope)
    ]
    if original:
        return []  # MUTANT-INVERT out-of-scope paths now accepted
    return [
        finding(
            "SCOPE_VIOLATION",
            "scope/mutant",
            "predicate inverted: in-scope paths now produce a finding",
        )
    ]"""


GR_TEST_SET_TAIL_OLD = """    patterns = [re.compile(str(p)) for p in data.get("tautology_patterns") or []]
    for assertion in data.get("added_assertions") or []:
        if any(pattern.search(str(assertion)) for pattern in patterns):
            findings.append(
                finding(
                    "TAUTOLOGICAL_ASSERTION",
                    "added-assertion",
                    "assertion matches a tautology pattern",
                )
            )
    return findings"""

GR_TEST_INFRA_TAIL_OLD = """                    "test-infrastructure path is outside capability.scope",
                )
            )
    return findings"""

GR_CHANGELOG_TAIL_OLD = """                    "diff path is not named by any added changelog row",
                )
            )
    return findings"""

GR_GATE_CONTROLS_TAIL_OLD = """    if record.get("result") != "PASS":
        findings.append(
            finding("GATE_CONTROL_FAILURE", "result", "record result is not PASS")
        )
    return findings"""

GR_SUITE_TAIL_OLD = """        exit_code = entry.get("exit_code")
        if exit_code is not None and int(exit_code) != 0:
            findings.append(
                finding(
                    "SUITE_FAILED",
                    engine,
                    f"test process exited {int(exit_code)} with an OK summary",
                )
            )
    return findings"""

GR_BFHP_TAIL_OLD = """        if characterization and not reason:
            findings.append(
                finding(
                    "INVALID",
                    test_id,
                    "characterization test has an empty reason",
                )
            )
    return findings"""

GR_MUTATION_TAIL_OLD = """        if _locus(locus) in changed:
            findings.append(
                finding(
                    "MUTATION_SURVIVOR",
                    locus or "survivor",
                    "surviving mutant lies on a changed line",
                )
            )
    return findings"""

GR_THREAD_RACE_TAIL_OLD = """    for name in flaky:
        findings.append(
            finding(
                "THREAD_RACE_FLAKE",
                name or "flaky",
                "repetition was flaky",
            )
        )
    return findings"""

GR_SCHEMA_FUZZ_TAIL_OLD = """    for error in data.get("errors") or []:
        findings.append(finding("SCHEMA_FAILURE", "errors", str(error)))
    return findings"""

GR_BOOTTEST_TAIL_OLD = """        if not bool(config.get("denied_probe")):
            findings.append(
                finding(
                    "BOOT_DENIED",
                    name,
                    "no denied action was proven after boot",
                )
            )
    return findings"""

GR_ZIZMOR_TAIL_OLD = """        findings.append(
            finding(
                "ZIZMOR_FINDING",
                locus,
                f"{item.get('rule') or 'unknown'} severity "
                f"{severity or '<missing>'} is at/above {threshold}",
            )
        )
    return findings"""

GR_DAST_TAIL_OLD = """        findings.append(
            finding(
                "DAST_ALERT",
                name,
                f"risk {risk or '<missing>'} is at/above {threshold}",
            )
        )
    return findings"""


def gr_always_pas_findings_new(tail: str, marker: str) -> str:
    return tail.replace("    return findings", f"    return []  # MUTANT-ALWAYS_PASS {marker}")


def gr_invert_findings_new(tail: str, finding_kind: str, loci: str, note: str) -> str:
    return tail.replace(
        "    return findings",
        f"""    if findings:
        return []  # MUTANT-INVERT {note}
    return [
        finding(
            {finding_kind!r},
            {loci!r},
            "predicate inverted: accepted input now produces a finding",
        )
    ]""",
    )


ADAPTERS: dict[tuple[str, str], tuple[list[tuple[str, str]] | None, str]] = {}


def _ad(check: str, mutation: str, pairs: list[tuple[str, str]] | None, reason: str = "") -> None:
    ADAPTERS[(check, mutation)] = (pairs, reason)


def _build_adapters() -> None:
    # ---- gate_run.py: SCOPE ------------------------------------------------
    _ad("SCOPE", "INVERT", [(GR_INVERT_SCOPE_OLD, gr_invert_scope_new("INVERT"))])
    _ad("SCOPE", "ALWAYS_PASS", [(GR_INVERT_SCOPE_OLD, "    return []  # MUTANT-ALWAYS_PASS the scope check accepts unconditionally")])
    _ad(
        "SCOPE",
        "TRUNCATE",
        [
            (
                """        for path in data.get("paths") or []
        if not matches(str(path), scope)""",
                """        for path in (data.get("paths") or [])[:1]
        if not matches(str(path), scope)  # MUTANT-TRUNCATE inspect only the first path""",
            )
        ],
    )

    # ---- gate_run.py: TEST_SET --------------------------------------------
    _ad("TEST_SET", "ALWAYS_PASS", [(GR_TEST_SET_TAIL_OLD, gr_always_pas_findings_new(GR_TEST_SET_TAIL_OLD, "the test-set check accepts unconditionally"))])
    _ad(
        "TEST_SET",
        "INVERT",
        [(GR_TEST_SET_TAIL_OLD, gr_invert_findings_new(GR_TEST_SET_TAIL_OLD, "TEST_REMOVAL_UNCOVERED", "test-set/mutant", "removals, skip markers and weakened assertions now accepted"))],
    )
    _ad(
        "TEST_SET",
        "TRUNCATE",
        [
            (
                """    for test_id in base:
        if test_id not in head and test_id not in allowed:""",
                """    for test_id in list(base)[:1]:  # MUTANT-TRUNCATE compare only the first base test
        if test_id not in head and test_id not in allowed:""",
            )
        ],
    )

    # ---- gate_run.py: TEST_INFRA ------------------------------------------
    _ad("TEST_INFRA", "ALWAYS_PASS", [(GR_TEST_INFRA_TAIL_OLD, gr_always_pas_findings_new(GR_TEST_INFRA_TAIL_OLD, "the test-infra check accepts unconditionally"))])
    _ad(
        "TEST_INFRA",
        "INVERT",
        [(GR_TEST_INFRA_TAIL_OLD, gr_invert_findings_new(GR_TEST_INFRA_TAIL_OLD, "TEST_INFRA_CHANGE", "test-infra/mutant", "out-of-scope test infra now accepted"))],
    )
    _ad(
        "TEST_INFRA",
        "TRUNCATE",
        [
            (
                """    for path in data.get("paths") or []:
        path = str(path)
        if matches(path, globs) and not matches(path, scope):""",
                """    for path in (data.get("paths") or [])[:1]:  # MUTANT-TRUNCATE inspect only the first path
        path = str(path)
        if matches(path, globs) and not matches(path, scope):""",
            )
        ],
    )

    # ---- gate_run.py: CHANGELOG -------------------------------------------
    _ad("CHANGELOG", "ALWAYS_PASS", [(GR_CHANGELOG_TAIL_OLD, gr_always_pas_findings_new(GR_CHANGELOG_TAIL_OLD, "the changelog check accepts unconditionally"))])
    _ad(
        "CHANGELOG",
        "INVERT",
        [(GR_CHANGELOG_TAIL_OLD, gr_invert_findings_new(GR_CHANGELOG_TAIL_OLD, "CHANGELOG_GAP", "changelog/mutant", "uncovered diff paths now accepted"))],
    )
    _ad(
        "CHANGELOG",
        "TRUNCATE",
        [
            (
                """    for path in sorted(paths - covered):
        if not matches(path, exempt):""",
                """    for path in sorted(paths - covered)[:1]:  # MUTANT-TRUNCATE inspect only the first uncovered path
        if not matches(path, exempt):""",
            )
        ],
    )

    # ---- gate_run.py: SECRETS (control scans via _scan_secrets_directory) --
    _ad(
        "SECRETS",
        "ALWAYS_PASS",
        [
            (
                "        return _gitleaks_findings(report, process)",
                "        return []  # MUTANT-ALWAYS_PASS the secrets scan accepts unconditionally",
            )
        ],
    )
    _ad(
        "SECRETS",
        "INVERT",
        [
            (
                "        return _gitleaks_findings(report, process)",
                """        _m_findings = _gitleaks_findings(report, process)
        if _m_findings:
            return []  # MUTANT-INVERT leaked keys now accepted
        return [
            finding(
                "SECRET_LEAK",
                "secrets/mutant",
                "predicate inverted: clean directories now produce a finding",
            )
        ]""",
            )
        ],
    )
    _ad(
        "SECRETS",
        "TRUNCATE",
        [
            (
                """    for leak in leaks:
        raw = str(leak.get("File", ""))""",
                """    for leak in leaks[:1]:  # MUTANT-TRUNCATE inspect only the first reported leak
        raw = str(leak.get("File", ""))""",
            )
        ],
    )
    _ad(
        "SECRETS",
        "EMPTY",
        [
            (
                """    if process.returncode == 1 and not findings:
        raise RuntimeError("gitleaks exited 1 but its report contains no leaks")
    return findings""",
                """    if process.returncode == 1 and not findings:
        raise RuntimeError("gitleaks exited 1 but its report contains no leaks")
    return findings[:0]  # MUTANT-EMPTY the secrets scan still runs but detects nothing""",
            )
        ],
    )

    # ---- gate_run.py: CONVENTION -------------------------------------------
    _ad(
        "CONVENTION",
        "ALWAYS_PASS",
        [
            (
                "    return findings, None",
                "    return [], None  # MUTANT-ALWAYS_PASS the convention check accepts unconditionally",
            )
        ],
    )
    _ad(
        "CONVENTION",
        "INVERT",
        [
            (
                "    return findings, None",
                """    if findings:
        return [], None  # MUTANT-INVERT violations now accepted
    return (
        [
            finding(
                "CONVENTION_VIOLATION",
                "convention/mutant",
                "predicate inverted: clean files now produce a finding",
            )
        ],
        None,
    )""",
            )
        ],
    )
    _ad(
        "CONVENTION",
        "TRUNCATE",
        [
            (
                """    for diagnostic in diagnostics:
        path = normalise(str(diagnostic.get("filename", "")))""",
                """    for diagnostic in diagnostics[:1]:  # MUTANT-TRUNCATE inspect only the first diagnostic
        path = normalise(str(diagnostic.get("filename", "")))""",
            )
        ],
    )
    _ad(
        "CONVENTION",
        "EMPTY",
        [
            (
                "    return findings, None",
                "    return findings[:0], None  # MUTANT-EMPTY the convention check still runs but detects nothing",
            )
        ],
    )

    # ---- gate_run.py: GATE_CONTROLS ----------------------------------------
    _ad(
        "GATE_CONTROLS",
        "ALWAYS_PASS",
        [(GR_GATE_CONTROLS_TAIL_OLD, gr_always_pas_findings_new(GR_GATE_CONTROLS_TAIL_OLD, "the gate-controls check accepts unconditionally"))],
    )
    _ad(
        "GATE_CONTROLS",
        "INVERT",
        [
            (
                GR_GATE_CONTROLS_TAIL_OLD,
                """    if record.get("result") != "PASS":
        findings.append(
            finding("GATE_CONTROL_FAILURE", "result", "record result is not PASS")
        )
    if findings:
        return []  # MUTANT-INVERT undercounted/failing records now accepted
    return [
        finding(
            "GATE_CONTROL_FAILURE",
            "gate-controls/mutant",
            "predicate inverted: valid records now produce a finding",
        )
    ]""",
            )
        ],
    )
    _ad(
        "GATE_CONTROLS",
        "TRUNCATE",
        [
            (
                '    controls = list(record.get("controls") or [])',
                "    controls = list(record.get(\"controls\") or [])[:1]  # MUTANT-TRUNCATE trust compares only the first control entry",
            )
        ],
    )

    # ---- gate_run.py: SUITE (aggregate: EMPTY must flip) -------------------
    _ad(
        "SUITE",
        "INVERT",
        [(GR_SUITE_TAIL_OLD, gr_invert_findings_new(GR_SUITE_TAIL_OLD, "SUITE_FAILED", "suite/mutant", "failing engine summaries now accepted"))],
    )
    _ad(
        "SUITE",
        "ALWAYS_PASS",
        [(GR_SUITE_TAIL_OLD, gr_always_pas_findings_new(GR_SUITE_TAIL_OLD, "the suite check accepts unconditionally"))],
    )
    _ad(
        "SUITE",
        "EMPTY",
        [(GR_SUITE_TAIL_OLD, GR_SUITE_TAIL_OLD.replace("    return findings", "    return findings[:0]  # MUTANT-EMPTY the suite check still parses evidence but detects nothing"))],
    )

    # ---- gate_run.py: BASE_FAIL_HEAD_PASS (collection: TRUNCATE must flip) --
    _ad(
        "BASE_FAIL_HEAD_PASS",
        "INVERT",
        [(GR_BFHP_TAIL_OLD, gr_invert_findings_new(GR_BFHP_TAIL_OLD, "NON_FALSIFIABLE", "base-fail-head-pass/mutant", "base-green and invalid added tests now accepted"))],
    )
    _ad(
        "BASE_FAIL_HEAD_PASS",
        "ALWAYS_PASS",
        [(GR_BFHP_TAIL_OLD, gr_always_pas_findings_new(GR_BFHP_TAIL_OLD, "the base-fail-head-pass check accepts unconditionally"))],
    )
    _ad(
        "BASE_FAIL_HEAD_PASS",
        "TRUNCATE",
        [
            (
                """    for index, test in enumerate(data.get("added_tests") or []):""",
                """    for index, test in enumerate((data.get("added_tests") or [])[:1]):  # MUTANT-TRUNCATE judge only the first added test""",
            )
        ],
    )

    # ---- gate_run.py: MUTATION (aggregate: EMPTY must flip) ----------------
    _ad(
        "MUTATION",
        "INVERT",
        [(GR_MUTATION_TAIL_OLD, gr_invert_findings_new(GR_MUTATION_TAIL_OLD, "MUTATION_SURVIVOR", "mutation/mutant", "score shortfalls and changed-line survivors now accepted"))],
    )
    _ad(
        "MUTATION",
        "ALWAYS_PASS",
        [(GR_MUTATION_TAIL_OLD, gr_always_pas_findings_new(GR_MUTATION_TAIL_OLD, "the mutation check accepts unconditionally"))],
    )
    _ad(
        "MUTATION",
        "EMPTY",
        [(GR_MUTATION_TAIL_OLD, GR_MUTATION_TAIL_OLD.replace("    return findings", "    return findings[:0]  # MUTANT-EMPTY the mutation check still runs but detects nothing"))],
    )

    # ---- gate_run.py: THREAD_RACE (aggregate: EMPTY must flip) -------------
    _ad(
        "THREAD_RACE",
        "INVERT",
        [(GR_THREAD_RACE_TAIL_OLD, gr_invert_findings_new(GR_THREAD_RACE_TAIL_OLD, "THREAD_RACE_FAILURE", "thread-race/mutant", "worker, repetition, failure and flake shortfalls now accepted"))],
    )
    _ad(
        "THREAD_RACE",
        "ALWAYS_PASS",
        [(GR_THREAD_RACE_TAIL_OLD, gr_always_pas_findings_new(GR_THREAD_RACE_TAIL_OLD, "the thread-race check accepts unconditionally"))],
    )
    _ad(
        "THREAD_RACE",
        "EMPTY",
        [(GR_THREAD_RACE_TAIL_OLD, GR_THREAD_RACE_TAIL_OLD.replace("    return findings", "    return findings[:0]  # MUTANT-EMPTY the thread-race check still runs but detects nothing"))],
    )

    # ---- gate_run.py: SCHEMA_FUZZ (aggregate: EMPTY must flip) -------------
    _ad(
        "SCHEMA_FUZZ",
        "INVERT",
        [(GR_SCHEMA_FUZZ_TAIL_OLD, gr_invert_findings_new(GR_SCHEMA_FUZZ_TAIL_OLD, "SCHEMA_FAILURE", "schema-fuzz/mutant", "engine, case-count and failure shortfalls now accepted"))],
    )
    _ad(
        "SCHEMA_FUZZ",
        "ALWAYS_PASS",
        [(GR_SCHEMA_FUZZ_TAIL_OLD, gr_always_pas_findings_new(GR_SCHEMA_FUZZ_TAIL_OLD, "the schema-fuzz check accepts unconditionally"))],
    )
    _ad(
        "SCHEMA_FUZZ",
        "EMPTY",
        [(GR_SCHEMA_FUZZ_TAIL_OLD, GR_SCHEMA_FUZZ_TAIL_OLD.replace("    return findings", "    return findings[:0]  # MUTANT-EMPTY the schema-fuzz check still parses evidence but detects nothing"))],
    )

    # ---- gate_run.py: BOOTTEST (collection: TRUNCATE must flip) ------------
    _ad(
        "BOOTTEST",
        "INVERT",
        [(GR_BOOTTEST_TAIL_OLD, gr_invert_findings_new(GR_BOOTTEST_TAIL_OLD, "BOOT_LOAD", "boottest/mutant", "broken boots and missing probes now accepted"))],
    )
    _ad(
        "BOOTTEST",
        "ALWAYS_PASS",
        [(GR_BOOTTEST_TAIL_OLD, gr_always_pas_findings_new(GR_BOOTTEST_TAIL_OLD, "the boot test accepts unconditionally"))],
    )
    _ad(
        "BOOTTEST",
        "TRUNCATE",
        [
            (
                """    for index, config in enumerate(configs):""",
                """    for index, config in enumerate(configs[:1]):  # MUTANT-TRUNCATE judge only the first boot config""",
            )
        ],
    )

    # ---- gate_run.py: ZIZMOR (aggregate: EMPTY must flip) ------------------
    _ad(
        "ZIZMOR",
        "INVERT",
        [(GR_ZIZMOR_TAIL_OLD, gr_invert_findings_new(GR_ZIZMOR_TAIL_OLD, "ZIZMOR_FINDING", "zizmor/mutant", "at/above-threshold workflow findings now accepted"))],
    )
    _ad(
        "ZIZMOR",
        "ALWAYS_PASS",
        [(GR_ZIZMOR_TAIL_OLD, gr_always_pas_findings_new(GR_ZIZMOR_TAIL_OLD, "the zizmor check accepts unconditionally"))],
    )
    _ad(
        "ZIZMOR",
        "EMPTY",
        [(GR_ZIZMOR_TAIL_OLD, GR_ZIZMOR_TAIL_OLD.replace("    return findings", "    return findings[:0]  # MUTANT-EMPTY the zizmor check still parses evidence but detects nothing"))],
    )

    # ---- gate_run.py: DAST_BASELINE (aggregate: EMPTY must flip) -----------
    _ad(
        "DAST_BASELINE",
        "INVERT",
        [(GR_DAST_TAIL_OLD, gr_invert_findings_new(GR_DAST_TAIL_OLD, "DAST_ALERT", "dast/mutant", "runtime, engine and alert shortfalls now accepted"))],
    )
    _ad(
        "DAST_BASELINE",
        "ALWAYS_PASS",
        [(GR_DAST_TAIL_OLD, gr_always_pas_findings_new(GR_DAST_TAIL_OLD, "the DAST baseline check accepts unconditionally"))],
    )
    _ad(
        "DAST_BASELINE",
        "EMPTY",
        [(GR_DAST_TAIL_OLD, GR_DAST_TAIL_OLD.replace("    return findings", "    return findings[:0]  # MUTANT-EMPTY the DAST baseline check still parses evidence but detects nothing"))],
    )

    # ---- smell.py (analyze_file -> py_test_smells) -------------------------
    _ad(
        "SMELL",
        "ALWAYS_PASS",
        [
            (
                """    findings = list(test_findings)
    findings.sort(key=lambda f: (f["path"], f["line"], f["class"], f["fingerprint"]))
    return findings, engine""",
                """    findings = []  # MUTANT-ALWAYS_PASS the smell analyzer accepts unconditionally
    findings.sort(key=lambda f: (f["path"], f["line"], f["class"], f["fingerprint"]))
    return findings, engine""",
            )
        ],
    )
    _ad(
        "SMELL",
        "INVERT",
        [
            (
                """    findings = list(test_findings)
    findings.sort(key=lambda f: (f["path"], f["line"], f["class"], f["fingerprint"]))
    return findings, engine""",
                """    if test_findings:
        findings = []  # MUTANT-INVERT smelly tests now accepted
    else:
        findings = [
            finding("ASSERTION_FREE", path, 1, "<mutant>", "0->1", "predicate inverted")
        ]
    findings.sort(key=lambda f: (f["path"], f["line"], f["class"], f["fingerprint"]))
    return findings, engine""",
            )
        ],
    )
    _ad(
        "SMELL",
        "TRUNCATE",
        [
            (
                """    for qual, fn in tests:
        name_counts[qual] = name_counts.get(qual, 0) + 1""",
                """    for qual, fn in tests[:1]:  # MUTANT-TRUNCATE analyze only the first test function
        name_counts[qual] = name_counts.get(qual, 0) + 1""",
            )
        ],
    )
    _ad(
        "SMELL",
        "EMPTY",
        [
            (
                """    findings = list(test_findings)
    findings.sort(key=lambda f: (f["path"], f["line"], f["class"], f["fingerprint"]))
    return findings, engine""",
                """    findings = list(test_findings)
    findings = findings[:0]  # MUTANT-EMPTY the smell analyzer still runs but detects nothing
    findings.sort(key=lambda f: (f["path"], f["line"], f["class"], f["fingerprint"]))
    return findings, engine""",
            ),
            (
                """        findings.sort(key=lambda f: (f["path"], f["line"], f["class"], f["fingerprint"]))
        code = 1 if findings else 0""",
                """        findings = findings[:0]  # MUTANT-EMPTY the smell report still runs but detects nothing
        findings.sort(key=lambda f: (f["path"], f["line"], f["class"], f["fingerprint"]))
        code = 1 if findings else 0""",
            ),
        ],
    )

    # ---- oracle_provenance.py (analyze_ast classification) ------------------
    ORACLE_CLASSIFY_OLD = """        cls = classify(
            assertion,
            assigned_calls,
            mock_values,
            mock_containers,
            input_literals,
            impl_constants,
            impl_values,
        )
        if cls is None:
            continue"""
    _ad(
        "ORACLE_PROVENANCE",
        "ALWAYS_PASS",
        [
            (
                ORACLE_CLASSIFY_OLD,
                """        cls = None  # MUTANT-ALWAYS_PASS every oracle is judged clean
        if cls is None:
            continue""",
            )
        ],
    )
    _ad(
        "ORACLE_PROVENANCE",
        "INVERT",
        [
            (
                ORACLE_CLASSIFY_OLD,
                """        cls = None
        if classify(
            assertion,
            assigned_calls,
            mock_values,
            mock_containers,
            input_literals,
            impl_constants,
            impl_values,
        ) is not None:
            cls = None  # MUTANT-INVERT oracle defects now accepted
        else:
            cls = "ORACLE_BY_COPY"  # MUTANT-INVERT clean assertions now flagged
        if cls is None:
            continue""",
            )
        ],
    )
    _ad(
        "ORACLE_PROVENANCE",
        "TRUNCATE",
        [
            (
                """    for assertion in assertions:
        line = find_line(assertion, added, lines)""",
                """    for assertion in assertions[:1]:  # MUTANT-TRUNCATE judge only the first assertion
        line = find_line(assertion, added, lines)""",
            )
        ],
    )
    _ad(
        "ORACLE_PROVENANCE",
        "EMPTY",
        [
            (
                """    findings.sort(key=lambda f: (f["path"], f["line"], f["class"], f["fingerprint"]))
    return findings, scanned, engine""",
                """    findings = findings[:0]  # MUTANT-EMPTY the oracle analysis still runs but detects nothing
    findings.sort(key=lambda f: (f["path"], f["line"], f["class"], f["fingerprint"]))
    return findings, scanned, engine""",
            )
        ],
    )

    # ---- semgrep_runner.py (collect / map_semgrep_results) ------------------
    _ad(
        "SEMGREP",
        "ALWAYS_PASS",
        [
            (
                """    findings: list[dict] = []
    preexisting = 0
    if engine == "semgrep":
""",
                """    findings: list[dict] = []
    preexisting = 0
    if True:  # MUTANT-ALWAYS_PASS the semgrep analysis accepts unconditionally
        stats = {"mode": mode, "files": len(sources)}
        return findings, preexisting, len(sources), engine, stats
    if engine == "semgrep":
""",
            )
        ],
    )
    _ad(
        "SEMGREP",
        "INVERT",
        [
            (
                """    findings.sort(key=lambda f: (f["path"], f["line"], f["rule_id"], f["fingerprint"]))
    stats = {"mode": mode, "files": len(sources)}
    return findings, preexisting, len(sources), engine, stats""",
                """    if findings:
        findings = []
    else:
        findings = [
            build_finding(
                "MUTANT_INVERTED",
                "mutant",
                "semgrep",
                1,
                "<module>",
                "predicate inverted: clean fixture now produces a finding",
                "inverted",
            )
        ]
    findings.sort(key=lambda f: (f["path"], f["line"], f["rule_id"], f["fingerprint"]))
    stats = {"mode": mode, "files": len(sources)}
    return findings, preexisting, len(sources), engine, stats  # MUTANT-INVERT clean fixtures now produce findings""",
            )
        ],
    )
    _ad(
        "SEMGREP",
        "TRUNCATE",
        [
            (
                """    for result in results:
        raw_path = result.get("path", "")""",
                """    for result in results[:1]:  # MUTANT-TRUNCATE map only the first engine result
        raw_path = result.get("path", "")""",
            )
        ],
    )
    _ad(
        "SEMGREP",
        "EMPTY",
        [
            (
                """    findings.sort(key=lambda f: (f["path"], f["line"], f["rule_id"], f["fingerprint"]))
    stats = {"mode": mode, "files": len(sources)}
    return findings, preexisting, len(sources), engine, stats""",
                """    findings = findings[:0]  # MUTANT-EMPTY the semgrep analysis still runs but detects nothing
    findings.sort(key=lambda f: (f["path"], f["line"], f["rule_id"], f["fingerprint"]))
    stats = {"mode": mode, "files": len(sources)}
    return findings, preexisting, len(sources), engine, stats""",
            )
        ],
    )

    # ---- guard_delta.py (evaluate) ------------------------------------------
    GUARD_INVERT_OLD = """            if covered_by is not None:
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
            )"""
    _ad(
        "GUARD_DELTA",
        "ALWAYS_PASS",
        [
            (
                """    findings.sort(key=lambda item: (item["path"], item["line"], item["class"], item["fingerprint"]))
    covered.sort(key=lambda item: (item["path"], item["line"]))""",
                """    findings.clear()  # MUTANT-ALWAYS_PASS the guard check accepts unconditionally
    findings.sort(key=lambda item: (item["path"], item["line"], item["class"], item["fingerprint"]))
    covered.sort(key=lambda item: (item["path"], item["line"]))""",
            )
        ],
    )
    _ad(
        "GUARD_DELTA",
        "INVERT",
        [
            (
                GUARD_INVERT_OLD,
                """            if covered_by is not None:
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
                )  # MUTANT-INVERT covered removals are now flagged
                continue

            removed = body.strip()
            covered.append(
                {
                    "path": fd.path,
                    "line": old_line,
                    "removed": removed,
                    "covered_by": None,
                }
            )  # MUTANT-INVERT uncovered removals are now tolerated""",
            )
        ],
    )
    _ad(
        "GUARD_DELTA",
        "TRUNCATE",
        [
            (
                """    for fd in files:
        hit = glob_map.best(fd.path)""",
                """    for fd in files[:1]:  # MUTANT-TRUNCATE evaluate only the first changed file
        hit = glob_map.best(fd.path)""",
            )
        ],
    )

    # ---- arch_check.py (evaluate) -------------------------------------------
    _ad(
        "ARCH",
        "ALWAYS_PASS",
        [
            (
                """    findings.sort(key=lambda item: (item["path"], item["line"], item["class"], item["fingerprint"]))""",
                """    findings.clear()  # MUTANT-ALWAYS_PASS the arch check accepts unconditionally
    findings.sort(key=lambda item: (item["path"], item["line"], item["class"], item["fingerprint"]))""",
            )
        ],
    )
    _ad(
        "ARCH",
        "INVERT",
        [
            (
                """    findings.sort(key=lambda item: (item["path"], item["line"], item["class"], item["fingerprint"]))""",
                """    if findings:
        findings = []  # MUTANT-INVERT architecture violations now accepted
    else:
        findings = [
            {
                "class": "ARCH_VIOLATION",
                "kind": "edge",
                "path": "arch/mutant",
                "line": 1,
                "from": "mutant",
                "to": "mutant",
                "symbol": "mutant",
                "evidence": "predicate inverted: clean diffs now produce a finding",
                "fingerprint": fingerprint("ARCH_VIOLATION", "arch/mutant", "mutant"),
            }
        ]
    findings.sort(key=lambda item: (item["path"], item["line"], item["class"], item["fingerprint"]))""",
            ),
        ],
    )
    _ad(
        "ARCH",
        "TRUNCATE",
        [
            (
                """    for fd in files:
        path = fd.path""",
                """    for fd in files[:1]:  # MUTANT-TRUNCATE inspect only the first changed file
        path = fd.path""",
            )
        ],
    )
    _ad(
        "ARCH",
        "EMPTY",
        [
            (
                """    findings.sort(key=lambda item: (item["path"], item["line"], item["class"], item["fingerprint"]))
    allowed.sort(key=lambda item: (item["path"], item["line"], item["kind"], item["to"]))""",
                """    findings = findings[:0]  # MUTANT-EMPTY the arch check still runs but detects nothing
    findings.sort(key=lambda item: (item["path"], item["line"], item["class"], item["fingerprint"]))
    allowed.sort(key=lambda item: (item["path"], item["line"], item["kind"], item["to"]))""",
            )
        ],
    )

    # ---- authz_matrix.py ----------------------------------------------------
    _ad(
        "AUTHZ_MATRIX",
        "INVERT",
        [
            (
                """    if gate is None:
        return derivation
    if derivation in {"PUBLIC", "UNKNOWN", "AUTHENTICATED"}:
        return gate
    return derivation""",
                """    if gate is None:
        return derivation
    return derivation  # MUTANT-INVERT gate amplification is negated, not applied""",
            )
        ],
    )
    _ad(
        "AUTHZ_MATRIX",
        "ALWAYS_PASS",
        [
            (
                """        if summary["missing_rows"] or required_missing or required_derivation_missing:
            return 1
        return 0""",
                """        if False:  # MUTANT-ALWAYS_PASS the check accepts unconditionally
            return 1
        return 0""",
            )
        ],
    )
    _ad(
        "AUTHZ_MATRIX",
        "TRUNCATE",
        [
            (
                """    emitted_routes = {row["route"] for row in rows}""",
                """    emitted_routes = {row["route"] for row in rows[:1]}  # MUTANT-TRUNCATE compare only the first row""",
            ),
            (
                """            matched = [row for row in rows if row["route"] == expected_route]""",
                """            matched = [row for row in rows if row["route"] == expected_route]
            matched = matched[:1]  # MUTANT-TRUNCATE compare only the first matched row""",
            ),
        ],
    )

    # ---- policy_digest.py (collect/digest) ----------------------------------
    PD_COLLECT_OLD = """    for name in COVERED:
        path = os.path.join(root, name)
        with open(path, "rb") as handle:
            digest = hashlib.sha256(handle.read()).hexdigest()
        files.append({"path": name, "sha256": digest})"""
    _ad(
        "POLICY_DIGEST",
        "INVERT",
        [
            (
                PD_COLLECT_OLD,
                """    for name in COVERED:
        path = os.path.join(root, name)
        with open(path, "rb"):  # noqa: SIM115  MUTANT-INVERT file content is ignored; a missing file still raises
            pass
        digest = hashlib.sha256(b"").hexdigest()
        files.append({"path": name, "sha256": digest})""",
            )
        ],
    )
    _ad(
        "POLICY_DIGEST",
        "ALWAYS_PASS",
        [
            (
                PD_COLLECT_OLD,
                """    for name in COVERED:
        path = os.path.join(root, name)
        if not os.path.isfile(path):  # MUTANT-ALWAYS_PASS a missing covered file is accepted
            continue
        files.append({"path": name, "sha256": hashlib.sha256(b"").hexdigest()})""",
            )
        ],
    )
    _ad(
        "POLICY_DIGEST",
        "TRUNCATE",
        [
            (
                """    for name in COVERED:
        path = os.path.join(root, name)
        with open(path, "rb") as handle:""",
                """    for name in COVERED[:1]:  # MUTANT-TRUNCATE digest inspects only the first covered file
        path = os.path.join(root, name)
        with open(path, "rb") as handle:""",
            )
        ],
    )

    # ---- agt_parity.py (check) ----------------------------------------------
    _ad(
        "AGT_PARITY",
        "ALWAYS_PASS",
        [
            (
                """    return findings


def outcome(findings: list[dict]) -> str:""",
                """    return []  # MUTANT-ALWAYS_PASS the parity check accepts unconditionally


def outcome(findings: list[dict]) -> str:""",
            ),
        ],
    )
    _ad(
        "AGT_PARITY",
        "INVERT",
        [
            (
                """    return findings


def outcome(findings: list[dict]) -> str:""",
                """    if findings:
        return []  # MUTANT-INVERT deviating roots are now accepted
    return [finding("mutant", "predicate inverted: compliant roots now produce a finding")]


def outcome(findings: list[dict]) -> str:""",
            ),
        ],
    )
    _ad(
        "AGT_PARITY",
        "TRUNCATE",
        [
            (
                """        for key in sorted(set(MANDATED_POLICY) | set(policy)):""",
                """        for key in sorted(set(MANDATED_POLICY) | set(policy))[:1]:  # MUTANT-TRUNCATE compare only the first policy key""",
            ),
        ],
    )

    # ---- agt_audit.py (check) ------------------------------------------------
    _ad(
        "AGT_AUDIT",
        "ALWAYS_PASS",
        [
            (
                """                f"golden expectation says a deny occurred ({source}), but no deny entry exists",
            )
        )
    return findings""",
                """                f"golden expectation says a deny occurred ({source}), but no deny entry exists",
            )
        )
    return []  # MUTANT-ALWAYS_PASS the audit check accepts unconditionally""",
            ),
        ],
    )
    _ad(
        "AGT_AUDIT",
        "INVERT",
        [
            (
                """                f"golden expectation says a deny occurred ({source}), but no deny entry exists",
            )
        )
    return findings""",
                """                f"golden expectation says a deny occurred ({source}), but no deny entry exists",
            )
        )
    if findings:
        return []  # MUTANT-INVERT deny evidence gaps are now accepted
    return [finding("mutant", "predicate inverted: clean logs now produce a finding")]""",
            ),
        ],
    )
    _ad(
        "AGT_AUDIT",
        "TRUNCATE",
        [
            (
                """    for index, entry in enumerate(entries):
        if entry.get("decision") != "deny":""",
                """    for index, entry in enumerate(entries[:1]):  # MUTANT-TRUNCATE inspect only the first entry
        if entry.get("decision") != "deny":""",
            ),
        ],
    )


# ---------------------------------------------------------------------------
# Harness mechanics
# ---------------------------------------------------------------------------


def mutation_root() -> Path:
    """Per-process root: two invocations never share or clean each other's runs."""
    return Path(tempfile.gettempdir()) / "opencode" / "mutation" / str(os.getpid())


def load_predicate_kinds() -> dict[str, str]:
    """Read predicate_kind for every check declared in policies/checks.json."""
    doc = json.loads(CHECKS_PATH.read_text(encoding="utf-8"))
    kinds: dict[str, str] = {}
    for check_id, body in (doc.get("checks") or {}).items():
        kind = body.get("predicate_kind")
        if kind not in OPERATORS_BY_KIND:
            raise RuntimeError(
                f"checks.json: {check_id} has predicate_kind {kind!r}; "
                f"expected one of {sorted(OPERATORS_BY_KIND)}"
            )
        kinds[check_id] = kind
    return kinds


def load_copy_gate_control(files_dir: Path):
    """Import the copy's gate_control.py and reuse its observation logic."""
    path = files_dir / "tools" / "gate_control.py"
    spec = importlib.util.spec_from_file_location("gate_control_copy", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def fresh_copy(destination: Path) -> Path:
    shutil.rmtree(destination, ignore_errors=True)
    destination.parent.mkdir(parents=True, exist_ok=True)
    tree = destination / "files"
    shutil.copytree(
        FILES_ROOT,
        tree,
        ignore=shutil.ignore_patterns("__pycache__", ".ruff_cache", "*.pyc"),
    )
    return tree


def marker_lines(text: str, mutation: str) -> list[int]:
    needle = f"MUTANT-{mutation}"
    return [
        index
        for index, line in enumerate(text.splitlines(), start=1)
        if needle in line
    ]


def run_entries(run_name: str, only_check: str | None = None) -> tuple[list[dict], int]:
    """Copy live files/ and observe every control entry through the copy."""
    run_dir = mutation_root() / run_name
    files_dir = fresh_copy(run_dir)
    gc = load_copy_gate_control(files_dir)
    manifest = gc.load_json(files_dir / "policies" / "negative-controls.json")
    entries = gc.resolved_manifest(manifest)
    if only_check:
        entries = [e for e in entries if e["check_id"] == only_check]
    results = []
    for entry in entries:
        try:
            observed, error = gc.observed_for(entry)
        except Exception as exc:  # noqa: BLE001
            observed, error = "ERROR", f"{type(exc).__name__}: {exc}"
        results.append(
            {
                "check_id": entry["check_id"],
                "control_id": entry["control_id"],
                "fixture_ref": entry["fixture_ref"],
                "runner": entry["runner"],
                "expected_outcome": entry["expected_outcome"],
                "observed_outcome": observed,
                "detail": error,
            }
        )
    (run_dir / "result.json").write_text(
        json.dumps({"run": run_name, "results": results}, indent=2), encoding="utf-8"
    )
    return results, base_exit(results)


def base_exit(results: list[dict]) -> int:
    return 1 if any(r["observed_outcome"] != r["expected_outcome"] for r in results) else 0


def apply_patch(tool_path: Path, check_id: str, mutation: str) -> tuple[str, list[int]]:
    pairs, reason = ADAPTERS[(check_id, mutation)]
    if pairs is None:
        raise RuntimeError(f"NOT_APPLICABLE {check_id}/{mutation}: {reason}")
    text = tool_path.read_text(encoding="utf-8")
    for old, new in pairs:
        if text.count(old) != 1:
            raise RuntimeError(
                f"patch anchor not unique ({text.count(old)} hits) for "
                f"{check_id}/{mutation}: {old[:60]!r}"
            )
        text = text.replace(old, new)
    tool_path.write_text(text, encoding="utf-8")
    return str(tool_path.relative_to(mutation_root())), marker_lines(text, mutation)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all", action="store_true", help="run every check group")
    parser.add_argument("--sample", type=int, default=0, metavar="N", help="run the first N check groups (manifest order)")
    parser.add_argument(
        "--skip-baseline-copy",
        action="store_true",
        help="reuse run-000-baseline if it exists (baseline comparison still runs)",
    )
    args = parser.parse_args(argv)
    if not args.all and not args.sample:
        parser.error("provide --all or --sample N")

    _build_adapters()

    manifest_path = FILES_ROOT / "policies" / "negative-controls.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    groups = list((manifest.get("controls") or {}).keys())
    if args.sample:
        groups = groups[: args.sample]

    try:
        predicate_kinds = load_predicate_kinds()
    except (OSError, json.JSONDecodeError, RuntimeError) as exc:
        print(json.dumps({"fatal": f"cannot read predicate kinds: {exc}"}))
        return 2
    missing = [check_id for check_id in groups if check_id not in predicate_kinds]
    if missing:
        print(json.dumps({"fatal": f"checks.json has no predicate_kind for: {missing}"}))
        return 2

    root = mutation_root()
    if args.all:
        shutil.rmtree(root, ignore_errors=True)  # only this process's own root
    root.mkdir(parents=True, exist_ok=True)

    print(
        json.dumps(
            {
                "harness": "control_mutation",
                "files_root": str(FILES_ROOT),
                "mutation_root": str(root),
                "groups": groups,
                "predicate_kinds": {check_id: predicate_kinds[check_id] for check_id in groups},
                "mode": "--all" if args.all else f"--sample {args.sample}",
            }
        )
    )

    # Baseline: fresh copy, observe everything in the selected groups.
    baseline_name = "run-000-baseline"
    baseline_dir = mutation_root() / baseline_name
    if args.skip_baseline_copy and baseline_dir.exists():
        shutil.rmtree(baseline_dir)
    baseline_results, _ = run_entries(baseline_name)

    failures = [
        r
        for r in baseline_results
        if r["observed_outcome"] != r["expected_outcome"]
    ]
    if failures:
        print(
            json.dumps(
                {
                    "fatal": "baseline mismatch: the control set is broken before mutation",
                    "mismatches": [
                        f"{r['control_id']}: expected {r['expected_outcome']}, "
                        f"observed {r['observed_outcome']} ({r['detail'] or 'no detail'})"
                        for r in failures
                    ],
                }
            )
        )
        return 2
    print(
        json.dumps(
            {
                "baseline": "PASS",
                "entries": len(baseline_results),
                "mismatches": 0,
            }
        )
    )

    rows = []
    counters = {"index": 1}
    for check_id in groups:
        kind = predicate_kinds[check_id]
        operators = OPERATORS_BY_KIND[kind]
        mutants = {}
        expected_by_control = {r["control_id"]: r for r in baseline_results if r["check_id"] == check_id}
        for mutation in operators:
            run_name = f"run-{counters['index']:03d}-{check_id}-{mutation}"
            counters["index"] += 1
            pairs, reason = ADAPTERS.get((check_id, mutation), (None, "no adapter"))
            if pairs is None:
                mutants[mutation] = {
                    "status": "NOT_APPLICABLE",
                    "reason": reason,
                    "flips": [],
                }
                continue
            # Copy + patch in one directory.
            run_dir = mutation_root() / run_name
            files_dir = fresh_copy(run_dir)
            tool_rel = GROUP_TOOL[check_id]
            try:
                _path, lines = apply_patch(files_dir / tool_rel, check_id, mutation)
            except Exception as exc:  # noqa: BLE001
                mutants[mutation] = {
                    "status": "NOT_APPLICABLE",
                    "reason": f"patch failed: {type(exc).__name__}: {exc}",
                    "flips": [],
                }
                continue
            gc = load_copy_gate_control(files_dir)
            m_manifest = gc.load_json(files_dir / "policies" / "negative-controls.json")
            entries = [e for e in gc.resolved_manifest(m_manifest) if e["check_id"] == check_id]
            flips = []
            observed_results = []
            for entry in entries:
                try:
                    observed, error = gc.observed_for(entry)
                except Exception as exc:  # noqa: BLE001
                    observed, error = "ERROR", f"{type(exc).__name__}: {exc}"
                base_expected = expected_by_control[entry["control_id"]]["expected_outcome"]
                observed_results.append(
                    {
                        "control_id": entry["control_id"],
                        "expected_outcome": base_expected,
                        "observed_outcome": observed,
                        "detail": error,
                    }
                )
                if observed != base_expected:
                    flips.append(
                        {
                            "control_id": entry["control_id"],
                            "expected": base_expected,
                            "observed": observed,
                            "detail": error,
                            "line": lines[0] if lines else None,
                            "mutant_file": f"{run_name}/files/{tool_rel}",
                            "command": entry["runner"],
                        }
                    )
            (run_dir / "result.json").write_text(
                json.dumps({"run": run_name, "mutation": mutation, "results": observed_results}, indent=2),
                encoding="utf-8",
            )
            mutants[mutation] = {
                "status": "APPLIED",
                "flips": flips,
            }
        survivor = not all(
            mutants[m]["status"] == "APPLIED" and mutants[m]["flips"] for m in operators
        )
        rows.append(
            {
                "check": check_id,
                "kind": kind,
                "operators": operators,
                "mutants": mutants,
                "survivor": survivor,
            }
        )

    # Table: the operator set actually used, its three flip columns, survivors.
    print()
    print("E/T = EMPTY for aggregate checks, TRUNCATE for collection checks.")
    print(
        f"{'check':<18}{'kind':<12}{'operators':<31}{'ent':>4}{'base':>6}"
        f"{'INV':>5}{'ALW':>5}{'E/T':>5}{'surv':>6}  evidence"
    )
    survivors = []
    for row in rows:
        mutants = row["mutants"]

        def cell(m: str) -> str:
            status = mutants[m]["status"]
            if status != "APPLIED":
                return "n/a"
            return "Y" if mutants[m]["flips"] else "N"

        operators = row["operators"]
        evidence = ""
        for m in operators:
            for flip in mutants[m]["flips"]:
                evidence = (
                    f"{flip['mutant_file']}:{flip['line']} {m} "
                    f"{flip['control_id']} {flip['expected']}->{flip['observed']}"
                )
                break
            if evidence:
                break
        baseline_ok = all(
            r["observed_outcome"] == r["expected_outcome"]
            for r in baseline_results
            if r["check_id"] == row["check"]
        )
        entries = sum(1 for r in baseline_results if r["check_id"] == row["check"])
        flag = "Y" if row["survivor"] else "N"
        if row["survivor"]:
            survivors.append(row["check"])
        print(
            f"{row['check']:<18}{row['kind']:<12}{','.join(operators):<31}"
            f"{entries:>4}{('ok' if baseline_ok else 'ERR'):>6}"
            f"{cell('INVERT'):>5}{cell('ALWAYS_PASS'):>5}{cell(operators[2]):>5}{flag:>6}  {evidence}"
        )

    print()
    if survivors:
        print(
            json.dumps(
                {
                    "survivors": survivors,
                    "detail": "groups where any mutation leaves every control entry passing "
                    "(not mutation-sensitive)",
                }
            )
        )
        return 1
    print("No survivors: every check group flipped under its predicate_kind operator set.")
    print(json.dumps({"survivors": []}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
