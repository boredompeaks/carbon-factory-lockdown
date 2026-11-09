#!/usr/bin/env python3
"""DOC path-scope gate check (patch module for gate_run.py).

CONCURRENCY NOTE
----------------
Another agent may be editing ``files/tools/gate_run.py`` (e.g. the mutation
cap / ``check_mutation``) concurrently. This patch therefore MUST NOT edit
``gate_run.py`` directly. Instead the finalizer merges it with the exact
insertion steps below. This file is the sole owned artifact of the DOC task.

Source of truth (authoritative policy, mirrored verbatim as the defaults):
  * ``files/policies/task-kinds.json``  -> ``DOC.allowed_path_globs``,
    ``DOC.denied_path_globs``, ``DOC.denied_extensions``,
    ``DOC.allowed_rule``, ``DOC.reject_code`` ("DOC_PATH_VIOLATION"),
    ``DOC.backend_docs_note``
  * ``files/policies/task-limits.json`` -> identical ``DOC`` globs / reject code.

Policy rule enforced here (``DOC.allowed_rule``):
    EVERY diff path MUST match an ``allowed_path_globs`` entry AND MUST NOT
    match ``denied_extensions`` AND MUST NOT match ``denied_path_globs``
    EXCEPT the ``backend/docs/**`` docs exception
    (``backend/docs/**/*.md|rst|txt`` and ``**/docs/**/*.md|rst|txt`` override
    the ``backend/**`` deny; ``**/*.py`` overrides everything, including
    ``backend/docs/**``).

Input shape (gate_run.py envelope convention, cf. ``check_scope``)::

    {"paths": ["<diff path>", ...]}

``data["diff_paths"]`` and ``data["files"]`` are accepted as fallbacks.
Optional overrides: ``data["allowed_path_globs"]``,
``data["denied_path_globs"]``, ``data["denied_extensions"]`` replace the
defaults when present and non-empty (lets the runner pass policy-loaded
values and lets tests pin them). One ``DOC_PATH_VIOLATION`` finding is
returned per offending path; an empty ``paths`` list passes vacuously.

Return shape matches gate_run.py: ``[{"class", "locus", "detail"}, ...]``
with ``class == "DOC_PATH_VIOLATION"``.

FINALIZER INSERTION INSTRUCTIONS (exact steps for gate_run.py)
---------------------------------------------------------------
Apply these three edits to ``files/tools/gate_run.py`` AFTER the mutation-cap
agent has finished, then re-run the selftest below and ``--verify``:

1. Import (one line, next to the other stdlib imports at the top; the file
   is a script in ``files/tools/`` so a sibling import resolves via
   ``sys.path[0]`` when run as ``python files/tools/gate_run.py``)::

       from gate_run_doc_patch import check_doc_scope

2. Register the check id. In the ``CHECKS`` tuple, insert ``"DOC"`` as the
   last entry (after ``"DAST_BASELINE"``)::

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

3. Dispatch (one entry in the ``CHECK_FUNCTIONS`` dict)::

       CHECK_FUNCTIONS = {
           ...  # existing entries unchanged
           "DAST_BASELINE": check_dast_baseline,
           "DOC": check_doc_scope,
       }

After the merge:
  * ``python files/tools/gate_run.py --check DOC --input <json>`` works with
    the ``{"paths": [...]}`` shape above (exit 0 = accept, 1 = reject).
  * The helper names ``normalise`` / ``finding`` are intentionally duplicated
    here (byte-identical semantics to gate_run.py) so this module is usable
    standalone and the import in step 1 creates no circular dependency.
  * Control fixtures (``--control``) are intentionally NOT part of this patch:
    the finalizer should add ``files/tools/fixtures/doc/bad.json`` (e.g.
    ``{"paths": ["backend/app.py"]}`` -> reject) and ``clean.json`` (e.g.
    ``{"paths": ["backend/docs/x.md"]}`` -> accept) plus a ``"DOC"`` entry in
    ``control_specs()``. Fixtures -- not this patch -- are the only other
    files that change.
  * ``checks.json`` / ``gate.json`` / ``ci.json`` / ``tiers.json`` /
    ``check-runners.json`` deliberately stay untouched (out of owned scope);
    ``check_harness_config.py``'s gate/checks partition invariants therefore
    keep passing until a separate policy patch adds a ``DOC`` check entry.
  * This patch file itself is NOT in ``policy_manifest.TOOL_BODIES`` and is
    NOT in the gate-impl digest, so adding it does not disturb
    ``scripts/policy_manifest.py --verify`` (see verification notes in the
    task return). Do NOT run ``policy_manifest --write`` as part of this patch.

Glob-matching note (deliberate, documented divergence):
    gate_run.py's generic ``matches()`` uses ``fnmatch.fnmatchcase`` verbatim,
    which requires a ``/`` for ``**/*.md`` and so misses repo-root files
    (``README.md``) and ``docs/x.md``. The DOC globs in policy are written
    shell-style where ``**`` means zero-or-more directories, so this module
    expands each glob with the zero-directory variants (``**/`` -> ``""``
    and ``/**/`` -> ``/``) before applying ``fnmatchcase``. Without this,
    ``README.md`` would wrongly FAIL a DOC change. See ``_glob_variants``.

Selftest:
    python files/tools/gate_run_doc_patch.py
    -> exit 0 on success (also via ``python -m py_compile`` cleanliness).
"""

from __future__ import annotations

import fnmatch

DOC_CHECK_ID = "DOC"
DOC_REJECT_CODE = "DOC_PATH_VIOLATION"

# Mirrored verbatim from task-kinds.json / task-limits.json DOC blocks.
DOC_ALLOWED_PATH_GLOBS: tuple[str, ...] = (
    "**/*.md",
    "**/*.rst",
    "**/*.txt",
    "**/docs/**/*.md",
    "**/docs/**/*.rst",
    "**/docs/**/*.txt",
)
DOC_DENIED_PATH_GLOBS: tuple[str, ...] = (
    "**/*.py",
    "policies/**",
    "files/policies/**",
    "tools/**",
    "files/tools/**",
    ".opencode/**",
    "backend/**",
)
DOC_DENIED_EXTENSIONS: tuple[str, ...] = (".py",)
# Extensions that make backend/docs/** exempt from the backend/** deny.
DOC_ALLOWED_DOC_EXTENSIONS: tuple[str, ...] = (".md", ".rst", ".txt")


def normalise(path: str) -> str:
    """Same normalisation as gate_run.normalise (kept byte-identical)."""
    return path.replace("\\", "/").lstrip("./")


def finding(kind: str, locus: str, detail: str) -> dict:
    """Same finding shape as gate_run.finding (kept byte-identical)."""
    return {"class": kind, "locus": locus, "detail": detail}


def _glob_variants(glob: str) -> set[str]:
    """Zero-directory expansions so '**' means zero-or-more directories.

    ``fnmatchcase`` treats '**' exactly like '*', so '**/*.md' needs a '/'.
    The DOC policy globs intend shell-`**` semantics where the leading
    '**/' and every '/**/' may match zero directories. Expanding explicitly
    fixes root files (``README.md``) and direct docs children
    (``docs/x.md``, ``backend/docs/x.md``) without changing any other
    fnmatch semantics (``*`` still matches '/').
    """
    variants = {glob}
    stripped = glob[3:] if glob.startswith("**/") else glob
    variants.add(stripped)
    if "/**/" in glob:
        variants.add(glob.replace("/**/", "/"))
    if "/**/" in stripped:
        variants.add(stripped.replace("/**/", "/"))
    return variants


def _doc_matches(path: str, globs: list[str]) -> bool:
    """True when a normalised path matches any glob (zero-dir aware)."""
    normalised = normalise(path)
    for glob in globs:
        for variant in _glob_variants(normalise(glob)):
            if fnmatch.fnmatchcase(normalised, variant):
                return True
    return False


def _is_backend_docs_exception(normalised_path: str) -> bool:
    """True for backend/docs/** docs (.md/.rst/.txt), False for .py.

    The exception covers exactly the ``backend/**`` deny, not the other
    denies (policies/tools/.opencode) and not the ``.py`` deny: a ``.py``
    under ``backend/docs/`` is still rejected (checked by the caller first).
    """
    lower = normalised_path.lower()
    if any(lower.endswith(ext) for ext in DOC_DENIED_EXTENSIONS):
        return False
    if not any(lower.endswith(ext) for ext in DOC_ALLOWED_DOC_EXTENSIONS):
        return False
    segments = normalised_path.split("/")
    return any(
        segments[i] == "backend" and segments[i + 1] == "docs"
        for i in range(len(segments) - 1)
    )


def _as_str_list(value: object) -> list[str]:
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return []


def _extract_paths(data: dict) -> list[str]:
    """Diff paths from ``paths`` (first), ``diff_paths``, then ``files``."""
    for key in ("paths", "diff_paths", "files"):
        value = data.get(key)
        if isinstance(value, (list, tuple)):
            return [str(item) for item in value]
    return []


def check_doc_scope(data: dict) -> list[dict]:
    """DOC path-scope gate: every diff path must be documentation-only.

    Args:
        data: ``{"paths": [...], ...}`` (see module docstring). Optional
            ``allowed_path_globs`` / ``denied_path_globs`` /
            ``denied_extensions`` replace the policy defaults when non-empty.

    Returns:
        One ``{"class": "DOC_PATH_VIOLATION", ...}`` finding per offending
        path, in input order; ``[]`` when every path is allowed. An
        explicitly empty ``paths: []`` passes vacuously (documented
        empty-diff case), but a missing paths/diff_paths/files key is
        DOC_PATH_VIOLATION (missing evidence, fail-closed). Pure
        function: no I/O, no globals mutated.
    """
    # Fail-closed on missing evidence: {} (no paths key at all) fails.
    if "paths" not in data and "diff_paths" not in data and "files" not in data:
        return [finding(DOC_REJECT_CODE, "paths", "paths evidence is missing")]
    paths = _extract_paths(data)
    allowed = _as_str_list(data.get("allowed_path_globs")) or list(
        DOC_ALLOWED_PATH_GLOBS
    )
    denied = _as_str_list(data.get("denied_path_globs")) or list(
        DOC_DENIED_PATH_GLOBS
    )
    denied_extensions = _as_str_list(data.get("denied_extensions")) or list(
        DOC_DENIED_EXTENSIONS
    )
    denied_extensions_lower = [str(ext).lower() for ext in denied_extensions]

    findings: list[dict] = []
    for raw_path in paths:
        path = normalise(str(raw_path))
        if not path:
            findings.append(
                finding(
                    DOC_REJECT_CODE,
                    str(raw_path),
                    "empty diff path does not match any allowed doc glob",
                )
            )
            continue

        # 1. Denied extensions (.py) override EVERYTHING, including the
        #    backend/docs exception. Checked case-insensitively because
        #    fnmatchcase "**/*.py" is case-sensitive.
        lower = path.lower()
        hit_extension = next(
            (ext for ext in denied_extensions_lower if lower.endswith(ext)),
            None,
        )
        if hit_extension is not None:
            findings.append(
                finding(
                    DOC_REJECT_CODE,
                    path,
                    f"denied extension {hit_extension}: "
                    f"**/*.py overrides everything, including backend/docs/**",
                )
            )
            continue

        # 2. Denied globs (policies/tools/.opencode/backend-code). Collect
        #    every matching deny; the backend/docs/** docs exception lifts
        #    ONLY backend-flavoured denies, all other denies still apply.
        #    (Denied .py was already rejected in step 1 and never reaches here.)
        backend_docs = _is_backend_docs_exception(path)
        denied_hits = [glob for glob in denied if _doc_matches(path, [glob])]
        if backend_docs:
            denied_hits = [
                glob
                for glob in denied_hits
                if normalise(glob) not in ("backend/**", "**/backend/**")
                and not normalise(glob).endswith("/backend/**")
            ]
        if denied_hits:
            findings.append(
                finding(
                    DOC_REJECT_CODE,
                    path,
                    f"path matches denied glob {denied_hits[0]!r}",
                )
            )
            continue

        # 3. Must match an allowed doc glob.
        if not _doc_matches(path, allowed):
            findings.append(
                finding(
                    DOC_REJECT_CODE,
                    path,
                    "path does not match any allowed doc glob "
                    "(**/*.md, **/*.rst, **/*.txt, **/docs/**/*.md|rst|txt)",
                )
            )
            continue

    return findings


# ---------------------------------------------------------------------------
# Selftest (offline, no fixtures on disk, no gate_run import)
# ---------------------------------------------------------------------------


def _selftest() -> int:
    """Run the four required task cases plus edge cases. 0 = all pass."""
    cases: list[tuple[str, dict, bool]] = [
        ("DOC .md PASS", {"paths": ["docs/guide.md"]}, True),
        ("DOC root .md PASS", {"paths": ["README.md"]}, True),
        ("DOC backend/docs/x.md PASS", {"paths": ["backend/docs/x.md"]}, True),
        ("DOC backend/docs deep PASS", {"paths": ["backend/docs/sub/x.rst"]}, True),
        ("DOC .py FAIL", {"paths": ["backend/app.py"]}, False),
        ("DOC root .py FAIL", {"paths": ["foo.py"]}, False),
        ("DOC uppercase .PY FAIL", {"paths": ["foo.PY"]}, False),
        ("DOC backend/docs .py FAIL (py overrides)", {"paths": ["backend/docs/x.py"]}, False),
        ("DOC policies/mutation.json FAIL", {"paths": ["policies/mutation.json"]}, False),
        ("DOC files/policies FAIL", {"paths": ["files/policies/mutation.json"]}, False),
        ("DOC tools/ .py FAIL", {"paths": ["files/tools/gate_run.py"]}, False),
        ("DOC tools/ .md FAIL (denied tools/**)", {"paths": ["tools/foo.md"]}, False),
        ("DOC .opencode FAIL (denied)", {"paths": [".opencode/agent.md"]}, False),
        ("DOC backend foo.md FAIL (backend/** deny)", {"paths": ["backend/foo.md"]}, False),
        ("DOC Makefile FAIL (not allowed)", {"paths": ["Makefile"]}, False),
        ("DOC empty PASS (vacuous)", {"paths": []}, True),
    ]
    # A mixed diff must reject exactly the offending path, in order.
    mixed = {"paths": ["docs/a.md", "backend/app.py"]}
    mixed_findings = check_doc_scope(mixed)

    failures = 0
    for name, data, expect_pass in cases:
        findings = check_doc_scope(data)
        passed = (len(findings) == 0) == expect_pass
        if not passed:
            failures += 1
        status = "PASS" if passed else "FAIL"
        detail = (
            f"findings={[f['class'] + ':' + f['locus'] for f in findings]}"
            if findings
            else "findings=[]"
        )
        print(f"{status}  {name}: {detail}")

    mixed_ok = (
        len(mixed_findings) == 1
        and mixed_findings[0]["class"] == DOC_REJECT_CODE
        and mixed_findings[0]["locus"] == "backend/app.py"
    )
    if not mixed_ok:
        failures += 1
    print(
        f"{'PASS' if mixed_ok else 'FAIL'}  mixed diff rejects only app.py: "
        f"findings={[f['class'] + ':' + f['locus'] for f in mixed_findings]}"
    )

    # Purity: same input twice -> identical output, no mutation of input.
    snapshot = {"paths": ["docs/a.md"]}
    first = check_doc_scope(snapshot)
    second = check_doc_scope(snapshot)
    pure_ok = first == second and snapshot == {"paths": ["docs/a.md"]}
    if not pure_ok:
        failures += 1
    print(f"{'PASS' if pure_ok else 'FAIL'}  check_doc_scope is pure/deterministic")

    print(f"selftest: {failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(_selftest())
