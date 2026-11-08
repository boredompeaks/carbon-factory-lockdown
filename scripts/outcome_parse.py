#!/usr/bin/env python3
"""S5a -- outcome extraction from a test runner's own summary.

The verdict is the runner's summary line, never the shell wrapper's exit code.
A command can be piped through ``Tee-Object``, ``Out-File``, ``|| true`` or a
trailing ``; Get-ChildItem`` and still return 0 while the suite failed.

Supported summaries (the last one in the text wins):

* Django / unittest::

      Ran 34 tests in 4.200s

      OK
      OK (skipped=2)
      FAILED (failures=1, errors=2)

* pytest::

      ===== 3 failed, 40 passed in 1.21s =====

* vitest / jest::

      Tests  3 failed | 40 passed (43)

Django's suite writes its "System check identified..." line on stderr, so with
``2>&1`` the verdict can land *after* that line even though it was printed
first. The parser therefore associates a verdict line with the nearest
preceding ``Ran N tests`` block instead of requiring it on the next line.

A text with no recognised summary is ``UNMEASURED``. For gate purposes
``UNMEASURED`` is a FAIL: a missing summary is not green.

Usage::

    python scripts/outcome_parse.py <path-to-log>

or import :func:`parse_outcome` / :func:`verdict`.
"""

from __future__ import annotations

import re
import sys
from dataclasses import asdict, dataclass

OK = "OK"
FAILED = "FAILED"
UNMEASURED = "UNMEASURED"

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

# Django's run header. The verdict may be separated from it by interleaved
# stderr, so the two are matched independently and then associated.
_RAN = re.compile(r"^Ran (?P<ran>\d+) tests? in [\d.]+s\s*$", re.MULTILINE)

# A verdict must start a line. This deliberately excludes wrapper prose such
# as ``test-evidence: OK - 99.84% >= fail_under=90%``: that is the wrapper
# talking, not the runner.
_VERDICT = re.compile(
    r"^[ \t]*(?P<verdict>OK|FAILED)\b(?:[ \t]*\((?P<detail>[^)]*)\))?",
    re.MULTILINE,
)

# pytest summary.
_PYTEST = re.compile(
    r"^=+ "
    r"(?:(?P<failed>\d+) failed,? )?"
    r"(?:(?P<errors>\d+) errors?,? )?"
    r"(?:(?P<skipped>\d+) skipped,? )?"
    r"(?P<passed>\d+) passed"
    r"(?:, (?P<deselected>\d+) deselected)?"
    r".*? in [\d.]+s"
    r"(?: \([\d:]+\))?"
    r" =+\s*$",
    re.MULTILINE,
)

# vitest / jest.
_VITEST = re.compile(
    r"^\s*Tests\s+"
    r"(?:(?P<failed>\d+) failed \| )?"
    r"(?P<passed>\d+) passed"
    r"(?: \| (?P<skipped>\d+) skipped)?",
    re.MULTILINE,
)

# How far after a "Ran N tests" line a verdict may appear. Django prints the
# block immediately; the allowance only covers interleaved single lines.
_VERDICT_WINDOW = 2000


@dataclass(frozen=True)
class Outcome:
    status: str
    source: str
    ran: int | None = None
    passed: int | None = None
    failures: int = 0
    errors: int = 0
    skipped: int = 0
    detail: str = ""
    summary: str = ""

    @property
    def measured(self) -> bool:
        return self.status in (OK, FAILED)

    def as_dict(self) -> dict:
        return asdict(self)


def _detail_counts(detail: str) -> dict:
    """Parse ``failures=1, errors=2, skipped=3`` style detail text."""
    counts = {}
    for key in ("failures", "errors", "skipped", "expected failures"):
        match = re.search(rf"{re.escape(key)}=(\d+)", detail or "")
        if match:
            counts[key.replace(" ", "_")] = int(match.group(1))
    return counts


def _django_outcome(match: re.Match, ran: int | None) -> Outcome:
    detail = match.group("detail") or ""
    counts = _detail_counts(detail)
    verdict = match.group("verdict")
    failures = counts.get("failures", 0)
    errors = counts.get("errors", 0)
    if verdict == FAILED and not (failures or errors):
        # A bare FAILED with no detail still means the suite did not pass.
        failures = 1
    return Outcome(
        status=OK if verdict == OK else FAILED,
        source="django" if ran is not None else "bare",
        ran=ran,
        passed=None,
        failures=failures,
        errors=errors,
        skipped=counts.get("skipped", 0),
        detail=detail,
        summary=match.group(0).strip(),
    )


def _pytest_outcome(match: re.Match) -> Outcome:
    failed = int(match.group("failed") or 0)
    errors = int(match.group("errors") or 0)
    return Outcome(
        status=OK if not (failed or errors) else FAILED,
        source="pytest",
        ran=None,
        passed=int(match.group("passed") or 0),
        failures=failed,
        errors=errors,
        skipped=int(match.group("skipped") or 0),
        summary=match.group(0).strip(),
    )


def _vitest_outcome(match: re.Match) -> Outcome:
    failed = int(match.group("failed") or 0)
    return Outcome(
        status=OK if not failed else FAILED,
        source="vitest",
        ran=None,
        passed=int(match.group("passed") or 0),
        failures=failed,
        errors=0,
        skipped=int(match.group("skipped") or 0),
        summary=match.group(0).strip(),
    )


def parse_outcome(text: str) -> Outcome:
    """Return the LAST recognised runner summary in ``text``.

    Taking the last summary is what stops a log that records a failed mutation
    probe and then a green suite from being classified as failed, and vice
    versa. If no summary is present the text is UNMEASURED.
    """
    if not text:
        return Outcome(status=UNMEASURED, source="none")

    cleaned = _ANSI.sub("", text)

    candidates: list[tuple[int, Outcome]] = []

    runs = [(m.start(), int(m.group("ran"))) for m in _RAN.finditer(cleaned)]

    for match in _VERDICT.finditer(cleaned):
        position = match.end()
        # Nearest preceding "Ran N tests" inside the window, but never one
        # that belongs to an earlier verdict's block.
        ran = None
        for run_start, run_count in runs:
            if run_start > position:
                break
            if position - run_start <= _VERDICT_WINDOW:
                ran = run_count
        candidates.append((position, _django_outcome(match, ran)))

    for match in _PYTEST.finditer(cleaned):
        candidates.append((match.end(), _pytest_outcome(match)))
    for match in _VITEST.finditer(cleaned):
        candidates.append((match.end(), _vitest_outcome(match)))

    if not candidates:
        return Outcome(status=UNMEASURED, source="none")

    candidates.sort(key=lambda item: item[0])
    return candidates[-1][1]


def verdict(outcome: Outcome) -> str:
    """Gate verdict: UNMEASURED is a FAIL, never green."""
    return FAILED if outcome.status == UNMEASURED else outcome.status


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 1:
        print("usage: outcome_parse.py <log-file>", file=sys.stderr)
        return 2
    with open(argv[0], "r", encoding="utf-8", errors="replace") as handle:
        outcome = parse_outcome(handle.read())
    print(outcome.as_dict())
    return 0 if verdict(outcome) == OK else 1


if __name__ == "__main__":
    raise SystemExit(main())
