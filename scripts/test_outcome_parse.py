#!/usr/bin/env python3
"""Tests for S5a outcome extraction. Run: python -m unittest scripts.test_outcome_parse"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from outcome_parse import (  # noqa: E402
    FAILED,
    OK,
    UNMEASURED,
    parse_outcome,
    verdict,
)


class DjangoSummaryTests(unittest.TestCase):
    def test_ok(self):
        out = parse_outcome(
            "Found 34 test(s).\nSystem check identified no issues.\n"
            "..................................\n"
            "----------------------------------------------------------------------\n"
            "Ran 34 tests in 4.200s\n\nOK\n"
            "Destroying test database for alias 'default'...\n"
        )
        self.assertEqual(out.status, OK)
        self.assertEqual(out.ran, 34)
        self.assertEqual(out.source, "django")

    def test_failed_with_failures_and_errors(self):
        out = parse_outcome(
            "Ran 7 tests in 0.913s\n\nFAILED (failures=2, errors=3)\n"
        )
        self.assertEqual(out.status, FAILED)
        self.assertEqual(out.failures, 2)
        self.assertEqual(out.errors, 3)

    def test_ok_with_skips_is_green(self):
        out = parse_outcome("Ran 9 tests in 0.500s\n\nOK (skipped=2)\n")
        self.assertEqual(out.status, OK)
        self.assertEqual(out.skipped, 2)

    def test_zero_errors_does_not_fail(self):
        out = parse_outcome("Ran 5 tests in 0.200s\n\nOK (skipped=0)\n")
        self.assertEqual(out.status, OK)

    def test_last_summary_wins_when_a_failing_run_precedes_a_green_one(self):
        text = (
            "Ran 3 tests in 0.100s\n\nFAILED (failures=1)\n"
            "\n$ rerun after the fix\n"
            "Ran 3 tests in 0.100s\n\nOK\n"
        )
        self.assertEqual(parse_outcome(text).status, OK)

    def test_last_summary_wins_when_a_green_run_precedes_a_failing_one(self):
        text = (
            "Ran 3 tests in 0.100s\n\nOK\n"
            "\n$ rerun after a regression\n"
            "Ran 3 tests in 0.100s\n\nFAILED (errors=1)\n"
        )
        self.assertEqual(parse_outcome(text).status, FAILED)

    def test_truncated_ran_line_is_unmeasured(self):
        self.assertEqual(
            parse_outcome("Ran 41 tests in 2.100s\n").status, UNMEASURED
        )


class pytestSummaryTests(unittest.TestCase):
    def test_failed(self):
        out = parse_outcome("===== 3 failed, 40 passed in 1.21s =====\n")
        self.assertEqual(out.status, FAILED)
        self.assertEqual(out.failures, 3)
        self.assertEqual(out.passed, 40)

    def test_ok(self):
        out = parse_outcome("===== 40 passed in 1.21s =====\n")
        self.assertEqual(out.status, OK)
        self.assertEqual(out.passed, 40)


class VitestSummaryTests(unittest.TestCase):
    def test_failed(self):
        out = parse_outcome(" Tests  3 failed | 40 passed (43)\n")
        self.assertEqual(out.status, FAILED)
        self.assertEqual(out.failures, 3)

    def test_ok(self):
        out = parse_outcome(" Tests  40 passed (40)\n")
        self.assertEqual(out.status, OK)


class UnmeasuredTests(unittest.TestCase):
    def test_missing_summary_is_unmeasured(self):
        out = parse_outcome("FAILED (failures=1)\n")
        # A bare FAILED is still a measured failure; a text with neither a
        # "Ran N tests" line nor any verdict line is the unmeasured case.
        self.assertEqual(out.status, FAILED)

    def test_no_runner_output_at_all(self):
        self.assertEqual(
            parse_outcome("Command executed successfully.\n").status, UNMEASURED
        )

    def test_gate_verdict_turns_unmeasured_into_fail(self):
        self.assertEqual(verdict(parse_outcome("no output")), FAILED)

    def test_empty_text(self):
        self.assertEqual(parse_outcome("").status, UNMEASURED)


class ExitCodeIndependenceTests(unittest.TestCase):
    def test_parser_has_no_exit_code_parameter(self):
        # The API must not accept an exit code: a caller cannot accidentally
        # make the exit code the verdict.
        with self.assertRaises(TypeError):
            parse_outcome("Ran 1 tests in 0.1s\n\nOK\n", 0)  # type: ignore[call-arg]


if __name__ == "__main__":
    unittest.main(verbosity=2)
