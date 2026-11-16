"""Unit tests for retest.py script."""
import json
import os
import shutil
import tempfile
import unittest

from retest import _finding_lines, _fmt_delta, _rows, main, parse_args
from vulnscope.diff import compare_scans


class TestRetest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.base_data = {
            "scan_id": "VS-BASE-01",
            "target": "https://example.local",
            "host": "example.local",
            "risk_score": 80,
            "grade": "F",
            "started": 1700000000.0,
            "findings": [
                {"key": "sqli", "title": "SQL Injection", "severity": "critical", "category": "Injection"},
                {"key": "csp", "title": "Missing CSP", "severity": "low", "category": "Headers"},
            ],
        }
        self.after_data = {
            "scan_id": "VS-RETEST-01",
            "target": "https://example.local",
            "host": "example.local",
            "risk_score": 10,
            "grade": "A",
            "started": 1700003600.0,
            "findings": [
                {"key": "csp", "title": "Missing CSP", "severity": "low", "category": "Headers"},
            ],
        }
        self.base_file = os.path.join(self.temp_dir, "base.json")
        self.after_file = os.path.join(self.temp_dir, "after.json")
        with open(self.base_file, "w", encoding="utf-8") as f:
            json.dump(self.base_data, f)
        with open(self.after_file, "w", encoding="utf-8") as f:
            json.dump(self.after_data, f)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_fmt_delta(self):
        self.assertIn("-5", _fmt_delta(-5))
        self.assertIn("+3", _fmt_delta(3))
        self.assertIn("+0", _fmt_delta(0))

    def test_rows_and_finding_lines(self):
        diff = compare_scans(self.base_data, self.after_data)
        rows = _rows(diff)
        self.assertTrue(len(rows) > 0)
        lines = _finding_lines(diff.resolved)
        self.assertTrue(any("SQL Injection" in line for line in lines))

    def test_parse_args(self):
        args = parse_args(["file1.json", "file2.json", "--fail-on", "high"])
        self.assertEqual(args.paths, ["file1.json", "file2.json"])
        self.assertEqual(args.fail_on, "high")

    def test_retest_main_offline_success(self):
        out_dir = os.path.join(self.temp_dir, "out_reports")
        exit_code = main([self.base_file, self.after_file, "--out", out_dir, "--quiet"])
        self.assertEqual(exit_code, 0)
        # Check that reports were generated in nested directory
        found_html = False
        for root, _, files in os.walk(out_dir):
            if any(f.endswith(".html") for f in files):
                found_html = True
                break
        self.assertTrue(found_html)

    def test_retest_ci_gate_failure(self):
        out_dir = os.path.join(self.temp_dir, "out_reports")
        # Base has critical, after has critical still open
        base_with_crit = dict(self.base_data)
        after_with_crit = dict(self.base_data)
        f_b = os.path.join(self.temp_dir, "fb.json")
        f_a = os.path.join(self.temp_dir, "fa.json")
        with open(f_b, "w") as f: json.dump(base_with_crit, f)
        with open(f_a, "w") as f: json.dump(after_with_crit, f)

        # Gate fail-on critical should return exit code 1
        exit_code = main([f_b, f_a, "--fail-on", "critical", "--out", out_dir, "--quiet"])
        self.assertEqual(exit_code, 1)


if __name__ == "__main__":
    unittest.main()
