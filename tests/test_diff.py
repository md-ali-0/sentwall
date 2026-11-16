import unittest
from vulnscope.diff import compare_scans


class TestDiff(unittest.TestCase):
    def test_compare_scans(self):
        baseline = {
            "scan_id": "VS-BASE",
            "target": "https://example.com",
            "risk_score": 85,
            "grade": "F",
            "findings": [
                {"key": "sqli", "title": "SQL Injection", "severity": "critical", "location": "/search"},
                {"key": "xss", "title": "Reflected XSS", "severity": "high", "location": "/q"},
                {"key": "csp", "title": "Missing CSP", "severity": "low", "location": "/"},
            ]
        }
        current = {
            "scan_id": "VS-RETEST",
            "target": "https://example.com",
            "risk_score": 12,
            "grade": "B",
            "findings": [
                {"key": "csp", "title": "Missing CSP", "severity": "low", "location": "/"},
                {"key": "hsts", "title": "Missing HSTS", "severity": "medium", "location": "/"},
            ]
        }

        diff = compare_scans(baseline, current)
        self.assertEqual(diff.score_change, -73)
        self.assertEqual(len(diff.resolved), 2)  # sqli and xss resolved!
        self.assertEqual(len(diff.persistent), 1)  # csp still open
        self.assertEqual(len(diff.new_findings), 1)  # hsts newly discovered

        md = diff.to_markdown()
        self.assertIn("Remediation Verification Report", md)
        self.assertIn("SQL Injection", md)


if __name__ == "__main__":
    unittest.main()
