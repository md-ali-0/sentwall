"""Unit tests for vulnscope.ui CLI styling engine."""
import unittest
import time

from vulnscope.models import Finding, ScanResult, Severity
from vulnscope.ui import (
    badge_severity,
    chip_severity,
    draw_card,
    format_module_result,
    render_artifacts_tree,
    render_banner,
    render_delta_card,
    render_findings_table,
    render_legal_prompt,
    render_progress_bar,
    render_summary_dashboard,
    render_target_card,
    render_top_poc_spotlight,
    strip_ansi,
    visual_len,
)


class TestUiEngine(unittest.TestCase):
    def test_strip_ansi_and_visual_len(self):
        colored = "\033[1;31mTesting Error\033[0m"
        self.assertEqual(strip_ansi(colored), "Testing Error")
        self.assertEqual(visual_len(colored), 13)

    def test_render_banner(self):
        banner = render_banner("1.0.0")
        self.assertIn("VULNSCOPE ENTERPRISE", banner)
        self.assertIn("v1.0.0", banner)

    def test_draw_card(self):
        card = draw_card("TEST TITLE", ["Line 1", "Line 2 is longer"], border_color="cyan")
        self.assertIn("TEST TITLE", card)
        self.assertIn("Line 1", card)
        self.assertTrue(card.startswith("╭─ "))
        self.assertTrue(card.endswith("╯"))

    def test_badges_and_chips(self):
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
            b = badge_severity(sev)
            c = chip_severity(sev)
            self.assertIn(sev.value.upper()[:4], strip_ansi(c))

    def test_render_target_card(self):
        card = render_target_card("https://test.local", ["127.0.0.1"], "deep", True, True, True, 8)
        self.assertIn("https://test.local", card)
        self.assertIn("127.0.0.1", card)
        self.assertIn("DEEP BLIND PROBES", card)

    def test_render_summary_dashboard(self):
        r = ScanResult("https://target.local", "target.local", time.time() - 5.0, time.time())
        r.requests_made = 42
        r.pages_scanned = ["https://target.local/"]
        card = render_summary_dashboard(r)
        self.assertIn("EXECUTIVE SECURITY POSTURE", card)
        self.assertIn("GRADE", card)
        self.assertIn("42 requests", card)

    def test_render_findings_table(self):
        f = Finding("test-key", "Test SQL Injection Found", Severity.CRITICAL, "Injection",
                    description="SQL injection in search", cvss=9.8, cwe="CWE-89")
        table = render_findings_table([f])
        self.assertIn("Test SQL Injection Found", table)
        self.assertIn("CWE-89", table)

    def test_render_top_poc_spotlight(self):
        f = Finding("dot-env", "Exposed .env configuration file", Severity.CRITICAL, "Sensitive Files",
                    description="Environment secrets exposed", cvss=9.8,
                    location="https://test.local/.env")
        spot = render_top_poc_spotlight(f, "https://test.local")
        self.assertIsNotNone(spot)
        self.assertIn("curl", spot)

    def test_render_artifacts_tree(self):
        paths = [
            "reports/target.local/2026-11-16_12-00-00/report.html",
            "reports/target.local/2026-11-16_12-00-00/report.json",
        ]
        tree = render_artifacts_tree(paths)
        self.assertIn("target.local", tree)
        self.assertIn("report.html", tree)


if __name__ == "__main__":
    unittest.main()
