import unittest
from sentwall.models import Finding, ScanResult, Severity, quick_wins


class TestModels(unittest.TestCase):
    def test_severity_ranks_and_weights(self):
        f_crit = Finding(key="k1", title="Crit", severity=Severity.CRITICAL, category="Cat", description="Desc")
        f_high = Finding(key="k2", title="High", severity=Severity.HIGH, category="Cat", description="Desc")
        self.assertGreater(f_crit.severity.rank, f_high.severity.rank)
        self.assertGreater(f_crit.weight, f_high.weight)

    def test_poc_generation(self):
        f = Finding(key="k1", title="Test", severity=Severity.HIGH, category="Cat", description="Desc", location="http://example.com/admin")
        curl = f.get_poc_curl()
        self.assertIn("curl", curl)
        self.assertIn("http://example.com/admin", curl)

        py = f.get_poc_python()
        self.assertIn("requests.get", py)

    def test_sarif_export(self):
        res = ScanResult(target="http://target.local", host="target.local", started=1000.0)
        res.add(Finding(key="sqli", title="SQL Injection", severity=Severity.CRITICAL, category="Injection", description="Desc", location="http://target.local/search"))
        sarif = res.to_sarif()
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(len(sarif["runs"][0]["tool"]["driver"]["rules"]), 1)
        self.assertEqual(len(sarif["runs"][0]["results"]), 1)

    def test_csv_export(self):
        res = ScanResult(target="http://target.local", host="target.local", started=1000.0)
        res.add(Finding(key="k1", title="Test Finding", severity=Severity.HIGH, category="Cat", description="Desc"))
        csv_out = res.to_csv()
        self.assertIn("Test Finding", csv_out)
        self.assertIn("HIGH", csv_out)

    def test_financial_risk_calculation(self):
        res = ScanResult(target="http://target.local", host="target.local", started=1000.0)
        res.add(Finding(key="c1", title="Crit 1", severity=Severity.CRITICAL, category="Cat", description="Desc"))
        res.add(Finding(key="c2", title="Crit 2", severity=Severity.CRITICAL, category="Cat", description="Desc"))
        fin = res.financial_risk()
        self.assertGreaterEqual(fin["breach_probability_pct"], 90)
        self.assertGreater(fin["estimated_financial_loss_usd"], 100000)

    def test_client_pitch_packages(self):
        res = ScanResult(target="http://target.local", host="target.local", started=1000.0)
        res.add(Finding(key="c1", title="Crit 1", severity=Severity.CRITICAL, category="Cat", description="Desc", effort="quick"))
        packages = res.client_pitch_packages(currency="USD", hourly_rate=150.0)
        self.assertEqual(len(packages["packages"]), 3)
        self.assertEqual(packages["currency_symbol"], "$")


if __name__ == "__main__":
    unittest.main()
