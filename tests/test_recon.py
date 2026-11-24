import unittest

from sentwall.recon import (
    HostInfo,
    ReconResult,
    _valid_name,
    render_html,
    render_markdown,
    to_csv,
    to_dict,
)


def _sample() -> ReconResult:
    result = ReconResult(domain="example.com", started=1700000000.0, elapsed=3.2)
    result.sources = {"certificate transparency": 4, "dns brute force": 1}
    result.discovered = ["api.example.com", "example.com", "www.example.com", "dead.example.com"]
    result.hosts = [
        HostInfo(host="example.com", ips=["1.2.3.4"], scheme="https", status=200,
                 server="nginx", title="Example", tech=["Nginx"], tls_trusted=True,
                 tls_days=90, findings=3, critical=1, high=1, score=40, grade="D"),
        HostInfo(host="api.example.com", ips=["1.2.3.5"], scheme="https", status=401,
                 server="cloudflare", title="", tls_trusted=False, tls_days=12,
                 findings=0, score=0, grade="A"),
        HostInfo(host="dead.example.com", error="name does not resolve"),
    ]
    return result


class TestValidName(unittest.TestCase):
    def test_accepts_hostnames(self):
        for name in ("www.example.com", "api-v2.example.co.uk", "a.b.c.example.com"):
            self.assertTrue(_valid_name(name), name)

    def test_rejects_crt_sh_junk(self):
        for name in ("user@example.com", "subjectname@example.com", "*.example.com",
                     "example.com ", "", "-bad.example.com", "bad-.example.com",
                     "no-dot", "exa mple.com"):
            self.assertFalse(_valid_name(name), name)


class TestReconOutput(unittest.TestCase):
    def test_live_and_risky(self):
        result = _sample()
        self.assertEqual(len(result.live_hosts), 2)
        self.assertEqual(len(result.risky), 1)

    def test_expiring(self):
        result = _sample()
        self.assertEqual([h.host for h in result.expiring], ["api.example.com"])

    def test_markdown_lists_live_hosts_only(self):
        md = render_markdown(_sample())
        self.assertIn("api.example.com", md)
        self.assertIn("Not responding (1)", md)

    def test_html_escapes_and_renders(self):
        result = _sample()
        result.hosts[0].title = '"><script>alert(1)</script>'
        out = render_html(result)
        self.assertNotIn("<script>alert(1)</script>", out)
        self.assertIn("&lt;script&gt;", out)
        self.assertIn("example.com", out)

    def test_csv_has_a_row_per_host(self):
        lines = to_csv(_sample()).strip().splitlines()
        self.assertEqual(len(lines), 4)  # header + 3 hosts
        self.assertTrue(lines[0].startswith("host,ip,scheme"))

    def test_dict_roundtrip(self):
        data = to_dict(_sample())
        self.assertEqual(data["domain"], "example.com")
        self.assertEqual(len(data["hosts"]), 3)
        self.assertEqual(data["hosts"][0]["tls_days"], 90)


if __name__ == "__main__":
    unittest.main()
