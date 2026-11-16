import os
import shutil
import threading
import time
import unittest
from http.server import ThreadingHTTPServer

from tests.vulnerable_app import Handler
from vulnscope.context import Options, ScanContext
from vulnscope.crawl import crawl
from vulnscope.checks import run_all
from vulnscope.models import ScanResult
from vulnscope.net import Http
from vulnscope.report import write_reports

TEST_PORT = 8199
BASE_URL = f"http://127.0.0.1:{TEST_PORT}"


class TestIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", TEST_PORT), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_full_scan_pipeline(self):
        http = Http(timeout=5.0, verify=False)
        options = Options(max_pages=15, threads=4, deep=False)
        ctx = ScanContext(BASE_URL, BASE_URL, "127.0.0.1", http, options)

        # 1. Crawl
        ctx.pages = crawl(http, BASE_URL, max_pages=10, depth=2)
        self.assertGreater(len(ctx.pages), 0)

        # 2. Run checks
        findings = run_all(ctx)
        self.assertGreater(len(findings), 3)

        keys = [f.key for f in findings]
        # Vulnerable app intentionally exposes .git/config, .env, and vulnerable headers
        self.assertTrue(any("git" in k or "env" in k or "cors" in k or "header" in k for k in keys))

        # 3. Create ScanResult & exports
        res = ScanResult(target=BASE_URL, host="127.0.0.1", started=time.time())
        res.findings = findings
        res.pages_scanned = [p.url for p in ctx.pages]

        out_dir = "tests/test_reports"
        written = write_reports(res, out_dir, formats=["html", "json", "md", "sarif", "csv"], include_proposal=True)
        self.assertGreaterEqual(len(written), 5)

        for p in written:
            self.assertTrue(os.path.exists(p))
            self.assertGreater(os.path.getsize(p), 50)

        # Cleanup test files
        shutil.rmtree(out_dir, ignore_errors=True)
        http.close()


if __name__ == "__main__":
    unittest.main()
