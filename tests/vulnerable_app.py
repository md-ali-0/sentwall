"""Deliberately vulnerable local app used to validate VulnScope's detections.

Never expose this to a network. Run:  python tests/vulnerable_app.py
"""
from __future__ import annotations

import html
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 8099


class Handler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.49"
    sys_version = "(Unix)"
    protocol_version = "HTTP/1.1"

    # ---------------------------------------------------------------- helpers
    def _send(self, body: str, status: int = 200, ctype: str = "text/html; charset=utf-8",
              extra: dict | None = None):
        raw = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Set-Cookie", "PHPSESSID=abc123def456; Path=/")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    def log_message(self, fmt, *args):
        pass

    # ---------------------------------------------------------------- routes
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        origin = self.headers.get("Origin")
        cors = {}
        if origin:
            cors["Access-Control-Allow-Origin"] = origin
            cors["Access-Control-Allow-Credentials"] = "true"

        if path == "/":
            q = qs.get("q", [""])[0]
            # reflected XSS: no encoding
            body = f"""<html><head><title>Vuln Test Shop</title>
<meta name="generator" content="WordPress 5.2">
</head><body>
<h1>Search</h1>
<p>Results for: {q}</p>
<form action="/search" method="get"><input name="q"><button>Go</button></form>
<form action="/login" method="post"><input name="user"><input type="password" name="pass"><button>Login</button></form>
<a href="https://example.com" target="_blank">partner</a>
<nav>
  <a href="/redirect?url=/home">Offers</a>
  <a href="/download?file=report.txt">Report</a>
  <a href="/render?name=guest">Greeting</a>
  <a href="/admin/">Admin</a>
  <a href="/uploads/">Uploads</a>
</nav>
<script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>
<!-- TODO: remove test admin:admin before launch -->
</body></html>"""
            self._send(body, extra=cors)
            return

        if path == "/search":
            q = qs.get("q", [""])[0]
            if "'" in q:
                self._send("<html><body>You have an error in your SQL syntax; check the manual "
                           "that corresponds to your MySQL server version near '" + q + "'</body></html>")
                return
            self._send(f"<html><body>You searched for {q}</body></html>")

        if path == "/redirect":
            target = qs.get("url", ["/"])[0]
            self.send_response(302)
            self.send_header("Location", target)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if path == "/download":
            f = qs.get("file", [""])[0]
            if "etc/passwd" in f:
                self._send("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
                           ctype="text/plain")
                return
            self._send("file not found", 404)

        if path == "/render":
            name = qs.get("name", [""])[0]
            import re as _re
            # naive template evaluation -> classic SSTI
            name = _re.sub(r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}",
                           lambda m: str(int(m.group(1)) * int(m.group(2))), name)
            self._send(f"<html><body>Hello {name}</body></html>")

        if path == "/.env":
            self._send("APP_NAME=TestShop\nAPP_KEY=base64:abcd1234SECRET\nDB_PASSWORD=hunter2\n",
                       ctype="text/plain")
            return

        if path == "/.git/config":
            self._send("[core]\n\trepositoryformatversion = 0\n\tbare = false\n", ctype="text/plain")
            return

        if path == "/backup.sql":
            self._send("-- MySQL dump\nCREATE TABLE users(id int);\nINSERT INTO users VALUES(1);\n",
                       ctype="text/plain")
            return

        if path == "/admin/":
            self._send("<html><head><title>Admin Login</title></head><body><h1>Admin</h1>"
                       "<form method=post><input name=u><input type=password name=p></form></body></html>")
            return

        if path == "/uploads/":
            self._send("<html><head><title>Index of /uploads</title></head><body>"
                       "<h1>Index of /uploads</h1><a href='invoice-2024.pdf'>invoice-2024.pdf</a>"
                       "</body></html>")
            return

        if path == "/robots.txt":
            self._send("User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /internal-api/\n",
                       ctype="text/plain")
            return

        if path == "/boom":
            self._send("<html><body><h1>Server Error</h1><pre>Traceback (most recent call last):\n"
                       '  File "/var/www/app/views.py", line 42, in index\n'
                       "    raise ValueError('boom')\nValueError: boom</pre></body></html>", 500)
            return

        # everything else -> 404 but with a *different* length so soft-404 logic is exercised
        self._send("<html><head><title>Not Found</title></head><body>Page not found</body></html>", 404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace")
        if self.path == "/login":
            self._send("<html><body>Invalid credentials</body></html>")
            return
        if self.path == "/search":
            q = urllib.parse.parse_qs(raw).get("q", [""])[0]
            self._send(f"<html><body>You searched for {q}</body></html>")
            return
        self._send("<html><body>ok</body></html>")

    def do_TRACE(self):
        self._send(f"TRACE {self.path} HTTP/1.1\r\nHost: {self.headers.get('Host')}\r\n",
                   ctype="message/http")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, OPTIONS, TRACE, PUT")
        self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin") or "*")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Content-Length", "0")
        self.end_headers()


if __name__ == "__main__":
    print(f"vulnerable test app on http://127.0.0.1:{PORT}")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
