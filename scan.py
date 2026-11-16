#!/usr/bin/env python3
"""VulnScope CLI - automated web security assessment.

Usage:
    python scan.py https://example.com --authorized
    python scan.py example.com --deep --subdomains --pitch --client "Acme Ltd"

Only scan systems you own or have written permission to test.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from typing import List

from vulnscope import __version__
from vulnscope.checks import run_all
from vulnscope.context import Options, ScanContext
from vulnscope.crawl import crawl
from vulnscope.models import ScanResult, Severity
from vulnscope.net import Http, normalise_target
from vulnscope.report import write_reports

# ---------------------------------------------------------------------------
BANNER = r"""
 __     __      _       ____
 \ \   / /_   _| |_ __ / ___|  ___ ___  _ __   ___
  \ \ / /| | | | | '_ \\___ \ / __/ _ \| '_ \ / _ \
   \ V / | |_| | | | | |___) | (_| (_) | |_) |  __/
    \_/   \__,_|_|_| |_|____/ \___\___/| .__/ \___|
                                       |_|
 automated web security assessment          v{ver}
"""

USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


SEV_STYLE = {
    Severity.CRITICAL: "1;97;41",
    Severity.HIGH: "1;31",
    Severity.MEDIUM: "1;33",
    Severity.LOW: "1;36",
    Severity.INFO: "0;37",
}


def say(msg: str = "") -> None:
    print(msg, flush=True)


def confirm_authorization(target: str) -> bool:
    say("")
    say(c("  Legal notice", "1;33"))
    say(f"  You are about to run active security tests against: {c(target, '1;37')}")
    say("  Unauthorised scanning is illegal in most jurisdictions (Computer Misuse Act,")
    say("  CFAA, ICT Act 2006 s.57 in Bangladesh, and equivalents elsewhere).")
    say("  Only continue if you own the system or hold written permission to test it.")
    say("")
    try:
        answer = input("  Type 'yes' to confirm you have authorisation: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer in ("yes", "y")


CHROME_CANDIDATES = [
    "google-chrome", "chromium", "chromium-browser", "chrome",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
]


def export_pdf(html_path: str, pdf_path: str) -> bool:
    """Render the HTML report to PDF with a locally installed Chromium browser."""
    import shutil
    import subprocess

    binary = ""
    for cand in CHROME_CANDIDATES:
        found = shutil.which(cand) or (cand if os.path.exists(cand) else "")
        if found:
            binary = found
            break
    if not binary:
        return False
    url = "file:///" + os.path.abspath(html_path).replace("\\", "/")
    try:
        subprocess.run(
            [binary, "--headless", "--disable-gpu", "--no-pdf-header-footer",
             "--virtual-time-budget=3000", f"--print-to-pdf={os.path.abspath(pdf_path)}", url],
            check=False, timeout=180,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except Exception:
        return False
    return os.path.exists(pdf_path)


def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="scan.py",
        description="VulnScope - automated web security assessment with client-ready reporting.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python scan.py https://example.com --authorized
  python scan.py example.com --authorized --deep --subdomains
  python scan.py https://shop.example.com --authorized --pitch \\
      --client "Acme Ltd" --auditor "Your Name" --out reports
""",
    )
    p.add_argument("target", help="URL or domain to assess, e.g. https://example.com")
    p.add_argument("-y", "--authorized", action="store_true",
                   help="confirm you have written authorisation (skips the prompt)")
    p.add_argument("-o", "--out", default="reports", help="output directory (default: reports)")
    p.add_argument("--formats", default="html,json,md", help="comma separated: html,json,md")
    p.add_argument("--pdf", action="store_true",
                   help="also export a PDF via headless Chrome/Edge (if installed)")
    p.add_argument("--pitch", action="store_true",
                   help="include the 'recommended engagement' section in the report")
    p.add_argument("--client", default="", help="client name shown on the cover")
    p.add_argument("--auditor", default="", help="your name / company shown on the cover")

    p.add_argument("--deep", action="store_true",
                   help="enable slower blind checks (time-based SQLi)")
    p.add_argument("--test-forms", action="store_true",
                   help="submit safe canaries through non-destructive forms")
    p.add_argument("--subdomains", action="store_true",
                   help="enumerate subdomains via certificate transparency and check takeover")
    p.add_argument("--max-pages", type=int, default=25, help="max pages to crawl (default 25)")
    p.add_argument("--depth", type=int, default=2, help="crawl depth (default 2)")
    p.add_argument("--delay", type=float, default=0.0, help="seconds between requests")
    p.add_argument("--threads", type=int, default=8, help="concurrent workers (default 8)")
    p.add_argument("--timeout", type=float, default=12.0, help="per-request timeout in seconds")
    p.add_argument("--header", action="append", default=[],
                   help="extra header, e.g. --header 'Authorization: Bearer x'")
    p.add_argument("--cookie", default="", help="raw Cookie header value")
    p.add_argument("--proxy", default="", help="proxy URL, e.g. http://127.0.0.1:8080")
    p.add_argument("--quiet", action="store_true", help="only print the final summary")
    p.add_argument("--version", action="version", version=f"VulnScope {__version__}")
    return p.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)

    if USE_COLOR:
        say(c(BANNER.format(ver=__version__), "36"))
    else:
        say(BANNER.format(ver=__version__))

    base_url, host = normalise_target(args.target)
    if not host:
        say(c("  ! could not parse a hostname from the target", "1;31"))
        return 2

    if not args.authorized:
        if not confirm_authorization(base_url):
            say(c("  Aborted: authorisation not confirmed.", "1;31"))
            return 1

    headers = {}
    for raw in args.header:
        if ":" in raw:
            k, v = raw.split(":", 1)
            headers[k.strip()] = v.strip()
    if args.cookie:
        headers["Cookie"] = args.cookie

    options = Options(
        deep=args.deep,
        test_forms=args.test_forms,
        subdomains=args.subdomains,
        max_pages=args.max_pages,
        depth=args.depth,
        delay=args.delay,
        timeout=args.timeout,
        threads=args.threads,
    )
    http = Http(
        timeout=args.timeout,
        delay=args.delay,
        verify=False,
        headers=headers or None,
        proxy=args.proxy or None,
    )

    result = ScanResult(target=base_url, host=host, started=time.time(),
                        auditor=args.auditor, client=args.client)

    def log(msg: str) -> None:
        if not args.quiet:
            say(msg)

    ctx = ScanContext(base_url, base_url, host, http, options, logger=log)

    try:
        log(c(f"\n  Target   {base_url}", "1;37"))
        log(c(f"  Mode     {'deep' if args.deep else 'standard'}"
              f"{' + subdomains' if args.subdomains else ''}"
              f"{' + form testing' if args.test_forms else ''}\n", "0;37"))

        log(c("[1] Resolving and crawling", "1;36"))
        ips = ctx.ips()
        log(f"  IP: {', '.join(ips) if ips else 'unresolved'}")
        if not ips:
            log(c("  ! host does not resolve - is the domain spelled correctly?", "1;31"))
            return 2

        ctx.pages = crawl(http, base_url, max_pages=options.max_pages, depth=options.depth, log=log)
        if not ctx.pages:
            log(c("  ! no pages could be retrieved", "1;31"))
            return 2
        result.pages_scanned = [p.url for p in ctx.pages]
        log(f"  crawled {len(ctx.pages)} page(s)\n")

        log(c("[2] Running security checks", "1;36"))
        result.findings = run_all(ctx, progress=lambda m: log("  " + m))
        result.metadata = ctx.meta
    except KeyboardInterrupt:
        say(c("\n  Interrupted - writing partial report...", "1;33"))
    finally:
        result.finished = time.time()
        result.requests_made = http.count
        http.close()

    if not result.findings:
        result.finished = result.finished or time.time()

    # ---------------------------------------------------------------- summary
    counts = result.counts()
    say("")
    say(c("  ── Summary " + "─" * 46, "0;37"))
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        n = counts[sev.value]
        label = c(f"{sev.label:9}", SEV_STYLE[sev])
        say(f"  {label} {n}")
    say("")
    score = result.risk_score()
    say(f"  Risk score : {c(str(score) + '/100', '1;37')}   Grade: {c(result.grade(), '1;37')}")
    say(f"  Verdict    : {result.grade_verdict()}")
    say(f"  Requests   : {result.requests_made}   Duration: {result.duration:.1f}s")

    top = [f for f in result.sorted_findings() if f.severity.rank >= 4][:5]
    if top:
        say("")
        say(c("  Top issues", "1;37"))
        for f in top:
            say(f"   {c(f.severity.value.upper(), SEV_STYLE[f.severity]):<10} {f.title}")

    # ---------------------------------------------------------------- reports
    formats = [x.strip() for x in args.formats.split(",") if x.strip()]
    paths = write_reports(result, args.out, formats, include_proposal=args.pitch)
    if args.pdf:
        html = next((p for p in paths if p.endswith(".html")), "")
        if html:
            pdf = html[:-5] + ".pdf"
            if export_pdf(html, pdf):
                paths.append(pdf)
            else:
                say(c("  ! no Chrome/Edge found for PDF export - use Print → Save as PDF", "1;33"))
    say("")
    say(c("  Reports", "1;37"))
    for p in paths:
        say(f"   {p}")
    say("")
    say(c("  Open the HTML file in a browser and use Print → Save as PDF to hand it to the client.",
          "0;37"))
    say("")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
