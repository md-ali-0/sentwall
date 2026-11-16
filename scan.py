#!/usr/bin/env python3
"""VulnScope Enterprise CLI - automated web security assessment and client report generator.

Usage:
    python scan.py https://example.com --authorized
    python scan.py example.com --deep --subdomains --pitch --client "Acme Ltd"
    python scan.py --diff reports/target/time1/report.json reports/target/time2/report.json
    python scan.py --generate-ci github

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
from vulnscope.ci import generate_github_workflow, generate_gitlab_ci
from vulnscope.context import Options, ScanContext
from vulnscope.crawl import crawl
from vulnscope.diff import compare_files, write_reports as write_diff_reports
from vulnscope.models import ScanResult, Severity
from vulnscope.net import Http, normalise_target
from vulnscope.report import write_reports
from vulnscope.ui import (
    bold,
    c_cyan,
    c_dark,
    c_emerald,
    c_green,
    c_orange,
    c_red,
    c_slate,
    c_white,
    c_yellow,
    format_module_result,
    render_artifacts_tree,
    render_banner,
    render_delta_card,
    render_findings_table,
    render_legal_prompt,
    render_summary_dashboard,
    render_target_card,
    render_top_poc_spotlight,
)

# ---------------------------------------------------------------------------
BANNER = r"""
 __     __      _       ____
 \ \   / /_   _| |_ __ / ___|  ___ ___  _ __   ___
  \ \ / /| | | | | '_ \\___ \ / __/ _ \| '_ \ / _ \
   \ V / | |_| | | | | |___) | (_| (_) | |_) |  __/
    \_/   \__,_|_|_| |_|____/ \___\___/| .__/ \___|
                                       |_|
 automated web security assessment v{ver}
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
    say(render_legal_prompt(target))
    say("")
    try:
        prompt_text = f"  {c_emerald('➤')} {bold(c_white('Do you hold valid written authorization to assess this target? [y/N]:'))} "
        answer = input(prompt_text).strip().lower()
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
        description="VulnScope Enterprise - Automated web security assessment with client-ready reporting.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python scan.py https://example.com --authorized
  python scan.py example.com --authorized --deep --subdomains
  python scan.py --diff reports/target/time1/report.json reports/target/time2/report.json
  python scan.py https://shop.example.com --authorized --pitch \\
      --client "Acme Ltd" --auditor "Your Name" --out reports
""",
    )
    p.add_argument("target", nargs="?", default="", help="URL or domain to assess, e.g. https://example.com")
    p.add_argument("-y", "--authorized", action="store_true",
                   help="confirm you have written authorisation (skips the prompt)")
    p.add_argument("--diff", nargs=2, metavar=("BASELINE", "CURRENT"),
                   help="compare two scan JSON results to compute the remediation delta")
    p.add_argument("--generate-ci", choices=["github", "gitlab"],
                   help="generate CI/CD security gate configuration")

    p.add_argument("-o", "--out", default="reports", help="output directory (default: reports)")
    p.add_argument("--formats", default="html,json,md,sarif,csv",
                   help="comma separated: html,json,md,sarif,csv,proposal")
    p.add_argument("--pdf", action="store_true",
                   help="also export a PDF via headless Chrome/Edge (if installed)")
    p.add_argument("--pitch", action="store_true",
                   help="include the 'recommended engagement' and financial ROI section")
    p.add_argument("--client", default="", help="client name shown on the cover")
    p.add_argument("--auditor", default="", help="your name / company shown on the cover")
    p.add_argument("--profile", default="standard", choices=["fast", "standard", "deep", "api"],
                   help="scan profile: fast, standard, deep, api")

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

    say(render_banner(__version__))

    # Mode 1: CI/CD Workflow Generation
    if args.generate_ci:
        if args.generate_ci == "github":
            content = generate_github_workflow()
            out_file = ".github/workflows/vulnscope.yml"
            os.makedirs(".github/workflows", exist_ok=True)
            with open(out_file, "w", encoding="utf-8") as fh:
                fh.write(content)
            say(c_green(f"  ✔ Generated GitHub Actions security workflow in: {out_file}\n"))
        elif args.generate_ci == "gitlab":
            content = generate_gitlab_ci()
            out_file = ".gitlab-ci.yml"
            with open(out_file, "w", encoding="utf-8") as fh:
                fh.write(content)
            say(c_green(f"  ✔ Generated GitLab CI security configuration in: {out_file}\n"))
        return 0

    # Mode 2: Delta Comparison
    if args.diff:
        b_file, c_file = args.diff
        if not os.path.exists(b_file) or not os.path.exists(c_file):
            say(c_red("  ! Error: Both baseline and current scan JSON files must exist."))
            return 2
        diff = compare_files(b_file, c_file)
        say(render_delta_card(diff))
        say("")
        diff_formats = tuple(f for f in ("html", "md", "json")
                             if f in [x.strip() for x in args.formats.split(",")])
        if diff_formats:
            written = write_diff_reports(diff, args.out, diff_formats)
            for path in written:
                say(f"  {c_slate('report')}  {c_emerald(path)}")
            say("")
        return 0

    # Mode 3: Target Assessment
    if not args.target:
        say(c_red("  ! Error: Please specify a target URL to assess."))
        say("    Usage: python scan.py https://target.com --authorized\n")
        return 2

    base_url, host = normalise_target(args.target)
    if not host:
        say(c_red("  ! Error: Could not parse a valid hostname from target coordinate.\n"))
        return 2

    if not args.authorized:
        if not confirm_authorization(base_url):
            say(c_red("  Aborted: Legal authorisation not confirmed.\n"))
            return 1

    headers = {}
    for raw in args.header:
        if ":" in raw:
            k, v = raw.split(":", 1)
            headers[k.strip()] = v.strip()
    if args.cookie:
        headers["Cookie"] = args.cookie

    is_deep = args.deep or (args.profile == "deep")
    options = Options(
        deep=is_deep,
        test_forms=args.test_forms or (args.profile in ("deep", "standard")),
        subdomains=args.subdomains or (args.profile == "deep"),
        max_pages=15 if args.profile == "fast" else args.max_pages,
        depth=args.depth,
        delay=args.delay,
        timeout=args.timeout,
        threads=args.threads,
        profile=args.profile,
    )
    http = Http(
        timeout=args.timeout,
        delay=args.delay,
        verify=False,
        headers=headers or None,
        proxy=args.proxy or None,
    )

    result = ScanResult(target=base_url, host=host, started=time.time(),
                        auditor=args.auditor, client=args.client, profile=args.profile)

    def log(msg: str) -> None:
        if not args.quiet:
            say(msg)

    ctx = ScanContext(base_url, base_url, host, http, options, logger=log)

    try:
        ips = ctx.ips()
        if not ips:
            say(c_red("  ! Error: Target host does not resolve. Is the domain spelled correctly?\n"))
            return 2

        if not args.quiet:
            say(render_target_card(base_url, ips, args.profile, is_deep, options.subdomains, options.test_forms, options.threads))
            say("")

        log(f"  {bold(c_cyan('[1/3]'))} {bold(c_white('Attack Surface Discovery & Crawling Engine'))}")
        ctx.pages = crawl(http, base_url, max_pages=options.max_pages, depth=options.depth, log=lambda m: log("      " + c_dark("• ") + c_slate(m)))
        if not ctx.pages:
            log(c_red("  ! Error: No pages could be retrieved from target.\n"))
            return 2
        result.pages_scanned = [p.url for p in ctx.pages]
        log(f"      {c_emerald('✔')} Discovered {bold(c_white(str(len(ctx.pages))))} accessible endpoint(s)\n")

        log(f"  {bold(c_cyan('[2/3]'))} {bold(c_white('Executing 15 Automated Security Vector Audits'))}")
        result.findings = run_all(
            ctx,
            progress=lambda m: log("  " + m),
            on_module_done=lambda i, tot, lbl, res, took: log(format_module_result(i, tot, lbl, res, took)),
        )
        result.metadata = ctx.meta
    except KeyboardInterrupt:
        say(c_yellow("\n  Interrupted by operator — generating partial assessment report..."))
    finally:
        result.finished = time.time()
        result.requests_made = http.count
        http.close()

    if not result.findings:
        result.finished = result.finished or time.time()

    # ---------------------------------------------------------------- summary & dashboard
    say("")
    say(f"  {bold(c_cyan('[3/3]'))} {bold(c_white('Audit Complete — Generating Executive Posture Intelligence'))}\n")
    say(render_summary_dashboard(result))
    say("")
    say(render_findings_table(result.sorted_findings()))

    # Spotlight #1 critical/high finding with instant PoC
    top_crit = next((f for f in result.sorted_findings() if f.severity in (Severity.CRITICAL, Severity.HIGH)), None)
    if top_crit:
        spot = render_top_poc_spotlight(top_crit, base_url)
        if spot:
            say("")
            say(spot)

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
                say(c_yellow("  ! Note: Headless Chrome/Edge not detected for automated PDF export."))
    say("")
    say(render_artifacts_tree(paths))
    say("")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
