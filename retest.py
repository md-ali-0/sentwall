#!/usr/bin/env python3
"""VulnScope Retest - Automated remediation verification & delta comparison suite.

Usage:
    python retest.py before.json after.json          # Offline comparison of two scans
    python retest.py reports/target/time/report.json # Automated live re-test against target!
    python retest.py --before old.json --after new.json --out reports
    python retest.py old.json new.json --fail-on high  # CI gate (exit 1 if high/crit remain)

Exit codes: 0 ok, 1 severity gate failed, 2 bad input.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional

from vulnscope import __version__, ui
from vulnscope.checks import run_all
from vulnscope.context import Options, ScanContext
from vulnscope.crawl import crawl
from vulnscope.diff import SEVERITIES, compare_files, compare_scans, write_reports as write_diff_reports
from vulnscope.models import ScanResult, Severity
from vulnscope.net import Http, normalise_target
from vulnscope.report import write_reports as write_scan_reports

SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _fmt_delta(value: int) -> str:
    colour = ui.c_green if value < 0 else (ui.c_red if value > 0 else ui.c_white)
    return ui.bold(colour(f"{value:+d}"))


def _rows(diff: Any) -> List[str]:
    cb, ca = diff.counts("baseline"), diff.counts("current")
    out = []
    for sev in SEV_ORDER:
        if not cb[sev] and not ca[sev]:
            continue
        d = ca[sev] - cb[sev]
        colour = ui.c_green if d < 0 else (ui.c_red if d > 0 else ui.c_slate)
        out.append(
            f"{ui.c_white(sev.capitalize().ljust(10))}"
            f"{ui.c_white(str(cb[sev]).rjust(4))}  →  {ui.c_white(str(ca[sev]).rjust(4))}"
            f"   {colour(('%+d' % d).rjust(5))}"
        )
    return out


def _finding_lines(findings: List[Dict[str, Any]], limit: int = 6) -> List[str]:
    if not findings:
        return [ui.c_slate("  none")]
    lines = []
    for f in findings[:limit]:
        sev = str(f.get("severity", "info")).lower()
        colour = {
            "critical": ui.c_red,
            "high": ui.c_orange,
            "medium": ui.c_yellow,
            "low": ui.c_blue,
        }.get(sev, ui.c_slate)
        chip = {
            "critical": "[CRIT]",
            "high": "[HIGH]",
            "medium": "[MED ]",
            "low": "[LOW ]",
        }.get(sev, "[INFO]")
        title_str = str(f.get("title", ""))[:56]
        lines.append(f"{colour(chip)} {ui.bold(ui.c_white(title_str))}")
        lines.append(f"       {ui.c_dark(str(f.get('key', '')))} {ui.c_slate('(' + str(f.get('category', '')) + ')')}")
    if len(findings) > limit:
        lines.append(ui.c_slate(f"  … and {len(findings) - limit} additional findings documented in report."))
    return lines


def run_live_retest_scan(baseline_file: str, out_dir: str = "reports") -> str:
    """Read target from baseline report, run a fresh live assessment, and return new report.json path."""
    with open(baseline_file, "r", encoding="utf-8") as fh:
        base_data = json.load(fh)

    target = base_data.get("target") or base_data.get("host")
    if not target:
        raise ValueError("Could not find 'target' or 'host' in baseline JSON report.")

    profile = base_data.get("profile", "standard")
    auditor = base_data.get("auditor", "VulnScope Retest")
    client = base_data.get("client", "")

    base_url, host = normalise_target(target)
    print(f"\n  {ui.c_emerald('⚡')} {ui.bold(ui.c_white('Auto-initiating live re-scan against target:'))} {ui.c_cyan(base_url)}")
    print(f"  {ui.c_slate('Baseline Reference:')} Score {base_data.get('risk_score', 'N/A')}/100 (Grade {base_data.get('grade', 'N/A')})\n")

    is_deep = profile == "deep"
    options = Options(
        deep=is_deep,
        test_forms=profile in ("deep", "standard"),
        subdomains=is_deep,
        max_pages=15 if profile == "fast" else 25,
        depth=2,
        delay=0.0,
        timeout=12.0,
        threads=8,
        profile=profile,
    )
    http = Http(timeout=12.0, verify=False)
    result = ScanResult(
        target=base_url,
        host=host,
        started=time.time(),
        auditor=auditor,
        client=client,
        profile=profile,
        baseline_id=base_data.get("scan_id", ""),
    )

    ctx = ScanContext(base_url, base_url, host, http, options)
    print(f"  {ui.bold(ui.c_cyan('[1/2]'))} {ui.bold(ui.c_white('Crawling live attack surface...'))}")
    ctx.pages = crawl(http, base_url, max_pages=options.max_pages, depth=options.depth)
    result.pages_scanned = [p.url for p in ctx.pages]
    print(f"      {ui.c_emerald('✔')} Discovered {len(ctx.pages)} page(s)\n")

    print(f"  {ui.bold(ui.c_cyan('[2/2]'))} {ui.bold(ui.c_white('Executing 15 security check modules...'))}")
    result.findings = run_all(
        ctx,
        on_module_done=lambda i, tot, lbl, res, took: print(ui.format_module_result(i, tot, lbl, res, took)),
    )
    result.finished = time.time()
    result.requests_made = http.count
    http.close()

    written = write_scan_reports(result, out_dir, formats=["json", "html"])
    new_json = next((p for p in written if p.endswith(".json")), "")
    print(f"\n  {ui.c_green('✔ Live re-scan completed.')} Generated: {ui.c_slate(new_json)}\n")
    return new_json


def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="retest",
        description="VulnScope Retest - Automated remediation verification & delta comparison suite.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python retest.py before.json after.json          # Offline comparison of two scans
  python retest.py reports/target/time/report.json # Automated live re-test against target!
  python retest.py --before old.json --after new.json --out reports
  python retest.py old.json new.json --fail-on high  # CI gate (exit 1 if high/crit remain)
""",
    )
    p.add_argument("paths", nargs="*", metavar="FILE",
                   help="one baseline JSON (for live retest) or two JSONs (baseline & current)")
    p.add_argument("--before", "-b", help="baseline scan JSON")
    p.add_argument("--after", "-a", help="retest scan JSON")
    p.add_argument("--live", "-l", action="store_true",
                   help="force live re-test against target from baseline JSON")
    p.add_argument("--out", default="reports", help="output directory (default: reports)")
    p.add_argument("--formats", default="html,md,json", help="comma separated: html,md,json")
    p.add_argument("--fail-on", default="none",
                   choices=["none", "critical", "high", "medium", "low"],
                   help="exit 1 if a finding at or above this severity is still open")
    p.add_argument("--quiet", action="store_true", help="only print the output paths")
    p.add_argument("--version", action="version", version=f"VulnScope Retest {__version__}")
    return p.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)

    if not args.quiet:
        print(ui.render_banner(__version__))
        print(f"  {ui.c_emerald('⚡')} {ui.bold(ui.c_white('REMEDIATION VERIFICATION & DELTA RETEST ENGINE'))}\n")

    # Determine before and after paths
    before = args.before or (args.paths[0] if len(args.paths) > 0 else None)
    after = args.after or (args.paths[1] if len(args.paths) > 1 else None)

    if not before:
        print(ui.c_red("  ! Error: Please specify at least one baseline scan JSON file."))
        print("    Usage (Offline): python retest.py baseline.json current.json")
        print("    Usage (Live)   : python retest.py reports/target/time/report.json\n")
        return 2

    if not os.path.exists(before):
        print(ui.c_red(f"  ! Error: Baseline file not found: {before}"))
        return 2

    # Mode A: Automated Live Re-test if only 1 baseline is given or --live flag set
    if not after or args.live:
        try:
            after = run_live_retest_scan(before, out_dir=args.out)
        except Exception as exc:
            print(ui.c_red(f"  ! Error during live re-test scan: {exc}"))
            return 2

    if not os.path.exists(after):
        print(ui.c_red(f"  ! Error: Retest file not found: {after}"))
        return 2

    try:
        diff = compare_files(before, after)
    except (ValueError, KeyError) as exc:
        print(ui.c_red(f"  ! Error reading scan data: {exc}"))
        return 2

    if not args.quiet:
        print(ui.render_delta_card(diff))
        print()
        print(ui.draw_card(
            "SEVERITY MOVEMENT (BASELINE → RETEST)",
            _rows(diff),
            border_color="cyan",
            min_width=64,
        ))
        print()

        if diff.resolved:
            print(ui.draw_card(
                f"✔ RESOLVED VULNERABILITIES ({len(diff.resolved)} FIXED)",
                _finding_lines(diff.resolved, limit=8),
                border_color="green",
                min_width=72,
            ))
            print()

        if diff.regressed:
            print(ui.draw_card(
                f"✖ SEVERITY REGRESSIONS ({len(diff.regressed)} GOT WORSE)",
                _finding_lines(diff.regressed, limit=6),
                border_color="red",
                min_width=72,
            ))
            print()

        if diff.new_findings:
            print(ui.draw_card(
                f"✖ NEWLY INTRODUCED FINDINGS ({len(diff.new_findings)} NEW)",
                _finding_lines(diff.new_findings, limit=6),
                border_color="red",
                min_width=72,
            ))
            print()

        if diff.still_open():
            print(ui.draw_card(
                f"⚠ STILL OPEN WEAKNESSES ({len(diff.still_open())} PENDING)",
                _finding_lines(diff.still_open(), limit=6),
                border_color="yellow",
                min_width=72,
            ))
            print()

    formats = tuple(x.strip() for x in args.formats.split(",") if x.strip())
    written = write_diff_reports(diff, args.out, formats)

    if not args.quiet:
        print(f"  {ui.bold(ui.c_white('Generated Remediation Verification Reports:'))}")
        for path in written:
            print(f"   {ui.c_dark('•')} {ui.c_emerald(path)}")

        html_retest = next((p for p in written if p.endswith(".html")), "")
        if html_retest:
            abs_html = os.path.abspath(html_retest).replace(os.sep, "/")
            print(f"\n  {ui.c_slate('Open retest report in browser:')}")
            print(f"  {ui.c_cyan('file:///' + abs_html)}\n")
        else:
            print()

    # CI Gate evaluation
    if args.fail_on != "none":
        remaining = diff.remaining_at_or_above(args.fail_on)
        if remaining:
            print(ui.c_red(f"  ✖ CI Security Gate FAILED: {remaining} finding(s) at or above "
                           f"'{args.fail_on.upper()}' are still open in retest."))
            return 1
        print(ui.c_green(f"  ✔ CI Security Gate PASSED: Zero findings at or above '{args.fail_on.upper()}' remain."))

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
