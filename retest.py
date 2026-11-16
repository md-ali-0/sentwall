#!/usr/bin/env python3
"""Compare two VulnScope scans and write a remediation verification report.

    python retest.py reports/a/report.json reports/b/report.json
    python retest.py --before old.json --after new.json --out reports
    python retest.py old.json new.json --fail-on high     # CI gate

Exit codes: 0 ok, 1 severity gate failed, 2 bad input.
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import List

from vulnscope import ui
from vulnscope.diff import SEVERITIES, compare_files, write_reports

SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _fmt_delta(value: int) -> str:
    colour = ui.c_green if value < 0 else (ui.c_red if value > 0 else ui.c_white)
    return ui.bold(colour(f"{value:+d}"))


def _rows(diff) -> List[str]:
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


def _finding_lines(findings, limit: int = 6) -> List[str]:
    if not findings:
        return [ui.c_slate("  none")]
    lines = []
    for f in findings[:limit]:
        sev = str(f.get("severity", "info")).lower()
        colour = {"critical": ui.c_red, "high": ui.c_orange, "medium": ui.c_yellow,
                  "low": ui.c_blue}.get(sev, ui.c_slate)
        lines.append(f"{colour('•')} {ui.c_white(str(f.get('title', ''))[:64])}")
        lines.append(f"  {ui.c_dark(str(f.get('key', '')))}")
    if len(findings) > limit:
        lines.append(ui.c_slate(f"  … and {len(findings) - limit} more"))
    return lines


def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="retest",
        description="Compare a baseline scan with a retest and report what actually got fixed.",
    )
    p.add_argument("paths", nargs="*", metavar="BASELINE CURRENT",
                   help="two VulnScope JSON reports (or use --before/--after)")
    p.add_argument("--before", "-b", help="baseline scan JSON")
    p.add_argument("--after", "-a", help="retest scan JSON")
    p.add_argument("--out", default="reports", help="output directory (default: reports)")
    p.add_argument("--formats", default="html,md,json", help="comma separated: html,md,json")
    p.add_argument("--fail-on", default="none",
                   choices=["none", "critical", "high", "medium", "low"],
                   help="exit 1 if a finding at or above this severity is still open")
    p.add_argument("--quiet", action="store_true", help="only print the output paths")
    return p.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)

    before = args.before or (args.paths[0] if len(args.paths) > 0 else None)
    after = args.after or (args.paths[1] if len(args.paths) > 1 else None)
    if not before or not after:
        print(ui.c_red("  ! need two scan files: retest.py BASELINE CURRENT"))
        print("    e.g. python retest.py reports/a/report.json reports/b/report.json")
        return 2
    for path in (before, after):
        if not os.path.exists(path):
            print(ui.c_red(f"  ! file not found: {path}"))
            return 2

    try:
        diff = compare_files(before, after)
    except (ValueError, KeyError) as exc:
        print(ui.c_red(f"  ! could not read scan: {exc}"))
        return 2

    if not args.quiet:
        print()
        print(ui.render_delta_card(diff))
        print()
        print(ui.draw_card(
            "SEVERITY MOVEMENT   before → after",
            _rows(diff),
            border_color="cyan",
            min_width=54,
        ))
        print()

        if diff.regressed:
            print(ui.c_red(ui.bold("  ✖ REGRESSIONS")))
            for line in _finding_lines(diff.regressed):
                print("  " + line)
            print()

        if diff.new_findings:
            print(ui.c_red(ui.bold("  ✖ NEW FINDINGS")))
            for line in _finding_lines(diff.new_findings):
                print("  " + line)
            print()

        if diff.still_open():
            print(ui.c_yellow(ui.bold("  ⚠ STILL OPEN")))
            for line in _finding_lines(diff.still_open()):
                print("  " + line)
            print()

        if diff.resolved:
            print(ui.c_green(ui.bold("  ✔ RESOLVED")))
            for line in _finding_lines(diff.resolved, limit=8):
                print("  " + line)
            print()

    formats = tuple(x.strip() for x in args.formats.split(",") if x.strip())
    written = write_reports(diff, args.out, formats)
    for path in written:
        print(f"  {ui.c_slate('report')}  {ui.c_emerald(path)}")
    print()

    if args.fail_on != "none":
        remaining = diff.remaining_at_or_above(args.fail_on)
        if remaining:
            print(ui.c_red(f"  ✖ gate failed: {remaining} finding(s) at or above "
                           f"'{args.fail_on}' are still open"))
            return 1
        print(ui.c_green(f"  ✔ gate passed: nothing at or above '{args.fail_on}' is open"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
