#!/usr/bin/env python3
"""Map a domain's external attack surface: discover, resolve, fingerprint, scan.

    python recon.py example.com --authorized
    python recon.py example.com --authorized --scan          # also scan each host
    python recon.py example.com --authorized --no-brute      # passive only

Requires --authorized. Discovery touches public data, but the fingerprint and
scan stages send real requests to hosts you may not own — that needs written
permission like any other assessment.
"""
from __future__ import annotations

import argparse
import sys
from typing import List

from sentwall import ui
from sentwall.recon import ReconResult, run, write_reports


def _log(msg: str, kind: str = "") -> None:
    mark = {"ok": ui.c_green("✔"), "warn": ui.c_yellow("!")}.get(kind, ui.c_slate("·"))
    print(f"  {mark} {msg}")


def _table(result: ReconResult) -> str:
    live = result.live_hosts
    if not live:
        return ui.c_slate("  no hosts responded")
    lines = [
        f"{ui.c_slate('HOST'.ljust(34))}{ui.c_slate('STATUS'.ljust(9))}"
        f"{ui.c_slate('TLS'.ljust(8))}{ui.c_slate('FINDINGS')}"
    ]
    for h in live[:40]:
        tls = "—" if h.tls_days is None else f"{h.tls_days}d"
        if h.tls_trusted is False:
            tls = ui.c_red("bad")
        elif h.tls_days is not None and h.tls_days < 30:
            tls = ui.c_yellow(tls)
        if h.critical:
            verdict = ui.c_red(f"{h.critical} critical")
        elif h.high:
            verdict = ui.c_orange(f"{h.high} high")
        elif h.findings:
            verdict = ui.c_slate(f"{h.findings} finding(s)")
        elif h.score is not None:
            verdict = ui.c_green("clean")
        else:
            verdict = ui.c_slate("—")
        lines.append(
            f"{ui.c_white(h.host[:33].ljust(34))}{ui.c_slate(str(h.status).ljust(9))}"
            f"{tls.ljust(8)}{verdict}"
        )
    if len(live) > 40:
        lines.append(ui.c_slate(f"  … and {len(live) - 40} more (see the report)"))
    return "\n".join(lines)


def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="recon",
        description="Discover and fingerprint a domain's external attack surface.",
    )
    p.add_argument("domain", help="registrable domain, e.g. example.com")
    p.add_argument("--authorized", "-y", action="store_true",
                   help="confirm you have written permission to probe these hosts")
    p.add_argument("--scan", action="store_true",
                   help="run a Sentwall scan against each live host")
    p.add_argument("--max-scan", type=int, default=10, help="cap how many hosts get scanned")
    p.add_argument("--profile", default="fast", choices=["fast", "standard", "deep", "api"])
    p.add_argument("--threads", type=int, default=12, help="concurrent workers (default 12)")
    p.add_argument("--wordlist", help="file with one subdomain prefix per line")
    p.add_argument("--no-crt", action="store_true", help="skip certificate transparency")
    p.add_argument("--no-brute", action="store_true", help="skip DNS brute force")
    p.add_argument("--no-tls", action="store_true", help="skip certificate inspection")
    p.add_argument("--out", "-o", default="reports", help="output directory (default reports)")
    p.add_argument("--formats", default="html,md,json,csv")
    p.add_argument("--quiet", action="store_true")
    return p.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)

    print()
    print(ui.c_cyan(ui.bold("  SENTWALL RECON")))
    print(ui.c_dark("  external attack surface mapping"))
    print()

    if not args.authorized:
        print(ui.c_red("  ✖ --authorized is required."))
        print(ui.c_slate("    Discovery uses public certificate data, but the probe and scan"))
        print(ui.c_slate("    stages send real requests to hosts. Get written permission first."))
        print()
        return 2

    words = None
    if args.wordlist:
        try:
            with open(args.wordlist, encoding="utf-8") as fh:
                words = [w.strip() for w in fh if w.strip() and not w.startswith("#")]
        except OSError as exc:
            print(ui.c_red(f"  ✖ cannot read wordlist: {exc}"))
            return 2

    print(ui.c_slate(f"  target  {ui.c_white(args.domain)}"))
    print()

    try:
        result = run(
            args.domain,
            use_crt=not args.no_crt,
            use_brute=not args.no_brute,
            wordlist=words,
            threads=args.threads,
            do_tls=not args.no_tls,
            do_scan=args.scan,
            max_scan=args.max_scan,
            profile=args.profile,
            log=_log,
        )
    except KeyboardInterrupt:
        print(ui.c_yellow("\n  interrupted"))
        return 130

    print()
    print(ui.draw_card("LIVE HOSTS", _table(result).split("\n"),
                       border_color="cyan", min_width=64))
    print()

    formats = tuple(x.strip() for x in args.formats.split(",") if x.strip())
    written = write_reports(result, args.out, formats)
    for path in written:
        print(f"  {ui.c_slate('report')}  {ui.c_emerald(path)}")
    print()
    print(ui.c_slate(f"  {len(result.discovered)} names · {len(result.live_hosts)} live · "
                     f"{len(result.risky)} with critical/high · {result.elapsed:.1f}s"))
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
