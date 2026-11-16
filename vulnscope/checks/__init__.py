"""Check registry."""
from __future__ import annotations

import time
from typing import Callable, List

from ..context import ScanContext
from ..models import Finding

from . import content, cookies, dnsemail, exposure, headers, injection, misconfig, tech, transport

MODULES = [
    transport,
    headers,
    cookies,
    misconfig,
    tech,
    content,
    exposure,
    dnsemail,
    injection,
]


def run_all(ctx: ScanContext, progress: Callable[[str], None] = lambda m: None) -> List[Finding]:
    findings: List[Finding] = []
    total = len(MODULES)
    for i, module in enumerate(MODULES, 1):
        label = getattr(module, "LABEL", module.NAME)
        progress(f"[{i}/{total}] {label}")
        started = time.time()
        try:
            result = module.run(ctx) or []
        except Exception as exc:  # a broken check must never kill the scan
            progress(f"    ! {module.NAME} failed: {exc}")
            result = []
        took = time.time() - started
        findings.extend(result)
        progress(f"    -> {len(result)} finding(s) in {took:.1f}s")
    return findings
