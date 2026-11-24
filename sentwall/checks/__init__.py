"""Check registry."""
from __future__ import annotations

import time
from typing import Callable, List, Optional

from ..context import ScanContext
from ..models import Finding

from . import (
    api,
    auth_access,
    cloud,
    content,
    cookies,
    dnsemail,
    exposure,
    headers,
    injection,
    misconfig,
    secrets,
    ssrf_traversal,
    tech,
    transport,
    waf,
)

MODULES = [
    transport,
    headers,
    cookies,
    waf,
    misconfig,
    tech,
    content,
    exposure,
    api,
    cloud,
    secrets,
    auth_access,
    dnsemail,
    injection,
    ssrf_traversal,
]


def run_all(
    ctx: ScanContext,
    progress: Callable[[str], None] = lambda m: None,
    on_module_start: Optional[Callable[[int, int, str], None]] = None,
    on_module_done: Optional[Callable[[int, int, str, List[Finding], float], None]] = None,
) -> List[Finding]:
    findings: List[Finding] = []
    total = len(MODULES)
    for i, module in enumerate(MODULES, 1):
        label = getattr(module, "LABEL", module.NAME)
        if on_module_start:
            on_module_start(i, total, label)
        else:
            progress(f"[{i}/{total}] {label}")

        started = time.time()
        try:
            result = module.run(ctx) or []
        except Exception as exc:  # a broken check must never kill the scan
            progress(f"    ! {module.NAME} failed: {exc}")
            result = []
        took = time.time() - started
        findings.extend(result)

        if on_module_done:
            on_module_done(i, total, label, result, took)
        else:
            progress(f"    -> {len(result)} finding(s) in {took:.1f}s")
    return findings
