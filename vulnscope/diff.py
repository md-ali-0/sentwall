"""Delta comparison engine for baseline and re-assessment scans.

Computes resolved issues, persistent issues, new issues, and score improvements
to generate a client-ready Remediation Verification Report.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .models import Finding, ScanResult, Severity


@dataclass
class DiffResult:
    baseline_id: str
    current_id: str
    target: str
    baseline_score: int
    current_score: int
    score_change: int  # negative is good (reduced risk)
    baseline_grade: str
    current_grade: str
    resolved: List[Dict[str, Any]] = field(default_factory=list)
    persistent: List[Dict[str, Any]] = field(default_factory=list)
    new_findings: List[Dict[str, Any]] = field(default_factory=list)
    generated_at: str = field(default_factory=lambda: _dt.datetime.now().isoformat())

    @property
    def verdict(self) -> str:
        if self.score_change < -30:
            return "Exceptional improvement: Major attack surface eliminated."
        if self.score_change < 0:
            return "Positive progress: Risk score reduced."
        if self.score_change == 0:
            return "No change in aggregate risk posture."
        return "Regression alert: Risk score increased since baseline."

    def to_dict(self) -> Dict[str, Any]:
        return {
            "baseline_id": self.baseline_id,
            "current_id": self.current_id,
            "target": self.target,
            "baseline_score": self.baseline_score,
            "current_score": self.current_score,
            "score_change": self.score_change,
            "baseline_grade": self.baseline_grade,
            "current_grade": self.current_grade,
            "verdict": self.verdict,
            "resolved_count": len(self.resolved),
            "persistent_count": len(self.persistent),
            "new_count": len(self.new_findings),
            "resolved": self.resolved,
            "persistent": self.persistent,
            "new_findings": self.new_findings,
            "generated_at": self.generated_at,
        }

    def to_markdown(self) -> str:
        lines = [
            f"# VulnScope Remediation Verification Report",
            f"**Target:** `{self.target}`  ",
            f"**Baseline Scan:** `{self.baseline_id}` (Grade: {self.baseline_grade}, Score: {self.baseline_score}/100)  ",
            f"**Verification Scan:** `{self.current_id}` (Grade: {self.current_grade}, Score: {self.current_score}/100)  ",
            f"**Risk Delta:** **{self.score_change:+d} points**  ",
            f"**Verdict:** {self.verdict}  ",
            "",
            "---",
            "",
            "## 1. Remediation Scorecard",
            "",
            f"| Metric | Count | Status |",
            f"|---|---|---|",
            f"| **Resolved Vulnerabilities** | **{len(self.resolved)}** | Fixed / Closed |",
            f"| **Persistent Issues** | {len(self.persistent)} | Requires Attention |",
            f"| **New Issues Introduced** | {len(self.new_findings)} | Regression |",
            "",
        ]

        if self.resolved:
            lines.append("## 2. Successfully Resolved Vulnerabilities\n")
            for r in self.resolved:
                lines.append(f"- **[{r['severity'].upper()}]** {r['title']} (`{r['location'] or r['key']}`)")
            lines.append("")

        if self.persistent:
            lines.append("## 3. Persistent Open Vulnerabilities\n")
            for p in self.persistent:
                lines.append(f"- **[{p['severity'].upper()}]** {p['title']} (`{p['location'] or p['key']}`)")
            lines.append("")

        if self.new_findings:
            lines.append("## 4. Newly Introduced Issues\n")
            for n in self.new_findings:
                lines.append(f"- **[{n['severity'].upper()}]** {n['title']} (`{n['location'] or n['key']}`)")
            lines.append("")

        return "\n".join(lines)


def compare_scans(baseline: Dict[str, Any], current: Dict[str, Any]) -> DiffResult:
    """Compare two scan dictionaries and compute the remediation delta."""
    b_findings = {f["key"]: f for f in baseline.get("findings", [])}
    c_findings = {f["key"]: f for f in current.get("findings", [])}

    b_score = baseline.get("risk_score", 0)
    c_score = current.get("risk_score", 0)

    resolved = [f for key, f in b_findings.items() if key not in c_findings]
    persistent = [f for key, f in c_findings.items() if key in b_findings]
    new_findings = [f for key, f in c_findings.items() if key not in b_findings]

    return DiffResult(
        baseline_id=baseline.get("scan_id", "BASELINE"),
        current_id=current.get("scan_id", "CURRENT"),
        target=current.get("target") or baseline.get("target", "Target"),
        baseline_score=b_score,
        current_score=c_score,
        score_change=c_score - b_score,
        baseline_grade=baseline.get("grade", "?"),
        current_grade=current.get("grade", "?"),
        resolved=resolved,
        persistent=persistent,
        new_findings=new_findings,
    )


def compare_files(baseline_path: str, current_path: str) -> DiffResult:
    with open(baseline_path, "r", encoding="utf-8") as fb:
        b_data = json.load(fb)
    with open(current_path, "r", encoding="utf-8") as fc:
        c_data = json.load(fc)
    return compare_scans(b_data, c_data)
