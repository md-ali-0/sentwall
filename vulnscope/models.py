"""Core data models for VulnScope.

Everything the checks produce is a ``Finding``. The reporter consumes a
``ScanResult``. Keeping this layer dependency-free makes it easy to export to
JSON, HTML or Markdown.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @property
    def label(self) -> str:
        return self.value.capitalize()


_SEVERITY_RANK = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}

# How much a single finding pushes the aggregate risk score.
_SEVERITY_WEIGHT = {
    Severity.CRITICAL: 42.0,
    Severity.HIGH: 17.0,
    Severity.MEDIUM: 6.5,
    Severity.LOW: 1.8,
    Severity.INFO: 0.0,
}

_CONFIDENCE_FACTOR = {
    "certain": 1.0,
    "firm": 0.85,
    "tentative": 0.55,
}

EFFORT_LABEL = {
    "quick": "Quick fix (under 1 hour)",
    "moderate": "Moderate (half a day)",
    "involved": "Involved (1-3 days)",
}

SEVERITY_COLOR = {
    Severity.CRITICAL: "#8b1a1a",
    Severity.HIGH: "#c62828",
    Severity.MEDIUM: "#d97706",
    Severity.LOW: "#2563eb",
    Severity.INFO: "#6b7280",
}


@dataclass
class Finding:
    """A single security issue discovered during the assessment."""

    key: str
    title: str
    severity: Severity
    category: str
    description: str
    impact: str = ""
    remediation: str = ""
    evidence: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    cwe: str = ""
    owasp: str = ""
    confidence: str = "certain"
    effort: str = "moderate"
    cvss: Optional[float] = None
    vector: str = ""
    location: str = ""

    # ---------------------------------------------------------------- helpers
    @property
    def weight(self) -> float:
        base = _SEVERITY_WEIGHT[self.severity]
        return base * _CONFIDENCE_FACTOR.get(self.confidence, 1.0)

    @property
    def effort_label(self) -> str:
        return EFFORT_LABEL.get(self.effort, self.effort)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "description": self.description,
            "impact": self.impact,
            "remediation": self.remediation,
            "evidence": list(self.evidence),
            "references": list(self.references),
            "cwe": self.cwe,
            "owasp": self.owasp,
            "confidence": self.confidence,
            "effort": self.effort,
            "cvss": self.cvss,
            "vector": self.vector,
            "location": self.location,
        }


@dataclass
class ScanResult:
    """Aggregate output of one assessment run."""

    target: str
    host: str
    started: float
    finished: float = 0.0
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    pages_scanned: List[str] = field(default_factory=list)
    requests_made: int = 0
    auditor: str = ""
    client: str = ""

    # ---------------------------------------------------------------- helpers
    @property
    def scan_id(self) -> str:
        raw = f"{self.target}|{int(self.started)}".encode()
        return "VS-" + hashlib.sha1(raw).hexdigest()[:8].upper()

    @property
    def duration(self) -> float:
        end = self.finished or self.started
        return max(0.0, end - self.started)

    def sorted_findings(self) -> List[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (-f.severity.rank, -f.weight, f.title),
        )

    def by_severity(self) -> Dict[Severity, List[Finding]]:
        out: Dict[Severity, List[Finding]] = {s: [] for s in Severity}
        for f in self.sorted_findings():
            out[f.severity].append(f)
        return out

    def counts(self) -> Dict[str, int]:
        c = {s.value: 0 for s in Severity}
        for f in self.findings:
            c[f.severity.value] += 1
        return c

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    # ---------------------------------------------------------------- scoring
    def risk_score(self) -> int:
        """0 = clean, 100 = trivially compromised.

        Additive with a soft cap so a handful of criticals saturates the scale
        instead of producing absurd numbers.
        """
        total = 0.0
        for f in self.findings:
            if f.severity is Severity.INFO:
                continue
            total += f.weight
        # diminishing returns above 60
        if total > 60:
            total = 60 + (total - 60) * 0.45
        return int(round(min(100.0, total)))

    def grade(self) -> str:
        s = self.risk_score()
        if s >= 80:
            return "F"
        if s >= 65:
            return "E"
        if s >= 45:
            return "D"
        if s >= 28:
            return "C"
        if s >= 12:
            return "B"
        return "A"

    def grade_verdict(self) -> str:
        s = self.risk_score()
        if s >= 80:
            return "Critical exposure - immediate action required"
        if s >= 65:
            return "High risk - urgent remediation needed"
        if s >= 45:
            return "Elevated risk - significant weaknesses present"
        if s >= 28:
            return "Moderate risk - several issues to address"
        if s >= 12:
            return "Low risk - minor hardening opportunities"
        return "Strong posture - only informational observations"

    # ---------------------------------------------------------------- exports
    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "host": self.host,
            "auditor": self.auditor,
            "client": self.client,
            "started": _dt.datetime.fromtimestamp(self.started).isoformat(),
            "finished": _dt.datetime.fromtimestamp(self.finished or self.started).isoformat(),
            "duration_seconds": round(self.duration, 1),
            "risk_score": self.risk_score(),
            "grade": self.grade(),
            "verdict": self.grade_verdict(),
            "counts": self.counts(),
            "requests_made": self.requests_made,
            "pages_scanned": self.pages_scanned,
            "metadata": self.metadata,
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }


def quick_wins(result: ScanResult) -> List[Finding]:
    """Findings that are high value but cheap to fix - great for a proposal."""
    return [
        f
        for f in result.sorted_findings()
        if f.severity in (Severity.CRITICAL, Severity.HIGH) and f.effort == "quick"
    ]
