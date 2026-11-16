"""Core data models for VulnScope.

Everything the checks produce is a ``Finding``. The reporter consumes a
``ScanResult``. Keeping this layer dependency-free makes it easy to export to
JSON, HTML, SARIF, CSV or Markdown.
"""
from __future__ import annotations

import csv
import datetime as _dt
import hashlib
import io
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlparse


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

    @property
    def sarif_level(self) -> str:
        if self in (Severity.CRITICAL, Severity.HIGH):
            return "error"
        if self is Severity.MEDIUM:
            return "warning"
        return "note"


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

EFFORT_HOURS = {
    "quick": 1.0,
    "moderate": 4.0,
    "involved": 16.0,
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
    title_bn: str = ""
    description_bn: str = ""
    impact_bn: str = ""
    fix_patches: Dict[str, str] = field(default_factory=dict)
    poc_curl_template: str = ""

    # ---------------------------------------------------------------- helpers
    @property
    def weight(self) -> float:
        base = _SEVERITY_WEIGHT[self.severity]
        return base * _CONFIDENCE_FACTOR.get(self.confidence, 1.0)

    @property
    def effort_label(self) -> str:
        return EFFORT_LABEL.get(self.effort, self.effort)

    @property
    def effort_hours(self) -> float:
        return EFFORT_HOURS.get(self.effort, 4.0)

    def get_poc_curl(self, target_base: str = "") -> str:
        """Generate a reproducible cURL command for testing this finding."""
        if self.poc_curl_template:
            return self.poc_curl_template.replace("{{TARGET}}", target_base or "https://example.com")
        loc = self.location or target_base or "/"
        if not loc.startswith("http"):
            base = target_base.rstrip("/")
            url = f"{base}/{loc.lstrip('/')}" if base else loc
        else:
            url = loc
        if self.severity in (Severity.CRITICAL, Severity.HIGH):
            return f"curl -i -k -s -S '{url}'"
        return f"curl -I -k -s '{url}'"

    def get_poc_python(self, target_base: str = "") -> str:
        """Generate a Python script verifying this finding."""
        curl_cmd = self.get_poc_curl(target_base)
        match = re.search(r"'(https?://[^']+)'", curl_cmd)
        url = match.group(1) if match else (self.location or target_base or "https://example.com")
        return (
            "import requests\n\n"
            f"url = '{url}'\n"
            "resp = requests.get(url, verify=False, timeout=10)\n"
            "print(f'Status: {resp.status_code}')\n"
            "print('Headers:', resp.headers)\n"
            "print('Body preview:', resp.text[:400])\n"
        )

    def get_remediation_patch(self, flavor: str = "nginx") -> str:
        """Return a ready-to-paste server or code fix snippet."""
        if flavor in self.fix_patches:
            return self.fix_patches[flavor]
        # Automatic sensible defaults based on key/category
        k = self.key.lower()
        if "header" in k or "csp" in k or "hsts" in k or "x-frame" in k:
            if flavor == "nginx":
                return (
                    "# In nginx.conf or site block:\n"
                    "add_header X-Frame-Options \"DENY\" always;\n"
                    "add_header X-Content-Type-Options \"nosniff\" always;\n"
                    "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n"
                    "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self';\" always;\n"
                )
            if flavor == "apache":
                return (
                    "# In .htaccess or httpd.conf:\n"
                    "Header always set X-Frame-Options \"DENY\"\n"
                    "Header always set X-Content-Type-Options \"nosniff\"\n"
                    "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"\n"
                )
        if "git" in k or "env" in k or "backup" in k or "exposure" in k:
            if flavor == "nginx":
                return (
                    "# In nginx server block:\n"
                    "location ~ /\\.(git|env|bak|config|sql) {\n"
                    "    deny all;\n"
                    "    return 404;\n"
                    "}\n"
                )
            if flavor == "apache":
                return (
                    "# In .htaccess:\n"
                    "<FilesMatch \"^(\\..*|.*\\.sql|.*\\.env|.*\\.bak)$\">\n"
                    "    Require all denied\n"
                    "</FilesMatch>\n"
                )
        return self.remediation or "Apply principle of least privilege, input validation, and secure headers."

    def to_sarif_rule(self) -> Dict[str, Any]:
        return {
            "id": self.key,
            "name": re.sub(r"[^A-Za-z0-9_]", "_", self.key),
            "shortDescription": {"text": self.title},
            "fullDescription": {"text": self.description},
            "defaultConfiguration": {"level": self.severity.sarif_level},
            "help": {
                "text": f"{self.remediation}\n\nReferences:\n" + "\n".join(self.references),
                "markdown": f"### Remediation\n{self.remediation}\n\n### Impact\n{self.impact}\n",
            },
            "properties": {
                "tags": [x for x in [self.category, self.owasp, self.cwe] if x],
                "precision": "high" if self.confidence == "certain" else "medium",
                "security-severity": str(self.cvss or (_SEVERITY_RANK[self.severity] * 2.0)),
            },
        }

    def to_sarif_result(self) -> Dict[str, Any]:
        res: Dict[str, Any] = {
            "ruleId": self.key,
            "level": self.severity.sarif_level,
            "message": {"text": f"{self.title}: {self.description}"},
            "locations": [],
        }
        if self.location:
            res["locations"].append(
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": self.location},
                        "region": {"startLine": 1},
                    }
                }
            )
        return res

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "title": self.title,
            "title_bn": self.title_bn,
            "severity": self.severity.value,
            "category": self.category,
            "description": self.description,
            "description_bn": self.description_bn,
            "impact": self.impact,
            "impact_bn": self.impact_bn,
            "remediation": self.remediation,
            "evidence": list(self.evidence),
            "references": list(self.references),
            "cwe": self.cwe,
            "owasp": self.owasp,
            "confidence": self.confidence,
            "effort": self.effort,
            "effort_label": self.effort_label,
            "effort_hours": self.effort_hours,
            "cvss": self.cvss,
            "vector": self.vector,
            "location": self.location,
            "poc_curl": self.get_poc_curl(),
            "fix_patches": self.fix_patches,
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
    profile: str = "standard"
    baseline_id: str = ""

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

    def total_remediation_hours(self) -> float:
        """Estimated technical debt in engineering hours to patch all vulnerabilities."""
        return sum(f.effort_hours for f in self.findings if f.severity != Severity.INFO)

    def financial_risk(self) -> Dict[str, Any]:
        """Calculates commercial financial exposure based on global cybersecurity benchmarks.

        Metrics derived from IBM Cost of a Data Breach Report and GDPR Article 83 parameters.
        """
        counts = self.counts()
        crit = counts["critical"]
        high = counts["high"]
        med = counts["medium"]

        # Probability of exploitation within 12 months
        if crit >= 2:
            prob = 94
        elif crit == 1:
            prob = 78
        elif high >= 3:
            prob = 65
        elif high >= 1:
            prob = 48
        elif med >= 3:
            prob = 28
        else:
            prob = 10

        # Estimated average breach impact in USD
        base_loss = 45000.0
        loss_estimate = base_loss + (crit * 95000.0) + (high * 32000.0) + (med * 8000.0)
        # Cap for SME baseline
        loss_estimate = min(4450000.0, loss_estimate)

        hours = self.total_remediation_hours()

        return {
            "breach_probability_pct": prob,
            "estimated_financial_loss_usd": int(round(loss_estimate)),
            "regulatory_risk_rating": "Critical" if crit > 0 else ("High" if high > 0 else "Moderate"),
            "total_remediation_hours": round(hours, 1),
            "priority_action": (
                "IMMEDIATE EMERGENCY FIX" if crit > 0
                else ("URGENT - FIX WITHIN 7 DAYS" if high > 0 else "SCHEDULE NEXT SPRINT")
            ),
        }

    def client_pitch_packages(self, currency: str = "USD", hourly_rate: float = 120.0) -> Dict[str, Any]:
        """Generate 3 tailored proposal packages with transparent ROI metrics."""
        hours = self.total_remediation_hours()
        fin = self.financial_risk()

        symbol = "$" if currency == "USD" else ("৳" if currency == "BDT" else "€")

        quick_findings = [f for f in self.findings if f.effort == "quick" and f.severity in (Severity.CRITICAL, Severity.HIGH)]
        tier1_hours = max(4.0, sum(f.effort_hours for f in quick_findings))
        tier1_cost = int(round(tier1_hours * hourly_rate))

        tier2_hours = max(12.0, hours * 1.15)  # includes re-testing & verification
        tier2_cost = int(round(tier2_hours * hourly_rate))

        tier3_monthly = int(round(tier2_cost * 0.35))

        return {
            "currency": currency,
            "currency_symbol": symbol,
            "hourly_rate": hourly_rate,
            "financial_exposure": f"{symbol}{fin['estimated_financial_loss_usd']:,}",
            "packages": [
                {
                    "tier": "Tier 1: Emergency Quick Wins",
                    "badge": "Immediate Protection",
                    "hours": round(tier1_hours, 1),
                    "price": f"{symbol}{tier1_cost:,}",
                    "deliverables": [
                        "Immediate patching of high-impact critical vulnerabilities",
                        "Security header & TLS hardening",
                        "Removal of exposed credentials & sensitive endpoints",
                        "Re-scan confirmation certificate",
                    ],
                },
                {
                    "tier": "Tier 2: Complete Remediation & Verification",
                    "badge": "Most Recommended",
                    "hours": round(tier2_hours, 1),
                    "price": f"{symbol}{tier2_cost:,}",
                    "deliverables": [
                        "Full remediation of ALL identified vulnerabilities (Critical to Low)",
                        "Custom WAF and server virtual patching rules (Nginx/Apache/Cloudflare)",
                        "Code-level remediation support for developer team",
                        "Independent verification audit + Executive Letter of Attestation",
                        "Before vs After delta report proving Grade A posture",
                    ],
                },
                {
                    "tier": "Tier 3: Continuous Security Retainer",
                    "badge": "Full Peace of Mind",
                    "hours": "Continuous",
                    "price": f"{symbol}{tier3_monthly:,} / month",
                    "deliverables": [
                        "Weekly automated vulnerability scanning & monitoring",
                        "Continuous attack surface & subdomain monitoring",
                        "Priority incident response SLA (under 4 hours)",
                        "Monthly security compliance check (OWASP, ISO27001)",
                    ],
                },
            ],
        }

    # ---------------------------------------------------------------- exports
    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "host": self.host,
            "profile": self.profile,
            "baseline_id": self.baseline_id,
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
            "financial_risk": self.financial_risk(),
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }

    def to_csv(self) -> str:
        """Export findings to CSV format for spreadsheets."""
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Scan ID", "Severity", "Title", "Category", "CWE", "OWASP",
            "CVSS", "Location", "Effort", "Confidence", "Description", "Remediation"
        ])
        for f in self.sorted_findings():
            writer.writerow([
                self.scan_id,
                f.severity.value.upper(),
                f.title,
                f.category,
                f.cwe,
                f.owasp,
                f.cvss or "",
                f.location,
                f.effort_label,
                f.confidence,
                f.description,
                f.remediation,
            ])
        return output.getvalue()

    def to_sarif(self) -> Dict[str, Any]:
        """Export findings in official OASIS SARIF 2.1.0 format."""
        sorted_f = self.sorted_findings()
        rules = []
        rule_ids = set()
        for f in sorted_f:
            if f.key not in rule_ids:
                rules.append(f.to_sarif_rule())
                rule_ids.add(f.key)

        results = [f.to_sarif_result() for f in sorted_f]

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "VulnScope",
                            "semanticVersion": "2.0.0",
                            "informationUri": "https://github.com/vulnscope/vulnscope",
                            "rules": rules,
                        }
                    },
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": _dt.datetime.fromtimestamp(self.started, _dt.timezone.utc).isoformat(),
                            "endTimeUtc": _dt.datetime.fromtimestamp(self.finished or self.started, _dt.timezone.utc).isoformat(),
                        }
                    ],
                    "results": results,
                }
            ],
        }


def quick_wins(result: ScanResult) -> List[Finding]:
    """Findings that are high value but cheap to fix - great for a proposal."""
    return [
        f
        for f in result.sorted_findings()
        if f.severity in (Severity.CRITICAL, Severity.HIGH) and f.effort == "quick"
    ]
