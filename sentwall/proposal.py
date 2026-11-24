"""Client proposal, Statement of Work (SOW), and ROI presentation generator.

Enables penetration testers and security auditors to instantly produce a
commercial agreement, rules of engagement, and pitch deck for clients.
"""
from __future__ import annotations

import datetime as _dt
import html
from typing import Any, Dict, List, Optional

from .models import ScanResult, Severity

E = html.escape


def generate_proposal_markdown(
    result: ScanResult,
    currency: str = "USD",
    hourly_rate: float = 120.0,
    auditor_name: str = "",
    auditor_company: str = "",
    client_name: str = "",
) -> str:
    auditor = auditor_name or result.auditor or "Security Consultant"
    company = auditor_company or "Cybersecurity Services"
    client = client_name or result.client or "Valued Client"
    today = _dt.date.today().isoformat()

    fin = result.financial_risk()
    pitch = result.client_pitch_packages(currency=currency, hourly_rate=hourly_rate)
    sym = pitch["currency_symbol"]

    counts = result.counts()

    lines = [
        f"# Cybersecurity Remediation Proposal & Statement of Work",
        f"**Confidential — Prepared for:** {client}  ",
        f"**Prepared by:** {auditor} ({company})  ",
        f"**Date:** {today}  ",
        f"**Reference Scan ID:** `{result.scan_id}`  ",
        "",
        "---",
        "",
        "## 1. Executive Summary & Business Impact",
        "",
        f"A thorough non-destructive security assessment was conducted against `{result.target}`. "
        f"The system currently holds a **Security Grade of {result.grade()} (Risk Score: {result.risk_score()}/100)**, "
        f"classified as **'{result.grade_verdict()}'**.",
        "",
        "### Key Security Metrics",
        f"- **Critical Vulnerabilities:** {counts['critical']} (Immediate breach risk)",
        f"- **High Vulnerabilities:** {counts['high']} (Severe privilege / data leak exposure)",
        f"- **Medium / Low Issues:** {counts['medium'] + counts['low']} (Hygiene & hardening)",
        f"- **Estimated Financial Breach Exposure:** **{sym}{fin['estimated_financial_loss_usd']:,}**",
        f"- **Estimated Exploitation Likelihood:** **{fin['breach_probability_pct']}% within 12 months**",
        "",
        "---",
        "",
        "## 2. Recommended Service Packages",
        "",
    ]

    for pkg in pitch["packages"]:
        lines.append(f"### {pkg['tier']} — **{pkg['price']}**")
        lines.append(f"*{pkg['badge']}* | Estimated effort: {pkg['hours']} hours\n")
        lines.append("**Deliverables included:**")
        for d in pkg["deliverables"]:
            lines.append(f"- [x] {d}")
        lines.append("")

    lines.extend([
        "---",
        "",
        "## 3. Rules of Engagement & Authorization",
        "",
        "1. **Scope:** Remediation and re-testing are strictly confined to the agreed target URLs and endpoints.",
        "2. **Confidentiality:** All discovery data, logs, and vulnerability evidence remain strictly confidential under NDA.",
        "3. **Zero Downtime Guarantee:** All configuration updates and virtual patches are staged to prevent service disruption.",
        "",
        "### Sign-Off & Approval",
        "",
        "**Client Authorization:** ______________________________________    **Date:** _______________",
        "",
        "**Auditor Acceptance:** ______________________________________    **Date:** _______________",
    ])

    return "\n".join(lines)


def generate_proposal_html(
    result: ScanResult,
    currency: str = "USD",
    hourly_rate: float = 120.0,
    auditor_name: str = "",
    auditor_company: str = "",
    client_name: str = "",
) -> str:
    pitch = result.client_pitch_packages(currency=currency, hourly_rate=hourly_rate)
    fin = result.financial_risk()
    sym = pitch["currency_symbol"]
    counts = result.counts()

    pkg_cards = ""
    for pkg in pitch["packages"]:
        d_items = "".join(f"<li>{E(d)}</li>" for d in pkg["deliverables"])
        pkg_cards += f"""
        <div class="pitch-card {'featured' if 'Recommended' in pkg['badge'] else ''}">
            <div class="pkg-badge">{E(pkg['badge'])}</div>
            <h3>{E(pkg['tier'])}</h3>
            <div class="price">{E(pkg['price'])}</div>
            <div class="hours">Estimated effort: {pkg['hours']} hrs</div>
            <ul class="deliverables">{d_items}</ul>
            <div class="select-btn">Select Engagement</div>
        </div>
        """

    return f"""
    <section class="proposal-studio" id="proposal-section">
        <div class="sec-head">
            <span class="num">COMMERCIAL PROPOSAL</span>
            <h2>Client Remediation Pitch & SOW</h2>
        </div>
        <div class="card proposal-card">
            <div class="roi-summary">
                <div class="roi-item">
                    <span class="lbl">Current Posture</span>
                    <span class="val grade-{result.grade()}">Grade {result.grade()} ({result.risk_score()}/100)</span>
                </div>
                <div class="roi-item">
                    <span class="lbl">Breach Likelihood</span>
                    <span class="val danger">{fin['breach_probability_pct']}%</span>
                </div>
                <div class="roi-item">
                    <span class="lbl">Financial Exposure</span>
                    <span class="val highlight">{sym}{fin['estimated_financial_loss_usd']:,}</span>
                </div>
                <div class="roi-item">
                    <span class="lbl">Total Tech Debt</span>
                    <span class="val">{fin['total_remediation_hours']} hours</span>
                </div>
            </div>
            <p style="margin-top:16px; color:#475569;">
                Investing in proactive remediation neutralizes <strong>{sym}{fin['estimated_financial_loss_usd']:,}</strong> 
                in potential regulatory penalties and data breach liability while elevating system security to Grade A.
            </p>
            <div class="pitch-grid">
                {pkg_cards}
            </div>
        </div>
    </section>
    """
