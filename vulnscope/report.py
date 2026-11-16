"""Report rendering: a self-contained, print-ready HTML report plus JSON/Markdown."""
from __future__ import annotations

import datetime as _dt
import html
import json
import os
from typing import Dict, List

from .models import EFFORT_LABEL, SEVERITY_COLOR, Finding, ScanResult, Severity, quick_wins

E = html.escape

CSS = """
:root{
  --ink:#0f172a; --body:#25324a; --muted:#64748b; --line:#e2e8f0;
  --bg:#f4f6fa; --card:#ffffff; --accent:#0f766e; --accent-soft:#ecfdf5;
  --critical:#8b1a1a; --high:#c62828; --medium:#d97706; --low:#2563eb; --info:#64748b;
}
*{box-sizing:border-box}
body{
  margin:0; background:var(--bg); color:var(--body);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  font-size:14px; line-height:1.62; -webkit-font-smoothing:antialiased;
}
.wrap{max-width:1000px; margin:0 auto; padding:32px 20px 80px}
h1,h2,h3,h4{color:var(--ink); margin:0; line-height:1.3; font-weight:650; letter-spacing:-0.01em}
p{margin:0 0 12px}
a{color:var(--accent); text-decoration:none}
code,pre{font-family:"SFMono-Regular",Consolas,"Liberation Mono",Menlo,monospace}
pre{
  background:#0f172a; color:#e2e8f0; padding:14px 16px; border-radius:8px;
  font-size:12px; line-height:1.55; overflow-x:auto; white-space:pre-wrap;
  word-break:break-word; margin:8px 0 0;
}
pre.fix{background:#f8fafc; color:#1e293b; border:1px solid var(--line)}

/* ---------- cover ---------- */
.cover{
  background:linear-gradient(140deg,#0b1220 0%,#12263a 55%,#0f766e 160%);
  color:#e8eef6; border-radius:18px; padding:44px 40px; margin-bottom:28px;
  position:relative; overflow:hidden;
}
.cover:after{
  content:""; position:absolute; right:-90px; top:-90px; width:320px; height:320px;
  background:radial-gradient(circle,rgba(45,212,191,.28),transparent 68%); border-radius:50%;
}
.cover .kicker{
  font-size:11px; letter-spacing:.22em; text-transform:uppercase;
  color:#7dd3c0; font-weight:700; margin-bottom:14px;
}
.cover h1{color:#fff; font-size:34px; letter-spacing:-0.02em; margin-bottom:6px}
.cover .target{font-size:15px; color:#a8bccd; word-break:break-all}
.cover .grid{display:flex; flex-wrap:wrap; gap:24px 30px; margin-top:28px; position:relative; z-index:2}
.cover .grid div{min-width:92px}
.cover .grid dt{font-size:10px; letter-spacing:.14em; text-transform:uppercase; color:#7f97ab; margin-bottom:3px}
.cover .grid dd{margin:0; font-size:14px; color:#e8eef6; font-weight:600}
.grade-badge{
  position:absolute; right:40px; bottom:38px; text-align:center; z-index:2;
}
.grade-badge .g{
  font-size:64px; font-weight:800; line-height:1; color:#fff;
  text-shadow:0 6px 30px rgba(0,0,0,.35);
}
.grade-badge .l{font-size:10px; letter-spacing:.18em; text-transform:uppercase; color:#9fb4c6}

/* ---------- sections ---------- */
section{margin-bottom:34px}
.sec-head{display:flex; align-items:baseline; gap:12px; margin-bottom:14px;
  border-bottom:2px solid var(--line); padding-bottom:8px}
.sec-head h2{font-size:19px}
.sec-head .num{font-size:11px; font-weight:700; color:var(--accent); letter-spacing:.1em}
.card{background:var(--card); border:1px solid var(--line); border-radius:12px; padding:22px 24px}
.card + .card{margin-top:14px}

/* ---------- score row ---------- */
.score-row{display:flex; gap:20px; flex-wrap:wrap; align-items:stretch}
.gauge-box{flex:0 0 210px; display:flex; flex-direction:column; align-items:center;
  justify-content:center; padding:18px}
.gauge{width:150px; height:150px; border-radius:50%; display:grid; place-items:center; position:relative}
.gauge .inner{
  width:112px; height:112px; background:#fff; border-radius:50%;
  display:grid; place-items:center; text-align:center;
}
.gauge .val{font-size:34px; font-weight:750; color:var(--ink); line-height:1}
.gauge .lbl{font-size:9px; letter-spacing:.16em; text-transform:uppercase; color:var(--muted); margin-top:4px}
.stat-grid{flex:1; display:grid; grid-template-columns:repeat(auto-fit,minmax(120px,1fr)); gap:10px}
.stat{background:var(--card); border:1px solid var(--line); border-radius:10px; padding:14px 16px}
.stat .n{font-size:26px; font-weight:750; line-height:1.1}
.stat .t{font-size:11px; color:var(--muted); letter-spacing:.06em; text-transform:uppercase; margin-top:2px}

/* ---------- chips / bars ---------- */
.chip{
  display:inline-block; padding:2px 9px; border-radius:999px; font-size:10px;
  font-weight:750; letter-spacing:.1em; text-transform:uppercase; color:#fff;
}
.chip.critical{background:var(--critical)} .chip.high{background:var(--high)}
.chip.medium{background:var(--medium)} .chip.low{background:var(--low)}
.chip.info{background:var(--info)}
.bars{margin-top:6px}
.bar-row{display:grid; grid-template-columns:78px 1fr 34px; gap:12px; align-items:center;
  margin-bottom:7px; font-size:12px}
.bar-track{height:9px; background:#eef2f7; border-radius:6px; overflow:hidden}
.bar-fill{height:100%; border-radius:6px}
.bar-n{text-align:right; font-weight:700; color:var(--ink)}

/* ---------- table ---------- */
table{width:100%; border-collapse:collapse; font-size:12.5px}
th{
  text-align:left; font-size:10px; letter-spacing:.1em; text-transform:uppercase;
  color:var(--muted); border-bottom:2px solid var(--line); padding:8px 10px; font-weight:700;
}
td{padding:9px 10px; border-bottom:1px solid #eef2f7; vertical-align:top}
tr:last-child td{border-bottom:none}
td.num{text-align:right; white-space:nowrap}

/* ---------- finding ---------- */
.finding{
  background:var(--card); border:1px solid var(--line); border-left:5px solid var(--info);
  border-radius:10px; padding:20px 22px; margin-bottom:14px; break-inside:avoid;
}
.finding.critical{border-left-color:var(--critical)}
.finding.high{border-left-color:var(--high)}
.finding.medium{border-left-color:var(--medium)}
.finding.low{border-left-color:var(--low)}
.finding header{display:flex; align-items:flex-start; gap:10px; flex-wrap:wrap; margin-bottom:10px}
.finding header h3{font-size:16px; flex:1; min-width:240px}
.finding .tags{font-size:11px; color:var(--muted); display:flex; gap:12px; flex-wrap:wrap; margin-bottom:14px}
.finding h4{
  font-size:10px; letter-spacing:.12em; text-transform:uppercase; color:var(--muted);
  margin:16px 0 6px; font-weight:700;
}
.finding h4:first-of-type{margin-top:0}
.finding ul{margin:0; padding-left:18px}
.finding li{margin-bottom:4px}
.finding ul.evidence li{
  font-family:"SFMono-Regular",Consolas,"Liberation Mono",Menlo,monospace;
  font-size:11.5px; color:#334155; background:#f8fafc; border:1px solid #eef2f7;
  border-radius:5px; padding:4px 8px; list-style:none; margin-left:-18px; margin-bottom:5px;
  word-break:break-all;
}
.finding .foot{
  margin-top:14px; padding-top:10px; border-top:1px dashed var(--line);
  font-size:11px; color:var(--muted); display:flex; gap:18px; flex-wrap:wrap;
}
.kv{display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:10px 22px; margin-top:6px}
.kv div{font-size:12.5px}
.kv span{display:block; font-size:10px; letter-spacing:.1em; text-transform:uppercase; color:var(--muted)}

/* ---------- misc ---------- */
.callout{
  border-radius:10px; padding:16px 18px; font-size:13px;
  background:var(--accent-soft); border:1px solid #cdeee2; color:#14532d;
}
.callout.warn{background:#fff7ed; border-color:#fed7aa; color:#7c2d12}
.note{font-size:12px; color:var(--muted)}
.two-col{display:grid; grid-template-columns:1fr 1fr; gap:22px}
@media(max-width:760px){.two-col{grid-template-columns:1fr}}
.pill-list{display:flex; flex-wrap:wrap; gap:6px; margin-top:8px}
.pill{background:#f1f5f9; border:1px solid var(--line); border-radius:6px; padding:3px 8px;
  font-size:11px; color:#334155; font-family:Consolas,monospace}
footer.rep{margin-top:44px; padding-top:16px; border-top:1px solid var(--line);
  font-size:11px; color:var(--muted); display:flex; justify-content:space-between; gap:16px; flex-wrap:wrap}

@media print{
  body{background:#fff; font-size:10.5pt}
  .wrap{max-width:none; padding:0}
  .cover{border-radius:0; -webkit-print-color-adjust:exact; print-color-adjust:exact}
  .page-break{page-break-before:always}
  .finding,.card,.stat{break-inside:avoid}
  a{color:inherit}
  pre{font-size:8.5pt}
}
@page{size:A4; margin:14mm}
"""


def _chip(sev: Severity) -> str:
    return f'<span class="chip {sev.value}">{sev.value}</span>'


def _gauge(score: int) -> str:
    color = (
        SEVERITY_COLOR[Severity.CRITICAL] if score >= 80
        else SEVERITY_COLOR[Severity.HIGH] if score >= 65
        else SEVERITY_COLOR[Severity.MEDIUM] if score >= 45
        else SEVERITY_COLOR[Severity.LOW] if score >= 12
        else "#0f766e"
    )
    deg = score * 3.6
    return (
        f'<div class="gauge" style="background:conic-gradient({color} {deg}deg,#e8eef5 {deg}deg)">'
        f'<div class="inner"><div><div class="val" style="color:{color}">{score}</div>'
        f'<div class="lbl">risk / 100</div></div></div></div>'
    )


def _bars(counts: Dict[str, int]) -> str:
    total = sum(counts.values()) or 1
    rows = []
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        n = counts[sev.value]
        pct = max(2.0, n / total * 100) if n else 0
        rows.append(
            f'<div class="bar-row"><div>{sev.label}</div>'
            f'<div class="bar-track"><div class="bar-fill" style="width:{pct:.1f}%;'
            f'background:{SEVERITY_COLOR[sev]}"></div></div>'
            f'<div class="bar-n">{n}</div></div>'
        )
    return '<div class="bars">' + "".join(rows) + "</div>"


def _exec_summary(result: ScanResult) -> str:
    c = result.counts()
    crit, high, med = c["critical"], c["high"], c["medium"]
    total = sum(c.values())
    tech = result.metadata.get("technology") or {}

    if crit or high:
        opening = (
            f"The assessment identified <strong>{crit + high} high-impact issue(s)</strong> "
            f"that should be treated as urgent, alongside {med} medium and "
            f"{c['low']} low-severity findings."
        )
    elif med:
        opening = (
            f"No directly exploitable critical flaws were found, but {med} medium-severity "
            f"issue(s) still weaken the site's defences and should be addressed."
        )
    else:
        opening = "The site shows a solid baseline configuration with only minor hardening opportunities."

    lines = [
        f"<p>{opening}</p>",
        f"<p>In total <strong>{total} observations</strong> were recorded against "
        f"<strong>{E(result.target)}</strong> during a non-intrusive assessment. The overall "
        f"security score is <strong>{result.risk_score()}/100</strong> "
        f"(grade {result.grade()}), described as: {E(result.grade_verdict().lower())}.</p>",
    ]

    top = [f for f in result.sorted_findings() if f.severity.rank >= 3][:3]
    if top:
        lines.append("<p>The three items that matter most to the business:</p><ul>")
        for f in top:
            lines.append(f"<li><strong>{E(f.title)}</strong> &mdash; {E(_short(f.impact or f.description, 150))}</li>")
        lines.append("</ul>")

    if tech:
        shown = {k: v for k, v in tech.items() if not (k == "Server" and len(tech) > 2)}
        pills = "".join(f'<span class="pill">{E(k)}: {E(str(v))}</span>' for k, v in shown.items())
        lines.append(f'<p class="note" style="margin-top:14px">Detected stack</p><div class="pill-list">{pills}</div>')

    lines.append(
        '<div class="callout" style="margin-top:18px"><strong>What this means in practice:</strong> '
        + (
            "an attacker with modest skill could likely reach customer data or take over accounts "
            "using only publicly available tools. Remediation should start this week."
            if (crit or high) else
            "the site is not trivially breakable, but the gaps listed below reduce defence in depth "
            "and should be closed on a normal maintenance cycle."
        )
        + "</div>"
    )
    return "".join(lines)


def _short(text: str, n: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= n else text[: n - 1].rstrip() + "…"


def _finding_card(f: Finding, index: int) -> str:
    evidence = "".join(f"<li>{E(x)}</li>" for x in f.evidence) if f.evidence else "<li>(no evidence recorded)</li>"
    refs = ""
    if f.references:
        refs = '<h4>References</h4><ul>' + "".join(
            f'<li><a href="{E(r)}">{E(r)}</a></li>' for r in f.references
        ) + "</ul>"

    tags = []
    if f.cvss:
        tags.append(f"CVSS ~{f.cvss:.1f}")
    if f.cwe:
        tags.append(f.cwe)
    if f.owasp:
        tags.append(f.owasp)
    tags.append(f"confidence: {f.confidence}")

    return f"""
<article class="finding {f.severity.value}">
  <header>
    {_chip(f.severity)}
    <h3>{index}. {E(f.title)}</h3>
  </header>
  <div class="tags">{' &middot; '.join(E(t) for t in tags)}</div>

  <h4>What we found</h4>
  <p>{E(f.description)}</p>
  {f'<h4>Business impact</h4><p>{E(f.impact)}</p>' if f.impact else ''}
  <h4>Evidence</h4>
  <ul class="evidence">{evidence}</ul>
  {f'<h4>How to fix it</h4><pre class="fix">{E(f.remediation)}</pre>' if f.remediation else ''}
  {refs}
  <div class="foot">
    <span><strong>Category:</strong> {E(f.category)}</span>
    <span><strong>Effort:</strong> {E(f.effort_label)}</span>
    {f'<span><strong>Location:</strong> {E(f.location)}</span>' if f.location else ''}
  </div>
</article>"""


def _summary_table(findings: List[Finding]) -> str:
    rows = []
    for i, f in enumerate(findings, 1):
        rows.append(
            f"<tr><td class='num'>{i}</td><td>{_chip(f.severity)}</td>"
            f"<td>{E(f.title)}</td><td>{E(f.category)}</td>"
            f"<td class='num'>{('%.1f' % f.cvss) if f.cvss else '&ndash;'}</td>"
            f"<td>{E(EFFORT_LABEL.get(f.effort, f.effort))}</td></tr>"
        )
    return (
        "<table><thead><tr><th>#</th><th>Severity</th><th>Finding</th><th>Category</th>"
        "<th>CVSS</th><th>Fix effort</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _roadmap(result: ScanResult) -> str:
    wins = quick_wins(result)
    medium_term = [
        f for f in result.sorted_findings()
        if f.severity.rank >= 3 and f.effort in ("moderate", "involved") and f not in wins
    ]
    long_term = [f for f in result.sorted_findings() if f.severity.rank <= 2]

    def block(title, subtitle, items):
        if not items:
            return ""
        lis = "".join(f"<li>{_chip(f.severity)} {E(f.title)}</li>" for f in items[:12])
        return (
            f'<div class="card"><h3 style="font-size:15px;margin-bottom:4px">{title}</h3>'
            f'<p class="note" style="margin-bottom:10px">{subtitle}</p>'
            f'<ul style="margin:0;padding-left:18px">{lis}</ul></div>'
        )

    parts = [
        block("Phase 1 &mdash; Immediate (this week)",
              "High-impact items that are cheap to fix. These alone will move the score the most.",
              wins),
        block("Phase 2 &mdash; Short term (2&ndash;4 weeks)",
              "Structural fixes that need development time or a change in how the app is built.",
              medium_term),
        block("Phase 3 &mdash; Ongoing hardening",
              "Lower-risk items and hygiene improvements to fold into the normal release cycle.",
              long_term),
    ]
    return "".join(parts) or '<div class="card"><p>No remediation items recorded.</p></div>'


def _proposal(result: ScanResult) -> str:
    c = result.counts()
    wins = len(quick_wins(result))
    total = sum(c.values())
    return f"""
<section class="page-break">
  <div class="sec-head"><span class="num">07</span><h2>Recommended engagement</h2></div>
  <div class="card">
    <p>This report covers <strong>{total} findings</strong>, of which <strong>{wins}</strong> are
    high-impact and quick to fix. The following packages are structured around that workload.
    Prices are to be agreed; the scope column is derived from the findings above.</p>
    <table style="margin-top:14px">
      <thead><tr><th>Package</th><th>Scope</th><th>Indicative price</th></tr></thead>
      <tbody>
        <tr><td><strong>Essential</strong></td>
            <td>Fix all Critical and High findings ({c['critical'] + c['high']} items), re-test,
                written verification report</td>
            <td class="num">___________</td></tr>
        <tr><td><strong>Complete</strong></td>
            <td>Everything in Essential plus all Medium findings ({c['medium']} items), security
                header rollout, dependency upgrades</td>
            <td class="num">___________</td></tr>
        <tr><td><strong>Retainer</strong></td>
            <td>Complete remediation plus monthly re-scan, patch monitoring and a quarterly
                review call</td>
            <td class="num">___________</td></tr>
      </tbody>
    </table>
    <h4 style="margin-top:20px">Deliverables</h4>
    <ul>
      <li>Fixed code / configuration, deployed and verified on your server</li>
      <li>A follow-up scan proving each finding is closed (before/after score comparison)</li>
      <li>Short handover note so your team can maintain the fixes</li>
    </ul>
    <h4>Assumptions</h4>
    <ul>
      <li>Work is performed on a staging copy where possible, then promoted to production</li>
      <li>You provide access to the codebase or server configuration for the fixes</li>
      <li>Third-party services (hosting, DNS, payment gateway) are configured by their owners</li>
    </ul>
  </div>
</section>"""


def _appendix(result: ScanResult) -> str:
    md = result.metadata
    rows = []
    for key, label in (
        ("ip_addresses", "Resolved IPs"),
        ("allowed_methods", "Allowed HTTP methods"),
        ("spf", "SPF record"),
        ("dmarc", "DMARC record"),
        ("dkim_selectors", "DKIM selectors found"),
        ("caa", "CAA records"),
        ("mx", "MX records"),
        ("waf", "WAF / CDN detected"),
        ("security_txt", "security.txt present"),
        ("subdomains", "Subdomains discovered"),
    ):
        if key in md and md[key] not in (None, [], "", False):
            val = md[key]
            if isinstance(val, list):
                val = ", ".join(str(v) for v in val[:8]) + (" …" if len(val) > 8 else "")
            rows.append(f"<tr><td><strong>{label}</strong></td><td>{E(str(val))}</td></tr>")

    tls = md.get("tls") or {}
    if tls:
        rows.append(
            "<tr><td><strong>TLS</strong></td><td>"
            f"{E(str(tls.get('protocol')))} &middot; {E(str(tls.get('cipher'))) } &middot; "
            f"expires {E(str(tls.get('not_after'))) } ({tls.get('days_left')} days)</td></tr>"
        )

    hdrs = md.get("response_headers") or {}
    hdr_html = "".join(
        f"<tr><td><code>{E(k)}</code></td><td>{E(str(v)[:160])}</td></tr>" for k, v in hdrs.items()
    )

    pages = result.pages_scanned[:40]
    page_html = "".join(f"<li><code>{E(p)}</code></li>" for p in pages)

    return f"""
<section class="page-break">
  <div class="sec-head"><span class="num">08</span><h2>Appendix</h2></div>
  <div class="card">
    <h3 style="font-size:15px;margin-bottom:10px">Infrastructure observations</h3>
    <table><tbody>{''.join(rows) or '<tr><td>No data</td></tr>'}</tbody></table>
  </div>
  <div class="card">
    <h3 style="font-size:15px;margin-bottom:10px">Response headers observed</h3>
    <table><tbody>{hdr_html or '<tr><td>No headers captured</td></tr>'}</tbody></table>
  </div>
  <div class="card">
    <h3 style="font-size:15px;margin-bottom:10px">Pages crawled ({len(result.pages_scanned)})</h3>
    <ul style="margin:0;padding-left:18px;font-size:12px">{page_html or '<li>none</li>'}</ul>
  </div>
</section>"""


def _methodology(result: ScanResult) -> str:
    return f"""
<section>
  <div class="sec-head"><span class="num">09</span><h2>Methodology, scope &amp; limitations</h2></div>
  <div class="card two-col">
    <div>
      <h3 style="font-size:14px;margin-bottom:8px">What was tested</h3>
      <ul style="margin:0;padding-left:18px;font-size:12.5px">
        <li>Transport encryption, certificate validity and protocol support</li>
        <li>HTTP security headers, cookie attributes and browser hardening</li>
        <li>Server configuration: HTTP methods, CORS policy, error handling, host header trust</li>
        <li>Exposure of backups, configuration files, repositories and admin panels</li>
        <li>Technology fingerprinting and outdated component detection</li>
        <li>Client-side content: mixed content, leaked secrets, third-party script integrity</li>
        <li>DNS and email authentication: SPF, DMARC, DKIM, CAA, DNSSEC</li>
        <li>Non-destructive injection probes on discovered parameters
            (reflected XSS, SQL error signatures, open redirect, path traversal, template injection, CRLF)</li>
      </ul>
    </div>
    <div>
      <h3 style="font-size:14px;margin-bottom:8px">What this scan does not replace</h3>
      <ul style="margin:0;padding-left:18px;font-size:12.5px">
        <li>Authenticated testing of logged-in roles and privilege boundaries</li>
        <li>Business-logic abuse (price manipulation, workflow bypass, race conditions)</li>
        <li>Mobile application and API client testing</li>
        <li>Source-code review and infrastructure / network penetration testing</li>
        <li>Social engineering and physical access</li>
      </ul>
      <p class="note" style="margin-top:10px">
        Findings are based on external observation only. Absence of a finding does not prove
        absence of a vulnerability.
      </p>
    </div>
  </div>
  <div class="card">
    <h3 style="font-size:14px;margin-bottom:8px">How severity is assigned</h3>
    <table>
      <tbody>
        <tr><td style="width:110px">{_chip(Severity.CRITICAL)}</td>
            <td>Direct path to full compromise or mass data disclosure. Exploitable by an
                unskilled attacker, often without authentication. Fix immediately.</td></tr>
        <tr><td>{_chip(Severity.HIGH)}</td>
            <td>Serious weakness that leads to account or data compromise, or a clear compliance
                failure. Fix within days.</td></tr>
        <tr><td>{_chip(Severity.MEDIUM)}</td>
            <td>Weakens defences or requires chaining with another flaw. Fix within weeks.</td></tr>
        <tr><td>{_chip(Severity.LOW)}</td>
            <td>Hardening gap with limited direct impact. Fix on a normal maintenance cycle.</td></tr>
        <tr><td>{_chip(Severity.INFO)}</td>
            <td>Observation, best-practice note, or context for the other findings.</td></tr>
      </tbody>
    </table>
  </div>
  <div class="card">
    <h3 style="font-size:14px;margin-bottom:8px">Authorisation &amp; conduct</h3>
    <p style="font-size:12.5px">
      Testing was carried out with the authorisation of the site owner. All probes were
      non-destructive: no data was created, modified or deleted, no authentication was bypassed,
      and no denial-of-service or brute-force activity was performed. Request rate was limited
      throughout. Scan ID <strong>{E(result.scan_id)}</strong>, performed
      {E(_dt.datetime.fromtimestamp(result.started).strftime('%d %B %Y, %H:%M'))} in
      {round(result.duration)}s over {result.requests_made} requests.
    </p>
  </div>
</section>"""


def render_html(result: ScanResult, include_proposal: bool = False) -> str:
    findings = result.sorted_findings()
    counts = result.counts()
    date = _dt.datetime.fromtimestamp(result.started).strftime("%d %B %Y")
    detail = "".join(_finding_card(f, i) for i, f in enumerate(findings, 1))
    if not detail:
        detail = '<div class="card"><p>No findings were recorded.</p></div>'

    proposal = _proposal(result) if include_proposal else ""
    sec = 7 if include_proposal else 0
    appendix_num = "08" if include_proposal else "07"
    method_num = "09" if include_proposal else "08"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Assessment &mdash; {E(result.host)}</title>
<style>{CSS}</style>
</head>
<body>
<div class="wrap">

  <div class="cover">
    <div class="kicker">Web Application Security Assessment</div>
    <h1>Security Assessment Report</h1>
    <div class="target">{E(result.target)}</div>
    <div class="grid">
      <div><dt>Report ID</dt><dd>{E(result.scan_id)}</dd></div>
      <div><dt>Date</dt><dd>{E(date)}</dd></div>
      <div><dt>Prepared for</dt><dd>{E(result.client or 'Site Owner')}</dd></div>
      <div><dt>Prepared by</dt><dd>{E(result.auditor or 'Security Consultant')}</dd></div>
      <div><dt>Findings</dt><dd>{len(findings)}</dd></div>
    </div>
    <div class="grade-badge">
      <div class="g">{E(result.grade())}</div>
      <div class="l">Security grade</div>
    </div>
  </div>

  <section>
    <div class="sec-head"><span class="num">01</span><h2>Executive summary</h2></div>
    <div class="card">{_exec_summary(result)}</div>
  </section>

  <section>
    <div class="sec-head"><span class="num">02</span><h2>Risk overview</h2></div>
    <div class="score-row">
      <div class="card gauge-box">
        {_gauge(result.risk_score())}
        <div style="margin-top:12px;text-align:center;font-size:11.5px;color:var(--muted)">
          {E(result.grade_verdict())}
        </div>
      </div>
      <div class="stat-grid">
        <div class="stat"><div class="n" style="color:var(--critical)">{counts['critical']}</div><div class="t">Critical</div></div>
        <div class="stat"><div class="n" style="color:var(--high)">{counts['high']}</div><div class="t">High</div></div>
        <div class="stat"><div class="n" style="color:var(--medium)">{counts['medium']}</div><div class="t">Medium</div></div>
        <div class="stat"><div class="n" style="color:var(--low)">{counts['low']}</div><div class="t">Low</div></div>
        <div class="stat"><div class="n" style="color:var(--info)">{counts['info']}</div><div class="t">Info</div></div>
        <div class="stat"><div class="n">{result.requests_made}</div><div class="t">Requests</div></div>
      </div>
    </div>
    <div class="card" style="margin-top:14px">
      <h3 style="font-size:14px;margin-bottom:10px">Severity distribution</h3>
      {_bars(counts)}
    </div>
  </section>

  <section>
    <div class="sec-head"><span class="num">03</span><h2>Findings summary</h2></div>
    <div class="card" style="padding:12px 8px">{_summary_table(findings)}</div>
  </section>

  <section class="page-break">
    <div class="sec-head"><span class="num">04</span><h2>Detailed findings</h2></div>
    {detail}
  </section>

  <section>
    <div class="sec-head"><span class="num">05</span><h2>Remediation roadmap</h2></div>
    {_roadmap(result)}
  </section>

  <section>
    <div class="sec-head"><span class="num">06</span><h2>Compliance mapping</h2></div>
    <div class="card">
      <p style="font-size:12.5px">Findings mapped to OWASP Top 10 (2021) categories, for use in
      audits and customer security questionnaires.</p>
      {_owasp_table(findings)}
    </div>
  </section>

  {proposal}
  {_appendix(result)}
  {_methodology(result)}

  <footer class="rep">
    <span>{E(result.scan_id)} &middot; VulnScope automated assessment</span>
    <span>External, non-intrusive testing &middot; {E(date)}</span>
  </footer>
</div>
</body>
</html>"""


def _owasp_table(findings: List[Finding]) -> str:
    buckets: Dict[str, List[Finding]] = {}
    for f in findings:
        key = f.owasp or "Unmapped"
        buckets.setdefault(key, []).append(f)
    rows = []
    for cat in sorted(buckets, key=lambda k: -max(f.severity.rank for f in buckets[k])):
        items = buckets[cat]
        worst = max(items, key=lambda f: f.severity.rank).severity
        rows.append(
            f"<tr><td>{_chip(worst)}</td><td><strong>{E(cat)}</strong></td>"
            f"<td class='num'>{len(items)}</td></tr>"
        )
    return (
        "<table style='margin-top:10px'><thead><tr><th>Worst severity</th><th>OWASP category</th>"
        "<th>Findings</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )


# ---------------------------------------------------------------------------
def render_markdown(result: ScanResult) -> str:
    c = result.counts()
    lines = [
        f"# Security Assessment Report",
        "",
        f"**Target:** {result.target}  ",
        f"**Report ID:** {result.scan_id}  ",
        f"**Date:** {_dt.datetime.fromtimestamp(result.started).strftime('%d %B %Y')}  ",
        f"**Risk score:** {result.risk_score()}/100 (grade {result.grade()})  ",
        f"**Findings:** {c['critical']} critical, {c['high']} high, {c['medium']} medium, "
        f"{c['low']} low, {c['info']} info",
        "",
        "---",
        "",
        "## Findings",
        "",
        "| # | Severity | Finding | Category | CVSS |",
        "|---|----------|---------|----------|------|",
    ]
    for i, f in enumerate(result.sorted_findings(), 1):
        lines.append(
            f"| {i} | {f.severity.label} | {f.title} | {f.category} | "
            f"{('%.1f' % f.cvss) if f.cvss else '-'} |"
        )
    lines.append("")
    for i, f in enumerate(result.sorted_findings(), 1):
        lines += [
            f"## {i}. {f.title}",
            "",
            f"**Severity:** {f.severity.label} · **CVSS:** {f.cvss or '-'} · **{f.cwe}** · {f.owasp}",
            "",
            f"**What we found:** {f.description}",
            "",
        ]
        if f.impact:
            lines += [f"**Impact:** {f.impact}", ""]
        if f.evidence:
            lines.append("**Evidence:**")
            lines += [f"- `{e}`" for e in f.evidence]
            lines.append("")
        if f.remediation:
            lines += ["**Remediation:**", "", "```", f.remediation, "```", ""]
    return "\n".join(lines)


def write_reports(
    result: ScanResult,
    outdir: str,
    formats: List[str] = ("html", "json", "md"),
    include_proposal: bool = False,
) -> List[str]:
    os.makedirs(outdir, exist_ok=True)
    stamp = _dt.datetime.fromtimestamp(result.started).strftime("%Y%m%d-%H%M%S")
    base = os.path.join(outdir, f"vulnscope-{result.host.replace('.', '-')}-{stamp}")
    written: List[str] = []
    if "html" in formats:
        path = base + ".html"
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(render_html(result, include_proposal))
        written.append(path)
    if "json" in formats:
        path = base + ".json"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(result.to_dict(), fh, indent=2, ensure_ascii=False)
        written.append(path)
    if "md" in formats:
        path = base + ".md"
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(render_markdown(result))
        written.append(path)
    return written
