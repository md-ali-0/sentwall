"""Report rendering: a self-contained, print-ready HTML report plus JSON, Markdown, SARIF, and CSV."""
from __future__ import annotations

import datetime as _dt
import html
import json
import os
from typing import Dict, List

from .models import EFFORT_LABEL, SEVERITY_COLOR, Finding, ScanResult, Severity, quick_wins
from .proposal import generate_proposal_html, generate_proposal_markdown

E = html.escape

CSS = """
:root{
  --ink:#0f172a; --body:#25324a; --muted:#64748b; --line:#e2e8f0;
  --bg:#f4f6fa; --card:#ffffff; --accent:#0f766e; --accent-soft:#ecfdf5;
  --critical:#8b1a1a; --high:#c62828; --medium:#d97706; --low:#2563eb; --info:#64748b;
  --code-bg:#0f172a; --code-text:#e2e8f0;
}
[data-theme="dark"]{
  --ink:#f8fafc; --body:#cbd5e1; --muted:#94a3b8; --line:#334155;
  --bg:#090d16; --card:#131c2e; --accent:#2dd4bf; --accent-soft:#134e48;
  --code-bg:#050811; --code-text:#f1f5f9;
}
*{box-sizing:border-box}
body{
  margin:0; background:var(--bg); color:var(--body);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  font-size:14px; line-height:1.62; -webkit-font-smoothing:antialiased;
  transition:background .2s ease, color .2s ease;
}
.wrap{max-width:1050px; margin:0 auto; padding:32px 20px 80px}
h1,h2,h3,h4{color:var(--ink); margin:0; line-height:1.3; font-weight:650; letter-spacing:-0.01em}
p{margin:0 0 12px}
a{color:var(--accent); text-decoration:none}
code,pre{font-family:"SFMono-Regular",Consolas,"Liberation Mono",Menlo,monospace}
pre{
  background:var(--code-bg); color:var(--code-text); padding:14px 16px; border-radius:8px;
  font-size:12px; line-height:1.55; overflow-x:auto; white-space:pre-wrap;
  word-break:break-word; margin:8px 0 0;
}
pre.fix{background:var(--card); color:var(--ink); border:1px solid var(--line)}

/* ---------- top nav & controls ---------- */
.top-toolbar{display:flex; justify-content:space-between; align-items:center; margin-bottom:18px}
.brand{font-size:18px; font-weight:800; color:var(--ink); display:flex; align-items:center; gap:8px}
.brand .dot{width:10px; height:10px; background:var(--accent); border-radius:50%}
.actions-bar{display:flex; gap:10px; align-items:center}
.btn{
  background:var(--card); color:var(--ink); border:1px solid var(--line);
  padding:6px 14px; border-radius:8px; font-size:12px; font-weight:600; cursor:pointer;
  transition:all .15s ease;
}
.btn:hover{border-color:var(--accent); color:var(--accent)}
.btn-primary{background:var(--accent); color:#fff; border-color:var(--accent)}
.btn-primary:hover{opacity:.9; color:#fff}

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
  width:112px; height:112px; background:var(--card); border-radius:50%;
  display:grid; place-items:center; text-align:center;
}
.gauge .val{font-size:34px; font-weight:750; color:var(--ink); line-height:1}
.gauge .lbl{font-size:9px; letter-spacing:.16em; text-transform:uppercase; color:var(--muted); margin-top:4px}
.stat-grid{flex:1; display:grid; grid-template-columns:repeat(auto-fit,minmax(120px,1fr)); gap:10px}
.stat{background:var(--card); border:1px solid var(--line); border-radius:10px; padding:14px 16px}
.stat .n{font-size:26px; font-weight:750; line-height:1.1}
.stat .t{font-size:11px; color:var(--muted); letter-spacing:.06em; text-transform:uppercase; margin-top:2px}

/* ---------- financial risk card ---------- */
.fin-grid{display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:14px; margin-top:14px}
.fin-item{background:var(--accent-soft); border:1px solid var(--line); border-radius:10px; padding:14px 16px}
.fin-item .lbl{font-size:11px; text-transform:uppercase; letter-spacing:.08em; color:var(--muted); margin-bottom:4px}
.fin-item .val{font-size:22px; font-weight:800; color:var(--ink)}

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
.bar-track{height:9px; background:var(--line); border-radius:6px; overflow:hidden}
.bar-fill{height:100%; border-radius:6px}
.bar-n{text-align:right; font-weight:700; color:var(--ink)}

/* ---------- interactive filter bar ---------- */
.filter-bar{display:flex; flex-wrap:wrap; gap:10px; align-items:center; margin-bottom:16px}
.filter-pill{
  background:var(--card); border:1px solid var(--line); padding:6px 14px; border-radius:999px;
  font-size:12px; font-weight:600; cursor:pointer; color:var(--muted);
}
.filter-pill.active{background:var(--accent); color:#fff; border-color:var(--accent)}
.search-input{
  flex:1; min-width:200px; background:var(--card); border:1px solid var(--line);
  padding:8px 14px; border-radius:8px; font-size:13px; color:var(--ink);
}

/* ---------- table ---------- */
table{width:100%; border-collapse:collapse; font-size:12.5px}
th{
  text-align:left; font-size:10px; letter-spacing:.1em; text-transform:uppercase;
  color:var(--muted); border-bottom:2px solid var(--line); padding:8px 10px; font-weight:700;
}
td{padding:9px 10px; border-bottom:1px solid var(--line); vertical-align:top}
tr:last-child td{border-bottom:none}
td.num{text-align:right; white-space:nowrap}

/* ---------- finding ---------- */
.finding{
  background:var(--card); border:1px solid var(--line); border-left:5px solid var(--info);
  border-radius:10px; padding:20px 22px; margin-bottom:14px; break-inside:avoid;
  transition:all .15s ease;
}
.finding.critical{border-left-color:var(--critical)}
.finding.high{border-left-color:var(--high)}
.finding.medium{border-left-color:var(--medium)}
.finding.low{border-left-color:var(--low)}
.finding.info{border-left-color:var(--info)}
.finding header{display:flex; align-items:center; gap:10px; margin-bottom:8px}
.finding header h3{font-size:15px; margin:0}
.finding .tags{font-size:11px; color:var(--muted); margin-bottom:12px}
.finding h4{font-size:12px; text-transform:uppercase; letter-spacing:.08em; color:var(--muted);
  margin:12px 0 4px}
.finding ul.evidence{margin:0; padding-left:18px; font-family:"SFMono-Regular",Consolas,monospace;
  font-size:12px; color:var(--ink)}
.finding ul.evidence li{word-break:break-all; margin-bottom:4px}
.finding .foot{display:flex; gap:16px; flex-wrap:wrap; margin-top:14px; padding-top:12px;
  border-top:1px solid var(--line); font-size:11px; color:var(--muted)}

.poc-box{display:flex; gap:8px; margin-top:10px}
.btn-copy{
  background:var(--line); border:none; padding:4px 10px; border-radius:6px;
  font-size:11px; font-weight:600; cursor:pointer; color:var(--ink);
}
.btn-copy:hover{background:var(--accent); color:#fff}

/* ---------- pitch cards ---------- */
.pitch-grid{display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:18px; margin-top:20px}
.pitch-card{
  background:var(--card); border:1px solid var(--line); border-radius:14px; padding:24px;
  position:relative; display:flex; flex-direction:column;
}
.pitch-card.featured{border:2px solid var(--accent); box-shadow:0 8px 30px rgba(15,118,110,.12)}
.pkg-badge{display:inline-block; font-size:10px; font-weight:700; text-transform:uppercase;
  letter-spacing:.1em; color:var(--accent); margin-bottom:8px}
.pitch-card h3{font-size:18px; margin-bottom:6px}
.pitch-card .price{font-size:28px; font-weight:800; color:var(--ink); margin:8px 0 2px}
.pitch-card .hours{font-size:12px; color:var(--muted); margin-bottom:16px}
.deliverables{margin:0 0 20px; padding-left:18px; font-size:12.5px; flex:1}
.deliverables li{margin-bottom:8px}

@media print{
  body{background:#fff; color:#0f172a}
  .top-toolbar, .filter-bar, .poc-box, .btn{display:none !important}
  .wrap{max-width:100%; padding:0}
  .card{border:1px solid #cbd5e1; page-break-inside:avoid}
  .finding{page-break-inside:avoid}
}
"""

JS = """
function setTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('vulnscope_theme', theme);
}
function toggleTheme() {
  const cur = document.documentElement.getAttribute('data-theme') || 'light';
  setTheme(cur === 'dark' ? 'light' : 'dark');
}
function filterSeverity(sev) {
  document.querySelectorAll('.filter-pill').forEach(p => p.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.finding').forEach(el => {
    if (sev === 'all' || el.classList.contains(sev)) {
      el.style.display = '';
    } else {
      el.style.display = 'none';
    }
  });
}
function searchFindings() {
  const q = document.getElementById('findingSearch').value.toLowerCase();
  document.querySelectorAll('.finding').forEach(el => {
    const text = el.innerText.toLowerCase();
    el.style.display = text.includes(q) ? '' : 'none';
  });
}
function copyText(str) {
  navigator.clipboard.writeText(str).then(() => {
    alert('Copied to clipboard: ' + str);
  });
}
window.addEventListener('DOMContentLoaded', () => {
  const saved = localStorage.getItem('vulnscope_theme');
  if (saved) document.documentElement.setAttribute('data-theme', saved);
});
"""


def _chip(sev: Severity) -> str:
    return f'<span class="chip {sev.value}">{sev.label}</span>'


def _cover(result: ScanResult) -> str:
    grade = result.grade()
    date_str = _dt.datetime.fromtimestamp(result.started).strftime("%d %B %Y")
    auditor = result.auditor or "Automated Assessment Engine"
    client = result.client or "Executive Briefing"

    return f"""
<div class="top-toolbar">
  <div class="brand"><span class="dot"></span>VulnScope Enterprise</div>
  <div class="actions-bar">
    <button class="btn" onclick="toggleTheme()">Toggle Theme</button>
    <button class="btn btn-primary" onclick="window.print()">Print / PDF</button>
  </div>
</div>
<div class="cover">
  <div class="kicker">Confidential Security Assessment Report</div>
  <h1>{E(result.host)}</h1>
  <div class="target">{E(result.target)}</div>
  <dl class="grid">
    <div><dt>Report ID</dt><dd>{E(result.scan_id)}</dd></div>
    <div><dt>Date</dt><dd>{date_str}</dd></div>
    <div><dt>Assessed For</dt><dd>{E(client)}</dd></div>
    <div><dt>Assessor</dt><dd>{E(auditor)}</dd></div>
    <div><dt>Profile</dt><dd>{E(result.profile.capitalize())}</dd></div>
    <div><dt>Requests</dt><dd>{result.requests_made}</dd></div>
  </dl>
  <div class="grade-badge">
    <div class="g">{grade}</div>
    <div class="l">Security Grade</div>
  </div>
</div>"""


def _score_overview(result: ScanResult) -> str:
    score = result.risk_score()
    counts = result.counts()
    fin = result.financial_risk()

    # Gauge ring background gradient
    deg = int(score * 3.6)
    gauge_bg = f"conic-gradient(#c62828 0deg {deg}deg, var(--line) {deg}deg 360deg)"

    return f"""
<section>
  <div class="sec-head"><span class="num">01</span><h2>Executive Security Posture</h2></div>
  <div class="score-row">
    <div class="card gauge-box">
      <div class="gauge" style="background:{gauge_bg}">
        <div class="inner">
          <div class="val">{score}</div>
          <div class="lbl">Risk / 100</div>
        </div>
      </div>
      <div style="margin-top:14px; text-align:center; font-weight:700; color:var(--ink);">
        {E(result.grade_verdict())}
      </div>
    </div>
    <div class="stat-grid">
      <div class="stat"><div class="n" style="color:var(--critical)">{counts['critical']}</div><div class="t">Critical</div></div>
      <div class="stat"><div class="n" style="color:var(--high)">{counts['high']}</div><div class="t">High</div></div>
      <div class="stat"><div class="n" style="color:var(--medium)">{counts['medium']}</div><div class="t">Medium</div></div>
      <div class="stat"><div class="n" style="color:var(--low)">{counts['low']}</div><div class="t">Low</div></div>
      <div class="stat"><div class="n" style="color:var(--info)">{counts['info']}</div><div class="t">Informational</div></div>
      <div class="stat"><div class="n" style="color:var(--accent)">{len(result.pages_scanned)}</div><div class="t">Pages Audited</div></div>
    </div>
  </div>

  <div class="card" style="margin-top:14px">
    <h3 style="font-size:14px; text-transform:uppercase; letter-spacing:.08em; color:var(--muted)">Financial Risk & Business Impact Forecast</h3>
    <div class="fin-grid">
      <div class="fin-item">
        <div class="lbl">Estimated Breach Likelihood</div>
        <div class="val" style="color:var(--critical)">{fin['breach_probability_pct']}%</div>
      </div>
      <div class="fin-item">
        <div class="lbl">Estimated Financial Exposure</div>
        <div class="val" style="color:var(--high)">${fin['estimated_financial_loss_usd']:,}</div>
      </div>
      <div class="fin-item">
        <div class="lbl">Technical Debt / Fix Time</div>
        <div class="val">{fin['total_remediation_hours']} Hours</div>
      </div>
      <div class="fin-item">
        <div class="lbl">Recommended Urgency</div>
        <div class="val" style="font-size:16px; color:var(--accent)">{fin['priority_action']}</div>
      </div>
    </div>
  </div>
</section>"""


def _finding_card(f: Finding, index: int, target: str) -> str:
    evidence = "".join(f"<li>{E(x)}</li>" for x in f.evidence) if f.evidence else "<li>(No raw evidence captured)</li>"
    refs = ""
    if f.references:
        refs = "<h4>References</h4><ul>" + "".join(f'<li><a href="{E(r)}" target="_blank">{E(r)}</a></li>' for r in f.references) + "</ul>"

    curl_poc = f.get_poc_curl(target)
    python_poc = f.get_poc_python(target)

    # Clean patch snippet
    patch_snippet = f.get_remediation_patch("nginx")

    return f"""
<article class="finding {f.severity.value}">
  <header>
    {_chip(f.severity)}
    <h3>{index}. {E(f.title)}</h3>
  </header>
  <div class="tags">
    <strong>Category:</strong> {E(f.category)} &middot;
    <strong>CWE:</strong> {E(f.cwe or 'CWE-None')} &middot;
    <strong>OWASP:</strong> {E(f.owasp or 'OWASP')} &middot;
    <strong>CVSS:</strong> {f.cvss or 'N/A'} &middot;
    <strong>Fix Effort:</strong> {E(f.effort_label)}
  </div>

  <h4>What we observed</h4>
  <p>{E(f.description)}</p>

  {f'<h4>Business Impact</h4><p>{E(f.impact)}</p>' if f.impact else ''}

  <h4>Evidence & Canary Output</h4>
  <ul class="evidence">{evidence}</ul>

  <h4>Automated Verification PoC</h4>
  <div class="poc-box">
    <button class="btn-copy" onclick="copyText({json.dumps(curl_poc)})">Copy cURL Command</button>
    <button class="btn-copy" onclick="copyText({json.dumps(python_poc)})">Copy Python Script</button>
  </div>
  <pre>{E(curl_poc)}</pre>

  <h4>Recommended Remediation Patch</h4>
  <pre class="fix">{E(patch_snippet)}</pre>

  {refs}
</article>"""


def render_html(result: ScanResult, include_proposal: bool = False) -> str:
    cards = "".join(_finding_card(f, i, result.target) for i, f in enumerate(result.sorted_findings(), 1))
    proposal_sec = generate_proposal_html(result) if include_proposal else ""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>VulnScope Security Assessment - {E(result.host)}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>{CSS}</style>
</head>
<body>
<div class="wrap">
  {_cover(result)}
  {_score_overview(result)}

  <section id="findings-section">
    <div class="sec-head">
      <span class="num">02</span>
      <h2>Identified Vulnerabilities & Remediation Steps</h2>
    </div>

    <div class="filter-bar">
      <div class="filter-pill active" onclick="filterSeverity('all')">All ({len(result.findings)})</div>
      <div class="filter-pill" onclick="filterSeverity('critical')">Critical</div>
      <div class="filter-pill" onclick="filterSeverity('high')">High</div>
      <div class="filter-pill" onclick="filterSeverity('medium')">Medium</div>
      <div class="filter-pill" onclick="filterSeverity('low')">Low</div>
      <div class="filter-pill" onclick="filterSeverity('info')">Info</div>
      <input type="text" id="findingSearch" class="search-input" placeholder="Search findings, CVEs, CWEs..." onkeyup="searchFindings()">
    </div>

    <div class="findings-container">
      {cards or '<div class="card"><p>No vulnerabilities detected!</p></div>'}
    </div>
  </section>

  {proposal_sec}
</div>
<script>{JS}</script>
</body>
</html>"""


def render_markdown(result: ScanResult) -> str:
    c = result.counts()
    fin = result.financial_risk()
    lines = [
        f"# VulnScope Comprehensive Security Assessment Report",
        "",
        f"**Target:** `{result.target}`  ",
        f"**Report ID:** `{result.scan_id}`  ",
        f"**Audit Date:** {_dt.datetime.fromtimestamp(result.started).strftime('%d %B %Y')}  ",
        f"**Risk Score:** **{result.risk_score()}/100** (Grade: **{result.grade()}**)  ",
        f"**Financial Exposure:** **${fin['estimated_financial_loss_usd']:,}** ({fin['breach_probability_pct']}% breach probability)  ",
        f"**Findings:** {c['critical']} critical, {c['high']} high, {c['medium']} medium, {c['low']} low, {c['info']} info  ",
        "",
        "---",
        "",
        "## 1. Findings Summary",
        "",
        "| # | Severity | Finding | Category | CVSS | Fix Effort |",
        "|---|----------|---------|----------|------|------------|",
    ]
    for i, f in enumerate(result.sorted_findings(), 1):
        lines.append(
            f"| {i} | {f.severity.label} | {f.title} | {f.category} | "
            f"{('%.1f' % f.cvss) if f.cvss else '-'} | {f.effort_label} |"
        )
    lines.append("\n---\n\n## 2. Detailed Technical Findings\n")
    for i, f in enumerate(result.sorted_findings(), 1):
        lines += [
            f"### {i}. {f.title}",
            "",
            f"**Severity:** {f.severity.label} · **CVSS:** {f.cvss or '-'} · **{f.cwe}** · {f.owasp}",
            "",
            f"**Description:** {f.description}",
            "",
        ]
        if f.impact:
            lines += [f"**Business Impact:** {f.impact}", ""]
        if f.evidence:
            lines.append("**Evidence:**")
            lines += [f"- `{e}`" for e in f.evidence]
            lines.append("")
        lines += [
            "**Verification PoC:**",
            "```bash",
            f.get_poc_curl(result.target),
            "```",
            "",
            "**Remediation Patch:**",
            "```nginx",
            f.get_remediation_patch("nginx"),
            "```",
            "",
        ]
    return "\n".join(lines)


def write_reports(
    result: ScanResult,
    outdir: str,
    formats: List[str] = ("html", "json", "md", "sarif", "csv"),
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

    if "sarif" in formats:
        path = base + ".sarif"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(result.to_sarif(), fh, indent=2)
        written.append(path)

    if "csv" in formats:
        path = base + ".csv"
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(result.to_csv())
        written.append(path)

    if include_proposal or "proposal" in formats:
        prop_path = base + "-proposal.md"
        with open(prop_path, "w", encoding="utf-8") as fh:
            fh.write(generate_proposal_markdown(result))
        written.append(prop_path)

    return written
