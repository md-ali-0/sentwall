"""Delta comparison engine for baseline and re-assessment scans.

Computes resolved issues, persistent issues, new issues, severity regressions
and score movement, then renders a client-ready Remediation Verification
Report in HTML, Markdown or JSON.

The public names here (``DiffResult``, ``compare_scans``, ``compare_files``)
predate this module's rewrite and are still used by ``scan.py --diff`` and
``ui.render_delta_card``, so their shape is kept stable.
"""
from __future__ import annotations

import datetime as _dt
import html
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .styles import BASE_CSS

E = html.escape

SEVERITIES = ["critical", "high", "medium", "low", "info"]
RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _sev(finding: Dict[str, Any]) -> str:
    return str(finding.get("severity") or "info").lower()


def _rank(finding: Dict[str, Any]) -> int:
    return RANK.get(_sev(finding), 0)


def _title(finding: Dict[str, Any]) -> str:
    return str(finding.get("title") or finding.get("key") or "Unnamed finding")


# ---------------------------------------------------------------- result
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
    regressed: List[Dict[str, Any]] = field(default_factory=list)
    improved: List[Dict[str, Any]] = field(default_factory=list)
    baseline_findings: List[Dict[str, Any]] = field(default_factory=list)
    current_findings: List[Dict[str, Any]] = field(default_factory=list)
    baseline_started: str = ""
    current_started: str = ""
    client: str = ""
    auditor: str = ""
    generated_at: str = field(default_factory=lambda: _dt.datetime.now().isoformat())

    # -- derived ---------------------------------------------------------
    @property
    def host(self) -> str:
        return re.sub(r"^\w+://", "", self.target).split("/")[0] or "target"

    @property
    def verdict(self) -> str:
        if self.score_change < -30:
            return "Exceptional improvement: Major attack surface eliminated."
        if self.score_change < 0:
            return "Positive progress: Risk score reduced."
        if self.score_change == 0:
            return "No change in aggregate risk posture."
        return "Regression alert: Risk score increased since baseline."

    @property
    def fix_rate(self) -> float:
        total = len(self.baseline_findings) or (len(self.resolved) + len(self.persistent))
        return (len(self.resolved) / total * 100.0) if total else 0.0

    def counts(self, side: str = "baseline") -> Dict[str, int]:
        source = self.baseline_findings if side == "baseline" else self.current_findings
        out = {s: 0 for s in SEVERITIES}
        for f in source:
            key = _sev(f)
            out[key] = out.get(key, 0) + 1
        return out

    def still_open(self) -> List[Dict[str, Any]]:
        """Persistent findings whose severity did not change either way."""
        moved = {id(f) for f in self.regressed} | {id(f) for f in self.improved}
        return [f for f in self.persistent if id(f) not in moved]

    def remaining_at_or_above(self, severity: str = "high") -> int:
        floor = RANK.get(severity, 0)
        return sum(1 for f in self.persistent + self.new_findings if _rank(f) >= floor)

    # -- serialisation ---------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        return {
            "baseline_id": self.baseline_id,
            "current_id": self.current_id,
            "target": self.target,
            "host": self.host,
            "baseline_score": self.baseline_score,
            "current_score": self.current_score,
            "score_change": self.score_change,
            "baseline_grade": self.baseline_grade,
            "current_grade": self.current_grade,
            "verdict": self.verdict,
            "fix_rate_percent": round(self.fix_rate, 1),
            "resolved_count": len(self.resolved),
            "persistent_count": len(self.persistent),
            "new_count": len(self.new_findings),
            "regressed_count": len(self.regressed),
            "improved_count": len(self.improved),
            "remaining_high_or_critical": self.remaining_at_or_above("high"),
            "severity_baseline": self.counts("baseline"),
            "severity_current": self.counts("current"),
            "resolved": self.resolved,
            "persistent": self.persistent,
            "new_findings": self.new_findings,
            "regressed": self.regressed,
            "improved": self.improved,
            "generated_at": self.generated_at,
        }

    def to_markdown(self) -> str:
        return render_markdown(self)


# ---------------------------------------------------------------- compare
def _index(findings: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        key = str(f.get("key") or "").strip() or re.sub(
            r"[^a-z0-9]+", "-", _title(f).lower()
        ).strip("-")
        if key and key not in out:
            out[key] = f
    return out


def compare_scans(baseline: Dict[str, Any], current: Dict[str, Any]) -> DiffResult:
    """Compare two scan dictionaries and compute the remediation delta."""
    old = _index(baseline.get("findings", []))
    new = _index(current.get("findings", []))

    resolved: List[Dict[str, Any]] = []
    persistent: List[Dict[str, Any]] = []
    regressed: List[Dict[str, Any]] = []
    improved: List[Dict[str, Any]] = []

    for key, f in old.items():
        if key not in new:
            resolved.append(f)
            continue
        g = new[key]
        persistent.append(g)
        before_rank, after_rank = _rank(f), _rank(g)
        if after_rank > before_rank:
            regressed.append({**g, "previous_severity": _sev(f)})
        elif after_rank < before_rank:
            improved.append({**g, "previous_severity": _sev(f)})

    new_findings = [f for key, f in new.items() if key not in old]

    b_score = int(baseline.get("risk_score", 0) or 0)
    c_score = int(current.get("risk_score", 0) or 0)

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
        regressed=regressed,
        improved=improved,
        baseline_findings=list(baseline.get("findings", [])),
        current_findings=list(current.get("findings", [])),
        baseline_started=baseline.get("started", ""),
        current_started=current.get("started", ""),
        client=current.get("client") or baseline.get("client") or "",
        auditor=current.get("auditor") or baseline.get("auditor") or "",
    )


def compare_files(baseline_path: str, current_path: str) -> DiffResult:
    with open(baseline_path, "r", encoding="utf-8") as fb:
        b_data = json.load(fb)
    with open(current_path, "r", encoding="utf-8") as fc:
        c_data = json.load(fc)
    return compare_scans(b_data, c_data)


# ---------------------------------------------------------------- helpers
def _when(iso: str) -> str:
    try:
        return _dt.datetime.fromisoformat(iso).strftime("%d %B %Y, %H:%M")
    except (TypeError, ValueError):
        return iso or "unknown"


def _delta(before: int, after: int) -> str:
    d = after - before
    return f"+{d}" if d > 0 else str(d)


def _grade_colour(grade: str) -> str:
    return {"A": "#10b981", "B": "#22c55e", "C": "#f59e0b",
            "D": "#f97316", "E": "#ef4444", "F": "#dc2626"}.get(grade, "#64748b")


def _sort(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(findings, key=lambda f: (-_rank(f), _title(f).lower()))


# ---------------------------------------------------------------- styles
RETEST_CSS = """
.rt-head{padding:24px 0 18px;border-bottom:1px solid var(--line);margin-bottom:22px}
.rt-kicker{font-size:11px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;
  color:var(--accent);margin-bottom:10px}
.rt-head h1{font-size:29px;letter-spacing:-0.02em;margin-bottom:6px}
.rt-sub{font-size:12.5px;color:var(--muted);font-family:"SFMono-Regular",Consolas,monospace}
.rt-meta{display:flex;flex-wrap:wrap;gap:8px 34px;margin:20px 0 0;padding:0}
.rt-meta div{min-width:118px}
.rt-meta dt{font-size:10.5px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;
  color:var(--muted);margin-bottom:3px}
.rt-meta dd{margin:0;font-size:13px;color:var(--ink);font-weight:600}
.rt-verdict{display:flex;align-items:center;gap:34px;flex-wrap:wrap;
  background:var(--card);border:1px solid var(--line);border-radius:12px;padding:24px 26px;margin-bottom:20px}
.rt-grades{display:flex;align-items:center;gap:14px}
.rt-g{width:74px;height:74px;border-radius:14px;display:flex;align-items:center;justify-content:center;
  font-size:32px;font-weight:800;line-height:1}
.rt-g-wrap{text-align:center}
.rt-g-wrap .cap{font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;
  color:var(--muted);margin-top:7px}
.rt-arrow{font-size:20px;color:var(--muted)}
.rt-stats{display:flex;gap:28px;flex-wrap:wrap}
.rt-stat .n{font-size:25px;font-weight:800;color:var(--ink);line-height:1.1}
.rt-stat .l{font-size:10.5px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
.rt-counters{display:grid;grid-template-columns:repeat(auto-fit,minmax(132px,1fr));gap:12px;margin-bottom:28px}
.rt-count{background:var(--card);border:1px solid var(--line);border-left-width:4px;
  border-radius:10px;padding:15px 17px}
.rt-count .n{font-size:26px;font-weight:800;line-height:1.1;color:var(--ink)}
.rt-count .l{font-size:11px;font-weight:600;color:var(--muted);margin-top:2px}
.rt-count.fixed{border-left-color:#10b981}
.rt-count.open{border-left-color:#f59e0b}
.rt-count.new{border-left-color:#ef4444}
.rt-count.regressed{border-left-color:#dc2626}
.rt-count.improved{border-left-color:#3b82f6}
.rt-table{width:100%;border-collapse:collapse;font-size:12.5px;margin-top:10px}
.rt-table th{text-align:left;font-size:10.5px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;
  color:var(--muted);padding:8px 10px;border-bottom:1px solid var(--line)}
.rt-table td{padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
.rt-table td.num{text-align:right;font-variant-numeric:tabular-nums;font-weight:600;color:var(--ink)}
.rt-table tr:last-child td{border-bottom:none}
.rt-item{background:var(--card);border:1px solid var(--line);border-left-width:4px;
  border-radius:8px;padding:13px 16px;margin-bottom:9px}
.rt-item.fixed{border-left-color:#10b981}
.rt-item.open{border-left-color:#f59e0b}
.rt-item.new{border-left-color:#ef4444}
.rt-item.regressed{border-left-color:#dc2626}
.rt-item.improved{border-left-color:#3b82f6}
.rt-item h4{font-size:13.5px;margin:0 0 5px}
.rt-item .meta{font-size:11.5px;color:var(--muted);display:flex;gap:12px;flex-wrap:wrap;align-items:center}
.rt-item .why{font-size:12.5px;color:var(--body);margin-top:7px}
.rt-empty{font-size:12.5px;color:var(--muted);font-style:italic;padding:4px 0 2px}
.rt-foot{margin-top:38px;padding-top:16px;border-top:1px solid var(--line);font-size:11.5px;color:var(--muted)}
@media print{
  .top-toolbar{display:none}
  .rt-item,.rt-count,.rt-verdict{break-inside:avoid}
}
"""

STATUS_NOTE = {
    "fixed": "No longer detected on re-scan.",
    "open": "Unchanged — still reproducible exactly as before.",
    "new": "Appeared only in the second scan — check what changed.",
    "regressed": "Severity increased since the baseline.",
    "improved": "Severity reduced but the issue is not gone.",
}


# ---------------------------------------------------------------- markdown
def render_markdown(diff: DiffResult) -> str:
    lines: List[str] = []
    add = lines.append
    cb, ca = diff.counts("baseline"), diff.counts("current")

    add("# Remediation Verification Report")
    add("")
    add(f"**Target:** `{diff.target}`  ")
    add(f"**Client:** {diff.client or '—'}  ")
    add(f"**Assessor:** {diff.auditor or '—'}  ")
    add("")
    add("| | Baseline | Retest |")
    add("|---|---|---|")
    add(f"| Scan ID | `{diff.baseline_id}` | `{diff.current_id}` |")
    add(f"| Date | {_when(diff.baseline_started)} | {_when(diff.current_started)} |")
    add(f"| Risk score | {diff.baseline_score}/100 | {diff.current_score}/100 |")
    add(f"| Grade | {diff.baseline_grade} | {diff.current_grade} |")
    add(f"| Findings | {len(diff.baseline_findings)} | {len(diff.current_findings)} |")
    add("")
    add(f"**Risk delta:** {diff.score_change:+d} points · "
        f"**Fix rate:** {diff.fix_rate:.0f}% · **Verdict:** {diff.verdict}")
    add("")

    add("## Scorecard")
    add("")
    add("| Metric | Count |")
    add("|---|---|")
    add(f"| Resolved | {len(diff.resolved)} |")
    add(f"| Still open | {len(diff.still_open())} |")
    add(f"| Regressed | {len(diff.regressed)} |")
    add(f"| Improved | {len(diff.improved)} |")
    add(f"| New | {len(diff.new_findings)} |")
    add("")

    add("## Severity breakdown")
    add("")
    add("| Severity | Baseline | Retest | Change |")
    add("|---|---|---|---|")
    for sev in SEVERITIES:
        if not cb[sev] and not ca[sev]:
            continue
        add(f"| {sev.capitalize()} | {cb[sev]} | {ca[sev]} | {_delta(cb[sev], ca[sev])} |")
    add("")

    for heading, bucket, status in (
        ("Still open", diff.still_open(), "open"),
        ("Regressed", diff.regressed, "regressed"),
        ("New", diff.new_findings, "new"),
        ("Improved", diff.improved, "improved"),
        ("Resolved", diff.resolved, "fixed"),
    ):
        if not bucket:
            continue
        add(f"## {heading} ({len(bucket)})")
        add("")
        add(f"_{STATUS_NOTE[status]}_")
        add("")
        for f in _sort(bucket):
            extra = ""
            prev = f.get("previous_severity")
            if prev:
                extra = f" ({prev} → {_sev(f)})"
            add(f"- **[{_sev(f).upper()}]** {_title(f)}{extra} — `{f.get('key', '')}`")
        add("")

    add("## Next steps")
    add("")
    remaining = diff.remaining_at_or_above("high")
    if remaining:
        add(f"1. {remaining} high or critical issue(s) are still open — close them before release.")
        add("2. Re-scan after the next round of fixes and compare again.")
        add("3. Keep this report with the baseline; the trend is the evidence.")
    else:
        add("1. No high or critical issues remain open.")
        add("2. Schedule a periodic re-scan to catch regressions early.")
    add("")
    return "\n".join(lines)


# ---------------------------------------------------------------- html
def _grade_block(grade: str, caption: str) -> str:
    colour = _grade_colour(grade)
    return f"""<div class="rt-g-wrap">
      <div class="rt-g" style="background:{colour}1a;color:{colour};border:1px solid {colour}40">{E(grade)}</div>
      <div class="cap">{E(caption)}</div>
    </div>"""


def _item(f: Dict[str, Any], status: str) -> str:
    sev = _sev(f)
    prev = f.get("previous_severity")
    sev_label = f"{prev} &rarr; {sev}" if prev else sev.capitalize()
    chip = f'<span class="chip {sev}">{E(sev.capitalize())}</span>' if prev is None else ""
    return f"""
  <div class="rt-item {status}">
    <h4>{E(_title(f))}</h4>
    <div class="meta">{chip}<span><code>{E(str(f.get('key', '')))}</code></span>
      <span>{E(str(f.get('category', '')))}</span>
      {f'<span>{sev_label}</span>' if prev else ''}</div>
    <div class="why">{E(STATUS_NOTE[status])}</div>
  </div>"""


def _bucket(heading: str, findings: List[Dict[str, Any]], status: str,
            hint: str, empty: str) -> str:
    body = "".join(_item(f, status) for f in _sort(findings)) if findings \
        else f'<div class="rt-empty">{E(empty)}</div>'
    return f"""
<section>
  <div class="sec-head"><h2>{E(heading)} <span style="color:var(--muted);font-weight:600">({len(findings)})</span></h2></div>
  <p style="font-size:12.5px;color:var(--muted);margin:-4px 0 13px">{E(hint)}</p>
  {body}
</section>"""


def render_html(diff: DiffResult) -> str:
    cb, ca = diff.counts("baseline"), diff.counts("current")
    delta_colour = "#10b981" if diff.score_change < 0 else ("#ef4444" if diff.score_change > 0 else "#64748b")

    rows = ""
    for sev in SEVERITIES:
        if not cb[sev] and not ca[sev]:
            continue
        rows += (f"<tr><td><span class='chip {sev}'>{sev.capitalize()}</span></td>"
                 f"<td class='num'>{cb[sev]}</td><td class='num'>{ca[sev]}</td>"
                 f"<td class='num'>{_delta(cb[sev], ca[sev])}</td></tr>")

    remaining = diff.remaining_at_or_above("high")
    verdict_line = (
        f"{remaining} high or critical issue(s) remain open — close these before the next release."
        if remaining else "No high or critical issues remain open."
    )
    total_before = len(diff.baseline_findings)

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Retest — {E(diff.host)}</title>
<style>{BASE_CSS}{RETEST_CSS}</style></head>
<body><div class="wrap">

<div class="top-toolbar">
  <div class="brand"><span class="dot"></span>VulnScope Retest</div>
  <div class="actions-bar"><button class="btn btn-primary" onclick="window.print()">Print / PDF</button></div>
</div>

<header class="rt-head">
  <div class="rt-kicker">Remediation verification</div>
  <h1>{E(diff.host)}</h1>
  <div class="rt-sub">{E(diff.target)}</div>
  <dl class="rt-meta">
    <div><dt>Client</dt><dd>{E(diff.client or '—')}</dd></div>
    <div><dt>Assessor</dt><dd>{E(diff.auditor or '—')}</dd></div>
    <div><dt>Baseline</dt><dd>{E(_when(diff.baseline_started))}</dd></div>
    <div><dt>Retest</dt><dd>{E(_when(diff.current_started))}</dd></div>
  </dl>
</header>

<section class="rt-verdict">
  <div class="rt-grades">
    {_grade_block(diff.baseline_grade, "Before")}
    <div class="rt-arrow">&rarr;</div>
    {_grade_block(diff.current_grade, "After")}
  </div>
  <div class="rt-stats">
    <div class="rt-stat"><div class="n">{diff.baseline_score}</div><div class="l">Score before</div></div>
    <div class="rt-stat"><div class="n">{diff.current_score}</div><div class="l">Score after</div></div>
    <div class="rt-stat"><div class="n" style="color:{delta_colour}">{_delta(diff.baseline_score, diff.current_score)}</div><div class="l">Risk change</div></div>
    <div class="rt-stat"><div class="n">{diff.fix_rate:.0f}%</div><div class="l">Fix rate</div></div>
  </div>
</section>

<div class="rt-counters">
  <div class="rt-count fixed"><div class="n">{len(diff.resolved)}</div><div class="l">Resolved</div></div>
  <div class="rt-count open"><div class="n">{len(diff.still_open())}</div><div class="l">Still open</div></div>
  <div class="rt-count regressed"><div class="n">{len(diff.regressed)}</div><div class="l">Regressed</div></div>
  <div class="rt-count improved"><div class="n">{len(diff.improved)}</div><div class="l">Improved</div></div>
  <div class="rt-count new"><div class="n">{len(diff.new_findings)}</div><div class="l">New</div></div>
</div>

<section>
  <div class="sec-head"><h2>Verdict</h2></div>
  <p>{len(diff.resolved)} of {total_before} findings are resolved. Risk score moved from
  <b>{diff.baseline_score}</b> to <b>{diff.current_score}</b>, grade
  <b>{E(diff.baseline_grade)}</b> to <b>{E(diff.current_grade)}</b>.
  {E(verdict_line)}</p>
</section>

<section>
  <div class="sec-head"><h2>Severity breakdown</h2></div>
  <table class="rt-table">
    <thead><tr><th>Severity</th><th style="text-align:right">Baseline</th>
    <th style="text-align:right">Retest</th><th style="text-align:right">Change</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</section>

{_bucket("Still open", diff.still_open(), "open", "Priority for the next round.", "Nothing outstanding.")}
{_bucket("Regressed", diff.regressed, "regressed", "These got worse — inspect the recent changes.", "No regressions.")}
{_bucket("New", diff.new_findings, "new", "Detected only in the second scan.", "No new findings.")}
{_bucket("Improved", diff.improved, "improved", "Severity reduced but not eliminated.", "None.")}
{_bucket("Resolved", diff.resolved, "fixed", "Confirmed gone on re-scan.", "Nothing resolved yet.")}

<div class="rt-foot">
  Generated {_dt.datetime.now().strftime('%d %B %Y, %H:%M')} · findings matched by stable key ·
  both scans produced by VulnScope against the same target with identical options.
</div>

</div></body></html>"""


# ---------------------------------------------------------------- writing
def write_reports(diff: DiffResult, out_dir: str,
                  formats: Tuple[str, ...] = ("html", "md", "json")) -> List[str]:
    os.makedirs(out_dir, exist_ok=True)
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    safe_host = re.sub(r"[^a-zA-Z0-9.\-_]", "-", diff.host.lower())
    base = os.path.join(out_dir, f"retest-{safe_host}-{stamp}")
    written: List[str] = []

    if "html" in formats:
        path = base + ".html"
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(render_html(diff))
        written.append(path)
    if "md" in formats:
        path = base + ".md"
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(render_markdown(diff))
        written.append(path)
    if "json" in formats:
        path = base + ".json"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(diff.to_dict(), fh, indent=2, ensure_ascii=False)
        written.append(path)
    return written
