"""A small, self-contained stylesheet for the companion reports.

``report.py`` owns the look of the main assessment report and gets redesigned
from time to time — variable names and class names both change. The retest and
recon documents therefore do not import it: they share this file instead, so a
redesign of the main report can never silently break them.
"""
from __future__ import annotations

BASE_CSS = """
:root{
  --ink:#0f172a; --body:#334155; --muted:#64748b; --line:#e2e8f0;
  --bg:#f8fafc; --card:#ffffff; --accent:#10b981;
  --critical:#ef4444; --high:#f97316; --medium:#f59e0b; --low:#3b82f6; --info:#64748b;
}
*{box-sizing:border-box}
body{
  margin:0; background:var(--bg); color:var(--body);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  font-size:13.5px; line-height:1.6; -webkit-font-smoothing:antialiased;
}
.wrap{max-width:1050px; margin:0 auto; padding:30px 20px 70px}
h1,h2,h3,h4{color:var(--ink); margin:0; line-height:1.3; font-weight:700; letter-spacing:-.01em}
p{margin:0 0 12px}
code{font-family:"SFMono-Regular",Consolas,Menlo,monospace; background:#f1f5f9;
  padding:1px 5px; border-radius:4px; font-size:11.5px; color:#334155}
.top-toolbar{display:flex; justify-content:space-between; align-items:center; margin-bottom:16px}
.brand{font-size:16px; font-weight:800; color:var(--ink); display:flex; align-items:center; gap:8px}
.brand .dot{width:9px; height:9px; background:var(--accent); border-radius:50%}
.actions-bar{display:flex; gap:10px; align-items:center}
.btn{background:var(--card); color:var(--ink); border:1px solid var(--line);
  padding:6px 14px; border-radius:6px; font-size:12px; font-weight:600; cursor:pointer;
  transition:border-color .15s ease,color .15s ease}
.btn:hover{border-color:var(--accent); color:var(--accent)}
.btn-primary{background:var(--accent); color:#042f24; font-weight:700; border-color:var(--accent)}
.sec-head{display:flex; align-items:baseline; gap:10px; margin:28px 0 10px;
  padding-bottom:8px; border-bottom:1px solid var(--line)}
.sec-head h2{font-size:15px; letter-spacing:-.01em}
.chip{display:inline-block; padding:1px 8px; border-radius:4px; font-size:10.5px;
  font-weight:700; letter-spacing:.02em; text-transform:uppercase}
.chip.critical{background:rgba(239,68,68,.12); color:#b91c1c}
.chip.high{background:rgba(249,115,22,.14); color:#9a3412}
.chip.medium{background:rgba(245,158,11,.16); color:#92400e}
.chip.low{background:rgba(59,130,246,.12); color:#1d4ed8}
.chip.info{background:rgba(100,116,139,.12); color:#475569}
@media print{ .top-toolbar{display:none} }
"""
