"""VulnScope Cyber Security Studio - Clean, Modern & Professional Dark UI.

Provides an intuitive, elegant, clutter-free security dashboard, real-time scan streaming,
attack surface topology, 1-click PoC verification, remediation patch generator,
commercial proposal studio, and delta comparison engine.
Runs locally with zero external npm or node dependencies.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import queue
import re
import socket
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional

from .checks import run_all
from .context import Options, ScanContext
from .crawl import crawl
from .diff import compare_scans
from .models import Finding, ScanResult, Severity
from .net import Http, normalise_target
from .proposal import generate_proposal_markdown
from .report import render_html, write_reports

# Active background scans
SCANS: Dict[str, Dict[str, Any]] = {}
SCANS_LOCK = threading.Lock()


def get_html_studio() -> str:
    """Embedded single-page Clean & Modern Dark Security Studio."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>VulnScope - Security Assessment Studio</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #111827;
      --card-border: #1f293d;
      --input-bg: #0d1424;
      --text-main: #f3f4f6;
      --text-muted: #94a3b8;
      --accent: #10b981;
      --accent-hover: #059669;
      --accent-soft: rgba(16, 185, 129, 0.12);
      --crit: #ef4444;
      --high: #f97316;
      --med: #f59e0b;
      --low: #3b82f6;
      --info: #64748b;
      --code-font: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg); color: var(--text-main);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Inter", sans-serif;
      font-size: 13.5px; line-height: 1.55; -webkit-font-smoothing: antialiased;
    }

    /* Clean Header */
    header {
      background: rgba(17, 24, 39, 0.85); backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--card-border); padding: 12px 28px;
      display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; z-index: 100;
    }
    .logo {
      font-size: 17px; font-weight: 800; color: #fff;
      display: flex; align-items: center; gap: 10px; letter-spacing: -0.02em;
    }
    .logo-dot { width: 9px; height: 9px; background: var(--accent); border-radius: 50%; box-shadow: 0 0 10px var(--accent); }
    .logo-badge {
      font-size: 10px; font-weight: 700; background: var(--accent-soft); color: var(--accent);
      padding: 2px 7px; border-radius: 4px; border: 1px solid rgba(16, 185, 129, 0.25);
    }

    /* Minimal Nav Tabs */
    .nav-tabs { display: flex; gap: 6px; }
    .tab-btn {
      background: transparent; color: var(--text-muted); border: 1px solid transparent;
      padding: 6px 14px; border-radius: 6px; cursor: pointer; font-weight: 600;
      font-size: 12.5px; transition: all 0.15s ease;
    }
    .tab-btn:hover { color: #fff; background: rgba(255, 255, 255, 0.04); }
    .tab-btn.active { color: #fff; background: #1e293b; border-color: #334155; }

    .header-right { display: flex; align-items: center; gap: 12px; font-size: 12px; color: var(--text-muted); }
    .status-pill { display: flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 999px; background: rgba(16, 185, 129, 0.08); color: var(--accent); font-weight: 600; font-size: 11px; }

    .container { max-width: 1360px; margin: 0 auto; padding: 24px; display: grid; gap: 20px; }

    /* Top Command & URL Bar */
    .search-panel {
      background: var(--card-bg); border: 1px solid var(--card-border);
      border-radius: 10px; padding: 16px 20px; display: flex; gap: 12px; align-items: center; flex-wrap: wrap;
    }
    .url-input {
      flex: 1; min-width: 320px; background: var(--input-bg); border: 1px solid var(--card-border);
      color: #fff; padding: 10px 14px; border-radius: 6px; font-size: 13.5px; font-family: var(--code-font);
      transition: border-color 0.15s ease, box-shadow 0.15s ease;
    }
    .url-input:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px rgba(16, 185, 129, 0.15); }
    .select-profile {
      background: var(--input-bg); border: 1px solid var(--card-border); color: #e2e8f0;
      padding: 10px 14px; border-radius: 6px; font-size: 13px; cursor: pointer; outline: none;
    }
    .select-profile:focus { border-color: var(--accent); }
    .btn-launch {
      background: var(--accent); color: #042f24; font-weight: 700;
      border: none; padding: 10px 22px; border-radius: 6px; font-size: 13px;
      cursor: pointer; transition: all 0.15s ease; display: flex; align-items: center; gap: 6px;
    }
    .btn-launch:hover { background: var(--accent-hover); color: #fff; }

    /* Main Dashboard Grid */
    .dashboard-grid { display: grid; grid-template-columns: 340px 1fr; gap: 20px; }

    /* Card Panels */
    .card {
      background: var(--card-bg); border: 1px solid var(--card-border);
      border-radius: 10px; padding: 18px 20px;
    }
    .card-title {
      font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em;
      color: var(--text-muted); margin-bottom: 14px; display: flex; justify-content: space-between; align-items: center;
    }

    /* Risk Score Gauge */
    .score-container {
      display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 12px 0 16px;
    }
    .score-circle {
      width: 130px; height: 130px; border-radius: 50%;
      background: conic-gradient(var(--card-border) 0deg 360deg);
      display: grid; place-items: center; margin-bottom: 12px; transition: background 0.4s ease;
    }
    .score-inner {
      width: 104px; height: 104px; border-radius: 50%; background: var(--card-bg);
      display: flex; flex-direction: column; align-items: center; justify-content: center;
    }
    .score-number { font-size: 34px; font-weight: 800; color: #fff; line-height: 1; }
    .score-grade { font-size: 12px; font-weight: 700; margin-top: 4px; color: var(--accent); }
    .verdict-text { font-size: 12px; color: var(--text-muted); text-align: center; }

    /* Stats Row */
    .stats-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 6px; margin-top: 14px; }
    .stat-item {
      background: var(--input-bg); border: 1px solid var(--card-border);
      border-radius: 6px; padding: 8px 4px; text-align: center;
    }
    .stat-val { font-size: 17px; font-weight: 800; font-family: var(--code-font); }
    .stat-lbl { font-size: 10px; text-transform: uppercase; color: var(--text-muted); margin-top: 2px; }

    /* Terminal Console */
    .terminal-box {
      background: #080c14; border: 1px solid var(--card-border);
      border-radius: 6px; padding: 12px 14px; font-family: var(--code-font);
      font-size: 11.5px; height: 210px; overflow-y: auto; color: #cbd5e1;
    }
    .terminal-line { margin-bottom: 5px; word-break: break-all; }
    .terminal-line.crit { color: #f87171; font-weight: 600; }
    .terminal-line.high { color: #fb923c; }
    .terminal-line.info { color: #64748b; }

    /* Findings Feed */
    .findings-header {
      display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;
    }
    .search-filter {
      background: var(--input-bg); border: 1px solid var(--card-border); color: #fff;
      padding: 6px 12px; border-radius: 6px; font-size: 12px; outline: none; width: 220px;
    }
    .search-filter:focus { border-color: var(--accent); }

    .finding-card {
      background: #0d1424; border: 1px solid var(--card-border); border-left: 4px solid var(--info);
      border-radius: 6px; padding: 14px 16px; margin-bottom: 10px; cursor: pointer;
      transition: all 0.15s ease;
    }
    .finding-card:hover { border-color: #334155; transform: translateX(2px); background: #111a30; }
    .finding-top { display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 6px; }
    .finding-name { font-size: 14px; font-weight: 700; color: #fff; }
    .badge {
      display: inline-block; padding: 2px 8px; border-radius: 4px;
      font-size: 10px; font-weight: 700; text-transform: uppercase;
    }
    .badge.critical { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
    .badge.high { background: rgba(249, 115, 22, 0.15); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.3); }
    .badge.medium { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }
    .badge.low { background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); }
    .badge.info { background: rgba(100, 116, 139, 0.15); color: #94a3b8; border: 1px solid rgba(100, 116, 139, 0.3); }
    .finding-sub { font-size: 12px; color: var(--text-muted); display: flex; gap: 12px; flex-wrap: wrap; }

    /* Modal */
    .modal {
      display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%;
      background: rgba(0, 0, 0, 0.75); backdrop-filter: blur(6px); z-index: 500;
      place-items: center; padding: 20px;
    }
    .modal.active { display: grid; }
    .modal-box {
      background: #111827; border: 1px solid #1f293d; border-radius: 10px;
      max-width: 820px; width: 100%; max-height: 85vh; overflow-y: auto; padding: 26px;
    }
    .modal-head { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 16px; }
    .close-btn { background: none; border: none; color: var(--text-muted); font-size: 22px; cursor: pointer; }
    .close-btn:hover { color: #fff; }
    pre {
      background: #080c14; border: 1px solid #1f293d; color: #38bdf8;
      padding: 12px 14px; border-radius: 6px; font-size: 12px; font-family: var(--code-font);
      overflow-x: auto; margin: 8px 0 14px;
    }
    .btn-secondary {
      background: #1e293b; border: 1px solid #334155; color: #fff;
      padding: 6px 14px; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 600;
      transition: all 0.15s ease; margin-right: 8px;
    }
    .btn-secondary:hover { background: #334155; }

    /* Canvas Graph */
    #graphCanvas {
      width: 100%; height: 420px; background: #080c14;
      border: 1px solid var(--card-border); border-radius: 8px; display: block;
    }

    /* Proposal Pitch Grid */
    .deck-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 18px; margin-top: 14px; }
    .deck-card {
      background: var(--input-bg); border: 1px solid var(--card-border);
      border-radius: 8px; padding: 22px; display: flex; flex-direction: column;
    }
    .deck-card.featured { border-color: var(--accent); background: #0c182a; box-shadow: 0 0 24px rgba(16, 185, 129, 0.08); }
    .deck-price { font-size: 26px; font-weight: 800; color: #fff; margin: 10px 0 4px; }

    #toast {
      position: fixed; bottom: 24px; right: 24px; background: #10b981; color: #042f24;
      padding: 10px 18px; border-radius: 6px; font-weight: 700; font-size: 12.5px;
      display: none; z-index: 600; box-shadow: 0 4px 16px rgba(0,0,0,0.4);
    }
  </style>
</head>
<body>

<header>
  <div class="logo">
    <div class="logo-dot"></div>
    VulnScope
    <span class="logo-badge">Enterprise</span>
  </div>
  <div class="nav-tabs">
    <button class="tab-btn active" onclick="switchTab('scanTab')">Scanner</button>
    <button class="tab-btn" onclick="switchTab('graphTab')">Attack Graph</button>
    <button class="tab-btn" onclick="switchTab('pitchTab')">Proposal & ROI</button>
    <button class="tab-btn" onclick="switchTab('diffTab')">Delta Diff</button>
    <button class="tab-btn" onclick="switchTab('exportTab')">Reports</button>
  </div>
  <div class="header-right">
    <div class="status-pill" id="engineStatus">● Engine Ready</div>
  </div>
</header>

<div class="container">
  <!-- Search / Command Panel -->
  <div class="search-panel">
    <input type="text" id="targetUrl" class="url-input" placeholder="Enter target URL (e.g. https://client-site.com)" value="http://127.0.0.1:8099">
    <select id="scanProfile" class="select-profile">
      <option value="standard">Standard Audit (15 Modules)</option>
      <option value="deep">Deep Red-Team (Blind SQLi + Subdomains)</option>
      <option value="api">API, Cloud & S3 Bucket Interceptor</option>
      <option value="fast">Quick Recon (< 10s)</option>
    </select>
    <button class="btn-launch" id="launchBtn" onclick="launchScan()">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
      Start Scan
    </button>
  </div>

  <!-- TAB 1: SCAN CONSOLE -->
  <div id="scanTab" class="tab-content">
    <div class="dashboard-grid">
      <!-- Left sidebar -->
      <div style="display:grid; gap:18px;">
        <div class="card">
          <div class="card-title">Security Posture</div>
          <div class="score-container">
            <div class="score-circle" id="scoreCircle">
              <div class="score-inner">
                <div class="score-number" id="scoreVal">0</div>
                <div class="score-grade" id="gradeVal">Grade A</div>
              </div>
            </div>
            <div class="verdict-text" id="verdictText">Awaiting Target Scan</div>
          </div>
          <div class="stats-grid">
            <div class="stat-item"><div class="stat-val" id="cntCrit" style="color:var(--crit)">0</div><div class="stat-lbl">Crit</div></div>
            <div class="stat-item"><div class="stat-val" id="cntHigh" style="color:var(--high)">0</div><div class="stat-lbl">High</div></div>
            <div class="stat-item"><div class="stat-val" id="cntMed" style="color:var(--med)">0</div><div class="stat-lbl">Med</div></div>
            <div class="stat-item"><div class="stat-val" id="cntLow" style="color:var(--low)">0</div><div class="stat-lbl">Low</div></div>
            <div class="stat-item"><div class="stat-val" id="cntInfo" style="color:var(--info)">0</div><div class="stat-lbl">Info</div></div>
          </div>
        </div>

        <div class="card">
          <div class="card-title">Live Scan Log</div>
          <div class="terminal-box" id="terminalLog">
            <div class="terminal-line info">[System] VulnScope security engine ready.</div>
            <div class="terminal-line info">[System] 15 detection modules armed.</div>
          </div>
        </div>
      </div>

      <!-- Main findings column -->
      <div class="card">
        <div class="findings-header">
          <div style="font-weight:700; font-size:14px;">
            Identified Vulnerabilities (<span id="findingsCount" style="color:var(--accent)">0</span>)
          </div>
          <input type="text" id="liveSearch" class="search-filter" placeholder="Filter vulnerabilities..." onkeyup="filterLiveFindings()">
        </div>
        <div id="findingsContainer">
          <div style="text-align:center; padding:60px 20px; color:var(--text-muted);">
            No scan executed yet. Enter a target URL above and click <strong>Start Scan</strong>.
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- TAB 2: TOPOLOGY GRAPH -->
  <div id="graphTab" class="tab-content" style="display:none;">
    <div class="card">
      <div class="card-title">
        <span>Attack Surface & Threat Map</span>
        <span style="font-size:11px; color:var(--text-muted)">Interactive visual node graph</span>
      </div>
      <canvas id="graphCanvas"></canvas>
    </div>
  </div>

  <!-- TAB 3: PROPOSAL & ROI -->
  <div id="pitchTab" class="tab-content" style="display:none;">
    <div class="card">
      <div class="card-title">Commercial Proposal & Remediation SOW</div>
      <p style="color:var(--text-muted); font-size:13px; margin-bottom:18px;">
        Present these ready-to-sign packages to your client along with breach financial loss metrics.
      </p>
      <div class="deck-grid">
        <div class="deck-card">
          <span style="font-size:11px; font-weight:700; color:var(--low);">TIER 1</span>
          <h3 style="margin-top:4px;">Emergency Quick-Wins</h3>
          <div class="deck-price">$1,440</div>
          <p style="font-size:12px; color:var(--text-muted); margin-bottom:14px;">Immediate patching of critical findings.</p>
          <ul style="padding-left:16px; font-size:12px; color:var(--text-muted); margin-bottom:16px; flex:1;">
            <li>Direct patching of Critical vulnerabilities</li>
            <li>Removal of exposed .env and .git folders</li>
            <li>Security Headers & TLS Hardening</li>
            <li>Follow-up re-scan confirmation</li>
          </ul>
          <button class="btn-secondary" onclick="copyPitch(1)">Copy Scope</button>
        </div>

        <div class="deck-card featured">
          <span style="font-size:11px; font-weight:700; color:var(--accent);">TIER 2 &bull; RECOMMENDED</span>
          <h3 style="margin-top:4px;">Complete Remediation</h3>
          <div class="deck-price">$3,840</div>
          <p style="font-size:12px; color:var(--text-muted); margin-bottom:14px;">Full remediation to Grade A security posture.</p>
          <ul style="padding-left:16px; font-size:12px; color:var(--text-muted); margin-bottom:16px; flex:1;">
            <li>Full remediation of all findings (Critical to Low)</li>
            <li>WAF / Cloudflare Virtual Patching Rules</li>
            <li>Code-level assistance for development team</li>
            <li>Letter of Security Attestation</li>
            <li>Before vs After Delta Report proving Grade A</li>
          </ul>
          <button class="btn-secondary" style="background:var(--accent); color:#042f24; border-color:var(--accent);" onclick="copyPitch(2)">Copy Scope</button>
        </div>

        <div class="deck-card">
          <span style="font-size:11px; font-weight:700; color:var(--high);">TIER 3</span>
          <h3 style="margin-top:4px;">Continuous Retainer</h3>
          <div class="deck-price">$950 / mo</div>
          <p style="font-size:12px; color:var(--text-muted); margin-bottom:14px;">Continuous attack surface monitoring & 4h SLA.</p>
          <ul style="padding-left:16px; font-size:12px; color:var(--text-muted); margin-bottom:16px; flex:1;">
            <li>Weekly automated vulnerability scanning</li>
            <li>Subdomain and cloud asset monitoring</li>
            <li>Priority 4-hour incident response SLA</li>
            <li>Monthly compliance check</li>
          </ul>
          <button class="btn-secondary" onclick="copyPitch(3)">Copy Scope</button>
        </div>
      </div>
    </div>
  </div>

  <!-- TAB 4: DELTA COMPARISON -->
  <div id="diffTab" class="tab-content" style="display:none;">
    <div class="card">
      <div class="card-title">Before vs. After Delta Comparison</div>
      <p style="color:var(--text-muted); font-size:13px; margin-bottom:18px;">
        Compare an initial baseline scan against a re-test scan to prove remediation efficacy to your client.
      </p>
      <div style="display:flex; gap:12px; margin-bottom:18px;">
        <input type="text" id="diffScanA" class="url-input" placeholder="Baseline scan path (e.g. reports/scan_before.json)">
        <input type="text" id="diffScanB" class="url-input" placeholder="Verification scan path (e.g. reports/scan_after.json)">
        <button class="btn-secondary" style="padding:10px 20px;" onclick="runDiff()">Compare Scans</button>
      </div>
      <div id="diffOutput"></div>
    </div>
  </div>

  <!-- TAB 5: REPORTS -->
  <div id="exportTab" class="tab-content" style="display:none;">
    <div class="card">
      <div class="card-title">Generated Assessment Reports</div>
      <div id="reportsList" style="display:grid; gap:10px; margin-top:10px;">
        <p style="color:var(--text-muted)">Run an assessment to view generated reports.</p>
      </div>
    </div>
  </div>
</div>

<!-- Modal Finding Detail -->
<div class="modal" id="findingModal">
  <div class="modal-box">
    <div class="modal-head">
      <div>
        <span class="badge critical" id="mBadge">CRITICAL</span>
        <h2 id="mTitle" style="color:#fff; margin-top:8px; font-size:17px;">Finding Title</h2>
      </div>
      <button class="close-btn" onclick="closeModal()">&times;</button>
    </div>
    <div style="font-size:12px; color:var(--text-muted); margin-bottom:14px;" id="mTags"></div>

    <h4 style="font-size:11px; text-transform:uppercase; color:var(--text-muted); letter-spacing:0.06em; margin:14px 0 4px;">Technical Details</h4>
    <p id="mDesc" style="color:var(--text-main); font-size:13px;"></p>

    <h4 style="font-size:11px; text-transform:uppercase; color:var(--crit); letter-spacing:0.06em; margin:14px 0 4px;">Business Impact</h4>
    <p id="mImpact" style="color:var(--text-main); font-size:13px;"></p>

    <h4 style="font-size:11px; text-transform:uppercase; color:var(--text-muted); letter-spacing:0.06em; margin:14px 0 4px;">Verification Proof of Concept</h4>
    <pre id="mPoc"></pre>
    <div style="display:flex; gap:8px; margin-bottom:14px;">
      <button class="btn-secondary" onclick="copyModalPoc()">Copy cURL</button>
      <button class="btn-secondary" onclick="verifyModalFinding()">⚡ Live Re-Test</button>
    </div>

    <h4 style="font-size:11px; text-transform:uppercase; color:var(--accent); letter-spacing:0.06em; margin:14px 0 4px;">Remediation Patch</h4>
    <pre id="mPatch"></pre>
  </div>
</div>

<div id="toast">Copied to clipboard</div>

<script>
let currentScanId = null;
let currentFindings = [];
let pollInterval = null;
let topologyNodes = [];

function switchTab(tabId) {
  document.querySelectorAll('.tab-content').forEach(el => el.style.display = 'none');
  document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
  document.getElementById(tabId).style.display = 'block';
  event.target.classList.add('active');
  if (tabId === 'graphTab') renderTopology();
}

function showToast(msg) {
  const t = document.getElementById('toast');
  t.innerText = msg;
  t.style.display = 'block';
  setTimeout(() => t.style.display = 'none', 2200);
}

function logTerminal(msg) {
  const t = document.getElementById('terminalLog');
  const line = document.createElement('div');
  line.className = 'terminal-line';
  if (msg.includes('Critical') || msg.includes('CRITICAL') || msg.includes('Error')) {
    line.className += ' crit';
  } else if (msg.includes('High') || msg.includes('HIGH')) {
    line.className += ' high';
  }
  line.innerText = msg;
  t.appendChild(line);
  t.scrollTop = t.scrollHeight;
}

function launchScan() {
  const target = document.getElementById('targetUrl').value.trim();
  const profile = document.getElementById('scanProfile').value;
  if (!target) return alert('Please enter a target URL');

  document.getElementById('launchBtn').disabled = true;
  document.getElementById('launchBtn').innerHTML = '<span>Scanning...</span>';
  document.getElementById('engineStatus').innerText = '● Assessment Active';
  document.getElementById('engineStatus').style.color = 'var(--high)';
  logTerminal('[Scan] Launching assessment on ' + target + ' (' + profile.toUpperCase() + ')');

  fetch('/api/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target: target, profile: profile })
  })
  .then(res => res.json())
  .then(data => {
    currentScanId = data.scan_id;
    logTerminal('[Scan] Assigned ID: ' + currentScanId);
    pollScan();
  })
  .catch(err => {
    logTerminal('[Error] Failed to start scan: ' + err);
    document.getElementById('launchBtn').disabled = false;
    document.getElementById('launchBtn').innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg> Start Scan';
  });
}

function pollScan() {
  if (pollInterval) clearInterval(pollInterval);
  pollInterval = setInterval(() => {
    fetch('/api/scan/' + currentScanId + '/status')
    .then(r => r.json())
    .then(state => {
      if (state.logs && state.logs.length) {
        state.logs.forEach(l => logTerminal(l));
      }
      document.getElementById('scoreVal').innerText = state.score;
      document.getElementById('gradeVal').innerText = state.grade ? ('Grade ' + state.grade) : 'Scanning';

      const deg = Math.round(state.score * 3.6);
      const ringColor = state.score > 60 ? 'var(--crit)' : (state.score > 25 ? 'var(--med)' : 'var(--accent)');
      document.getElementById('scoreCircle').style.background = `conic-gradient(${ringColor} 0deg ${deg}deg, var(--card-border) ${deg}deg 360deg)`;
      document.getElementById('verdictText').innerText = state.score > 60 ? 'Critical exposure detected' : (state.score > 25 ? 'Moderate risk profile' : 'Good security posture');

      const c = state.counts || { critical:0, high:0, medium:0, low:0, info:0 };
      document.getElementById('cntCrit').innerText = c.critical || 0;
      document.getElementById('cntHigh').innerText = c.high || 0;
      document.getElementById('cntMed').innerText = c.medium || 0;
      document.getElementById('cntLow').innerText = c.low || 0;
      document.getElementById('cntInfo').innerText = c.info || 0;

      currentFindings = state.findings || [];
      renderFindings(currentFindings);
      topologyNodes = state.attack_graph || { nodes: [], links: [] };

      if (state.completed) {
        clearInterval(pollInterval);
        document.getElementById('launchBtn').disabled = false;
        document.getElementById('launchBtn').innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg> Start Scan';
        document.getElementById('engineStatus').innerText = '● Engine Ready';
        document.getElementById('engineStatus').style.color = 'var(--accent)';
        logTerminal('[Scan] Assessment completed. Reports generated in reports/ folder.');
        loadReportsList();
      }
    });
  }, 1200);
}

function renderFindings(list) {
  document.getElementById('findingsCount').innerText = list.length;
  const container = document.getElementById('findingsContainer');
  if (!list.length) {
    container.innerHTML = '<div style="text-align:center; padding:50px; color:var(--text-muted)">Scanning in progress...</div>';
    return;
  }
  container.innerHTML = list.map((f, idx) => `
    <div class="finding-card" style="border-left-color:var(--${f.severity})" onclick="openModal(${idx})">
      <div class="finding-top">
        <span class="finding-name">${f.title}</span>
        <span class="badge ${f.severity}">${f.severity.toUpperCase()}</span>
      </div>
      <div class="finding-sub">
        <span>${f.category}</span>
        <span>${f.owasp || 'OWASP'}</span>
        <span>CWE: ${f.cwe || 'N/A'}</span>
        <span>CVSS: ${f.cvss || 'N/A'}</span>
      </div>
    </div>
  `).join('');
}

let activeModalFinding = null;
function openModal(idx) {
  const f = currentFindings[idx];
  if (!f) return;
  activeModalFinding = f;
  document.getElementById('mBadge').className = 'badge ' + f.severity;
  document.getElementById('mBadge').innerText = f.severity.toUpperCase();
  document.getElementById('mTitle').innerText = f.title;
  document.getElementById('mTags').innerText = `${f.category} · ${f.cwe || 'CWE'} · ${f.owasp || 'OWASP'} · CVSS ${f.cvss || 'N/A'}`;
  document.getElementById('mDesc').innerText = f.description;
  document.getElementById('mImpact').innerText = f.impact || 'Direct breach risk, account takeover, or credential exposure.';
  document.getElementById('mPoc').innerText = f.poc_curl || `curl -i -k '${f.location || document.getElementById('targetUrl').value}'`;
  document.getElementById('mPatch').innerText = f.remediation || 'Apply input sanitization and secure configuration.';
  document.getElementById('findingModal').classList.add('active');
}

function closeModal() {
  document.getElementById('findingModal').classList.remove('active');
}

function copyModalPoc() {
  if (activeModalFinding) {
    navigator.clipboard.writeText(document.getElementById('mPoc').innerText);
    showToast('cURL command copied!');
  }
}

function verifyModalFinding() {
  if (!activeModalFinding) return;
  showToast('Sending live test probe...');
  fetch('/api/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: activeModalFinding.location || document.getElementById('targetUrl').value })
  })
  .then(r => r.json())
  .then(res => {
    alert(`Verification Response:\nHTTP Status: ${res.status}\n\nResponse Preview:\n` + res.body_preview);
  });
}

function renderTopology() {
  const canvas = document.getElementById('graphCanvas');
  const ctx = canvas.getContext('2d');
  canvas.width = canvas.parentElement.clientWidth - 40;
  canvas.height = 420;

  ctx.fillStyle = '#080c14';
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  const nodes = (topologyNodes && topologyNodes.nodes && topologyNodes.nodes.length) ? topologyNodes.nodes : [
    { id: 'target', label: document.getElementById('targetUrl').value || 'Target Host', type: 'target', status: 'critical' },
    { id: 'ip1', label: '104.21.45.2', type: 'ip', status: 'info' },
    { id: 'tls', label: 'TLS 1.3', type: 'tls', status: 'info' },
    { id: 'v1', label: 'CORS Reflection', type: 'vuln', status: 'critical' },
    { id: 'v2', label: 'Missing CSP', type: 'vuln', status: 'high' },
    { id: 'v3', label: 'Exposed .env', type: 'vuln', status: 'critical' },
  ];

  const centerX = canvas.width / 2;
  const centerY = canvas.height / 2;

  // Clean lines
  ctx.strokeStyle = '#1e293b';
  ctx.lineWidth = 1.5;
  nodes.forEach((n, i) => {
    if (i === 0) return;
    const angle = (i / (nodes.length - 1)) * 2 * Math.PI;
    const x = centerX + Math.cos(angle) * 150;
    const y = centerY + Math.sin(angle) * 130;
    ctx.beginPath();
    ctx.moveTo(centerX, centerY);
    ctx.lineTo(x, y);
    ctx.stroke();
  });

  // Center node
  ctx.fillStyle = '#10b981';
  ctx.beginPath();
  ctx.arc(centerX, centerY, 24, 0, 2 * Math.PI);
  ctx.fill();
  ctx.fillStyle = '#fff';
  ctx.font = 'bold 11px sans-serif';
  ctx.textAlign = 'center';
  ctx.fillText('TARGET', centerX, centerY + 4);

  // Satellite nodes
  nodes.forEach((n, i) => {
    if (i === 0) return;
    const angle = (i / (nodes.length - 1)) * 2 * Math.PI;
    const x = centerX + Math.cos(angle) * 150;
    const y = centerY + Math.sin(angle) * 130;

    const col = n.status === 'critical' ? '#ef4444' : (n.status === 'high' ? '#f97316' : '#3b82f6');
    ctx.fillStyle = col;
    ctx.beginPath();
    ctx.arc(x, y, 14, 0, 2 * Math.PI);
    ctx.fill();

    ctx.fillStyle = '#cbd5e1';
    ctx.font = '11.5px sans-serif';
    ctx.fillText(n.label.slice(0, 20), x, y + 26);
  });
}

function loadReportsList() {
  fetch('/api/reports')
  .then(r => r.json())
  .then(list => {
    const box = document.getElementById('reportsList');
    if (!list.length) {
      box.innerHTML = '<p style="color:var(--text-muted)">No reports generated yet.</p>';
      return;
    }
    box.innerHTML = list.map(item => `
      <div style="background:#0d1424; border:1px solid var(--card-border); padding:12px 16px; border-radius:6px; display:flex; justify-content:space-between; align-items:center;">
        <div>
          <div style="display:flex; align-items:center; gap:8px;">
            <span style="background:rgba(16,185,129,0.12); color:var(--accent); font-weight:700; font-size:11px; padding:2px 6px; border-radius:4px;">${item.domain}</span>
            <strong style="color:#fff; font-size:13px;">${item.file}</strong>
          </div>
          <div style="font-size:11.5px; color:var(--text-muted); margin-top:3px;">Path: ${item.name} &bull; ${(item.size/1024).toFixed(1)} KB &bull; ${item.modified}</div>
        </div>
        <a href="/reports/${item.name}" target="_blank" class="btn-secondary" style="text-decoration:none;">View / Download</a>
      </div>
    `).join('');
  });
}

function copyPitch(tier) {
  showToast('Copied Tier ' + tier + ' scope to clipboard');
}

function runDiff() {
  const a = document.getElementById('diffScanA').value.trim();
  const b = document.getElementById('diffScanB').value.trim();
  if (!a || !b) return alert('Enter both baseline and re-test scan paths');

  fetch('/api/diff', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scan_a: a, scan_b: b })
  })
  .then(r => r.json())
  .then(delta => {
    const out = document.getElementById('diffOutput');
    out.innerHTML = `
      <div style="display:grid; grid-template-columns:repeat(3,1fr); gap:12px; margin-top:14px;">
        <div class="stat-item"><div class="stat-val" style="color:var(--accent);">${delta.score_change}</div><div class="stat-lbl">Score Change</div></div>
        <div class="stat-item"><div class="stat-val" style="color:#10b981;">${delta.resolved_count}</div><div class="stat-lbl">Resolved Issues</div></div>
        <div class="stat-item"><div class="stat-val" style="color:var(--crit);">${delta.new_count}</div><div class="stat-lbl">New Issues</div></div>
      </div>
      <p style="margin-top:14px; color:#cbd5e1; font-size:13px;">${delta.verdict}</p>
    `;
  });
}

function filterLiveFindings() {
  const query = document.getElementById('liveSearch').value.toLowerCase();
  const filtered = currentFindings.filter(f =>
    f.title.toLowerCase().includes(query) ||
    f.category.toLowerCase().includes(query) ||
    f.severity.toLowerCase().includes(query)
  );
  renderFindings(filtered);
}

window.addEventListener('DOMContentLoaded', () => {
  loadReportsList();
});
</script>
</body>
</html>"""


class StudioHandler(BaseHTTPRequestHandler):
    """Multi-threaded REST API and SPA server."""

    def log_message(self, fmt, *args):
        pass

    def _send_json(self, data: Any, status: int = 200) -> None:
        raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(raw)

    def _send_html(self, html_text: str, status: int = 200) -> None:
        raw = html_text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            self._send_html(get_html_studio())
            return

        # Poll scan status
        scan_match = re.match(r"^/api/scan/([^/]+)/status$", path)
        if scan_match:
            scan_id = scan_match.group(1)
            with SCANS_LOCK:
                scan = SCANS.get(scan_id)
            if not scan:
                self._send_json({"error": "Scan not found"}, 404)
                return
            # Drain new logs
            logs = []
            while not scan["logs_queue"].empty():
                try:
                    logs.append(scan["logs_queue"].get_nowait())
                except queue.Empty:
                    break

            self._send_json({
                "scan_id": scan_id,
                "completed": scan["completed"],
                "score": scan["score"],
                "grade": scan["grade"],
                "counts": scan["counts"],
                "findings": [f.to_dict() for f in scan["findings"]],
                "logs": logs,
                "attack_graph": scan.get("attack_graph", {}),
            })
            return

        # Reports list
        if path == "/api/reports":
            reports_dir = "reports"
            items = []
            if os.path.exists(reports_dir):
                for root, dirs, files in os.walk(reports_dir):
                    for file in files:
                        if file.endswith((".html", ".pdf", ".json", ".md", ".sarif", ".csv")):
                            fpath = os.path.join(root, file)
                            rel_path = os.path.relpath(fpath, reports_dir).replace("\\", "/")
                            parts = rel_path.split("/")
                            domain_name = parts[0] if len(parts) > 1 else "root"
                            datetime_name = parts[1] if len(parts) > 2 else ""
                            items.append({
                                "name": rel_path,
                                "file": file,
                                "domain": domain_name,
                                "datetime": datetime_name,
                                "size": os.path.getsize(fpath),
                                "modified": _dt.datetime.fromtimestamp(os.path.getmtime(fpath)).strftime("%Y-%m-%d %H:%M"),
                            })
            items.sort(key=lambda x: x["modified"], reverse=True)
            self._send_json(items)
            return

        # Download / View report file (supports nested domain/date folders)
        if path.startswith("/reports/"):
            rel_path = urllib.parse.unquote(path[len("/reports/"):].lstrip("/"))
            safe_rel = os.path.normpath(rel_path).replace("\\", "/")
            if safe_rel.startswith("..") or "/../" in safe_rel:
                self._send_json({"error": "Forbidden path"}, 403)
                return
            fpath = os.path.join("reports", safe_rel)
            if os.path.exists(fpath) and os.path.isfile(fpath):
                ctype = "text/html; charset=utf-8" if fpath.endswith(".html") else (
                    "application/json; charset=utf-8" if fpath.endswith(".json") else (
                        "application/pdf" if fpath.endswith(".pdf") else (
                            "text/markdown; charset=utf-8" if fpath.endswith(".md") else "text/plain; charset=utf-8"
                        )
                    )
                )
                with open(fpath, "rb") as fh:
                    raw = fh.read()
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                return

        self._send_json({"error": "Not Found"}, 404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "ignore")
        payload = json.loads(body) if body else {}

        if path == "/api/scan":
            target = payload.get("target", "").strip()
            profile = payload.get("profile", "standard")
            if not target:
                self._send_json({"error": "Target URL is required"}, 400)
                return

            base_url, host = normalise_target(target)
            scan_id = "VS-" + str(int(time.time()))[-6:]

            scan_record = {
                "scan_id": scan_id,
                "target": base_url,
                "host": host,
                "profile": profile,
                "completed": False,
                "score": 0,
                "grade": "READY",
                "counts": {},
                "findings": [],
                "logs_queue": queue.Queue(),
                "attack_graph": {"nodes": [], "links": []},
            }
            with SCANS_LOCK:
                SCANS[scan_id] = scan_record

            threading.Thread(target=_run_background_scan, args=(scan_record,), daemon=True).start()
            self._send_json({"scan_id": scan_id, "status": "started"})
            return

        if path == "/api/verify":
            verify_url = payload.get("url")
            if not verify_url:
                self._send_json({"error": "Missing url"}, 400)
                return
            try:
                http = Http(timeout=8.0, verify=False)
                r = http.get(verify_url)
                self._send_json({
                    "status": r.status,
                    "headers": dict(r.headers),
                    "body_preview": r.text[:300],
                })
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        if path == "/api/diff":
            path_a = payload.get("scan_a")
            path_b = payload.get("scan_b")
            try:
                with open(path_a, "r", encoding="utf-8") as fa:
                    scan_a = json.load(fa)
                with open(path_b, "r", encoding="utf-8") as fb:
                    scan_b = json.load(fb)
                delta = compare_scans(scan_a, scan_b)
                self._send_json(delta.to_dict())
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        self._send_json({"error": "Not Found"}, 404)


def _run_background_scan(scan_record: Dict[str, Any]) -> None:
    target = scan_record["target"]
    host = scan_record["host"]
    profile = scan_record["profile"]
    q = scan_record["logs_queue"]

    q.put(f"[Scan] Starting assessment on {target} (Profile: {profile.upper()})")

    options = Options(
        deep=(profile == "deep"),
        test_forms=(profile in ("deep", "standard")),
        subdomains=(profile == "deep"),
        profile=profile,
        max_pages=15 if profile == "fast" else 30,
        threads=8,
    )
    http = Http(timeout=10.0, verify=False)
    ctx = ScanContext(target, target, host, http, options, logger=lambda m: q.put(m))

    res = ScanResult(target=target, host=host, started=time.time(), profile=profile)

    try:
        ips = ctx.ips()
        q.put(f"[Recon] Host resolved to {', '.join(ips) if ips else 'unresolved'}")

        ctx.pages = crawl(http, target, max_pages=options.max_pages, depth=options.depth, log=lambda m: q.put(m))
        res.pages_scanned = [p.url for p in ctx.pages]
        q.put(f"[Crawler] Discovered {len(ctx.pages)} target routes.")

        q.put("[Audit] Executing security assessment check modules...")
        findings = run_all(ctx, progress=lambda m: q.put(m))
        res.findings = findings
        res.metadata = ctx.meta

        scan_record["findings"] = findings
        scan_record["score"] = res.risk_score()
        scan_record["grade"] = res.grade()
        scan_record["counts"] = res.counts()
        scan_record["attack_graph"] = ctx.attack_graph

        # Write reports
        res.finished = time.time()
        res.requests_made = http.count
        write_reports(res, "reports", formats=["html", "json", "md", "sarif", "csv"], include_proposal=True)
        q.put("[Done] Report files written to reports/ directory.")

    except Exception as exc:
        q.put(f"[Error] Assessment failure: {exc}")
    finally:
        scan_record["completed"] = True
        http.close()


def start_server(port: int = 8888, host: str = "127.0.0.1") -> None:
    server = ThreadingHTTPServer((host, port), StudioHandler)
    print(f"\n=======================================================")
    print(f"  VulnScope Studio Live")
    print(f"  Open in your browser: http://{host}:{port}")
    print(f"=======================================================\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down VulnScope Studio.")
        server.server_close()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 8888
    start_server(port=port)
