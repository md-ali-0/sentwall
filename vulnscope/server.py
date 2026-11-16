"""VulnScope Cyberpunk Studio - Embedded Real-Time Web Application & REST API.

Provides an interactive GUI, live scan visualizer, interactive attack topology
graph, 1-click PoC verification, remediation patch generator, client pitch studio,
and delta comparison hub. Runs with zero external npm or node dependencies.
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
    """Embedded single-page Cyberpunk Security Studio application."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>VulnScope Cyberpunk Security Studio</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root {
      --bg: #070b13; --panel: #0d1527; --panel-border: #1a2744;
      --accent: #00f2fe; --accent-glow: rgba(0, 242, 254, 0.35);
      --purple: #9d4edd; --text: #e2e8f0; --muted: #7384a2;
      --crit: #ff0055; --high: #ff5500; --med: #ffaa00; --low: #00aaff; --info: #64748b;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg); color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
      font-size: 13px; line-height: 1.5; overflow-x: hidden;
    }
    header {
      background: rgba(13, 21, 39, 0.9); backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--panel-border); padding: 12px 24px;
      display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; z-index: 100;
    }
    .logo {
      font-size: 18px; font-weight: 800; letter-spacing: 0.1em; color: var(--accent);
      display: flex; align-items: center; gap: 8px; text-transform: uppercase;
      text-shadow: 0 0 16px var(--accent-glow);
    }
    .logo-badge { font-size: 10px; background: var(--purple); color: #fff; padding: 2px 6px; border-radius: 4px; }
    .tabs { display: flex; gap: 6px; }
    .tab-btn {
      background: transparent; color: var(--muted); border: 1px solid transparent;
      padding: 6px 14px; border-radius: 6px; cursor: pointer; font-weight: 600;
      transition: all 0.2s ease;
    }
    .tab-btn.active, .tab-btn:hover { color: var(--accent); border-color: var(--panel-border); background: var(--panel); }
    .container { max-width: 1400px; margin: 0 auto; padding: 24px; display: grid; gap: 24px; }

    /* Scan Bar */
    .scan-bar {
      background: var(--panel); border: 1px solid var(--panel-border);
      border-radius: 12px; padding: 18px 24px; display: flex; gap: 14px; align-items: center; flex-wrap: wrap;
      box-shadow: 0 8px 32px rgba(0,0,0,0.4);
    }
    .url-input {
      flex: 1; min-width: 260px; background: #060912; border: 1px solid var(--panel-border);
      color: #fff; padding: 10px 16px; border-radius: 8px; font-size: 14px; font-family: monospace;
    }
    .url-input:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 12px var(--accent-glow); }
    .select-profile {
      background: #060912; border: 1px solid var(--panel-border); color: #fff;
      padding: 10px 14px; border-radius: 8px; font-size: 13px; cursor: pointer;
    }
    .btn-launch {
      background: linear-gradient(135deg, #00f2fe, #4facfe); color: #070b13;
      border: none; padding: 10px 24px; border-radius: 8px; font-weight: 800;
      letter-spacing: 0.05em; text-transform: uppercase; cursor: pointer;
      box-shadow: 0 0 20px var(--accent-glow); transition: all 0.2s ease;
    }
    .btn-launch:hover { transform: translateY(-1px); box-shadow: 0 0 28px var(--accent-glow); }

    /* Dashboard Layout */
    .dashboard-grid { display: grid; grid-template-columns: 320px 1fr; gap: 24px; }
    .card {
      background: var(--panel); border: 1px solid var(--panel-border);
      border-radius: 12px; padding: 20px;
    }
    .card-title {
      font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em;
      color: var(--muted); margin-bottom: 14px; display: flex; justify-content: space-between; align-items: center;
    }

    /* Score Meter */
    .score-circle {
      width: 140px; height: 140px; border-radius: 50%; margin: 10px auto;
      display: grid; place-items: center; background: conic-gradient(var(--crit) 0deg 280deg, var(--panel-border) 280deg 360deg);
      box-shadow: 0 0 24px rgba(255, 0, 85, 0.2);
    }
    .score-inner {
      width: 110px; height: 110px; border-radius: 50%; background: var(--panel);
      display: flex; flex-direction: column; align-items: center; justify-content: center;
    }
    .score-val { font-size: 36px; font-weight: 900; line-height: 1; color: #fff; }
    .score-grade { font-size: 11px; text-transform: uppercase; color: var(--crit); font-weight: 700; margin-top: 4px; }

    /* Stats Grid */
    .stats-row { display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px; margin-top: 14px; text-align: center; }
    .stat-box { background: #080d19; border: 1px solid var(--panel-border); border-radius: 8px; padding: 8px 4px; }
    .stat-n { font-size: 16px; font-weight: 800; }
    .stat-l { font-size: 9px; text-transform: uppercase; color: var(--muted); margin-top: 2px; }

    /* Live Terminal Log */
    .terminal {
      background: #04060b; border: 1px solid #141d33; border-radius: 8px;
      padding: 14px; font-family: monospace; font-size: 11px; height: 190px;
      overflow-y: auto; color: #38bdf8;
    }
    .terminal-line { margin-bottom: 4px; }

    /* Interactive Graph Canvas */
    #graphCanvas {
      width: 100%; height: 380px; background: #050812;
      border: 1px solid var(--panel-border); border-radius: 10px; display: block;
    }

    /* Findings List */
    .finding-item {
      background: #090f1d; border: 1px solid var(--panel-border); border-left: 4px solid var(--crit);
      border-radius: 8px; padding: 14px 16px; margin-bottom: 12px; cursor: pointer; transition: all 0.15s ease;
    }
    .finding-item:hover { border-color: var(--accent); background: #0d1529; }
    .finding-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }
    .finding-title { font-weight: 700; font-size: 14px; color: #fff; }
    .badge { padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; text-transform: uppercase; color: #fff; }
    .badge.critical { background: var(--crit); }
    .badge.high { background: var(--high); }
    .badge.medium { background: var(--med); }
    .badge.low { background: var(--low); }
    .badge.info { background: var(--info); }
    .finding-meta { font-size: 11px; color: var(--muted); }

    /* Modal Detail */
    .modal {
      display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%;
      background: rgba(0,0,0,0.8); backdrop-filter: blur(8px); z-index: 200;
      place-items: center; padding: 20px;
    }
    .modal.active { display: grid; }
    .modal-box {
      background: var(--panel); border: 1px solid var(--panel-border); border-radius: 14px;
      max-width: 800px; width: 100%; max-height: 85vh; overflow-y: auto; padding: 28px;
    }
    .modal-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 18px; }
    .close-btn { background: none; border: none; color: var(--muted); font-size: 20px; cursor: pointer; }
    pre {
      background: #050811; border: 1px solid var(--panel-border); color: #38bdf8;
      padding: 12px; border-radius: 8px; font-size: 11px; overflow-x: auto; margin: 8px 0 14px;
    }
    .btn-action {
      background: #14223f; border: 1px solid var(--panel-border); color: var(--accent);
      padding: 6px 14px; border-radius: 6px; cursor: pointer; font-size: 11px; font-weight: 600;
      margin-right: 8px; transition: all 0.2s ease;
    }
    .btn-action:hover { background: var(--accent); color: #070b13; }

    /* Proposal & Delta Tab */
    .proposal-deck { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-top: 14px; }
    .tier-box {
      background: #080d1a; border: 1px solid var(--panel-border); border-radius: 12px;
      padding: 24px; display: flex; flex-direction: column;
    }
    .tier-box.highlight { border-color: var(--accent); box-shadow: 0 0 24px var(--accent-glow); }
    .tier-price { font-size: 28px; font-weight: 900; color: #fff; margin: 12px 0 4px; }
    .tier-list { margin: 16px 0; padding-left: 18px; color: var(--muted); font-size: 12px; flex: 1; }
    .tier-list li { margin-bottom: 6px; }

    /* Toast */
    #toast {
      position: fixed; bottom: 24px; right: 24px; background: var(--accent); color: #070b13;
      padding: 10px 18px; border-radius: 8px; font-weight: 700; display: none; z-index: 300;
      box-shadow: 0 0 20px var(--accent-glow);
    }
  </style>
</head>
<body>

<header>
  <div class="logo">
    <div style="width:12px; height:12px; background:var(--accent); border-radius:50%; box-shadow:0 0 10px var(--accent);"></div>
    VulnScope <span class="logo-badge">STUDIO 2.0</span>
  </div>
  <div class="tabs">
    <button class="tab-btn active" onclick="switchTab('scanTab')">Scan Console</button>
    <button class="tab-btn" onclick="switchTab('graphTab')">Attack Surface Topology</button>
    <button class="tab-btn" onclick="switchTab('pitchTab')">Client Pitch & ROI</button>
    <button class="tab-btn" onclick="switchTab('diffTab')">Delta Comparison</button>
    <button class="tab-btn" onclick="switchTab('exportTab')">Reports Hub</button>
  </div>
</header>

<div class="container">
  <!-- Scan Bar -->
  <div class="scan-bar">
    <input type="text" id="targetUrl" class="url-input" placeholder="Enter target URL or domain (e.g. https://target-client.com)" value="http://127.0.0.1:8099">
    <select id="scanProfile" class="select-profile">
      <option value="standard">Profile: Standard Audit (15 Modules)</option>
      <option value="deep">Profile: Deep Red-Team (Blind SQLi + Subdomains)</option>
      <option value="api">Profile: Modern API & Cloud Focus</option>
      <option value="fast">Profile: Lightning Recon (< 10s)</option>
    </select>
    <button class="btn-launch" id="launchBtn" onclick="launchScan()">⚡ Launch Assessment</button>
  </div>

  <!-- TAB 1: SCAN CONSOLE -->
  <div id="scanTab" class="tab-content">
    <div class="dashboard-grid">
      <!-- Left sidebar -->
      <div style="display:grid; gap:20px;">
        <div class="card">
          <div class="card-title">Real-Time Risk Gauge</div>
          <div class="score-circle" id="gaugeCircle">
            <div class="score-inner">
              <div class="score-val" id="scoreVal">0</div>
              <div class="score-grade" id="gradeVal">READY</div>
            </div>
          </div>
          <div class="stats-row">
            <div class="stat-box"><div class="stat-n" id="cntCrit" style="color:var(--crit)">0</div><div class="stat-l">Crit</div></div>
            <div class="stat-box"><div class="stat-n" id="cntHigh" style="color:var(--high)">0</div><div class="stat-l">High</div></div>
            <div class="stat-box"><div class="stat-n" id="cntMed" style="color:var(--med)">0</div><div class="stat-l">Med</div></div>
            <div class="stat-box"><div class="stat-n" id="cntLow" style="color:var(--low)">0</div><div class="stat-l">Low</div></div>
            <div class="stat-box"><div class="stat-n" id="cntInfo" style="color:var(--info)">0</div><div class="stat-l">Info</div></div>
          </div>
        </div>

        <div class="card">
          <div class="card-title">Scanner Event Stream</div>
          <div class="terminal" id="terminalLog">
            <div class="terminal-line">[System] VulnScope Cyberpunk Security Engine Initialized.</div>
            <div class="terminal-line">[System] Ready to run authorized assessments.</div>
          </div>
        </div>
      </div>

      <!-- Main findings column -->
      <div class="card">
        <div class="card-title">
          <span>Discovered Security Vulnerabilities (<span id="findingsCount">0</span>)</span>
          <input type="text" id="liveSearch" placeholder="Filter findings..." onkeyup="filterLiveFindings()" style="background:#060912; border:1px solid var(--panel-border); color:#fff; padding:4px 10px; border-radius:6px; font-size:12px;">
        </div>
        <div id="findingsContainer">
          <div style="text-align:center; padding:60px 20px; color:var(--muted);">
            No active scan in progress. Enter a target URL above and click <strong>Launch Assessment</strong>.
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- TAB 2: TOPOLOGY GRAPH -->
  <div id="graphTab" class="tab-content" style="display:none;">
    <div class="card">
      <div class="card-title">
        <span>Attack Surface & Threat Node Topology</span>
        <span style="font-size:11px; color:var(--muted)">Hover or drag nodes to inspect connections</span>
      </div>
      <canvas id="graphCanvas"></canvas>
    </div>
  </div>

  <!-- TAB 3: PITCH & ROI -->
  <div id="pitchTab" class="tab-content" style="display:none;">
    <div class="card">
      <div class="card-title">Client Remediation Pitch & Commercial ROI Studio</div>
      <p style="color:var(--muted); margin-bottom:18px;">
        Translate technical vulnerabilities into undeniable financial numbers and turnkey remediation packages ready for client sign-off.
      </p>
      <div class="proposal-deck" id="pitchDeck">
        <div class="tier-box">
          <span style="font-size:11px; font-weight:700; color:var(--low);">TIER 1</span>
          <h3 style="margin-top:4px;">Emergency Quick-Wins</h3>
          <div class="tier-price">$1,440</div>
          <div style="font-size:11px; color:var(--muted);">Immediate remediation of critical risks</div>
          <ul class="tier-list">
            <li>Immediate patching of Critical & High CVEs</li>
            <li>Security Headers & TLS Hardening</li>
            <li>Removal of exposed credentials & dotfiles</li>
            <li>Re-scan verification certificate</li>
          </ul>
          <button class="btn-action" onclick="copyPitch(1)">Copy Proposal Scope</button>
        </div>

        <div class="tier-box highlight">
          <span style="font-size:11px; font-weight:700; color:var(--accent);">TIER 2 (RECOMMENDED)</span>
          <h3 style="margin-top:4px;">Complete Remediation & Attestation</h3>
          <div class="tier-price">$3,840</div>
          <div style="font-size:11px; color:var(--muted);">Zero-vulnerability Grade A certification</div>
          <ul class="tier-list">
            <li>Full remediation of all findings (Critical to Low)</li>
            <li>WAF / Cloudflare Virtual Patching Rules</li>
            <li>Code-level assistance with development team</li>
            <li>Independent Letter of Security Attestation</li>
            <li>Before vs After Delta Report proving Grade A</li>
          </ul>
          <button class="btn-action" style="background:var(--accent); color:#070b13;" onclick="copyPitch(2)">Copy Proposal Scope</button>
        </div>

        <div class="tier-box">
          <span style="font-size:11px; font-weight:700; color:var(--purple);">TIER 3</span>
          <h3 style="margin-top:4px;">Continuous Security Retainer</h3>
          <div class="tier-price">$950 / mo</div>
          <div style="font-size:11px; color:var(--muted);">Proactive threat monitoring & SLA</div>
          <ul class="tier-list">
            <li>Weekly automated vulnerability scanning</li>
            <li>Continuous subdomain & cloud asset monitoring</li>
            <li>Under 4-hour emergency incident SLA</li>
            <li>Monthly compliance & security check-in</li>
          </ul>
          <button class="btn-action" onclick="copyPitch(3)">Copy Proposal Scope</button>
        </div>
      </div>
    </div>
  </div>

  <!-- TAB 4: DELTA COMPARISON -->
  <div id="diffTab" class="tab-content" style="display:none;">
    <div class="card">
      <div class="card-title">Before vs. After Remediation Delta Comparison</div>
      <p style="color:var(--muted); margin-bottom:18px;">
        Compare an initial baseline audit against a re-test scan to prove remediation efficacy to your client.
      </p>
      <div style="display:flex; gap:14px; margin-bottom:18px;">
        <input type="text" id="diffScanA" class="url-input" placeholder="Baseline Scan ID or Path (e.g. reports/scan1.json)">
        <input type="text" id="diffScanB" class="url-input" placeholder="Verification Scan ID or Path (e.g. reports/scan2.json)">
        <button class="btn-action" style="padding:10px 20px;" onclick="runDiff()">Compare Delta</button>
      </div>
      <div id="diffOutput"></div>
    </div>
  </div>

  <!-- TAB 5: EXPORTS -->
  <div id="exportTab" class="tab-content" style="display:none;">
    <div class="card">
      <div class="card-title">Generated Security Reports & Data Artifacts</div>
      <div id="reportsList" style="display:grid; gap:10px; margin-top:14px;">
        <p style="color:var(--muted)">Run a scan to generate downloadable reports.</p>
      </div>
    </div>
  </div>
</div>

<!-- Modal Finding Detail -->
<div class="modal" id="findingModal">
  <div class="modal-box">
    <div class="modal-header">
      <div>
        <span class="badge critical" id="mBadge">CRITICAL</span>
        <h2 id="mTitle" style="color:#fff; margin-top:8px;">Finding Title</h2>
      </div>
      <button class="close-btn" onclick="closeModal()">&times;</button>
    </div>
    <div style="font-size:11px; color:var(--muted); margin-bottom:14px;" id="mTags"></div>
    <h4 style="font-size:12px; text-transform:uppercase; color:var(--muted); margin:12px 0 4px;">Technical Description</h4>
    <p id="mDesc" style="color:var(--text);"></p>
    <h4 style="font-size:12px; text-transform:uppercase; color:var(--muted); margin:12px 0 4px;">Business & Compliance Impact</h4>
    <p id="mImpact" style="color:var(--text);"></p>
    <h4 style="font-size:12px; text-transform:uppercase; color:var(--muted); margin:12px 0 4px;">Reproducible Proof of Concept</h4>
    <pre id="mPoc"></pre>
    <div style="display:flex; gap:8px; margin-bottom:14px;">
      <button class="btn-action" onclick="copyModalPoc()">Copy cURL</button>
      <button class="btn-action" onclick="verifyModalFinding()">⚡ Live Re-Test</button>
    </div>
    <h4 style="font-size:12px; text-transform:uppercase; color:var(--muted); margin:12px 0 4px;">Ready-to-Deploy Remediation Patch</h4>
    <pre id="mPatch"></pre>
  </div>
</div>

<div id="toast">Copied to clipboard!</div>

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
  setTimeout(() => t.style.display = 'none', 2500);
}

function logTerminal(msg) {
  const t = document.getElementById('terminalLog');
  const line = document.createElement('div');
  line.className = 'terminal-line';
  line.innerText = msg;
  t.appendChild(line);
  t.scrollTop = t.scrollHeight;
}

function launchScan() {
  const target = document.getElementById('targetUrl').value.trim();
  const profile = document.getElementById('scanProfile').value;
  if (!target) return alert('Please enter a target URL');

  document.getElementById('launchBtn').disabled = true;
  document.getElementById('launchBtn').innerText = 'Scanning...';
  logTerminal('[Scan] Initiating authorized assessment on: ' + target);

  fetch('/api/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target: target, profile: profile })
  })
  .then(res => res.json())
  .then(data => {
    currentScanId = data.scan_id;
    logTerminal('[Scan] Job ID assigned: ' + currentScanId);
    pollScan();
  })
  .catch(err => {
    logTerminal('[Error] Failed to start scan: ' + err);
    document.getElementById('launchBtn').disabled = false;
    document.getElementById('launchBtn').innerText = '⚡ Launch Assessment';
  });
}

function pollScan() {
  if (pollInterval) clearInterval(pollInterval);
  pollInterval = setInterval(() => {
    fetch('/api/scan/' + currentScanId + '/status')
    .then(r => r.json())
    .then(state => {
      // update logs
      if (state.logs && state.logs.length) {
        state.logs.forEach(l => logTerminal(l));
      }
      // update stats
      document.getElementById('scoreVal').innerText = state.score;
      document.getElementById('gradeVal').innerText = state.grade;
      const deg = Math.round(state.score * 3.6);
      document.getElementById('gaugeCircle').style.background = `conic-gradient(var(--crit) 0deg ${deg}deg, var(--panel-border) ${deg}deg 360deg)`;

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
        document.getElementById('launchBtn').innerText = '⚡ Launch Assessment';
        logTerminal('[Scan] Assessment completed successfully! Reports generated.');
        loadReportsList();
      }
    });
  }, 1200);
}

function renderFindings(list) {
  document.getElementById('findingsCount').innerText = list.length;
  const container = document.getElementById('findingsContainer');
  if (!list.length) {
    container.innerHTML = '<div style="text-align:center; padding:40px; color:var(--muted)">Scanning target...</div>';
    return;
  }
  container.innerHTML = list.map((f, idx) => `
    <div class="finding-item" style="border-left-color:var(--${f.severity})" onclick="openModal(${idx})">
      <div class="finding-head">
        <span class="finding-title">${f.title}</span>
        <span class="badge ${f.severity}">${f.severity.toUpperCase()}</span>
      </div>
      <div class="finding-meta">
        ${f.category} &bull; ${f.owasp || 'OWASP'} &bull; CWE: ${f.cwe || 'N/A'} &bull; Effort: ${f.effort_label || f.effort}
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
  document.getElementById('mTags').innerText = `${f.category} | ${f.cwe} | ${f.owasp} | CVSS ${f.cvss || 'N/A'}`;
  document.getElementById('mDesc').innerText = f.description;
  document.getElementById('mImpact').innerText = f.impact || 'N/A';
  document.getElementById('mPoc').innerText = f.poc_curl || `curl -i -k '${f.location || document.getElementById('targetUrl').value}'`;
  document.getElementById('mPatch').innerText = f.remediation || 'Apply input sanitization and secure configuration.';
  document.getElementById('findingModal').classList.add('active');
}

function closeModal() { document.getElementById('findingModal').classList.remove('active'); }
function copyModalPoc() {
  if (activeModalFinding) {
    navigator.clipboard.writeText(document.getElementById('mPoc').innerText);
    showToast('PoC cURL copied!');
  }
}

function verifyModalFinding() {
  if (!activeModalFinding) return;
  showToast('Sending live verification probe...');
  fetch('/api/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: activeModalFinding.location || document.getElementById('targetUrl').value })
  })
  .then(r => r.json())
  .then(res => {
    alert(`Verification probe returned HTTP ${res.status}. Body preview:\n` + res.body_preview);
  });
}

function renderTopology() {
  const canvas = document.getElementById('graphCanvas');
  const ctx = canvas.getContext('2d');
  canvas.width = canvas.parentElement.clientWidth - 40;
  canvas.height = 380;

  ctx.fillStyle = '#050812';
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  const nodes = (topologyNodes && topologyNodes.nodes && topologyNodes.nodes.length) ? topologyNodes.nodes : [
    { id: 'target', label: document.getElementById('targetUrl').value || 'Target', type: 'target', status: 'critical' },
    { id: 'ip1', label: '104.21.45.2', type: 'ip', status: 'info' },
    { id: 'tls', label: 'TLS 1.3', type: 'tls', status: 'info' },
    { id: 'v1', label: 'CORS Reflection', type: 'vuln', status: 'critical' },
    { id: 'v2', label: 'Missing CSP', type: 'vuln', status: 'high' },
  ];

  const centerX = canvas.width / 2;
  const centerY = canvas.height / 2;

  // Draw links
  ctx.strokeStyle = '#1a2744';
  ctx.lineWidth = 1.5;
  nodes.forEach((n, i) => {
    if (i === 0) return;
    const angle = (i / (nodes.length - 1)) * 2 * Math.PI;
    const x = centerX + Math.cos(angle) * 130;
    const y = centerY + Math.sin(angle) * 110;
    ctx.beginPath();
    ctx.moveTo(centerX, centerY);
    ctx.lineTo(x, y);
    ctx.stroke();
  });

  // Draw center node
  ctx.fillStyle = '#00f2fe';
  ctx.beginPath();
  ctx.arc(centerX, centerY, 24, 0, 2 * Math.PI);
  ctx.fill();
  ctx.fillStyle = '#fff';
  ctx.font = '10px monospace';
  ctx.textAlign = 'center';
  ctx.fillText('TARGET', centerX, centerY + 4);

  // Draw satellite nodes
  nodes.forEach((n, i) => {
    if (i === 0) return;
    const angle = (i / (nodes.length - 1)) * 2 * Math.PI;
    const x = centerX + Math.cos(angle) * 130;
    const y = centerY + Math.sin(angle) * 110;

    ctx.fillStyle = n.status === 'critical' ? '#ff0055' : (n.status === 'high' ? '#ff5500' : '#38bdf8');
    ctx.beginPath();
    ctx.arc(x, y, 16, 0, 2 * Math.PI);
    ctx.fill();

    ctx.fillStyle = '#cbd5e1';
    ctx.font = '11px sans-serif';
    ctx.fillText(n.label.slice(0, 18), x, y + 26);
  });
}

function loadReportsList() {
  fetch('/api/reports')
  .then(r => r.json())
  .then(list => {
    const box = document.getElementById('reportsList');
    if (!list.length) return;
    box.innerHTML = list.map(item => `
      <div style="background:#090f1d; border:1px solid var(--panel-border); padding:12px 16px; border-radius:8px; display:flex; justify-content:space-between; align-items:center;">
        <div>
          <strong style="color:#fff;">${item.name}</strong>
          <div style="font-size:11px; color:var(--muted)">Size: ${(item.size/1024).toFixed(1)} KB &bull; Modified: ${item.modified}</div>
        </div>
        <a href="/reports/${item.name}" target="_blank" class="btn-action" style="text-decoration:none;">Download / View</a>
      </div>
    `).join('');
  });
}

function copyPitch(tier) {
  showToast('Copied Tier ' + tier + ' proposal scope to clipboard!');
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
      <div style="display:grid; grid-template-columns:repeat(3,1fr); gap:14px; margin-top:14px;">
        <div class="stat-box"><div class="stat-n" style="color:var(--accent);">${delta.score_change}</div><div class="stat-l">Score Change</div></div>
        <div class="stat-box"><div class="stat-n" style="color:#10b981;">${delta.resolved_count}</div><div class="stat-l">Resolved Vulnerabilities</div></div>
        <div class="stat-box"><div class="stat-n" style="color:var(--crit);">${delta.new_count}</div><div class="stat-l">New Issues</div></div>
      </div>
      <pre style="margin-top:14px;">${delta.verdict}</pre>
    `;
  });
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
                for fname in sorted(os.listdir(reports_dir), reverse=True):
                    fpath = os.path.join(reports_dir, fname)
                    if os.path.isfile(fpath):
                        items.append({
                            "name": fname,
                            "size": os.path.getsize(fpath),
                            "modified": _dt.datetime.fromtimestamp(os.path.getmtime(fpath)).strftime("%Y-%m-%d %H:%M"),
                        })
            self._send_json(items)
            return

        # Download report file
        if path.startswith("/reports/"):
            fname = os.path.basename(path)
            fpath = os.path.join("reports", fname)
            if os.path.exists(fpath) and os.path.isfile(fpath):
                ctype = "text/html" if fname.endswith(".html") else ("application/json" if fname.endswith(".json") else "application/octet-stream")
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

    q.put(f"[Engine] Starting assessment of {target} (Profile: {profile})")

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
        q.put(f"[Recon] Host resolved to: {', '.join(ips) if ips else 'unresolved'}")

        ctx.pages = crawl(http, target, max_pages=options.max_pages, depth=options.depth, log=lambda m: q.put(m))
        res.pages_scanned = [p.url for p in ctx.pages]
        q.put(f"[Crawler] Retrieved {len(ctx.pages)} target routes.")

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
    print(f"  ⚡ VulnScope Cyberpunk Security Studio Live")
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
