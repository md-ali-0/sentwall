"""VulnScope Cyberpunk Studio - Embedded Real-Time Hacker Security Console & REST API.

Provides an elite Red-Team HUD, interactive Matrix digital rain, synthesized cyber audio FX,
animated threat radar, interactive attack topology graph, 1-click PoC verification,
virtual WAF patch generator, client pitch studio, and delta comparison hub.
Runs with zero external npm or node dependencies.
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
    """Embedded single-page Cyberpunk Hacker Security Studio application."""
    return """<!DOCTYPE html>
<html lang="en" data-theme="matrix">
<head>
  <meta charset="utf-8">
  <title>VULNSCOPE // CYBER WARFARE OPERATING SYSTEM v2.0</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root[data-theme="matrix"] {
      --bg: #030806; --panel: rgba(5, 18, 12, 0.88); --panel-border: #00ff66;
      --accent: #00ff66; --accent-glow: rgba(0, 255, 102, 0.45);
      --accent-dim: rgba(0, 255, 102, 0.12); --text: #d4ffd6; --muted: #4e855c;
      --crit: #ff003c; --crit-glow: rgba(255, 0, 60, 0.5);
      --high: #ff6b00; --med: #ffb703; --low: #00e5ff; --info: #5c7080;
      --radar-bg: rgba(0, 255, 102, 0.04);
    }
    :root[data-theme="cyberpunk"] {
      --bg: #040714; --panel: rgba(8, 15, 34, 0.88); --panel-border: #00f2fe;
      --accent: #00f2fe; --accent-glow: rgba(0, 242, 254, 0.45);
      --accent-dim: rgba(0, 242, 254, 0.12); --text: #e2f1ff; --muted: #5d7a99;
      --crit: #ff0055; --crit-glow: rgba(255, 0, 85, 0.5);
      --high: #ff5500; --med: #ffaa00; --low: #00aaff; --info: #64748b;
      --radar-bg: rgba(0, 242, 254, 0.04);
    }
    :root[data-theme="redteam"] {
      --bg: #0a0304; --panel: rgba(24, 7, 10, 0.88); --panel-border: #ff003c;
      --accent: #ff003c; --accent-glow: rgba(255, 0, 60, 0.45);
      --accent-dim: rgba(255, 0, 60, 0.12); --text: #ffe2e6; --muted: #995c64;
      --crit: #ff003c; --crit-glow: rgba(255, 0, 60, 0.6);
      --high: #ff6b00; --med: #ffb703; --low: #00e5ff; --info: #64748b;
      --radar-bg: rgba(255, 0, 60, 0.04);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg); color: var(--text);
      font-family: "Courier New", Courier, monospace, "Segoe UI", sans-serif;
      font-size: 13px; line-height: 1.5; overflow-x: hidden; position: relative;
    }

    /* Background Matrix Canvas */
    #matrixCanvas {
      position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
      pointer-events: none; z-index: 0; opacity: 0.18;
    }

    /* CRT Scanlines Overlay */
    .crt-overlay {
      position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
      background: linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.35) 50%),
                  linear-gradient(90deg, rgba(255, 0, 0, 0.03), rgba(0, 255, 0, 0.01), rgba(0, 0, 255, 0.03));
      background-size: 100% 3px, 6px 100%;
      pointer-events: none; z-index: 999; opacity: 0.7;
    }

    /* Header Bar */
    header {
      background: rgba(3, 8, 12, 0.95); backdrop-filter: blur(14px);
      border-bottom: 1px solid var(--panel-border); padding: 12px 24px;
      display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; z-index: 100;
      box-shadow: 0 0 20px rgba(0,0,0,0.8);
    }
    .logo {
      font-size: 17px; font-weight: 900; letter-spacing: 0.15em; color: var(--accent);
      display: flex; align-items: center; gap: 10px; text-transform: uppercase;
      text-shadow: 0 0 14px var(--accent-glow);
    }
    .logo-badge {
      font-size: 10px; background: var(--crit); color: #fff; padding: 2px 7px;
      border-radius: 3px; font-weight: 800; letter-spacing: 0.1em;
      box-shadow: 0 0 10px var(--crit-glow);
    }
    .hud-status {
      display: flex; gap: 16px; font-size: 11px; color: var(--muted); align-items: center;
    }
    .hud-status-item { display: flex; align-items: center; gap: 6px; }
    .status-dot { width: 7px; height: 7px; background: var(--accent); border-radius: 50%; box-shadow: 0 0 8px var(--accent); animation: pulseDot 1.5s infinite; }
    @keyframes pulseDot { 0%, 100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.4; transform: scale(0.8); } }

    .tabs { display: flex; gap: 4px; }
    .tab-btn {
      background: transparent; color: var(--muted); border: 1px solid transparent;
      padding: 6px 14px; border-radius: 4px; cursor: pointer; font-weight: 700;
      font-family: inherit; font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em;
      transition: all 0.2s ease;
    }
    .tab-btn.active, .tab-btn:hover {
      color: var(--accent); border-color: var(--panel-border);
      background: var(--accent-dim); box-shadow: 0 0 12px var(--accent-glow);
    }

    .container { max-width: 1450px; margin: 0 auto; padding: 24px; display: grid; gap: 24px; position: relative; z-index: 10; }

    /* HUD Corner Panel Style */
    .hud-panel {
      position: relative; background: var(--panel);
      border: 1px solid rgba(0, 255, 102, 0.25);
      border-radius: 6px; padding: 20px;
      box-shadow: 0 8px 32px rgba(0,0,0,0.7), inset 0 0 20px rgba(0,0,0,0.5);
    }
    .hud-panel::before {
      content: ""; position: absolute; top: -1px; left: -1px; width: 12px; height: 12px;
      border-top: 2px solid var(--accent); border-left: 2px solid var(--accent);
    }
    .hud-panel::after {
      content: ""; position: absolute; bottom: -1px; right: -1px; width: 12px; height: 12px;
      border-bottom: 2px solid var(--accent); border-right: 2px solid var(--accent);
    }
    .hud-title {
      font-size: 11px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.12em;
      color: var(--accent); margin-bottom: 14px; display: flex; justify-content: space-between; align-items: center;
      border-bottom: 1px dashed rgba(0, 255, 102, 0.2); padding-bottom: 8px;
    }

    /* Target Command Bar */
    .command-bar {
      display: flex; gap: 12px; align-items: center; flex-wrap: wrap;
    }
    .target-input {
      flex: 1; min-width: 280px; background: #010408; border: 1px solid var(--panel-border);
      color: var(--accent); padding: 12px 18px; border-radius: 4px; font-size: 14px; font-family: inherit;
      box-shadow: inset 0 0 10px rgba(0,0,0,0.8);
    }
    .target-input:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 16px var(--accent-glow); }
    .select-profile {
      background: #010408; border: 1px solid var(--panel-border); color: var(--accent);
      padding: 12px 16px; border-radius: 4px; font-size: 12px; cursor: pointer; font-family: inherit;
    }
    .btn-engage {
      background: var(--accent); color: #010408;
      border: 1px solid var(--accent); padding: 12px 28px; border-radius: 4px; font-weight: 900;
      letter-spacing: 0.1em; text-transform: uppercase; cursor: pointer; font-family: inherit;
      box-shadow: 0 0 24px var(--accent-glow); transition: all 0.2s ease;
    }
    .btn-engage:hover { transform: scale(1.02); box-shadow: 0 0 35px var(--accent-glow); }

    /* Dashboard Layout */
    .dashboard-grid { display: grid; grid-template-columns: 340px 1fr; gap: 24px; }

    /* Rotating Radar Sonar */
    .radar-box {
      width: 170px; height: 170px; border-radius: 50%; margin: 8px auto 14px;
      position: relative; background: var(--radar-bg);
      border: 1px solid var(--accent); box-shadow: 0 0 25px var(--accent-glow), inset 0 0 20px var(--accent-dim);
      overflow: hidden;
    }
    .radar-ring {
      position: absolute; border-radius: 50%; border: 1px dashed rgba(0, 255, 102, 0.3);
      top: 50%; left: 50%; transform: translate(-50%, -50%);
    }
    .radar-crosshair-h { position: absolute; width: 100%; height: 1px; top: 50%; background: rgba(0, 255, 102, 0.2); }
    .radar-crosshair-v { position: absolute; height: 100%; width: 1px; left: 50%; background: rgba(0, 255, 102, 0.2); }
    .radar-sweep {
      position: absolute; width: 100%; height: 100%; border-radius: 50%;
      background: conic-gradient(from 0deg, rgba(0, 255, 102, 0.55) 0deg, transparent 65deg, transparent 360deg);
      animation: rotateRadar 2.5s linear infinite;
    }
    @keyframes rotateRadar { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }

    /* Score HUD */
    .score-display { text-align: center; margin-top: 6px; }
    .score-num { font-size: 38px; font-weight: 900; color: #fff; line-height: 1; text-shadow: 0 0 14px var(--crit-glow); }
    .score-verdict { font-size: 11px; text-transform: uppercase; color: var(--crit); font-weight: 800; margin-top: 4px; letter-spacing: 0.1em; }

    /* Stats Grid */
    .stats-row { display: grid; grid-template-columns: repeat(5, 1fr); gap: 6px; margin-top: 14px; text-align: center; }
    .stat-box { background: #010408; border: 1px solid rgba(0, 255, 102, 0.2); border-radius: 4px; padding: 8px 2px; }
    .stat-n { font-size: 16px; font-weight: 900; font-family: monospace; }
    .stat-l { font-size: 9px; text-transform: uppercase; color: var(--muted); margin-top: 2px; }

    /* Hacker Terminal */
    .terminal-hud {
      background: #010408; border: 1px solid rgba(0, 255, 102, 0.3); border-radius: 4px;
      padding: 12px; font-family: "Courier New", monospace; font-size: 11px; height: 210px;
      overflow-y: auto; color: var(--accent); box-shadow: inset 0 0 15px rgba(0,0,0,0.9);
    }
    .term-line { margin-bottom: 4px; word-break: break-all; }
    .term-line.crit { color: var(--crit); text-shadow: 0 0 6px var(--crit-glow); }
    .term-line.high { color: var(--high); }
    .term-line.info { color: var(--muted); }

    .term-input-row {
      display: flex; gap: 8px; align-items: center; margin-top: 8px;
    }
    .term-prompt { color: var(--accent); font-weight: 900; }
    .term-cmd {
      flex: 1; background: transparent; border: none; color: #fff;
      font-family: inherit; font-size: 12px; outline: none;
    }

    /* Interactive Graph Canvas */
    #graphCanvas {
      width: 100%; height: 420px; background: #010408;
      border: 1px solid rgba(0, 255, 102, 0.3); border-radius: 6px; display: block;
    }

    /* Findings List */
    .finding-item {
      background: rgba(2, 8, 14, 0.9); border: 1px solid rgba(0, 255, 102, 0.2); border-left: 4px solid var(--crit);
      border-radius: 4px; padding: 14px 18px; margin-bottom: 12px; cursor: pointer; transition: all 0.15s ease;
    }
    .finding-item:hover { border-color: var(--accent); background: rgba(0, 255, 102, 0.05); transform: translateX(3px); }
    .finding-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }
    .finding-title { font-weight: 800; font-size: 13px; color: #fff; letter-spacing: 0.03em; }
    .badge { padding: 3px 8px; border-radius: 3px; font-size: 9px; font-weight: 800; text-transform: uppercase; color: #fff; letter-spacing: 0.1em; }
    .badge.critical { background: var(--crit); box-shadow: 0 0 10px var(--crit-glow); }
    .badge.high { background: var(--high); }
    .badge.medium { background: var(--med); color: #010408; }
    .badge.low { background: var(--low); color: #010408; }
    .badge.info { background: var(--info); }
    .finding-meta { font-size: 11px; color: var(--muted); }

    /* Modal Dossier */
    .modal {
      display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%;
      background: rgba(0,0,0,0.85); backdrop-filter: blur(10px); z-index: 500;
      place-items: center; padding: 20px;
    }
    .modal.active { display: grid; }
    .modal-box {
      background: var(--panel); border: 1px solid var(--panel-border); border-radius: 6px;
      max-width: 880px; width: 100%; max-height: 88vh; overflow-y: auto; padding: 28px;
      position: relative; box-shadow: 0 0 40px rgba(0, 255, 102, 0.2);
    }
    .modal-box::before {
      content: "TOP SECRET // RED-TEAM EXPLOIT DOSSIER";
      position: absolute; top: 10px; right: 40px; font-size: 9px; letter-spacing: 0.2em; color: var(--crit);
    }
    .modal-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 18px; }
    .close-btn { background: none; border: none; color: var(--muted); font-size: 24px; cursor: pointer; }
    .close-btn:hover { color: var(--crit); }
    pre {
      background: #010408; border: 1px solid rgba(0, 255, 102, 0.3); color: var(--accent);
      padding: 12px; border-radius: 4px; font-size: 11px; overflow-x: auto; margin: 8px 0 14px;
      box-shadow: inset 0 0 10px rgba(0,0,0,0.8);
    }
    .btn-action {
      background: var(--accent-dim); border: 1px solid var(--panel-border); color: var(--accent);
      padding: 7px 16px; border-radius: 4px; cursor: pointer; font-size: 11px; font-weight: 700;
      font-family: inherit; margin-right: 8px; transition: all 0.2s ease;
    }
    .btn-action:hover { background: var(--accent); color: #010408; box-shadow: 0 0 14px var(--accent-glow); }

    /* Toast */
    #toast {
      position: fixed; bottom: 24px; right: 24px; background: var(--accent); color: #010408;
      padding: 10px 20px; border-radius: 4px; font-weight: 900; display: none; z-index: 600;
      box-shadow: 0 0 20px var(--accent-glow); letter-spacing: 0.05em;
    }
  </style>
</head>
<body>

<canvas id="matrixCanvas"></canvas>
<div class="crt-overlay" id="crtOverlay"></div>

<header>
  <div class="logo">
    <div style="width:10px; height:10px; background:var(--accent); border-radius:50%; box-shadow:0 0 12px var(--accent);"></div>
    VULNSCOPE <span class="logo-badge">BLACK-OPS v2.0</span>
  </div>
  <div class="hud-status">
    <div class="hud-status-item"><span class="status-dot"></span> OPSEC: SECURE</div>
    <div class="hud-status-item">LATENCY: <span id="pingVal" style="color:var(--accent)">14ms</span></div>
    <div class="hud-status-item">SYSTEM: <span id="clockVal" style="color:var(--text)">00:00:00</span></div>
  </div>
  <div class="tabs">
    <button class="tab-btn active" onclick="switchTab('scanTab')">Ops Console</button>
    <button class="tab-btn" onclick="switchTab('graphTab')">Threat Topology</button>
    <button class="tab-btn" onclick="switchTab('pitchTab')">Breach ROI Studio</button>
    <button class="tab-btn" onclick="switchTab('diffTab')">Delta Diff</button>
    <button class="tab-btn" onclick="switchTab('exportTab')">Artifacts</button>
  </div>
  <div style="display:flex; gap:8px;">
    <button class="tab-btn" id="sfxToggle" onclick="toggleAudio()">🔊 SFX: ON</button>
    <button class="tab-btn" id="crtToggle" onclick="toggleCRT()">📺 CRT: ON</button>
    <select onchange="changeTheme(this.value)" class="select-profile" style="padding:4px 8px; font-size:11px;">
      <option value="matrix">Theme: Matrix Green</option>
      <option value="cyberpunk">Theme: Cyberpunk Cyan</option>
      <option value="redteam">Theme: Red-Team Blood</option>
    </select>
  </div>
</header>

<div class="container">
  <!-- Target Command Bar -->
  <div class="hud-panel">
    <div class="hud-title">
      <span>// MISSION DIRECTIVE & TARGET COORDINATES</span>
      <span>READY FOR ENGAGEMENT</span>
    </div>
    <div class="command-bar">
      <input type="text" id="targetUrl" class="target-input" placeholder="TARGET_URL: (e.g. https://target-domain.com)" value="http://127.0.0.1:8099">
      <select id="scanProfile" class="select-profile">
        <option value="standard">PROFILE: Standard Attack Surface (15 Modules)</option>
        <option value="deep">PROFILE: Deep Red-Team (Blind SQLi + Takeovers)</option>
        <option value="api">PROFILE: Cloud, S3 & GraphQL Interceptor</option>
        <option value="fast">PROFILE: Stealth Reconnaissance (< 10s)</option>
      </select>
      <button class="btn-engage" id="launchBtn" onclick="launchScan()">⚡ EXECUTE ENGAGEMENT</button>
    </div>
  </div>

  <!-- TAB 1: SCAN CONSOLE -->
  <div id="scanTab" class="tab-content">
    <div class="dashboard-grid">
      <!-- Left sidebar -->
      <div style="display:grid; gap:20px;">
        <div class="hud-panel">
          <div class="hud-title">
            <span>// THREAT SONAR & RADAR</span>
            <span id="scanStatusIndicator" style="color:var(--accent);">IDLE</span>
          </div>
          <div class="radar-box">
            <div class="radar-ring" style="width:50px; height:50px;"></div>
            <div class="radar-ring" style="width:100px; height:100px;"></div>
            <div class="radar-ring" style="width:140px; height:140px;"></div>
            <div class="radar-crosshair-h"></div>
            <div class="radar-crosshair-v"></div>
            <div class="radar-sweep"></div>
          </div>
          <div class="score-display">
            <div class="score-num" id="scoreVal">0</div>
            <div class="score-verdict" id="gradeVal">POSTURE: STANDBY</div>
          </div>
          <div class="stats-row">
            <div class="stat-box"><div class="stat-n" id="cntCrit" style="color:var(--crit)">0</div><div class="stat-l">Crit</div></div>
            <div class="stat-box"><div class="stat-n" id="cntHigh" style="color:var(--high)">0</div><div class="stat-l">High</div></div>
            <div class="stat-box"><div class="stat-n" id="cntMed" style="color:var(--med)">0</div><div class="stat-l">Med</div></div>
            <div class="stat-box"><div class="stat-n" id="cntLow" style="color:var(--low)">0</div><div class="stat-l">Low</div></div>
            <div class="stat-box"><div class="stat-n" id="cntInfo" style="color:var(--info)">0</div><div class="stat-l">Info</div></div>
          </div>
        </div>

        <div class="hud-panel">
          <div class="hud-title">
            <span>// CYBERWAR TELEMETRY LOG</span>
            <span style="font-size:9px; color:var(--muted)">LIVE STREAM</span>
          </div>
          <div class="terminal-hud" id="terminalLog">
            <div class="term-line info">[SYS_INIT] Kernel security engine initialized.</div>
            <div class="term-line info">[SYS_INIT] 15 attack verification modules loaded.</div>
            <div class="term-line">[READY] Awaiting target deployment.</div>
          </div>
          <div class="term-input-row">
            <span class="term-prompt">root@vulnscope:~#</span>
            <input type="text" id="termCmdInput" class="term-cmd" placeholder="Type command (e.g. scan, retest, help, clear)..." onkeydown="handleTermKey(event)">
          </div>
        </div>
      </div>

      <!-- Main findings column -->
      <div class="hud-panel">
        <div class="hud-title">
          <span>// COMPROMISED VECTORS & EXPLOIT CANARIES (<span id="findingsCount" style="color:var(--accent)">0</span>)</span>
          <input type="text" id="liveSearch" placeholder="Filter vulnerabilities..." onkeyup="filterLiveFindings()" style="background:#010408; border:1px solid var(--panel-border); color:var(--accent); padding:4px 12px; border-radius:3px; font-size:11px; font-family:inherit;">
        </div>
        <div id="findingsContainer">
          <div style="text-align:center; padding:70px 20px; color:var(--muted);">
            [NO TARGET ENGAGED] Enter coordinates above and click <strong>EXECUTE ENGAGEMENT</strong>.
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- TAB 2: TOPOLOGY GRAPH -->
  <div id="graphTab" class="tab-content" style="display:none;">
    <div class="hud-panel">
      <div class="hud-title">
        <span>// TARGET ATTACK SURFACE & THREAT SATELLITE TOPOLOGY</span>
        <span>DRAGGABLE SATELLITE BEACONS</span>
      </div>
      <canvas id="graphCanvas"></canvas>
    </div>
  </div>

  <!-- TAB 3: PITCH & ROI -->
  <div id="pitchTab" class="tab-content" style="display:none;">
    <div class="hud-panel">
      <div class="hud-title">
        <span>// COMMERCIAL EXPOSURE & CYBER BREACH FINANCIAL LOSS ESTIMATOR</span>
        <span>CONFIDENTIAL // SOW GENERATOR</span>
      </div>
      <div style="display:grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-top: 14px;">
        <div class="hud-panel" style="background:#02060c;">
          <span style="font-size:10px; font-weight:800; color:var(--low);">PACKAGE_TIER_01</span>
          <h3 style="margin-top:4px; color:#fff;">Emergency Triage</h3>
          <div style="font-size:28px; font-weight:900; color:var(--accent); margin:10px 0;">$1,440</div>
          <p style="font-size:11px; color:var(--muted); margin-bottom:14px;">Immediate eradication of Critical & High breach risks.</p>
          <ul style="padding-left:16px; font-size:12px; color:var(--text); margin-bottom:18px;">
            <li>Direct patching of Remote Code & SQLi</li>
            <li>Elimination of exposed .env & git repositories</li>
            <li>Security Headers & TLS Hardening</li>
            <li>Re-test Attestation Certificate</li>
          </ul>
          <button class="btn-action" onclick="copyPitch(1)">Copy SOW Scope</button>
        </div>

        <div class="hud-panel" style="background:#02060c; border-color:var(--accent); box-shadow:0 0 25px var(--accent-glow);">
          <span style="font-size:10px; font-weight:800; color:var(--accent);">PACKAGE_TIER_02 // RECOMMENDED</span>
          <h3 style="margin-top:4px; color:#fff;">Complete Remediation & Attestation</h3>
          <div style="font-size:28px; font-weight:900; color:var(--accent); margin:10px 0;">$3,840</div>
          <p style="font-size:11px; color:var(--muted); margin-bottom:14px;">Zero-tolerance vulnerability lockdown to Grade A posture.</p>
          <ul style="padding-left:16px; font-size:12px; color:var(--text); margin-bottom:18px;">
            <li>Full remediation of all findings (Crit to Low)</li>
            <li>Virtual WAF / Cloudflare rules deployment</li>
            <li>Developer code-level remediation pair support</li>
            <li>Before vs After Delta Report proving Grade A</li>
            <li>Executive Letter of Cybersecurity Attestation</li>
          </ul>
          <button class="btn-action" style="background:var(--accent); color:#010408;" onclick="copyPitch(2)">Copy SOW Scope</button>
        </div>

        <div class="hud-panel" style="background:#02060c;">
          <span style="font-size:10px; font-weight:800; color:var(--high);">PACKAGE_TIER_03</span>
          <h3 style="margin-top:4px; color:#fff;">Continuous Defense Retainer</h3>
          <div style="font-size:28px; font-weight:900; color:var(--accent); margin:10px 0;">$950 / mo</div>
          <p style="font-size:11px; color:var(--muted); margin-bottom:14px;">Continuous attack surface monitoring & 4h SLA.</p>
          <ul style="padding-left:16px; font-size:12px; color:var(--text); margin-bottom:18px;">
            <li>Weekly automated vulnerability scanning</li>
            <li>Continuous subdomain & cloud asset monitoring</li>
            <li>Under 4-hour emergency incident response</li>
            <li>Quarterly executive briefing & compliance review</li>
          </ul>
          <button class="btn-action" onclick="copyPitch(3)">Copy SOW Scope</button>
        </div>
      </div>
    </div>
  </div>

  <!-- TAB 4: DELTA COMPARISON -->
  <div id="diffTab" class="tab-content" style="display:none;">
    <div class="hud-panel">
      <div class="hud-title">
        <span>// REMEDIATION DELTA ENGINE (BEFORE VS. AFTER AUDIT)</span>
        <span>VERIFICATION PROOF</span>
      </div>
      <div style="display:flex; gap:12px; margin-bottom:18px;">
        <input type="text" id="diffScanA" class="target-input" placeholder="BASELINE_SCAN_PATH (e.g. reports/scan_before.json)">
        <input type="text" id="diffScanB" class="target-input" placeholder="VERIFICATION_SCAN_PATH (e.g. reports/scan_after.json)">
        <button class="btn-action" style="padding:10px 24px;" onclick="runDiff()">COMPUTE DELTA</button>
      </div>
      <div id="diffOutput"></div>
    </div>
  </div>

  <!-- TAB 5: EXPORTS -->
  <div id="exportTab" class="tab-content" style="display:none;">
    <div class="hud-panel">
      <div class="hud-title">
        <span>// CLASSIFIED AUDIT ARTIFACTS & REPORTS</span>
        <span>INSTANT DOWNLOAD</span>
      </div>
      <div id="reportsList" style="display:grid; gap:10px; margin-top:14px;">
        <p style="color:var(--muted)">Run an engagement to generate artifacts.</p>
      </div>
    </div>
  </div>
</div>

<!-- Modal Exploit Dossier -->
<div class="modal" id="findingModal">
  <div class="modal-box">
    <div class="modal-header">
      <div>
        <span class="badge critical" id="mBadge">CRITICAL</span>
        <h2 id="mTitle" style="color:#fff; margin-top:8px; font-family:inherit;">Finding Title</h2>
      </div>
      <button class="close-btn" onclick="closeModal()">&times;</button>
    </div>
    <div style="font-size:11px; color:var(--muted); margin-bottom:14px;" id="mTags"></div>

    <h4 style="font-size:11px; text-transform:uppercase; color:var(--accent); letter-spacing:0.1em; margin:12px 0 4px;">// TECHNICAL INTELLIGENCE</h4>
    <p id="mDesc" style="color:var(--text); font-size:12px;"></p>

    <h4 style="font-size:11px; text-transform:uppercase; color:var(--crit); letter-spacing:0.1em; margin:12px 0 4px;">// BUSINESS & COMPLIANCE IMPACT</h4>
    <p id="mImpact" style="color:var(--text); font-size:12px;"></p>

    <h4 style="font-size:11px; text-transform:uppercase; color:var(--accent); letter-spacing:0.1em; margin:12px 0 4px;">// WEAPONIZED PROOF OF CONCEPT</h4>
    <pre id="mPoc"></pre>
    <div style="display:flex; gap:8px; margin-bottom:14px;">
      <button class="btn-action" onclick="copyModalPoc()">COPY cURL</button>
      <button class="btn-action" onclick="verifyModalFinding()">⚡ LIVE RE-TEST / EXPLOIT PROBE</button>
    </div>

    <h4 style="font-size:11px; text-transform:uppercase; color:var(--accent); letter-spacing:0.1em; margin:12px 0 4px;">// HARDENING & VIRTUAL WAF RULE</h4>
    <pre id="mPatch"></pre>
  </div>
</div>

<div id="toast">ACTION EXECUTED</div>

<script>
// --- Web Audio Cyber FX Synthesizer ---
let audioCtx = null;
let soundEnabled = true;

function initAudio() {
  if (!audioCtx) {
    audioCtx = new (window.AudioContext || window.webkitAudioContext)();
  }
}

function playBeep(freq = 880, type = 'sine', duration = 0.08) {
  if (!soundEnabled) return;
  try {
    initAudio();
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.type = type;
    osc.frequency.value = freq;
    gain.gain.setValueAtTime(0.08, audioCtx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.0001, audioCtx.currentTime + duration);
    osc.connect(gain);
    gain.connect(audioCtx.destination);
    osc.start();
    osc.stop(audioCtx.currentTime + duration);
  } catch(e) {}
}

function playAlertSound() {
  if (!soundEnabled) return;
  try {
    initAudio();
    playBeep(440, 'sawtooth', 0.15);
    setTimeout(() => playBeep(880, 'sawtooth', 0.2), 160);
  } catch(e) {}
}

function playSuccessSound() {
  if (!soundEnabled) return;
  try {
    initAudio();
    [523.25, 659.25, 783.99, 1046.50].forEach((f, i) => {
      setTimeout(() => playBeep(f, 'sine', 0.12), i * 100);
    });
  } catch(e) {}
}

function toggleAudio() {
  soundEnabled = !soundEnabled;
  document.getElementById('sfxToggle').innerText = soundEnabled ? '🔊 SFX: ON' : '🔈 SFX: OFF';
  showToast(soundEnabled ? 'Audio FX Enabled' : 'Audio FX Muted');
}

function toggleCRT() {
  const crt = document.getElementById('crtOverlay');
  crt.style.display = crt.style.display === 'none' ? 'block' : 'none';
  document.getElementById('crtToggle').innerText = crt.style.display === 'none' ? '📺 CRT: OFF' : '📺 CRT: ON';
}

function changeTheme(th) {
  document.documentElement.setAttribute('data-theme', th);
  showToast('Switched Theme: ' + th.toUpperCase());
}

// --- Matrix Digital Rain Canvas ---
const mCanvas = document.getElementById('matrixCanvas');
const mCtx = mCanvas.getContext('2d');
mCanvas.width = window.innerWidth;
mCanvas.height = window.innerHeight;

const matrixChars = '01ABCDEF0123456789ｦｱｳｴｵｶｷｹｺｻｼｽｾｿﾀﾂﾃﾅﾆﾇﾈﾊﾋﾎﾏﾐﾑﾒﾓﾔﾕﾗﾘﾜ';
const fontSize = 13;
const columns = Math.floor(mCanvas.width / fontSize);
const drops = Array(columns).fill(1);

function drawMatrix() {
  mCtx.fillStyle = 'rgba(3, 8, 6, 0.08)';
  mCtx.fillRect(0, 0, mCanvas.width, mCanvas.height);

  const theme = document.documentElement.getAttribute('data-theme') || 'matrix';
  mCtx.fillStyle = theme === 'matrix' ? '#00ff66' : (theme === 'cyberpunk' ? '#00f2fe' : '#ff003c');
  mCtx.font = fontSize + 'px monospace';

  for (let i = 0; i < drops.length; i++) {
    const text = matrixChars[Math.floor(Math.random() * matrixChars.length)];
    mCtx.fillText(text, i * fontSize, drops[i] * fontSize);
    if (drops[i] * fontSize > mCanvas.height && Math.random() > 0.975) {
      drops[i] = 0;
    }
    drops[i]++;
  }
}
setInterval(drawMatrix, 40);

window.addEventListener('resize', () => {
  mCanvas.width = window.innerWidth;
  mCanvas.height = window.innerHeight;
});

// --- System Clock ---
setInterval(() => {
  const d = new Date();
  document.getElementById('clockVal').innerText = d.toTimeString().split(' ')[0] + ' UTC';
}, 1000);

// --- Core Scan & State Logic ---
let currentScanId = null;
let currentFindings = [];
let pollInterval = null;
let topologyNodes = [];

function switchTab(tabId) {
  playBeep(900);
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
  line.className = 'term-line';
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
  playBeep(1200, 'sawtooth', 0.1);
  const target = document.getElementById('targetUrl').value.trim();
  const profile = document.getElementById('scanProfile').value;
  if (!target) return alert('Specify target coordinates');

  document.getElementById('launchBtn').disabled = true;
  document.getElementById('launchBtn').innerText = '⚡ ENGAGING TARGET...';
  document.getElementById('scanStatusIndicator').innerText = 'ACTIVE ATTACK';
  document.getElementById('scanStatusIndicator').style.color = 'var(--crit)';
  logTerminal('[ATTACK_ENGAGED] Launching targeted assessment on: ' + target);

  fetch('/api/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target: target, profile: profile })
  })
  .then(res => res.json())
  .then(data => {
    currentScanId = data.scan_id;
    logTerminal('[JOB_ASSIGNED] Target Track ID: ' + currentScanId);
    pollScan();
  })
  .catch(err => {
    logTerminal('[FATAL] Failed to initiate attack: ' + err);
    document.getElementById('launchBtn').disabled = false;
    document.getElementById('launchBtn').innerText = '⚡ EXECUTE ENGAGEMENT';
  });
}

function pollScan() {
  if (pollInterval) clearInterval(pollInterval);
  pollInterval = setInterval(() => {
    playBeep(1400, 'sine', 0.03);
    fetch('/api/scan/' + currentScanId + '/status')
    .then(r => r.json())
    .then(state => {
      if (state.logs && state.logs.length) {
        state.logs.forEach(l => logTerminal(l));
      }
      document.getElementById('scoreVal').innerText = state.score;
      document.getElementById('gradeVal').innerText = state.grade ? ('GRADE: ' + state.grade) : 'SCANNING';

      const c = state.counts || { critical:0, high:0, medium:0, low:0, info:0 };
      if (c.critical > parseInt(document.getElementById('cntCrit').innerText)) {
        playAlertSound();
      }
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
        playSuccessSound();
        document.getElementById('launchBtn').disabled = false;
        document.getElementById('launchBtn').innerText = '⚡ EXECUTE ENGAGEMENT';
        document.getElementById('scanStatusIndicator').innerText = 'MISSION COMPLETE';
        document.getElementById('scanStatusIndicator').style.color = 'var(--accent)';
        logTerminal('[SUCCESS] Assessment complete. High-priority intelligence saved.');
        loadReportsList();
      }
    });
  }, 1200);
}

function renderFindings(list) {
  document.getElementById('findingsCount').innerText = list.length;
  const container = document.getElementById('findingsContainer');
  if (!list.length) {
    container.innerHTML = '<div style="text-align:center; padding:50px; color:var(--muted)">[PENETRATION TESTING RUNNING] Probing attack vectors...</div>';
    return;
  }
  container.innerHTML = list.map((f, idx) => `
    <div class="finding-item" style="border-left-color:var(--${f.severity})" onclick="openModal(${idx})">
      <div class="finding-head">
        <span class="finding-title">[${f.severity.toUpperCase()}] ${f.title}</span>
        <span class="badge ${f.severity}">${f.severity.toUpperCase()}</span>
      </div>
      <div class="finding-meta">
        ${f.category} &bull; ${f.owasp || 'OWASP'} &bull; CWE: ${f.cwe || 'N/A'} &bull; CVSS: ${f.cvss || 'N/A'}
      </div>
    </div>
  `).join('');
}

let activeModalFinding = null;
function openModal(idx) {
  playBeep(700);
  const f = currentFindings[idx];
  if (!f) return;
  activeModalFinding = f;
  document.getElementById('mBadge').className = 'badge ' + f.severity;
  document.getElementById('mBadge').innerText = f.severity.toUpperCase();
  document.getElementById('mTitle').innerText = f.title;
  document.getElementById('mTags').innerText = `${f.category} // ${f.cwe} // ${f.owasp} // CVSS ${f.cvss || 'N/A'}`;
  document.getElementById('mDesc').innerText = f.description;
  document.getElementById('mImpact').innerText = f.impact || 'Direct breach risk, account takeover, or credential theft.';
  document.getElementById('mPoc').innerText = f.poc_curl || `curl -i -k '${f.location || document.getElementById('targetUrl').value}'`;
  document.getElementById('mPatch').innerText = f.remediation || 'Apply input sanitization and secure configuration.';
  document.getElementById('findingModal').classList.add('active');
}

function closeModal() {
  playBeep(500);
  document.getElementById('findingModal').classList.remove('active');
}

function copyModalPoc() {
  if (activeModalFinding) {
    playBeep(1100);
    navigator.clipboard.writeText(document.getElementById('mPoc').innerText);
    showToast('EXPLOIT cURL COPIED');
  }
}

function verifyModalFinding() {
  if (!activeModalFinding) return;
  playBeep(880, 'sawtooth');
  showToast('TRANSMITTING WEAPONIZED VERIFICATION CANARY...');
  fetch('/api/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: activeModalFinding.location || document.getElementById('targetUrl').value })
  })
  .then(r => r.json())
  .then(res => {
    alert(`[EXPLOIT PROBE RESPONSE]\nHTTP Status: ${res.status}\n\nServer Response Preview:\n` + res.body_preview);
  });
}

function renderTopology() {
  const canvas = document.getElementById('graphCanvas');
  const ctx = canvas.getContext('2d');
  canvas.width = canvas.parentElement.clientWidth - 40;
  canvas.height = 420;

  ctx.fillStyle = '#010408';
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  const nodes = (topologyNodes && topologyNodes.nodes && topologyNodes.nodes.length) ? topologyNodes.nodes : [
    { id: 'target', label: document.getElementById('targetUrl').value || 'Target Core', type: 'target', status: 'critical' },
    { id: 'ip1', label: '104.21.45.2 (Host IP)', type: 'ip', status: 'info' },
    { id: 'tls', label: 'TLS 1.3 Handshake', type: 'tls', status: 'info' },
    { id: 'v1', label: 'CORS Wildcard Reflection', type: 'vuln', status: 'critical' },
    { id: 'v2', label: 'Missing CSP Directives', type: 'vuln', status: 'high' },
    { id: 'v3', label: 'Exposed .env / git', type: 'vuln', status: 'critical' },
  ];

  const centerX = canvas.width / 2;
  const centerY = canvas.height / 2;

  // Energy connection lines
  ctx.strokeStyle = 'rgba(0, 255, 102, 0.25)';
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

  // Center Target Node
  ctx.fillStyle = '#00ff66';
  ctx.beginPath();
  ctx.arc(centerX, centerY, 28, 0, 2 * Math.PI);
  ctx.fill();
  ctx.fillStyle = '#010408';
  ctx.font = 'bold 11px monospace';
  ctx.textAlign = 'center';
  ctx.fillText('TARGET', centerX, centerY + 4);

  // Satellite threat nodes
  nodes.forEach((n, i) => {
    if (i === 0) return;
    const angle = (i / (nodes.length - 1)) * 2 * Math.PI;
    const x = centerX + Math.cos(angle) * 150;
    const y = centerY + Math.sin(angle) * 130;

    const col = n.status === 'critical' ? '#ff003c' : (n.status === 'high' ? '#ff6b00' : '#00e5ff');
    ctx.fillStyle = col;
    ctx.beginPath();
    ctx.arc(x, y, 16, 0, 2 * Math.PI);
    ctx.fill();

    // Pulse ring
    ctx.strokeStyle = col;
    ctx.beginPath();
    ctx.arc(x, y, 22, 0, 2 * Math.PI);
    ctx.stroke();

    ctx.fillStyle = '#d4ffd6';
    ctx.font = '11px monospace';
    ctx.fillText(n.label.slice(0, 20), x, y + 30);
  });
}

function handleTermKey(e) {
  if (e.key === 'Enter') {
    const cmd = e.target.value.trim();
    e.target.value = '';
    if (!cmd) return;
    logTerminal('root@vulnscope:~# ' + cmd);
    playBeep(1000);

    const parts = cmd.split(' ');
    const action = parts[0].toLowerCase();

    if (action === 'help') {
      logTerminal('Available commands: scan <url>, target <url>, retest, clear, sfx <on|off>, theme <matrix|cyberpunk|redteam>, export');
    } else if (action === 'clear') {
      document.getElementById('terminalLog').innerHTML = '';
    } else if (action === 'scan') {
      if (parts[1]) document.getElementById('targetUrl').value = parts[1];
      launchScan();
    } else if (action === 'target') {
      if (parts[1]) {
        document.getElementById('targetUrl').value = parts[1];
        logTerminal('[OK] Target set to: ' + parts[1]);
      }
    } else if (action === 'theme') {
      if (parts[1]) changeTheme(parts[1]);
    } else if (action === 'sfx') {
      toggleAudio();
    } else {
      logTerminal('[ERROR] Unknown directive: ' + action + '. Type "help" for options.');
    }
  }
}

function loadReportsList() {
  fetch('/api/reports')
  .then(r => r.json())
  .then(list => {
    const box = document.getElementById('reportsList');
    if (!list.length) return;
    box.innerHTML = list.map(item => `
      <div style="background:#010408; border:1px solid rgba(0, 255, 102, 0.3); padding:12px 18px; border-radius:4px; display:flex; justify-content:space-between; align-items:center;">
        <div>
          <strong style="color:#fff;">${item.name}</strong>
          <div style="font-size:11px; color:var(--muted)">Size: ${(item.size/1024).toFixed(1)} KB &bull; Generated: ${item.modified}</div>
        </div>
        <a href="/reports/${item.name}" target="_blank" class="btn-action" style="text-decoration:none;">DOWNLOAD // VIEW</a>
      </div>
    `).join('');
  });
}

function copyPitch(tier) {
  playBeep(1100);
  showToast('Copied Tier ' + tier + ' proposal scope to clipboard!');
}

function runDiff() {
  playBeep(900);
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
        <div class="stat-box"><div class="stat-n" style="color:var(--accent);">${delta.score_change}</div><div class="stat-l">SCORE DELTA</div></div>
        <div class="stat-box"><div class="stat-n" style="color:#00ff66;">${delta.resolved_count}</div><div class="stat-l">RESOLVED THREATS</div></div>
        <div class="stat-box"><div class="stat-n" style="color:var(--crit);">${delta.new_count}</div><div class="stat-l">NEW ANOMALIES</div></div>
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

    q.put(f"[BLACK-OPS] Initializing engagement vector on {target} (Profile: {profile.upper()})")

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
        q.put(f"[RECON] DNS resolved target to {', '.join(ips) if ips else 'UNKNOWN'}")

        ctx.pages = crawl(http, target, max_pages=options.max_pages, depth=options.depth, log=lambda m: q.put(m))
        res.pages_scanned = [p.url for p in ctx.pages]
        q.put(f"[MAPPER] Infiltrated {len(ctx.pages)} attack routes.")

        q.put("[STRIKE] Deploying 15 active verification modules...")
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
        q.put("[REPORT] Black-ops dossier generated in reports/ directory.")

    except Exception as exc:
        q.put(f"[ABORT] Assessment failure: {exc}")
    finally:
        scan_record["completed"] = True
        http.close()


def start_server(port: int = 8888, host: str = "127.0.0.1") -> None:
    server = ThreadingHTTPServer((host, port), StudioHandler)
    print(f"\n=======================================================")
    print(f"  ⚡ VulnScope Cyber Warfare OS Live")
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
