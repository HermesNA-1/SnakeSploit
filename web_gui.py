"""
SnakeSploit Web GUI — Premium Dashboard
Run with: snakesploit gui [--port 5000]
"""

import argparse
import json
import os
import sys
import threading
import time
from datetime import datetime
from functools import wraps

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from flask import Flask, jsonify, render_template_string, request, send_from_directory
except ImportError:
    print("  [-] Flask not installed. Run: pip install flask")
    sys.exit(1)


app = Flask(__name__)

# ── Lazy-loaded backend modules ──
BACKEND = {}


def load_backend():
    """Load SnakeSploit backend modules on demand."""
    if BACKEND:
        return BACKEND
    from core.module import ModuleManager
    from core.target import TargetManager
    from core.session import SessionManager
    from updater.cve_fetcher import CVEUpdater
    from updater.module_generator import ModuleGenerator, AutoUpdater
    from lib.network import PortScanner, HTTPClient
    from lib.payloads import PayloadGenerator
    from core.strix import StrixEngine

    BACKEND['mm'] = ModuleManager()
    BACKEND['tm'] = TargetManager()
    BACKEND['sm'] = SessionManager()
    BACKEND['cve'] = CVEUpdater()
    BACKEND['gen'] = ModuleGenerator()
    BACKEND['auto'] = AutoUpdater()
    BACKEND['scanner'] = PortScanner
    BACKEND['http'] = HTTPClient
    BACKEND['payloads'] = PayloadGenerator
    BACKEND['strix'] = StrixEngine()

    # Load targets
    BACKEND['tm'].load()

    # Discover and load modules
    BACKEND['mm'].discover()
    for cat, paths in BACKEND['mm'].categories.items():
        for p in paths:
            BACKEND['mm'].load_module(p)

    return BACKEND


# ── HTML Template ──────────────────────────────────────────────

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SnakeSploit Dashboard</title>
<style>
/* ── Reset & Base ── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
:root {
  --bg-primary: #0a0a1a;
  --bg-secondary: #111128;
  --bg-card: rgba(20, 20, 50, 0.6);
  --bg-card-hover: rgba(30, 30, 70, 0.8);
  --accent: #00ff88;
  --accent-dim: rgba(0, 255, 136, 0.15);
  --accent-glow: rgba(0, 255, 136, 0.3);
  --danger: #ff3355;
  --warning: #ffaa00;
  --text-primary: #e8e8f0;
  --text-secondary: #8888aa;
  --text-muted: #555577;
  --border: rgba(255, 255, 255, 0.06);
  --sidebar-width: 260px;
  --radius: 12px;
  --radius-sm: 8px;
}
html { font-size: 14px; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Inter, Roboto, sans-serif;
  background: var(--bg-primary);
  color: var(--text-primary);
  min-height: 100vh;
  display: flex;
  overflow: hidden;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--text-muted); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--text-secondary); }

/* ── Background Grid ── */
body::before {
  content: '';
  position: fixed;
  inset: 0;
  background:
    radial-gradient(ellipse at 20% 50%, rgba(0, 255, 136, 0.03) 0%, transparent 50%),
    radial-gradient(ellipse at 80% 20%, rgba(0, 100, 255, 0.03) 0%, transparent 50%),
    radial-gradient(ellipse at 50% 80%, rgba(255, 0, 100, 0.02) 0%, transparent 50%);
  pointer-events: none;
  z-index: 0;
}

/* ── Sidebar ── */
.sidebar {
  width: var(--sidebar-width);
  min-height: 100vh;
  background: var(--bg-secondary);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  position: fixed;
  left: 0;
  top: 0;
  z-index: 10;
}
.sidebar-header {
  padding: 24px 20px;
  border-bottom: 1px solid var(--border);
}
.sidebar-logo {
  display: flex;
  align-items: center;
  gap: 12px;
}
.sidebar-logo-icon {
  width: 36px;
  height: 36px;
  border-radius: 10px;
  background: linear-gradient(135deg, var(--accent), #0066ff);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 18px;
  font-weight: 800;
  color: #fff;
  box-shadow: 0 0 20px var(--accent-glow);
}
.sidebar-logo-text {
  font-size: 16px;
  font-weight: 700;
  letter-spacing: -0.5px;
}
.sidebar-logo-text span { color: var(--accent); }
.sidebar-nav {
  flex: 1;
  padding: 12px 10px;
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.nav-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 14px;
  border-radius: var(--radius-sm);
  color: var(--text-secondary);
  cursor: pointer;
  transition: all 0.2s;
  font-size: 13px;
  font-weight: 500;
  border: none;
  background: none;
  width: 100%;
  text-align: left;
}
.nav-item:hover { background: var(--bg-card); color: var(--text-primary); }
.nav-item.active {
  background: var(--accent-dim);
  color: var(--accent);
  box-shadow: inset 3px 0 0 var(--accent);
}
.nav-item svg { width: 18px; height: 18px; flex-shrink: 0; opacity: 0.8; }
.nav-item .badge {
  margin-left: auto;
  background: var(--accent-dim);
  color: var(--accent);
  font-size: 11px;
  padding: 2px 8px;
  border-radius: 10px;
  font-weight: 600;
}
.nav-divider {
  height: 1px;
  background: var(--border);
  margin: 8px 14px;
}
.nav-section-title {
  padding: 8px 14px 4px;
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 1px;
  color: var(--text-muted);
  font-weight: 600;
}
.sidebar-footer {
  padding: 16px 20px;
  border-top: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: 10px;
}
.status-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--accent);
  box-shadow: 0 0 8px var(--accent-glow);
  animation: pulse 2s infinite;
}
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}
.status-text { font-size: 12px; color: var(--text-secondary); }

/* ── Main Content ── */
.main-content {
  margin-left: var(--sidebar-width);
  flex: 1;
  padding: 0;
  overflow-y: auto;
  height: 100vh;
  position: relative;
  z-index: 1;
}
.page {
  display: none;
  padding: 32px 36px;
  animation: fadeIn 0.3s ease;
}
.page.active { display: block; }
@keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }

.page-header {
  margin-bottom: 28px;
}
.page-header h1 {
  font-size: 24px;
  font-weight: 700;
  letter-spacing: -0.5px;
  margin-bottom: 4px;
}
.page-header p {
  color: var(--text-secondary);
  font-size: 14px;
}

/* ── Stats Grid ── */
.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 16px;
  margin-bottom: 28px;
}
.stat-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 20px 24px;
  backdrop-filter: blur(12px);
  transition: all 0.3s;
}
.stat-card:hover {
  background: var(--bg-card-hover);
  transform: translateY(-2px);
  box-shadow: 0 8px 30px rgba(0, 0, 0, 0.3);
}
.stat-card .label {
  font-size: 12px;
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-bottom: 8px;
}
.stat-card .value {
  font-size: 28px;
  font-weight: 700;
  letter-spacing: -1px;
}
.stat-card .value.accent { color: var(--accent); }
.stat-card .value.danger { color: var(--danger); }
.stat-card .value.warning { color: var(--warning); }
.stat-card .sub {
  font-size: 12px;
  color: var(--text-muted);
  margin-top: 4px;
}

/* ── Cards ── */
.card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  backdrop-filter: blur(12px);
  margin-bottom: 20px;
  overflow: hidden;
}
.card-header {
  padding: 16px 20px;
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.card-header h3 {
  font-size: 14px;
  font-weight: 600;
}
.card-body { padding: 20px; }
.card-body:empty::after { content: 'No data'; color: var(--text-muted); font-style: italic; }

/* ── Tables ── */
.table-wrap { overflow-x: auto; }
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}
thead th {
  text-align: left;
  padding: 10px 16px;
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: var(--text-muted);
  font-weight: 600;
  border-bottom: 1px solid var(--border);
}
tbody td {
  padding: 10px 16px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.03);
  color: var(--text-secondary);
}
tbody tr:hover td { background: rgba(255, 255, 255, 0.02); }
.tag {
  display: inline-block;
  padding: 2px 10px;
  border-radius: 10px;
  font-size: 11px;
  font-weight: 600;
}
.tag-critical { background: rgba(255, 51, 85, 0.15); color: var(--danger); }
.tag-high { background: rgba(255, 170, 0, 0.15); color: var(--warning); }
.tag-medium { background: rgba(0, 200, 255, 0.15); color: #00c8ff; }
.tag-low { background: rgba(136, 136, 170, 0.15); color: var(--text-secondary); }
.tag-active { background: var(--accent-dim); color: var(--accent); }

/* ── Actions ── */
.action-bar {
  display: flex;
  gap: 10px;
  margin-bottom: 20px;
  flex-wrap: wrap;
}
.btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 8px 18px;
  border-radius: var(--radius-sm);
  font-size: 13px;
  font-weight: 600;
  border: none;
  cursor: pointer;
  transition: all 0.2s;
  background: var(--bg-card);
  color: var(--text-primary);
  border: 1px solid var(--border);
}
.btn:hover { background: var(--bg-card-hover); transform: translateY(-1px); }
.btn-primary {
  background: linear-gradient(135deg, var(--accent), #00cc6a);
  color: #000;
  border: none;
  box-shadow: 0 0 20px var(--accent-glow);
}
.btn-primary:hover { box-shadow: 0 0 30px var(--accent-glow); }
.btn-danger { border-color: var(--danger); color: var(--danger); }
.btn-danger:hover { background: rgba(255, 51, 85, 0.15); }
.btn-sm { padding: 5px 12px; font-size: 12px; }
.btn svg { width: 16px; height: 16px; }

/* ── Gradients ── */
.gradient-bar {
  height: 3px;
  background: linear-gradient(90deg, var(--accent), #0066ff, var(--danger));
  width: 100%;
  position: fixed;
  top: 0;
  left: 0;
  z-index: 100;
}

/* ── Alerts ── */
.alert {
  padding: 12px 16px;
  border-radius: var(--radius-sm);
  font-size: 13px;
  margin-bottom: 16px;
}
.alert-success { background: var(--accent-dim); color: var(--accent); border: 1px solid rgba(0, 255, 136, 0.2); }
.alert-error { background: rgba(255, 51, 85, 0.1); color: var(--danger); border: 1px solid rgba(255, 51, 85, 0.2); }

/* ── Output ── */
.output-box {
  background: rgba(0, 0, 0, 0.4);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 16px;
  font-family: 'JetBrains Mono', 'Fira Code', monospace;
  font-size: 12px;
  line-height: 1.6;
  color: var(--text-secondary);
  max-height: 400px;
  overflow-y: auto;
  white-space: pre-wrap;
}

/* ── Forms ── */
.input-group {
  display: flex;
  gap: 8px;
  margin-bottom: 12px;
}
.input-group input, .input-group select {
  flex: 1;
  padding: 8px 14px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border);
  background: rgba(0, 0, 0, 0.3);
  color: var(--text-primary);
  font-size: 13px;
  outline: none;
  transition: border-color 0.2s;
}
.input-group input:focus, .input-group select:focus { border-color: var(--accent); }
input::placeholder { color: var(--text-muted); }

/* ── Modal ── */
.modal-overlay {
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.6);
  backdrop-filter: blur(4px);
  z-index: 50;
  align-items: center;
  justify-content: center;
}
.modal-overlay.active { display: flex; }
.modal {
  background: var(--bg-secondary);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 28px;
  max-width: 500px;
  width: 90%;
  max-height: 80vh;
  overflow-y: auto;
}
.modal h2 { margin-bottom: 16px; }
.modal-actions { display: flex; gap: 8px; margin-top: 16px; justify-content: flex-end; }

/* ── Grid layout for 2-col ── */
.grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
@media (max-width: 1000px) { .grid-2 { grid-template-columns: 1fr; } }

/* ── Loading spinner ── */
.spinner {
  display: inline-block;
  width: 16px;
  height: 16px;
  border: 2px solid var(--border);
  border-top-color: var(--accent);
  border-radius: 50%;
  animation: spin 0.6s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }

/* ── Payload output ── */
.code-block {
  background: rgba(0, 0, 0, 0.5);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 14px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  line-height: 1.5;
  color: var(--accent);
  overflow-x: auto;
  word-break: break-all;
}
</style>
</head>
<body>

<div class="gradient-bar"></div>

<!-- Sidebar -->
<aside class="sidebar">
  <div class="sidebar-header">
    <div class="sidebar-logo">
      <div class="sidebar-logo-icon">S</div>
      <div class="sidebar-logo-text">Snake<span>Sploit</span></div>
    </div>
  </div>
  <nav class="sidebar-nav">
    <div class="nav-section-title">Overview</div>
    <button class="nav-item active" onclick="showPage('dashboard')" data-page="dashboard">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
      Dashboard
    </button>
    <button class="nav-item" onclick="showPage('targets')" data-page="targets">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>
      Targets
      <span class="badge" id="target-count">0</span>
    </button>
    <button class="nav-item" onclick="showPage('modules')" data-page="modules">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 3 21 3 21 8"/><line x1="4" y1="20" x2="21" y2="3"/><polyline points="21 16 21 21 16 21"/><line x1="15" y1="15" x2="21" y2="21"/><line x1="4" y1="4" x2="9" y2="9"/></svg>
      Modules
      <span class="badge" id="module-count">0</span>
    </button>
    <button class="nav-item" onclick="showPage('cve')" data-page="cve">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      CVE Updates
      <span class="badge" id="cve-count">0</span>
    </button>
    <div class="nav-divider"></div>
    <div class="nav-section-title">Actions</div>
    <button class="nav-item" onclick="showPage('scanner')" data-page="scanner">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 3l7.07 16.97 2.51-7.39 7.39-2.51L3 3z"/></svg>
      Port Scanner
    </button>
    <button class="nav-item" onclick="showPage('payloads')" data-page="payloads">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
      Payloads
    </button>
    <button class="nav-item" onclick="showPage('strix')" data-page="strix">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
      Strix Scanner
    </button>
    <div class="nav-divider"></div>
    <button class="nav-item" onclick="showPage('console')" data-page="console">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
      Console
    </button>
  </nav>
  <div class="sidebar-footer">
    <div class="status-dot"></div>
    <span class="status-text">Server running</span>
  </div>
</aside>

<!-- Main Content -->
<main class="main-content">

<!-- Dashboard Page -->
<div class="page active" id="page-dashboard">
  <div class="page-header">
    <h1>Dashboard</h1>
    <p>Real-time overview of your SnakeSploit instance</p>
  </div>
  <div class="stats-grid" id="dash-stats">
    <div class="stat-card"><div class="label">Targets</div><div class="value accent" id="stat-targets">—</div></div>
    <div class="stat-card"><div class="label">Open Services</div><div class="value" id="stat-services">—</div></div>
    <div class="stat-card"><div class="label">Vulnerabilities</div><div class="value danger" id="stat-vulns">—</div></div>
    <div class="stat-card"><div class="label">Modules Loaded</div><div class="value warning" id="stat-modules">—</div></div>
    <div class="stat-card"><div class="label">CVE Cache</div><div class="value accent" id="stat-cves">—</div></div>
    <div class="stat-card"><div class="label">Active Sessions</div><div class="value" id="stat-sessions">—</div></div>
  </div>
  <div class="grid-2">
    <div class="card">
      <div class="card-header"><h3>Recent Targets</h3></div>
      <div class="card-body" id="recent-targets"><div class="spinner"></div></div>
    </div>
    <div class="card">
      <div class="card-header"><h3>Top CVEs by Severity</h3></div>
      <div class="card-body" id="top-cves"></div>
    </div>
  </div>
</div>

<!-- Targets Page -->
<div class="page" id="page-targets">
  <div class="page-header">
    <h1>Targets</h1>
    <p>Manage your target database</p>
  </div>
  <div class="action-bar">
    <button class="btn btn-primary" onclick="showAddTargetModal()">+ Add Target</button>
    <button class="btn" onclick="refreshTargets()">⟳ Refresh</button>
  </div>
  <div class="card">
    <div class="table-wrap">
      <table>
        <thead><tr><th>Host</th><th>OS</th><th>Services</th><th>Vulnerabilities</th><th>Actions</th></tr></thead>
        <tbody id="targets-table"></tbody>
      </table>
    </div>
  </div>
</div>

<!-- Modules Page -->
<div class="page" id="page-modules">
  <div class="page-header">
    <h1>Modules</h1>
    <p>Browse and search exploit modules</p>
  </div>
  <div class="input-group">
    <input type="text" id="module-search" placeholder="Search modules by name, CVE, or keyword..." oninput="searchModules()">
  </div>
  <div class="card">
    <div class="table-wrap">
      <table>
        <thead><tr><th>Name</th><th>Description</th><th>CVEs</th><th>Platform</th></tr></thead>
        <tbody id="modules-table"></tbody>
      </table>
    </div>
  </div>
</div>

<!-- CVE Page -->
<div class="page" id="page-cve">
  <div class="page-header">
    <h1>CVE Updates</h1>
    <p>Auto-update engine status</p>
  </div>
  <div class="stats-grid" id="cve-stats"></div>
  <div class="action-bar">
    <button class="btn btn-primary" onclick="runCveUpdate()">⟳ Update CVEs</button>
    <button class="btn" onclick="runFullUpdate()">⚡ Full Pipeline</button>
    <button class="btn" onclick="refreshCve()">⟳ Refresh</button>
  </div>
  <div class="card">
    <div class="card-header"><h3>CVE List</h3></div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>CVE ID</th><th>Severity</th><th>Score</th><th>Description</th><th>PoC</th></tr></thead>
        <tbody id="cve-table"></tbody>
      </table>
    </div>
  </div>
</div>

<!-- Scanner Page -->
<div class="page" id="page-scanner">
  <div class="page-header">
    <h1>Port Scanner</h1>
    <p>Scan targets for open ports</p>
  </div>
  <div class="card">
    <div class="card-body">
      <div class="input-group">
        <input type="text" id="scan-host" placeholder="Target host (e.g. 192.168.1.1)">
        <input type="text" id="scan-ports" placeholder="Ports (e.g. 22,80,443 — leave empty for common ports)">
        <button class="btn btn-primary" onclick="runScan()">Scan</button>
      </div>
    </div>
  </div>
  <div class="card" id="scan-results-card" style="display:none">
    <div class="card-header"><h3>Scan Results</h3></div>
    <div class="card-body"><div class="table-wrap"><table><thead><tr><th>Port</th><th>State</th></tr></thead><tbody id="scan-results"></tbody></table></div></div>
  </div>
</div>

<!-- Payloads Page -->
<div class="page" id="page-payloads">
  <div class="page-header">
    <h1>Payload Generator</h1>
    <p>Generate reverse shells and bind shells</p>
  </div>
  <div class="card">
    <div class="card-body">
      <div class="input-group">
        <select id="payload-type">
          <option value="linux_reverse">Linux Reverse Shell (Bash)</option>
          <option value="python_reverse">Python Reverse Shell</option>
          <option value="nc_reverse">Netcat Reverse Shell</option>
          <option value="powershell_reverse">PowerShell Reverse Shell</option>
          <option value="perl_reverse">Perl Reverse Shell</option>
          <option value="python_bind">Python Bind Shell</option>
          <option value="php_reverse">PHP Reverse Shell</option>
        </select>
        <input type="text" id="payload-lhost" placeholder="LHOST (e.g. 10.0.0.5)">
        <input type="text" id="payload-lport" placeholder="LPORT (e.g. 4444)">
        <button class="btn btn-primary" onclick="generatePayload()">Generate</button>
      </div>
    </div>
  </div>
  <div class="card" id="payload-result" style="display:none">
    <div class="card-header"><h3>Generated Payload</h3><button class="btn btn-sm" onclick="copyPayload()">📋 Copy</button></div>
    <div class="card-body"><pre class="code-block" id="payload-code"></pre></div>
  </div>
</div>

<!-- Strix Page -->
<div class="page" id="page-strix">
  <div class="page-header">
    <h1>Strix AI Scanner</h1>
    <p>AI-powered web security scanning</p>
  </div>
  <div class="card" id="strix-config-card">
    <div class="card-header"><h3>Configuration</h3></div>
    <div class="card-body">
      <div class="input-group">
        <input type="text" id="strix-key" placeholder="Strix API Key">
        <button class="btn btn-primary" onclick="saveStrixKey()">Save Key</button>
      </div>
      <div id="strix-status"></div>
    </div>
  </div>
  <div class="card">
    <div class="card-body">
      <div class="input-group">
        <input type="text" id="strix-target" placeholder="Target URL (e.g. https://example.com)">
        <button class="btn btn-primary" onclick="runStrixScan()">Run Scan</button>
      </div>
    </div>
  </div>
  <div class="card" id="strix-result" style="display:none">
    <div class="card-header"><h3>Scan Result</h3></div>
    <div class="card-body"><div class="output-box" id="strix-output"></div></div>
  </div>
</div>

<!-- Console Page -->
<div class="page" id="page-console">
  <div class="page-header">
    <h1>Console</h1>
    <p>Run SnakeSploit commands</p>
  </div>
  <div class="input-group">
    <input type="text" id="console-input" placeholder="Enter command (e.g. search smb, cve stats, scan 127.0.0.1)" onkeydown="if(event.key==='Enter')runConsole()">
    <button class="btn btn-primary" onclick="runConsole()">Run</button>
    <button class="btn" onclick="clearConsole()">Clear</button>
  </div>
  <div class="card">
    <div class="card-body"><div class="output-box" id="console-output">Welcome to SnakeSploit Web Console. Type a command above.</div></div>
  </div>
</div>

</main>

<!-- Add Target Modal -->
<div class="modal-overlay" id="add-target-modal">
  <div class="modal">
    <h2>Add Target</h2>
    <div class="input-group"><input type="text" id="new-target-host" placeholder="Host (e.g. 192.168.1.100)"></div>
    <div class="modal-actions">
      <button class="btn" onclick="closeModal('add-target-modal')">Cancel</button>
      <button class="btn btn-primary" onclick="addTarget()">Add</button>
    </div>
  </div>
</div>

<script>
// ── Navigation ──
function showPage(id) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('page-' + id).classList.add('active');
  document.querySelector(`.nav-item[data-page="${id}"]`)?.classList.add('active');
  refreshPageData(id);
}

function refreshPageData(page) {
  if (page === 'dashboard') loadDashboard();
  else if (page === 'targets') loadTargets();
  else if (page === 'modules') loadModules();
  else if (page === 'cve') loadCveStats();
}

function closeModal(id) {
  document.getElementById(id).classList.remove('active');
}

function showAddTargetModal() {
  document.getElementById('add-target-modal').classList.add('active');
}

// ── API Helper ──
async function api(method, path, body) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch('/api' + path, opts);
  return await res.json();
}

async function apiGet(path) { return api('GET', path); }
async function apiPost(path, body) { return api('POST', path, body); }

// ── Dashboard ──
async function loadDashboard() {
  const data = await apiGet('/dashboard');
  document.getElementById('stat-targets').textContent = data.targets ?? '—';
  document.getElementById('stat-services').textContent = data.services ?? '—';
  document.getElementById('stat-vulns').textContent = data.vulnerabilities ?? '—';
  document.getElementById('stat-modules').textContent = data.modules ?? '—';
  document.getElementById('stat-cves').textContent = data.cves ?? '—';
  document.getElementById('stat-sessions').textContent = data.sessions ?? '—';
  document.getElementById('target-count').textContent = data.targets ?? '0';
  document.getElementById('module-count').textContent = data.modules ?? '0';

  // Recent targets
  const rt = document.getElementById('recent-targets');
  if (data.recent_targets && data.recent_targets.length) {
    rt.innerHTML = '<div class="table-wrap"><table><thead><tr><th>Host</th><th>Services</th><th>Vulns</th></tr></thead><tbody>' +
      data.recent_targets.map(t => `<tr><td>${t.host}</td><td>${t.services}</td><td>${t.vulns}</td></tr>`).join('') +
      '</tbody></table></div>';
  } else { rt.innerHTML = '<span style="color:var(--text-muted)">No targets yet</span>'; }

  // Top CVEs
  const tc = document.getElementById('top-cves');
  if (data.top_cves && data.top_cves.length) {
    tc.innerHTML = data.top_cves.map(c => `<div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border);font-size:13px">
      <span>${c.id}</span>
      <span class="tag tag-${c.severity.toLowerCase()}">${c.severity} (${c.score})</span>
    </div>`).join('');
  } else { tc.innerHTML = '<span style="color:var(--text-muted)">No CVEs cached</span>'; }
}

// ── Targets ──
async function loadTargets() {
  const data = await apiGet('/targets');
  const tb = document.getElementById('targets-table');
  if (data.targets && data.targets.length) {
    tb.innerHTML = data.targets.map(t => `<tr>
      <td style="font-weight:600;color:var(--text-primary)">${t.host}</td>
      <td>${t.os || 'unknown'}</td>
      <td>${t.services}</td>
      <td><span class="tag tag-critical">${t.vulns}</span></td>
      <td><button class="btn btn-sm" onclick="scanTarget('${t.host}')">Scan</button></td>
    </tr>`).join('');
    document.getElementById('target-count').textContent = data.targets.length;
  } else { tb.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-muted)">No targets</td></tr>'; }
}

async function addTarget() {
  const host = document.getElementById('new-target-host').value.trim();
  if (!host) return;
  await apiPost('/targets/add', { host });
  closeModal('add-target-modal');
  document.getElementById('new-target-host').value = '';
  loadTargets();
}

function refreshTargets() { loadTargets(); }

function scanTarget(host) {
  document.getElementById('scan-host').value = host;
  showPage('scanner');
}

// ── Modules ──
let allModules = [];

async function loadModules() {
  const data = await apiGet('/modules');
  allModules = data.modules || [];
  document.getElementById('module-count').textContent = allModules.length;
  renderModules(allModules);
}

function renderModules(modules) {
  const tb = document.getElementById('modules-table');
  if (modules.length) {
    tb.innerHTML = modules.slice(0, 50).map(m => `<tr>
      <td style="font-weight:600;color:var(--accent)">${m.name}</td>
      <td>${(m.description || '').slice(0, 80)}</td>
      <td>${m.cves ? m.cves.slice(0, 40) : '—'}</td>
      <td>${m.platform || '—'}</td>
    </tr>`).join('');
  } else { tb.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--text-muted)">No modules</td></tr>'; }
}

function searchModules() {
  const q = document.getElementById('module-search').value.toLowerCase();
  if (!q) { renderModules(allModules); return; }
  renderModules(allModules.filter(m =>
    m.name.toLowerCase().includes(q) ||
    (m.description || '').toLowerCase().includes(q) ||
    (m.cves || '').toLowerCase().includes(q)
  ));
}

// ── CVE ──
async function loadCveStats() {
  const data = await apiGet('/cve');
  document.getElementById('cve-stats').innerHTML = Object.entries(data.stats || {}).map(([k, v]) =>
    `<div class="stat-card"><div class="label">${k.replace(/_/g,' ')}</div><div class="value accent">${v}</div></div>`
  ).join('');
  document.getElementById('cve-count').textContent = data.stats?.total_cves ?? 0;

  const tb = document.getElementById('cve-table');
  if (data.cves && data.cves.length) {
    tb.innerHTML = data.cves.slice(0, 30).map(c => `<tr>
      <td style="font-weight:600;color:var(--text-primary)">${c.id}</td>
      <td><span class="tag tag-${(c.severity||'low').toLowerCase()}">${c.severity || 'N/A'}</span></td>
      <td>${c.score || '—'}</td>
      <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${(c.description||'').slice(0, 80)}</td>
      <td>${c.has_poc ? '✅' : '❌'}</td>
    </tr>`).join('');
  } else { tb.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-muted)">No CVEs cached. Run update first.</td></tr>'; }
}

async function runCveUpdate() {
  const btn = event.target; btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  const data = await apiPost('/cve/update', { days: 7 });
  btn.disabled = false; btn.innerHTML = '⟳ Update CVEs';
  loadCveStats();
}

async function runFullUpdate() {
  const btn = event.target; btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  const data = await apiPost('/cve/full-update', { days: 3 });
  btn.disabled = false; btn.innerHTML = '⚡ Full Pipeline';
  loadCveStats();
}

function refreshCve() { loadCveStats(); }

// ── Scanner ──
async function runScan() {
  const host = document.getElementById('scan-host').value.trim();
  if (!host) return;
  const ports = document.getElementById('scan-ports').value.trim();
  const data = await apiPost('/scan', { host, ports });
  const card = document.getElementById('scan-results-card');
  const tb = document.getElementById('scan-results');
  if (data.results && data.results.length) {
    card.style.display = 'block';
    tb.innerHTML = data.results.map(r => `<tr><td style="font-weight:600">${r.port}</td><td><span class="tag tag-active">${r.state}</span></td></tr>`).join('');
  } else {
    card.style.display = 'block';
    tb.innerHTML = '<tr><td colspan="2" style="text-align:center;color:var(--text-muted)">No open ports found</td></tr>';
  }
}

// ── Payloads ──
async function generatePayload() {
  const ptype = document.getElementById('payload-type').value;
  const lhost = document.getElementById('payload-lhost').value.trim();
  const lport = document.getElementById('payload-lport').value.trim();
  if (!lhost || !lport) return;
  const data = await apiPost('/payloads', { type: ptype, lhost, lport: parseInt(lport) });
  document.getElementById('payload-result').style.display = 'block';
  document.getElementById('payload-code').textContent = data.payload?.code || 'Error generating payload';
}

function copyPayload() {
  const code = document.getElementById('payload-code').textContent;
  navigator.clipboard?.writeText(code);
}

// ── Strix ──
async function saveStrixKey() {
  const key = document.getElementById('strix-key').value.trim();
  if (!key) return;
  const data = await apiPost('/strix/config', { api_key: key });
  document.getElementById('strix-status').innerHTML = `<div class="alert alert-success">${data.message || 'Saved'}</div>`;
}

async function runStrixScan() {
  const target = document.getElementById('strix-target').value.trim();
  if (!target) return;
  document.getElementById('strix-result').style.display = 'block';
  document.getElementById('strix-output').textContent = 'Running scan...';
  const data = await apiPost('/strix/scan', { target });
  document.getElementById('strix-output').textContent = data.output || data.error || 'No output';
}

// ── Console ──
async function runConsole() {
  const cmd = document.getElementById('console-input').value.trim();
  if (!cmd) return;
  const out = document.getElementById('console-output');
  out.textContent += `\n> ${cmd}\n`;
  out.scrollTop = out.scrollHeight;
  const data = await apiPost('/console', { command: cmd });
  out.textContent += (data.output || data.error || 'No output') + '\n';
  out.scrollTop = out.scrollHeight;
}

function clearConsole() {
  document.getElementById('console-output').textContent = 'Welcome to SnakeSploit Web Console. Type a command above.';
}

// ── Auto-refresh dashboard every 10s ──
setInterval(() => {
  const active = document.querySelector('.page.active');
  if (active && active.id === 'page-dashboard') loadDashboard();
}, 10000);

// ── Init ──
loadDashboard();
</script>
</body>
</html>"""


# ── API Routes ──

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route('/api/dashboard')
def api_dashboard():
    b = load_backend()
    tm = b['tm']
    mm = b['mm']
    sm = b['sm']
    cve = b['cve']

    all_targets = tm.all()
    total_services = sum(len(t.services) for t in all_targets)
    total_vulns = sum(len(t.vulnerabilities) for t in all_targets)

    stats = cve.get_statistics()
    top_cves = sorted(cve.index, key=lambda x: x.get('score', 0), reverse=True)[:8]

    recent = [{'host': t.host, 'services': len(t.services), 'vulns': len(t.vulnerabilities)} for t in all_targets[-8:]]

    return jsonify({
        'targets': len(all_targets),
        'services': total_services,
        'vulnerabilities': total_vulns,
        'modules': len(mm.modules),
        'cves': stats['total_cves'],
        'sessions': sm.summary()['active'],
        'recent_targets': recent,
        'top_cves': [{'id': c['id'], 'severity': c.get('severity', 'UNKNOWN'), 'score': c.get('score', 0)} for c in top_cves],
    })


@app.route('/api/targets')
def api_targets():
    b = load_backend()
    tm = b['tm']
    targets = [{'host': t.host, 'os': t.os, 'services': len(t.services), 'vulns': len(t.vulnerabilities)} for t in tm.all()]
    return jsonify({'targets': targets})


@app.route('/api/targets/add', methods=['POST'])
def api_targets_add():
    b = load_backend()
    data = request.get_json()
    if data and data.get('host'):
        t = b['tm'].add(data['host'])
        b['tm'].save()
        return jsonify({'success': True, 'host': t.host})
    return jsonify({'error': 'No host provided'}), 400


@app.route('/api/modules')
def api_modules():
    b = load_backend()
    modules = []
    for name, mod in b['mm'].modules.items():
        cves = ", ".join(mod.metadata.cve_ids) if mod.metadata.cve_ids else ""
        modules.append({
            'name': name,
            'description': mod.metadata.description[:120],
            'cves': cves,
            'platform': mod.metadata.platform,
        })
    return jsonify({'modules': modules})


@app.route('/api/cve')
def api_cve():
    b = load_backend()
    stats = b['cve'].get_statistics()
    cves = b['cve'].index[-50:]
    cves.reverse()
    return jsonify({'stats': stats, 'cves': cves})


@app.route('/api/cve/update', methods=['POST'])
def api_cve_update():
    b = load_backend()
    data = request.get_json() or {}
    days = data.get('days', 7)
    count = b['cve'].fetch_recent(days_back=days)
    return jsonify({'new_cves': count})


@app.route('/api/cve/full-update', methods=['POST'])
def api_cve_full_update():
    b = load_backend()
    data = request.get_json() or {}
    days = data.get('days', 3)
    results = b['auto'].run_full_update(days_back=days)
    return jsonify(results)


@app.route('/api/scan', methods=['POST'])
def api_scan():
    b = load_backend()
    data = request.get_json()
    host = data.get('host', '')
    ports_str = data.get('ports', '')
    ports = [int(p.strip()) for p in ports_str.split(',') if p.strip()] if ports_str else None
    results = b['scanner'].scan(host, ports)

    # Save to target DB
    if results:
        from core.target import Service
        t = b['tm'].add(host)
        for r in results:
            t.add_service(Service(port=r['port'], state=r['state']))
        b['tm'].save()

    return jsonify({'results': results})


@app.route('/api/payloads', methods=['POST'])
def api_payloads():
    b = load_backend()
    data = request.get_json()
    try:
        p = b['payloads'].generate(data.get('type', 'python_reverse'), data.get('lhost', '127.0.0.1'), data.get('lport', 4444))
        return jsonify({'payload': {'code': p.code, 'size': p.size, 'type': p.name}})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/strix/config', methods=['POST'])
def api_strix_config():
    data = request.get_json()
    key = data.get('api_key', '')
    if key:
        strix = load_backend()['strix']
        result = strix.set_api_key(key)
        return jsonify(result)
    return jsonify({'error': 'No key provided'}), 400


@app.route('/api/strix/scan', methods=['POST'])
def api_strix_scan():
    data = request.get_json()
    target = data.get('target', '')
    if not target:
        return jsonify({'error': 'No target'}), 400
    strix = load_backend()['strix']
    result = strix.scan(target)
    return jsonify({
        'output': result.get('output', '')[:3000],
        'success': result.get('success', False),
        'error': result.get('error'),
    })


@app.route('/api/console', methods=['POST'])
def api_console():
    b = load_backend()
    data = request.get_json()
    cmd = data.get('command', '').strip().lower()

    if cmd.startswith('search '):
        query = cmd.replace('search ', '', 1)
        results = b['mm'].search(query)
        output = '\n'.join([f"  {n}: {m.metadata.description[:80]}" for n, m in results]) if results else "No results"
        return jsonify({'output': output})

    elif cmd == 'cve stats':
        stats = b['cve'].get_statistics()
        output = '\n'.join([f"  {k}: {v}" for k, v in stats.items()])
        return jsonify({'output': output})

    elif cmd.startswith('scan '):
        parts = cmd.split()
        host = parts[1] if len(parts) > 1 else ''
        ports = parts[2] if len(parts) > 2 else ''
        ports_list = [int(p) for p in ports.split(',') if p] if ports else None
        results = b['scanner'].scan(host, ports_list)
        if results:
            output = '\n'.join([f"  Port {r['port']}: {r['state']}" for r in results]) if results else "No open ports"
        else:
            output = "No open ports found"
        return jsonify({'output': output})

    elif cmd == 'help':
        output = "Commands: search <q>, cve stats, scan <host> [ports], payloads"
        return jsonify({'output': output})

    else:
        return jsonify({'error': f"Unknown command: {cmd}"})


# ── Static Files ──

@app.route('/favicon.ico')
def favicon():
    return '', 204


# ── Main ──

def main():
    parser = argparse.ArgumentParser(description="SnakeSploit Web GUI")
    parser.add_argument('--port', type=int, default=5000, help='Web server port (default: 5000)')
    parser.add_argument('--host', default='0.0.0.0', help='Bind address (default: 0.0.0.0)')
    parser.add_argument('--debug', action='store_true', help='Debug mode')
    args = parser.parse_args()

    print(f"  [*] SnakeSploit Web GUI starting on http://{args.host}:{args.port}")
    print(f"  [*] Press Ctrl+C to stop")
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == '__main__':
    main()