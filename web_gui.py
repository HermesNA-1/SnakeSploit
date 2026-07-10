"""
SnakeSploit Web GUI — Flask Backend with CORS for GitHub Pages.
"""

import argparse
import json
import os
import sys
import subprocess
import threading
import time
from datetime import datetime
from functools import wraps

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from flask import Flask, jsonify, render_template_string, request, send_from_directory
except ImportError:
    print("  [-] Flask not found. Install: pip install flask")
    sys.exit(1)


app = Flask(__name__)


# ── CORS Middleware for GitHub Pages ──
@app.after_request
def add_cors(response):
    """Allow cross-origin requests from GitHub Pages."""
    origin = request.headers.get('Origin', '')
    allowed = [
        'https://hermesna-1.github.io',
        'http://localhost:5000',
        'http://127.0.0.1:5000',
    ]
    if any(a in origin for a in ['github.io', 'localhost', '127.0.0.1']):
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response


# Handle preflight OPTIONS requests
@app.route('/api/<path:path>', methods=['OPTIONS'])
@app.route('/api', methods=['OPTIONS'])
def handle_options(path=None):
    return jsonify({'ok': True})


# ── Backend Loader ──
BACKEND = {}

def load_backend():
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
    BACKEND['tm'].load()
    BACKEND['mm'].discover()
    for cat, paths in BACKEND['mm'].categories.items():
        for p in paths:
            BACKEND['mm'].load_module(p)
    return BACKEND


# ── API Routes ──

@app.route('/api/ping')
def api_ping():
    return jsonify({'status': 'ok', 'version': '1.0.0', 'name': 'SnakeSploit'})


@app.route('/api/dashboard')
def api_dashboard():
    b = load_backend()
    tm = b['tm']; mm = b['mm']; sm = b['sm']; cve = b['cve']
    all_t = tm.all()
    total_services = sum(len(t.services) for t in all_t)
    total_vulns = sum(len(t.vulnerabilities) for t in all_t)
    stats = cve.get_statistics()
    top_cves = sorted(cve.index, key=lambda x: x.get('score', 0), reverse=True)[:8]
    recent = [{'host': t.host, 'services': len(t.services), 'vulns': len(t.vulnerabilities)} for t in all_t[-8:]]
    return jsonify({
        'targets': len(all_t), 'services': total_services, 'vulnerabilities': total_vulns,
        'modules': len(mm.modules), 'cves': stats['total_cves'],
        'sessions': sm.summary()['active'],
        'recent_targets': recent,
        'top_cves': [{'id': c['id'], 'severity': c.get('severity', 'UNKNOWN'), 'score': c.get('score', 0)} for c in top_cves],
    })


@app.route('/api/targets')
def api_targets():
    b = load_backend()
    targets = [{'host': t.host, 'os': t.os, 'services': len(t.services), 'vulns': len(t.vulnerabilities)} for t in b['tm'].all()]
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
        modules.append({'name': name, 'description': mod.metadata.description[:120], 'cves': cves, 'platform': mod.metadata.platform})
    return jsonify({'modules': modules})


@app.route('/api/cve')
def api_cve():
    b = load_backend()
    stats = b['cve'].get_statistics()
    cves = list(reversed(b['cve'].index[-50:]))
    return jsonify({'stats': stats, 'cves': cves})


@app.route('/api/cve/update', methods=['POST'])
def api_cve_update():
    b = load_backend()
    data = request.get_json() or {}
    count = b['cve'].fetch_recent(days_back=data.get('days', 7))
    return jsonify({'new_cves': count})


@app.route('/api/cve/full-update', methods=['POST'])
def api_cve_full_update():
    b = load_backend()
    data = request.get_json() or {}
    results = b['auto'].run_full_update(days_back=data.get('days', 3))
    return jsonify(results)


@app.route('/api/scan', methods=['POST'])
def api_scan():
    b = load_backend()
    data = request.get_json()
    host = data.get('host', '')
    ports_str = data.get('ports', '')
    ports = [int(p.strip()) for p in ports_str.split(',') if p.strip()] if ports_str else None
    results = b['scanner'].scan(host, ports)
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
        result = load_backend()['strix'].set_api_key(key)
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
    return jsonify({'output': (result.get('output', '') or '')[:3000], 'success': result.get('success', False), 'error': result.get('error')})


@app.route('/api/console', methods=['POST'])
def api_console():
    b = load_backend()
    data = request.get_json()
    cmd = data.get('command', '').strip().lower()
    if cmd.startswith('search '):
        q = cmd.replace('search ', '', 1)
        results = b['mm'].search(q)
        output = '\n'.join([f"  {n}: {m.metadata.description[:80]}" for n, m in results]) if results else "No results"
        return jsonify({'output': output})
    elif cmd == 'cve stats':
        stats = b['cve'].get_statistics()
        output = '\n'.join([f"  {k}: {v}" for k, v in stats.items()])
        return jsonify({'output': output})
    elif cmd.startswith('scan '):
        parts = cmd.split()
        host = parts[1] if len(parts) > 1 else ''
        pstr = parts[2] if len(parts) > 2 else ''
        ports = [int(p) for p in pstr.split(',') if p] if pstr else None
        results = b['scanner'].scan(host, ports)
        output = '\n'.join([f"  Port {r['port']}: {r['state']}" for r in results]) if results else "No open ports"
        return jsonify({'output': output})
    elif cmd == 'help':
        return jsonify({'output': "Commands: search <q>, cve stats, scan <host> [ports], payloads"})
    else:
        return jsonify({'error': f"Unknown command: {cmd}"})


# ── Main ──

def main():
    parser = argparse.ArgumentParser(description="SnakeSploit Web GUI")
    parser.add_argument('--port', type=int, default=5000, help='Port (default: 5000)')
    parser.add_argument('--host', default='0.0.0.0', help='Bind address (default: 0.0.0.0)')
    args = parser.parse_args()
    print(f"  [*] SnakeSploit Web GUI on http://{args.host}:{args.port}")
    print(f"  [*] GitHub Pages frontend: https://HermesNA-1.github.io/SnakeSploit/")
    print(f"  [*] Press Ctrl+C to stop")
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == '__main__':
    main()