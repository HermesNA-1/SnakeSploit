"""
SnakeSploit MCP Server — Model Context Protocol integration.
Lets AI agents (Claude, Cline, etc.) discover and use SnakeSploit tools.
Implements the MCP stdio transport specification.

Usage:
  snakesploit mcp                     # Start MCP server (stdio mode)
  snakesploit mcp --http --port 8765  # Start MCP server (HTTP mode)
"""

import json
import os
import sys
import socket
import subprocess
import traceback
from typing import Any, Dict, List, Optional
from datetime import datetime
from pathlib import Path

# ── MCP Protocol Helpers ──────────────────────────────────────────

JSON_RPC_VERSION = "2.0"


def jsonrpc_request(method: str, params: dict = None, id: int = None) -> dict:
    msg = {
        "jsonrpc": JSON_RPC_VERSION,
        "method": method,
    }
    if params is not None:
        msg["params"] = params
    if id is not None:
        msg["id"] = id
    return msg


def jsonrpc_response(result: Any, id: int) -> dict:
    return {
        "jsonrpc": JSON_RPC_VERSION,
        "id": id,
        "result": result,
    }


def jsonrpc_error(code: int, message: str, id: int = None) -> dict:
    return {
        "jsonrpc": JSON_RPC_VERSION,
        "id": id,
        "error": {"code": code, "message": message},
    }


# ── Tool Definitions ─────────────────────────────────────────────

MCP_TOOLS = [
    {
        "name": "scan_ports",
        "description": "Scan a target host for open TCP ports",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Target IP or hostname"},
                "ports": {"type": "string", "description": "Optional comma-separated port list (default: common ports)"},
            },
            "required": ["host"],
        },
    },
    {
        "name": "http_get",
        "description": "Send an HTTP GET request to a URL",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Full URL to request"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "search_modules",
        "description": "Search SnakeSploit modules by name, CVE, or description",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "run_module",
        "description": "Run a SnakeSploit module against a target",
        "inputSchema": {
            "type": "object",
            "properties": {
                "module_name": {"type": "string", "description": "Module name (e.g. 'smb_version_scanner')"},
                "target": {"type": "string", "description": "Target host"},
                "port": {"type": "integer", "description": "Target port"},
            },
            "required": ["module_name", "target"],
        },
    },
    {
        "name": "generate_payload",
        "description": "Generate a reverse shell or bind shell payload",
        "inputSchema": {
            "type": "object",
            "properties": {
                "payload_type": {
                    "type": "string",
                    "description": "Type: linux_reverse, python_reverse, nc_reverse, powershell_reverse, perl_reverse, python_bind, php_reverse",
                },
                "lhost": {"type": "string", "description": "Listener IP"},
                "lport": {"type": "integer", "description": "Listener port"},
                "encode": {"type": "boolean", "description": "Base64 encode the payload"},
            },
            "required": ["payload_type", "lhost", "lport"],
        },
    },
    {
        "name": "cve_stats",
        "description": "Get CVE cache statistics",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "update_cves",
        "description": "Fetch latest CVEs from NVD",
        "inputSchema": {
            "type": "object",
            "properties": {
                "days": {"type": "integer", "description": "Days back to fetch (default: 7)"},
            },
        },
    },
    {
        "name": "self_update",
        "description": "Update SnakeSploit itself from GitHub",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "target_list",
        "description": "List all tracked targets in the database",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "strix_scan",
        "description": "Run a Strix AI security scan against a target",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL or IP"},
            },
            "required": ["target"],
        },
    },
]

# ── Tool Implementations ─────────────────────────────────────────

# Lazy imports to avoid circular dependencies
def _import_core():
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from lib.network import PortScanner, HTTPClient
    from core.module import ModuleManager
    from lib.payloads import PayloadGenerator
    from core.target import TargetManager
    from updater.cve_fetcher import CVEUpdater
    return PortScanner, HTTPClient, ModuleManager, PayloadGenerator, TargetManager, CVEUpdater


def _import_strix():
    try:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from core.strix import StrixEngine
        return StrixEngine
    except ImportError:
        return None


def handle_tool_call(name: str, arguments: dict) -> dict:
    """Execute a tool and return the result."""
    PortScanner, HTTPClient, ModuleManager, PayloadGenerator, TargetManager, CVEUpdater = _import_core()

    if name == "scan_ports":
        host = arguments["host"]
        ports_str = arguments.get("ports", "")
        ports = [int(p.strip()) for p in ports_str.split(",") if p.strip()] if ports_str else None
        results = PortScanner.scan(host, ports)
        return {
            "content": [{
                "type": "text",
                "text": json.dumps({
                    "target": host,
                    "open_ports": results,
                    "count": len(results),
                }, indent=2),
            }]
        }

    elif name == "http_get":
        url = arguments["url"]
        result = HTTPClient.get(url)
        if "error" in result:
            return {"content": [{"type": "text", "text": f"Error: {result['error']}"}]}
        return {
            "content": [{
                "type": "text",
                "text": json.dumps({
                    "status": result.get("status"),
                    "headers": {k: v for k, v in result.get("headers", {}).items() if k.lower() in 
                        ["server", "x-powered-by", "x-frame-options", "content-security-policy", "set-cookie"]},
                    "body_preview": result.get("text", "")[:1000],
                }, indent=2),
            }]
        }

    elif name == "search_modules":
        query = arguments["query"]
        mm = ModuleManager()
        mm.discover()
        for cat, paths in mm.categories.items():
            for p in paths:
                mm.load_module(p)
        results = mm.search(query)
        modules = []
        for name, mod in results:
            cves = ", ".join(mod.metadata.cve_ids) if mod.metadata.cve_ids else ""
            modules.append({
                "name": name,
                "description": mod.metadata.description[:120],
                "cves": cves,
                "type": mod.metadata.module_type,
                "platform": mod.metadata.platform,
            })
        return {
            "content": [{
                "type": "text",
                "text": json.dumps({"query": query, "count": len(modules), "modules": modules}, indent=2),
            }]
        }

    elif name == "run_module":
        module_name = arguments["module_name"]
        target = arguments["target"]
        port = arguments.get("port", 80)
        mm = ModuleManager()
        mm.discover()
        for cat, paths in mm.categories.items():
            for p in paths:
                mm.load_module(p)
        results = mm.search(module_name)
        if not results:
            return {"content": [{"type": "text", "text": f"Module '{module_name}' not found."}]}
        _, mod = results[0]
        fresh = type(mod)()
        fresh.setup(RHOSTS=target, RPORT=str(port))
        try:
            fresh.validate()
            output = fresh.run()
            return {
                "content": [{
                    "type": "text",
                    "text": json.dumps({
                        "module": module_name,
                        "target": f"{target}:{port}",
                        "result": output,
                    }, indent=2),
                }]
            }
        except Exception as e:
            return {"content": [{"type": "text", "text": f"Module execution failed: {e}"}]}

    elif name == "generate_payload":
        ptype = arguments["payload_type"]
        lhost = arguments["lhost"]
        lport = arguments["lport"]
        encode = arguments.get("encode", False)
        try:
            payload = PayloadGenerator.generate(ptype, lhost, lport, encode)
            return {
                "content": [{
                    "type": "text",
                    "text": json.dumps({
                        "type": ptype,
                        "lhost": lhost,
                        "lport": lport,
                        "encoded": encode,
                        "size": payload.size,
                        "code": payload.code,
                    }, indent=2),
                }]
            }
        except ValueError as e:
            return {"content": [{"type": "text", "text": f"Error: {e}"}]}

    elif name == "cve_stats":
        updater = CVEUpdater()
        stats = updater.get_statistics()
        return {
            "content": [{
                "type": "text",
                "text": json.dumps(stats, indent=2),
            }]
        }

    elif name == "update_cves":
        days = arguments.get("days", 7)
        updater = CVEUpdater()
        count = updater.fetch_recent(days_back=days)
        stats = updater.get_statistics()
        return {
            "content": [{
                "type": "text",
                "text": json.dumps({
                    "new_cves": count,
                    "total_cves": stats["total_cves"],
                    "critical": stats["critical"],
                    "high": stats["high"],
                }, indent=2),
            }]
        }

    elif name == "self_update":
        try:
            repo_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            result = subprocess.run(["git", "pull"], cwd=repo_dir, capture_output=True, text=True, timeout=30)
            return {
                "content": [{
                    "type": "text",
                    "text": result.stdout if result.returncode == 0 else f"Failed: {result.stderr}",
                }]
            }
        except Exception as e:
            return {"content": [{"type": "text", "text": f"Update failed: {e}"}]}

    elif name == "target_list":
        tm = TargetManager()
        tm.load()
        targets = []
        for t in tm.all():
            targets.append({
                "host": t.host,
                "services": [{"port": p, "service": s.service} for p, s in t.services.items()],
                "vulnerabilities": [v["cve_id"] for v in t.vulnerabilities],
            })
        return {
            "content": [{
                "type": "text",
                "text": json.dumps({"targets": targets, "count": len(targets)}, indent=2),
            }]
        }

    elif name == "strix_scan":
        StrixEngine = _import_strix()
        if not StrixEngine:
            return {"content": [{"type": "text", "text": "Strix integration not available."}]}
        strix = StrixEngine()
        if not strix.is_configured():
            return {"content": [{"type": "text", "text": "Strix API key not configured. Use 'strix config --key' first."}]}
        result = strix.scan(arguments["target"])
        return {
            "content": [{
                "type": "text",
                "text": json.dumps({
                    "target": arguments["target"],
                    "success": result.get("success", False),
                    "elapsed": result.get("elapsed_seconds", 0),
                    "error": result.get("error"),
                    "output_preview": (result.get("output") or "")[:2000],
                }, indent=2),
            }]
        }

    return {"content": [{"type": "text", "text": f"Unknown tool: {name}"}]}


# ── MCP Server Core ──────────────────────────────────────────────

class MCPServer:
    """MCP protocol server for SnakeSploit."""

    def __init__(self, transport: str = "stdio"):
        self.transport = transport
        self.request_id = 0

    def handle_message(self, message: dict) -> Optional[dict]:
        """Process a single JSON-RPC message."""
        method = message.get("method", "")
        msg_id = message.get("id")
        params = message.get("params", {}) or {}

        if method == "initialize":
            return jsonrpc_response({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {},
                    "resources": {},
                },
                "serverInfo": {
                    "name": "snakesploit-mcp",
                    "version": "1.0.0",
                },
            }, msg_id)

        elif method == "tools/list":
            return jsonrpc_response({"tools": MCP_TOOLS}, msg_id)

        elif method == "tools/call":
            name = params.get("name", "")
            arguments = params.get("arguments", {})
            try:
                return jsonrpc_response(handle_tool_call(name, arguments), msg_id)
            except Exception as e:
                return jsonrpc_response({
                    "content": [{"type": "text", "text": f"Error executing {name}: {traceback.format_exc()}"}],
                    "isError": True,
                }, msg_id)

        elif method == "resources/list":
            return jsonrpc_response({"resources": [
                {
                    "uri": "snakesploit://cve/stats",
                    "name": "CVE Cache Statistics",
                    "description": "Current CVE cache statistics",
                    "mimeType": "application/json",
                },
                {
                    "uri": "snakesploit://targets/list",
                    "name": "Target Database",
                    "description": "List of all tracked targets",
                    "mimeType": "application/json",
                },
            ]}, msg_id)

        elif method == "resources/read":
            uri = params.get("uri", "")
            if uri == "snakesploit://cve/stats":
                _, _, _, _, _, CVEUpdater = _import_core()
                updater = CVEUpdater()
                return jsonrpc_response({
                    "contents": [{
                        "uri": uri,
                        "mimeType": "application/json",
                        "text": json.dumps(updater.get_statistics(), indent=2),
                    }]
                }, msg_id)
            elif uri == "snakesploit://targets/list":
                _, _, _, _, TargetManager, _ = _import_core()
                tm = TargetManager()
                tm.load()
                targets = [{"host": t.host, "services": len(t.services), "vulns": len(t.vulnerabilities)} for t in tm.all()]
                return jsonrpc_response({
                    "contents": [{
                        "uri": uri,
                        "mimeType": "application/json",
                        "text": json.dumps(targets, indent=2),
                    }]
                }, msg_id)
            return jsonrpc_error(-32602, f"Resource not found: {uri}", msg_id)

        elif method == "ping":
            return jsonrpc_response({"status": "ok"}, msg_id)

        elif method == "notifications/initialized":
            return None  # No response needed for notifications

        return jsonrpc_error(-32601, f"Method not found: {method}", msg_id)

    def run_stdio(self):
        """Run MCP server over stdin/stdout (standard for AI agents)."""
        while True:
            try:
                line = sys.stdin.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                message = json.loads(line)
                response = self.handle_message(message)
                if response is not None:
                    sys.stdout.write(json.dumps(response) + "\n")
                    sys.stdout.flush()
            except json.JSONDecodeError:
                continue
            except EOFError:
                break
            except KeyboardInterrupt:
                break
            except Exception:
                sys.stderr.write(traceback.format_exc())
                sys.stderr.flush()

    def run_http(self, port: int = 8765):
        """Run MCP server over HTTP."""
        import http.server
        import socketserver

        class MCPHTTPHandler(http.server.BaseHTTPRequestHandler):
            server_instance = self

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length).decode()
                try:
                    message = json.loads(body)
                    response = self.server_instance.handle_message(message)
                    if response is not None:
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(json.dumps(response).encode())
                    else:
                        self.send_response(202)
                        self.end_headers()
                except Exception as e:
                    self.send_response(500)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": str(e)}).encode())

            def log_message(self, format, *args):
                sys.stderr.write(f"[MCP HTTP] {args[0]} {args[1]} {args[2]}\n")

        with socketserver.TCPServer(("127.0.0.1", port), MCPHTTPHandler) as httpd:
            print(f"SnakeSploit MCP server running on http://127.0.0.1:{port}")
            print(f"Connect AI agents (Claude, Cline, etc.) to this endpoint.")
            httpd.serve_forever()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="SnakeSploit MCP Server")
    parser.add_argument("--http", action="store_true", help="Run in HTTP mode instead of stdio")
    parser.add_argument("--port", type=int, default=8765, help="HTTP port (default: 8765)")
    args = parser.parse_args()

    server = MCPServer(transport="http" if args.http else "stdio")
    if args.http:
        server.run_http(port=args.port)
    else:
        server.run_stdio()


if __name__ == "__main__":
    main()