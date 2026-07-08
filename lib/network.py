"""
SnakeSploit Network Library — sockets, HTTP clients, proxy support.
"""

import socket
import ssl
import urllib.request
from typing import Dict, Optional, Tuple


class NovaSocket:
    """Wrapper around raw sockets with timeouts and error handling."""

    @staticmethod
    def create_connection(host: str, port: int, timeout: int = 10,
                          ssl: bool = False) -> Optional[socket.socket]:
        """Create a TCP connection, optionally with SSL."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            if ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)
            return sock
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            return None
        except Exception as e:
            return None

    @staticmethod
    def recv_until(sock: socket.socket, delimiter: bytes = b"\n",
                   max_size: int = 4096) -> bytes:
        """Receive data until delimiter is found or max_size reached."""
        data = b""
        while len(data) < max_size:
            try:
                chunk = sock.recv(1)
                if not chunk:
                    break
                data += chunk
                if data.endswith(delimiter):
                    break
            except socket.timeout:
                break
        return data

    @staticmethod
    def send_recv(sock: socket.socket, data: bytes,
                  timeout: float = 5.0) -> Optional[bytes]:
        """Send data and receive response."""
        try:
            sock.settimeout(timeout)
            sock.send(data)
            response = sock.recv(4096)
            return response
        except Exception:
            return None


class HTTPClient:
    """Simple HTTP client for web requests."""

    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    @staticmethod
    def get(url: str, timeout: int = 10,
            headers: Dict[str, str] = None) -> Optional[Dict]:
        """HTTP GET request."""
        req_headers = {
            "User-Agent": HTTPClient.USER_AGENT,
        }
        if headers:
            req_headers.update(headers)

        try:
            req = urllib.request.Request(url, headers=req_headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read()
                return {
                    "status": resp.status,
                    "headers": dict(resp.headers),
                    "body": body,
                    "text": body.decode(errors="replace"),
                }
        except urllib.error.HTTPError as e:
            return {
                "status": e.code,
                "headers": dict(e.headers),
                "body": e.read() if e.fp else b"",
                "text": e.read().decode(errors="replace") if e.fp else "",
                "error": str(e),
            }
        except Exception as e:
            return {"error": str(e)}


class PortScanner:
    """Fast port scanner for Nova."""

    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
        445, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432,
        5900, 5985, 5986, 6379, 8080, 8443, 9090, 27017,
    ]

    @staticmethod
    def scan_port(host: str, port: int, timeout: float = 1.0) -> str:
        """Check if a single TCP port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return "open" if result == 0 else "closed"
        except Exception:
            return "filtered"

    @staticmethod
    def scan(host: str, ports: list = None, timeout: float = 1.0) -> list:
        """Scan multiple ports on a host."""
        if ports is None:
            ports = PortScanner.COMMON_PORTS
        results = []
        for port in ports:
            state = PortScanner.scan_port(host, port, timeout)
            if state == "open":
                results.append({"port": port, "state": state})
        return results