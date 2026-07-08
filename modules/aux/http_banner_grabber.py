"""
Example Nova Module: HTTP Banner Grabber
Shows module writing conventions.
"""

import socket
import ssl

from core.module import NovaModule, ModuleMetadata


class Module(NovaModule):
    """HTTP banner grabber — fetches server headers."""

    metadata = ModuleMetadata(
        name="http_banner_grabber",
        description="Grab HTTP server banner and headers from a web server",
        author="SnakeSploit",
        version="1.0",
        module_type="auxiliary",
        platform="multi",
        arch="cmd",
        rank="normal",
    )

    required_options = ["RHOSTS", "RPORT"]

    def check(self) -> bool:
        host = self.options.get("RHOSTS", "127.0.0.1")
        port = int(self.options.get("RPORT", 80))
        ssl_enabled = self.options.get("SSL", "false").lower() == "true"

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            if ssl_enabled:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)
            sock.connect((host, port))
            sock.send(b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            response = sock.recv(4096)
            sock.close()
            self._results["banner_raw"] = response.decode(errors="replace")[:500]
            return True
        except Exception as e:
            self.print_error(f"Connection failed: {e}")
            return False

    def run(self) -> dict:
        host = self.options.get("RHOSTS", "127.0.0.1")
        port = int(self.options.get("RPORT", 80))
        ssl_enabled = self.options.get("SSL", "false").lower() == "true"
        uri = self.options.get("TARGETURI", "/")

        self.print_status(f"Connecting to {host}:{port}...")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            if ssl_enabled:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)
            sock.connect((host, port))

            request = f"GET {uri} HTTP/1.0\r\nHost: {host}\r\n\r\n"
            sock.send(request.encode())

            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except socket.timeout:
                    break

            sock.close()
            text = response.decode(errors="replace")

            # Parse headers
            headers = {}
            if "\r\n" in text:
                header_part = text.split("\r\n\r\n")[0]
                for line in header_part.split("\r\n")[1:]:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        headers[k.strip()] = v.strip()

            self.print_good(f"Connected to {host}:{port}")
            self.print_good(f"Response: {len(response)} bytes")

            # Show interesting headers
            interesting = ["Server", "X-Powered-By", "X-AspNet-Version",
                          "X-Frame-Options", "Content-Security-Policy"]
            for h in interesting:
                if h in headers:
                    self.print_status(f"{h}: {headers[h]}")

            self._results = {
                "host": host,
                "port": port,
                "status": "connected",
                "headers": headers,
                "response_size": len(response),
            }

            # Store loot
            self.store_loot(text, f"http_banner_{host}_{port}.txt")

            return self._results

        except Exception as e:
            self.print_error(f"Error: {e}")
            self._results = {"error": str(e)}
            return self._results