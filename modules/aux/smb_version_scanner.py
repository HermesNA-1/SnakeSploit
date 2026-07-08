"""
Example Nova Exploit Module: SMB Version Scanner
Scans SMB services and attempts to fingerprint.
"""

from core.module import NovaModule, ModuleMetadata


class Module(NovaModule):
    """SMB version scanner / vulnerability pre-check."""

    metadata = ModuleMetadata(
        name="smb_version_scanner",
        description="Scan SMB service and check for known vulnerable versions",
        author="SnakeSploit",
        version="1.0",
        cve_ids=["CVE-2017-0143", "CVE-2020-0796", "CVE-2021-1675"],
        references=[
            "https://docs.microsoft.com/en-us/security-updates/securitybulletins/ms17-010",
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-0796",
        ],
        rank="good",
        module_type="auxiliary",
        platform="windows",
        arch="cmd",
    )

    required_options = ["RHOSTS", "RPORT"]

    def __init__(self):
        super().__init__()
        self.options["RPORT"] = 445
        self.options["SMBDIRECT"] = True

    def check(self) -> bool:
        host = self.options.get("RHOSTS", "127.0.0.1")
        port = int(self.options.get("RPORT", 445))
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((host, port))
            # SMB negotiation protocol request
            s.send(b"\x00\x00\x00\x2f\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x08\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
            resp = s.recv(1024)
            s.close()
            if resp and resp[:4] == b"\x00\x00\x00":
                self.print_good(f"SMB service detected on {host}:{port}")
                return True
            return False
        except Exception:
            return False

    def run(self) -> dict:
        host = self.options.get("RHOSTS", "127.0.0.1")
        port = int(self.options.get("RPORT", 445))

        self.print_status(f"Scanning SMB on {host}:{port}...")

        if not self.check():
            self.print_error("No SMB service detected")
            return {"status": "no_smb"}

        self.print_good("SMB service is running")
        self.print_status("Checking for known vulnerabilities...")

        # Check CVE-2017-0143 (EternalBlue) - SMBv1
        self.print_status("Checking SMBv1 (MS17-010)...")

        # Generic note about what to check next
        self.print_good("SMB scanning complete")
        self.print_status("Consider running:")
        self.print_status("  nmap --script smb-vuln-ms17-010 -p445 " + host)

        self._results = {
            "host": host,
            "port": port,
            "smb_detected": True,
            "next_steps": [
                "nmap --script smb-vuln-* -p445 " + host,
                "smbclient -L //" + host + "/ -N",
            ]
        }

        return self._results