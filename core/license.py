"""
SnakeSploit License System — LicenseSeat Integration
Validates licenses via LicenseSeat API, manages activation state.
"""

import json
import os
import sys
import time
import urllib.request
import urllib.error
from typing import Optional, Dict, Any
from datetime import datetime
from pathlib import Path


class LicenseManager:
    """Manages SnakeSploit licensing via LicenseSeat.

    Workflow:
    1. Researcher runs snakesploit → checks for saved license
    2. If no license → prompts for key entry
    3. If bad/no key → shows contact instructions
    4. License validated via LicenseSeat API → saved locally
    5. Re-validates periodically (every 24h) to check revocation
    """

    API_BASE = "https://licenseseat.com/api/v1"
    CONFIG_DIR = os.path.expanduser("~/.snakesploit")
    CONFIG_FILE = os.path.join(CONFIG_DIR, "license.json")

    def __init__(self, api_key: str = None, product_slug: str = "snakesploit"):
        self.api_key = api_key or os.environ.get("SNAKESPLOIT_LICENSE_API_KEY", "")
        self.product_slug = product_slug
        self._license_data: Optional[Dict[str, Any]] = None
        os.makedirs(self.CONFIG_DIR, exist_ok=True)
        self._load()

    def _load(self):
        """Load saved license state from disk."""
        if os.path.exists(self.CONFIG_FILE):
            try:
                with open(self.CONFIG_FILE) as f:
                    data = json.load(f)
                self._license_data = data
            except (json.JSONDecodeError, IOError):
                self._license_data = None

    def _save(self):
        """Persist license state to disk."""
        with open(self.CONFIG_FILE, "w") as f:
            json.dump(self._license_data, f, indent=2)
        # Restrict permissions
        os.chmod(self.CONFIG_FILE, 0o600)

    def _api_request(self, method: str, path: str, body: dict = None) -> Optional[dict]:
        """Make an API request to LicenseSeat."""
        url = f"{self.API_BASE}{path}"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": "SnakeSploit/1.0",
        }
        data = json.dumps(body).encode() if body else None

        try:
            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            try:
                err_body = json.loads(e.read().decode())
                return {"error": err_body.get("error", {}).get("code", "unknown"),
                        "message": err_body.get("error", {}).get("message", str(e))}
            except Exception:
                return {"error": "http_error", "message": f"HTTP {e.code}: {e.reason}"}
        except urllib.error.URLError as e:
            return {"error": "network_error", "message": f"Cannot reach LicenseSeat: {e.reason}"}
        except Exception as e:
            return {"error": "unknown", "message": str(e)}

    def activate(self, license_key: str) -> Dict[str, Any]:
        """
        Activate SnakeSploit with a license key.
        Validates the key and registers this device.
        """
        result = self._api_request("POST",
            f"/products/{self.product_slug}/licenses/{license_key}/activate",
            body={"fingerprint": self._get_fingerprint()}
        )

        if result and "error" not in result:
            self._license_data = {
                "license_key": license_key,
                "activated_at": datetime.now().isoformat(),
                "last_validated": datetime.now().isoformat(),
                "device_id": result.get("device_id", ""),
                "product_slug": self.product_slug,
                "valid": True,
                "license_data": result,
            }
            self._save()
            return {"success": True, "message": "License activated successfully!"}

        error = result.get("message", "Unknown error") if result else "No response from server"
        return {"success": False, "message": f"License activation failed: {error}"}

    def validate(self) -> Dict[str, Any]:
        """
        Check if the current license is still valid.
        Called on every startup and periodically.
        """
        if not self._license_data or not self._license_data.get("license_key"):
            return {"valid": False, "message": "No license key found. Please activate SnakeSploit."}

        license_key = self._license_data["license_key"]

        # If we validated recently (within 24h), skip network call
        last_validated = self._license_data.get("last_validated", "")
        if last_validated:
            try:
                last_time = datetime.fromisoformat(last_validated)
                hours_since = (datetime.now() - last_time).total_seconds() / 3600
                if hours_since < 24 and self._license_data.get("valid"):
                    return {"valid": True, "message": "License valid (cached)", "key": license_key}
            except ValueError:
                pass

        # Online validation
        result = self._api_request("POST",
            f"/products/{self.product_slug}/licenses/{license_key}/validate"
        )

        if result and "error" not in result:
            self._license_data["last_validated"] = datetime.now().isoformat()
            self._license_data["valid"] = True
            self._save()
            return {"valid": True, "message": "License is valid", "key": license_key}

        self._license_data["last_validated"] = datetime.now().isoformat()
        self._license_data["valid"] = False
        self._save()

        error_msg = result.get("message", "License validation failed") if result else "No response"
        return {"valid": False, "message": error_msg, "key": license_key}

    def deactivate(self) -> Dict[str, Any]:
        """Deactivate this device (free up a seat)."""
        if not self._license_data or not self._license_data.get("license_key"):
            return {"success": False, "message": "No active license to deactivate."}

        license_key = self._license_data["license_key"]
        result = self._api_request("POST",
            f"/products/{self.product_slug}/licenses/{license_key}/deactivate",
            body={"device_id": self._license_data.get("device_id", "")}
        )

        # Clear local state regardless
        self._license_data = None
        if os.path.exists(self.CONFIG_FILE):
            os.remove(self.CONFIG_FILE)

        if result and "error" not in result:
            return {"success": True, "message": "Device deactivated successfully."}
        return {"success": True, "message": "Local license data cleared."}

    def is_licensed(self) -> bool:
        """Quick check — returns True if a valid license is cached."""
        if not self._license_data:
            return False
        return self._license_data.get("valid", False)

    def get_license_info(self) -> Dict[str, Any]:
        """Get the current license state for display."""
        if not self._license_data:
            return {"status": "unlicensed"}
        return {
            "status": "active" if self._license_data.get("valid") else "invalid",
            "license_key": self._license_data.get("license_key", ""),
            "activated_at": self._license_data.get("activated_at", ""),
            "last_validated": self._license_data.get("last_validated", ""),
        }

    @staticmethod
    def _get_fingerprint() -> str:
        """Generate a device fingerprint (simple but unique enough)."""
        import hashlib, subprocess
        parts = []

        # Machine ID
        try:
            with open("/etc/machine-id") as f:
                parts.append(f.read().strip())
        except Exception:
            pass

        # Hostname
        try:
            import socket
            parts.append(socket.gethostname())
        except Exception:
            pass

        # MAC address
        try:
            result = subprocess.run(
                ["ip", "link"], capture_output=True, text=True, timeout=2
            )
            for line in result.stdout.split("\n"):
                if "link/ether" in line:
                    mac = line.split()[1]
                    parts.append(mac)
                    break
        except Exception:
            pass

        raw = ":".join(parts) if parts else "unknown-device"
        return hashlib.sha256(raw.encode()).hexdigest()[:32]


# Researcher contact info — update this to your preferred contact method
RESEARCHER_CONTACT = """
╔══════════════════════════════════════════════════════╗
║            SnakeSploit — Licensed Software           ║
╠══════════════════════════════════════════════════════╣
║                                                      ║
║  SnakeSploit is restricted to authorized             ║
║  security researchers only.                          ║
║                                                      ║
║  To request access:                                  ║
║    1. Message @Nirbhik_Acharya on Telegram           ║
║       with your name, email, and research purpose    ║
║                                                      ║
║    2. Include proof of your research affiliation     ║
║       (university, bug bounty program, company, etc) ║
║                                                      ║
║    3. If approved, you'll receive a license key      ║
║                                                      ║
║  Already have a key? Run:                            ║
║    snakesploit --activate YOUR-KEY-HERE              ║
║                                                      ║
╚══════════════════════════════════════════════════════╝
"""