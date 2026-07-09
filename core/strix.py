"""
SnakeSploit Strix Integration — AI-powered web security scanner.
Runs against targets via the Strix engine, stores results.
"""

import json
import os
import subprocess
import time
from typing import Dict, Optional, Any
from datetime import datetime


STRIX_DIR = os.path.expanduser("~/.strix")
STRIX_RUNNER = os.path.join(STRIX_DIR, "run-strix.sh")
CONFIG_PATH = os.path.expanduser("~/.snakesploit/strix_config.json")


class StrixEngine:
    """Interface to the Strix AI security scanner."""

    def __init__(self):
        self.config = self._load_config()
        self._available = os.path.exists(STRIX_RUNNER)

    def _load_config(self) -> dict:
        if os.path.exists(CONFIG_PATH):
            try:
                with open(CONFIG_PATH) as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return {"api_key": "", "configured": False}

    def _save_config(self):
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        with open(CONFIG_PATH, "w") as f:
            json.dump(self.config, f, indent=2)
        os.chmod(CONFIG_PATH, 0o600)

    def is_installed(self) -> bool:
        """Check if Strix engine is available on this system."""
        return self._available

    def is_configured(self) -> bool:
        """Check if Strix has an API key configured."""
        return self.config.get("configured", False) and bool(self.config.get("api_key", ""))

    def set_api_key(self, api_key: str) -> dict:
        """Configure the Strix API key."""
        self.config["api_key"] = api_key.strip()
        self.config["configured"] = True
        self.config["updated_at"] = datetime.now().isoformat()
        self._save_config()

        # Also write to Strix's own config if it exists
        strix_config = os.path.join(STRIX_DIR, "cli-config.json")
        if os.path.exists(os.path.dirname(strix_config)):
            try:
                existing = {}
                if os.path.exists(strix_config):
                    with open(strix_config) as f:
                        existing = json.load(f)
                existing["api_key"] = api_key.strip()
                with open(strix_config, "w") as f:
                    json.dump(existing, f, indent=2)
            except Exception:
                pass

        return {"success": True, "message": "Strix API key configured successfully."}

    def remove_api_key(self) -> dict:
        """Remove the configured API key."""
        self.config["api_key"] = ""
        self.config["configured"] = False
        self._save_config()
        return {"success": True, "message": "Strix API key removed."}

    def scan(self, target: str, timeout: int = 300) -> Dict[str, Any]:
        """
        Run a Strix scan against a target.
        Returns structured results.
        """
        if not self._available:
            return {"success": False, "error": "Strix is not installed on this system.", "target": target}

        if not self.is_configured():
            return {"success": False, "error": "No API key configured. Use 'strix config --key YOUR_KEY' first.", "target": target}

        print(f"  [*] Strix scanning {target}...")
        print(f"  [*] This may take a few minutes...")

        start = time.time()

        try:
            result = subprocess.run(
                [STRIX_RUNNER, "--target", target, "--non-interactive"],
                capture_output=True,
                text=True,
                timeout=timeout,
                env={**os.environ, "STRIX_API_KEY": self.config.get("api_key", "")},
            )

            elapsed = time.time() - start
            output = result.stdout + result.stderr
            exit_code = result.returncode

            scan_result = {
                "success": exit_code == 0,
                "target": target,
                "exit_code": exit_code,
                "output": output[:5000],  # Cap at 5K chars
                "elapsed_seconds": round(elapsed, 1),
                "timestamp": datetime.now().isoformat(),
            }

            # Save full output to file
            log_dir = os.path.expanduser("~/.snakesploit/strix_scans")
            os.makedirs(log_dir, exist_ok=True)
            safe_name = target.replace("://", "_").replace("/", "_").replace(".", "_")[:50]
            log_path = os.path.join(log_dir, f"strix_{safe_name}_{int(time.time())}.txt")
            with open(log_path, "w") as f:
                f.write(output)
            scan_result["log_path"] = log_path

            return scan_result

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "target": target,
                "error": f"Scan timed out after {timeout} seconds.",
                "elapsed_seconds": timeout,
            }
        except FileNotFoundError:
            self._available = False
            return {"success": False, "target": target, "error": "Strix runner not found at ~/.strix/run-strix.sh"}
        except Exception as e:
            return {"success": False, "target": target, "error": str(e)}

    def get_status(self) -> dict:
        """Get a status report for the Strix integration."""
        return {
            "installed": self._available,
            "configured": self.is_configured(),
            "has_api_key": bool(self.config.get("api_key", "")),
            "runner_path": STRIX_RUNNER if self._available else "NOT FOUND",
            "last_updated": self.config.get("updated_at", "never"),
        }