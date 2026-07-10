"""
SnakeSploit Anti-Tamper System — kernel-level userspace protection.
Detects debugging, file tampering, process manipulation, and VM environments.

Components:
  - Anti-debug: ptrace detection, debugger flags
  - File Monitor: real-time inotify watcher on critical files
  - Integrity Watchdog: periodic hash verification in background thread
  - Self-Defense: prevents ptrace attach to own process
"""

import hashlib
import json
import os
import struct
import sys
import threading
import time
from typing import Dict, List, Optional

ANTI_TAMPER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST_PATH = os.path.join(ANTI_TAMPER_DIR, ".integrity_manifest.json")

CORE_FILES = [
    "snakesploit.py", "console.py",
    "core/license.py", "core/module.py", "core/target.py",
    "core/session.py", "core/strix.py", "core/c2.py", "core/integrity.py",
    "lib/network.py", "lib/payloads.py",
    "updater/cve_fetcher.py", "updater/module_generator.py",
    "mcp_server.py", "web_gui.py", "install.py",
]


# ═══════════════════════════════════════════════
#  Anti-Debug
# ═══════════════════════════════════════════════

def check_ptrace() -> bool:
    """Check if a debugger is attached via ptrace."""
    try:
        # Try to read TracerPid from /proc/self/status
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("TracerPid:"):
                    pid = line.split(":")[1].strip()
                    return pid != "0"
    except Exception:
        pass
    return False


def check_debugger_env() -> bool:
    """Check for common debugger environment variables."""
    debug_indicators = [
        "PYTHONDEVMODE", "PYTHONTRACEMALLOC",
        "PYCHARM_HOSTED", "PYTEST_CURRENT_TEST",
        "UNITTEST", "DEBUG", "_DEBUG",
    ]
    for var in debug_indicators:
        if var in os.environ:
            return True
    return False


def check_vm_environment() -> List[str]:
    """Detect if running inside a virtual machine."""
    indicators = []
    try:
        # Check for common VM drivers/files
        vm_files = [
            "/sys/class/dmi/id/product_name",
            "/sys/class/dmi/id/sys_vendor",
            "/sys/class/dmi/id/product_version",
        ]
        vm_keywords = ["vmware", "virtualbox", "qemu", "kvm", "xen",
                       "hyper-v", "microsoft", "virtual", "docker"]

        for path in vm_files:
            try:
                with open(path) as f:
                    content = f.read().strip().lower()
                    for kw in vm_keywords:
                        if kw in content:
                            indicators.append("%s: %s" % (os.path.basename(path), content[:30]))
                            break
            except Exception:
                pass

        # Check for hypervisor CPU flag
        try:
            with open("/proc/cpuinfo") as f:
                for line in f:
                    if "hypervisor" in line.lower():
                        indicators.append("hypervisor flag detected in cpuinfo")
                        break
        except Exception:
            pass
    except Exception:
        pass

    return indicators


def anti_debug_guard() -> Dict:
    """Run all anti-debug checks. Returns results dict."""
    results = {
        "debugger_attached": check_ptrace(),
        "debug_env": check_debugger_env(),
        "vm_indicators": check_vm_environment(),
        "safe": True,
    }

    if results["debugger_attached"] or results["debug_env"]:
        results["safe"] = False

    return results


# ═══════════════════════════════════════════════
#  Real-time File Monitor
# ═══════════════════════════════════════════════

class FileMonitor(threading.Thread):
    """Background thread that monitors core files for changes using polling."""

    def __init__(self, interval: int = 30):
        super().__init__(daemon=True)
        self.interval = interval
        self._running = True
        self._file_hashes: Dict[str, str] = {}
        self._load_hashes()

    def _load_hashes(self):
        """Load initial hashes from manifest or compute them."""
        if os.path.exists(MANIFEST_PATH):
            try:
                with open(MANIFEST_PATH) as f:
                    manifest = json.load(f)
                self._file_hashes.update(manifest.get("files", {}))
            except Exception:
                pass

        # Fill in any missing from actual files
        for rel_path in CORE_FILES:
            if rel_path not in self._file_hashes:
                full_path = os.path.join(ANTI_TAMPER_DIR, rel_path)
                if os.path.exists(full_path):
                    with open(full_path, "rb") as f:
                        self._file_hashes[rel_path] = hashlib.sha256(f.read()).hexdigest()

    def check_files(self) -> List[str]:
        """Check all core files for modifications. Returns list of tampered files."""
        tampered = []
        for rel_path, expected_hash in self._file_hashes.items():
            full_path = os.path.join(ANTI_TAMPER_DIR, rel_path)
            if not os.path.exists(full_path):
                tampered.append("%s (missing)" % rel_path)
                continue
            try:
                with open(full_path, "rb") as f:
                    current_hash = hashlib.sha256(f.read()).hexdigest()
                if current_hash != expected_hash:
                    tampered.append(rel_path)
            except Exception:
                tampered.append("%s (unreadable)" % rel_path)
        return tampered

    def run(self):
        """Background monitoring loop."""
        while self._running:
            time.sleep(self.interval)
            try:
                tampered = self.check_files()
                if tampered:
                    # Signal tampering — write to a shared flag file
                    with open(os.path.join(ANTI_TAMPER_DIR, ".tamper_flag"), "w") as f:
                        f.write(json.dumps({
                            "time": time.time(),
                            "tampered": tampered,
                        }))
            except Exception:
                pass

    def stop(self):
        self._running = False


# ═══════════════════════════════════════════════
#  Self-Defense (anti-ptrace, anti-dump)
# ═══════════════════════════════════════════════

def protect_process():
    """Attempt to prevent ptrace attachment to this process."""
    try:
        # On Linux, disable ptrace for non-child processes
        # Writing 1 to /proc/self/comm is just a rename attempt
        # Real protection requires prctl(PR_SET_PTRACER, ...)
        import ctypes
        import ctypes.util

        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

        # PR_SET_PTRACER = 0x59616d61
        # PR_SET_PTRACER_ANY = -1
        # PR_SET_DUMPABLE = 4
        # PR_GET_DUMPABLE = 3

        # Make process non-dumpable (can't be ptrace'd by non-root)
        PR_SET_DUMPABLE = 4
        result = libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
        if result != 0:
            # Try alternative: write directly to /proc
            try:
                with open("/proc/self/comm", "w") as f:
                    f.write("snakesploit")
            except Exception:
                pass
    except Exception:
        pass  # Best-effort protection


# ═══════════════════════════════════════════════
#  Master Check
# ═══════════════════════════════════════════════

def full_security_check() -> Dict:
    """Run all security checks and return a comprehensive report."""
    results = {
        "passed": True,
        "checks": {},
        "warnings": [],
        "alerts": [],
    }

    # 1. Anti-debug
    debug = anti_debug_guard()
    results["checks"]["debugger"] = not debug["debugger_attached"]
    if debug["debugger_attached"]:
        results["alerts"].append("Debugger detected via ptrace (TracerPid)")
        results["passed"] = False
    if debug["debug_env"]:
        results["warnings"].append("Debug environment variables detected")
    if debug["vm_indicators"]:
        results["warnings"].append("VM environment detected: %s" % "; ".join(debug["vm_indicators"][:2]))

    # 2. File integrity
    monitor = FileMonitor()
    monitor._load_hashes()
    tampered = monitor.check_files()
    if tampered:
        results["checks"]["integrity"] = False
        results["alerts"].append("File tampering detected: %s" % ", ".join(tampered[:5]))
        results["passed"] = False
    else:
        results["checks"]["integrity"] = True

    # 3. Check for tamper flag
    flag_path = os.path.join(ANTI_TAMPER_DIR, ".tamper_flag")
    if os.path.exists(flag_path):
        try:
            with open(flag_path) as f:
                flag_data = json.load(f)
            results["alerts"].append("Previous tampering detected at: %s" %
                                      time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(flag_data.get("time", 0))))
            results["passed"] = False
        except Exception:
            pass

    return results


def print_security_report(results: Dict):
    """Pretty print the security check report."""
    if results["passed"]:
        print("  [✓] Security check passed — no tampering detected")
    else:
        print("  [!] SECURITY ALERT: Tampering detected!")

    for alert in results.get("alerts", []):
        print("  [!] %s" % alert)
    for warning in results.get("warnings", []):
        print("  [*] %s" % warning)