"""
SnakeSploit Integrity Verifier — detects code tampering.
Generates a signed manifest of file hashes and verifies them on launch.

Usage:
  python3 -c "from core.integrity import generate_manifest; generate_manifest()"
  snakesploit --verify
"""

import hashlib
import json
import os
import sys
from typing import Dict, List, Optional

INTEGRITY_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST_PATH = os.path.join(INTEGRITY_DIR, ".integrity_manifest.json")
# Core files that must not be tampered with — these control licensing, auth, and core logic
CORE_FILES = [
    "snakesploit.py",
    "console.py",
    "core/license.py",
    "core/module.py",
    "core/target.py",
    "core/session.py",
    "core/strix.py",
    "core/c2.py",
    "lib/network.py",
    "lib/payloads.py",
    "updater/cve_fetcher.py",
    "updater/module_generator.py",
    "mcp_server.py",
    "web_gui.py",
    "install.py",
]


def hash_file(filepath: str) -> Optional[str]:
    """Compute SHA-256 hash of a file."""
    try:
        with open(filepath, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except FileNotFoundError:
        return None
    except IOError:
        return None


def compute_hashes() -> Dict[str, str]:
    """Compute hashes for all core files."""
    hashes = {}
    for rel_path in CORE_FILES:
        full_path = os.path.join(INTEGRITY_DIR, rel_path)
        file_hash = hash_file(full_path)
        if file_hash:
            hashes[rel_path] = file_hash
    return hashes


def generate_manifest(secret: str = "") -> Dict[str, str]:
    """Generate a new integrity manifest with file hashes."""
    hashes = compute_hashes()

    manifest = {
        "version": "1.0",
        "files": hashes,
    }

    # Create a simple HMAC-like signature over the manifest data
    if secret:
        data = json.dumps(hashes, sort_keys=True) + secret
        manifest["signature"] = hashlib.sha256(data.encode()).hexdigest()

    with open(MANIFEST_PATH, "w") as f:
        json.dump(manifest, f, indent=2)

    print("  [+] Integrity manifest generated: %s" % MANIFEST_PATH)
    print("  [+] %d files registered" % len(hashes))
    return manifest


def verify_integrity(secret: str = "") -> Dict:
    """
    Verify all core files against the integrity manifest.
    Returns a dict with status, tampered files, missing files, and new files.
    """
    result = {
        "valid": True,
        "tampered": [],
        "missing": [],
        "new_files": [],
        "total_checked": 0,
        "message": "Integrity check passed",
    }

    if not os.path.exists(MANIFEST_PATH):
        result["valid"] = False
        result["message"] = "No integrity manifest found. Run the generator first."
        return result

    try:
        with open(MANIFEST_PATH) as f:
            manifest = json.load(f)
    except (json.JSONDecodeError, IOError):
        result["valid"] = False
        result["message"] = "Integrity manifest is corrupt."
        return result

    # Check manifest signature
    if "signature" in manifest and secret:
        expected_sig = hashlib.sha256(
            (json.dumps(manifest["files"], sort_keys=True) + secret).encode()
        ).hexdigest()
        if manifest["signature"] != expected_sig:
            result["valid"] = False
            result["message"] = "Integrity manifest signature is invalid — manifest has been tampered with."
            return result

    stored_hashes = manifest.get("files", {})
    current_hashes = compute_hashes()

    # Check for tampered files (hash mismatch)
    for rel_path, expected_hash in stored_hashes.items():
        current_hash = current_hashes.get(rel_path)
        if current_hash is None:
            result["missing"].append(rel_path)
            result["valid"] = False
        elif current_hash != expected_hash:
            result["tampered"].append(rel_path)
            result["valid"] = False

    # Check for new files not in manifest
    for rel_path in current_hashes:
        if rel_path not in stored_hashes:
            result["new_files"].append(rel_path)
            result["valid"] = False

    result["total_checked"] = len(stored_hashes)

    if result["tampered"]:
        result["message"] = "Tampering detected: %d files modified" % len(result["tampered"])
    elif result["missing"]:
        result["message"] = "Integrity error: %d files missing" % len(result["missing"])
    elif result["new_files"]:
        result["message"] = "Integrity error: %d unexpected files found" % len(result["new_files"])
    else:
        result["message"] = "Integrity check passed — all %d files are authentic." % len(stored_hashes)

    return result


def print_verification_result(result: Dict):
    """Pretty-print the verification result."""
    if result["valid"]:
        print("  [✓] " + result["message"])
        return

    print("  [!] " + result["message"])
    if result["tampered"]:
        print("  [!] Tampered files:")
        for f in result["tampered"]:
            print("      - %s" % f)
    if result["missing"]:
        print("  [!] Missing files:")
        for f in result["missing"]:
            print("      - %s" % f)
    if result["new_files"]:
        print("  [!] Unknown files:")
        for f in result["new_files"]:
            print("      - %s" % f)


if __name__ == "__main__":
    if "--generate" in sys.argv:
        generate_manifest()
    elif "--verify" in sys.argv:
        result = verify_integrity()
        print_verification_result(result)
        sys.exit(0 if result["valid"] else 1)
    else:
        print("Usage: python3 -m core.integrity --generate | --verify")