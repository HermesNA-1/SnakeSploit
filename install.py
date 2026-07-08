#!/usr/bin/env python3
"""
SnakeSploit Installer — sets up framework, symlink, cron, and initial CVE fetch.
Auto-detects its own directory so it works from any clone path.
"""

import os
import subprocess
import sys
from pathlib import Path

# Auto-detect the SnakeSploit directory (works even if cloned to ~/SnakeSploit, ~/snakesploit, etc.)
NOVA_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.expanduser("~/.snakesploit")


def run(cmd: str) -> bool:
    print(f"  [+] Running: {cmd}")
    result = subprocess.run(cmd, shell=True)
    return result.returncode == 0


def install():
    print("""
╔══════════════════════════════════════╗
║     SnakeSploit Framework Install   ║
║  Python-Powered Exploit Framework   ║
╚══════════════════════════════════════╝
    """)

    # Step 1: Create directories
    print("[*] Creating SnakeSploit directories...")
    dirs = [
        os.path.join(DATA_DIR, "cve_cache"),
        os.path.join(DATA_DIR, "poc_cache"),
        os.path.join(DATA_DIR, "loot"),
        os.path.join(DATA_DIR, "logs"),
    ]
    for d in dirs:
        os.makedirs(d, exist_ok=True)

    # Step 2: Make entry point executable
    print("[*] Making executable...")
    entry_path = os.path.join(NOVA_DIR, "snakesploit.py")
    if not os.path.exists(entry_path):
        print(f"  [!] snakesploit.py not found at {entry_path}")
        print(f"  [!] Current directory: {NOVA_DIR}")
        print(f"  [!] Files: {os.listdir(NOVA_DIR)}")
        return
    os.chmod(entry_path, 0o755)

    # Step 3: Create symlink
    print("[*] Creating symlink: ~/.local/bin/snakesploit...")
    os.makedirs(os.path.expanduser("~/.local/bin"), exist_ok=True)
    link_path = os.path.expanduser("~/.local/bin/snakesploit")
    if os.path.exists(link_path):
        os.remove(link_path)
    os.symlink(entry_path, link_path)

    # Step 4: Check Python dependencies
    print("[*] Checking Python dependencies...")
    deps = ["requests", "urllib3"]
    for dep in deps:
        result = subprocess.run(
            [sys.executable, "-c", f"import {dep.replace('-', '_')}"],
            capture_output=True
        )
        if result.returncode != 0:
            print(f"  [*] Installing {dep}...")
            subprocess.run([sys.executable, "-m", "pip", "install", dep, "--user"])

    # Step 5: Check msfvenom availability
    print("[*] Checking external tools...")
    for tool in ["nmap", "curl", "git"]:
        result = subprocess.run(["which", tool], capture_output=True)
        if result.returncode == 0:
            print(f"  [+] {tool} found")
        else:
            print(f"  [!] {tool} not found (optional)")

    # Step 6: Install cron job for auto-updates
    print("[*] Setting up auto-update cron job...")

    # Write the cron script regardless
    cron_script = f"""#!/bin/bash
# SnakeSploit Auto-Update — runs every 6 hours
cd {NOVA_DIR}
python3 snakesploit.py --update --non-interactive >> {DATA_DIR}/logs/update.log 2>&1
"""
    cron_path = os.path.join(DATA_DIR, "snakesploit_update.sh")
    os.makedirs(os.path.dirname(cron_path), exist_ok=True)
    with open(cron_path, "w") as f:
        f.write(cron_script)
    os.chmod(cron_path, 0o755)

    # Try to install in crontab (non-fatal if crontab isn't available)
    try:
        result = subprocess.run(
            ["crontab", "-l"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        current_crontab = result.stdout if result.returncode == 0 else ""
    except FileNotFoundError:
        print(f"  [!] 'crontab' not found. Manual cron setup needed.")
        print(f"  [!] To set up auto-update manually, add this to your crontab:")
        print(f"      echo '0 */6 * * * {cron_path} # SnakeSploit auto-update' | crontab -")
        current_crontab = ""  # Skip cron install

    nova_cron = f"0 */6 * * * {cron_path} # SnakeSploit auto-update"
    if current_crontab != "":
        if nova_cron not in current_crontab:
            new_crontab = current_crontab + nova_cron + "\n"
            proc = subprocess.run(
                ["crontab", "-"],
                input=new_crontab,
                text=True,
                timeout=5,
            )
            if proc.returncode == 0:
                print("  [+] Cron job installed (every 6 hours)")
            else:
                print(f"  [!] Could not install cron job. Add manually:")
                print(f"      echo '{nova_cron}' | crontab -")
        else:
            print("  [+] Cron job already exists")

    # Step 7: Initial CVE fetch
    print("\n[*] Running initial CVE fetch...")
    subprocess.run(
        [sys.executable, entry_path, "--update", "--non-interactive"],
        cwd=NOVA_DIR,
    )

    # Step 8: Summary
    print(f"""
╔══════════════════════════════════════╗
║  SnakeSploit Installed!              ║
╠══════════════════════════════════════╣
║  Run:  snakesploit  (console)        ║
║  Run:  snakesploit --update (CVEs)   ║
║  Run:  snakesploit --full (pipeline) ║
║                                      ║
║  Modules: {NOVA_DIR}/modules/        ║
║  CVEs:    {DATA_DIR}/cve_cache/  ║
║  Loot:    {DATA_DIR}/loot/       ║
║  Auto-update: every 6h via cron      ║
╚══════════════════════════════════════╝
    """)


if __name__ == "__main__":
    install()