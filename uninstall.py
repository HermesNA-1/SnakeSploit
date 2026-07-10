#!/usr/bin/env python3
"""
SnakeSploit Uninstaller — cleanly removes all traces.
"""

import os
import shutil
import subprocess
import sys


def main():
    print("""
╔══════════════════════════════════════╗
║     SnakeSploit Uninstaller          ║
╚══════════════════════════════════════╝
""")

    confirm = input("This will remove SnakeSploit entirely. Continue? [y/N]: ").strip().lower()
    if confirm != "y":
        print("  [!] Aborted.")
        return

    # Remove symlink
    symlink = os.path.expanduser("~/.local/bin/snakesploit")
    if os.path.exists(symlink):
        os.remove(symlink)
        print("  [+] Removed symlink: ~/.local/bin/snakesploit")

    # Remove data directory
    data_dir = os.path.expanduser("~/.snakesploit")
    if os.path.exists(data_dir):
        shutil.rmtree(data_dir)
        print("  [+] Removed data directory: ~/.snakesploit")

    # Remove cron job
    try:
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            crontab = result.stdout
            new_crontab = "\n".join([
                line for line in crontab.split("\n")
                if "snakesploit" not in line and "SnakeSploit" not in line
            ])
            proc = subprocess.run(["crontab", "-"], input=new_crontab, text=True, timeout=5)
            if proc.returncode == 0:
                print("  [+] Removed cron job")
    except FileNotFoundError:
        pass
    except Exception:
        pass

    # Ask about source directory
    source_dir = os.path.dirname(os.path.abspath(__file__))
    remove_source = input("Remove source directory %s? [y/N]: " % source_dir).strip().lower()
    if remove_source == "y":
        shutil.rmtree(source_dir)
        print("  [+] Removed source directory: %s" % source_dir)

    print("""
╔══════════════════════════════════════╗
║     SnakeSploit Uninstalled          ║
╚══════════════════════════════════════╝
""")


if __name__ == "__main__":
    main()