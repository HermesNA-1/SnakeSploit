"""
SnakeSploit Interactive Console — the primary user interface.

Welcome to Nova. Type 'help' for commands, 'update' to fetch CVEs,
'search' to find modules, 'use' to load a module, 'sessions' to
interact with active shells.
"""

import cmd
import os
import shlex
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Any

# SnakeSploit imports
sys.path.insert(0, os.path.expanduser("~/snakesploit"))
from core.module import ModuleManager, NovaModule
from core.target import TargetManager
from core.session import SessionManager
from updater.cve_fetcher import CVEUpdater, PoCScraper
from updater.module_generator import ModuleGenerator, AutoUpdater
from lib.network import PortScanner, HTTPClient
from lib.payloads import PayloadGenerator


# ─────────────────────────────────────────────
# ANSI colors
# ─────────────────────────────────────────────
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


BANNER = f"""{Colors.GREEN}
   _____  _        _        _____           _ _ _       _
  / ____|| |      ( )      / ____|         | (_) |     | |
 | (___  | | _____ _/ ___ | |     ___  _ __| |_| |_ ___| | ___
  \\___ \\ | |/ / _ \\ / __|| |    / _ \\| '__| | | __/ _ \\ |/ _ \\
  ____) ||   <  __/ \\__ \\| |___| (_) | |  | | | ||  __/ |  __/
 |_____/ |_|\\_\\___| |___/ \\_____\\___/|_|  |_|_|\\__\\___|_|\\___|
{Colors.CYAN}  -- Python-Powered Exploit Framework --{Colors.RESET}
"""

prompt = f"{Colors.GREEN}snakesploit{Colors.RESET} > "


class SnakeSploitConsole(cmd.Cmd):
    """Interactive SnakeSploit console."""

    intro = f"{BANNER}\n{Colors.GREEN}Type 'help' for commands | 'update' to pull CVEs | 'exit' to quit{Colors.RESET}\n"
    prompt = f"{Colors.GREEN}snakesploit{Colors.RESET} > "

    def __init__(self, license_mgr=None):
        super().__init__()
        self.module_manager = ModuleManager()
        self.target_manager = TargetManager()
        self.session_manager = SessionManager()
        self.cve_updater = CVEUpdater()
        self.poc_scraper = PoCScraper()
        self.module_generator = ModuleGenerator()
        self.auto_updater = AutoUpdater()
        self._active_module: Optional[NovaModule] = None
        self._active_module_name: str = ""
        self._listener_threads: Dict[str, threading.Thread] = {}
        self._running = True
        self._license_mgr = license_mgr

        # Start background license validation (checks every 3 min)
        if self._license_mgr and self._license_mgr.is_licensed():
            if not getattr(self, '_license_thread_started', False):
                self._license_thread_started = True
            t = threading.Thread(target=self._license_check_loop, daemon=True)
            t.start()

        # Load state
        self.target_manager.load()
        self.session_manager.load()
        self.module_manager.discover()
        for cat, paths in self.module_manager.categories.items():
            for path in paths:
                self.module_manager.load_module(path)

        print(f"  [+] Loaded {len(self.module_manager.modules)} modules")
        print(f"  [+] {self.target_manager.summary()['total_targets']} targets in database")
        print(f"  [+] {self.cve_updater.get_statistics()['total_cves']} CVEs cached")

    # ──────────────────────────────────────────
    # Prompt updates
    # ──────────────────────────────────────────

    def postcmd(self, stop, line):
        if self._active_module:
            self.prompt = f"{Colors.GREEN}snakesploit{Colors.RESET}({Colors.YELLOW}{self._active_module_name}{Colors.RESET}) > "
        else:
            self.prompt = f"{Colors.GREEN}snakesploit{Colors.RESET} > "
        return stop

    def _license_check_loop(self):
        """Background thread: re-validates license every 3 minutes."""
        import time as ttime
        ttime.sleep(10)  # Initial delay to let console start
        while self._running:
            try:
                if self._license_mgr and self._license_mgr.is_licensed():
                    result = self._license_mgr.validate()
                    if result.get("revoked"):
                        print(f"\n{Colors.RED}[!] LICENSE REVOKED! Access denied.{Colors.RESET}")
                        print(f"{Colors.RED}    Your license has been revoked by the administrator.{Colors.RESET}")
                        self._running = False
                        ttime.sleep(1)
                        # Exit the process
                        import os
                        os._exit(1)
            except Exception:
                pass
            ttime.sleep(180)  # Check every 3 minutes

    # ──────────────────────────────────────────
    # Core commands
    # ──────────────────────────────────────────

    def do_help(self, arg):
        """Show help. 'help <command>' for details."""
        if arg:
            super().do_help(arg)
        else:
            print(f"""
{Colors.BOLD}╔══════════════════════════════════════════════╗
║           SNAKESPLOIT COMMAND REFERENCE            ║
╚══════════════════════════════════════════════╝{Colors.RESET}

{Colors.CYAN}─── Core Commands ───{Colors.RESET}
  help                  Show this help
  exit / quit           Exit SnakeSploit

{Colors.CYAN}─── Update System (CVE + PoC) ───{Colors.RESET}
  update [days]        Fetch CVEs from NVD (last N days, default 7)
  update full [days]   Full pipeline: CVEs → PoCs → Module Gen
  update-self          Update SnakeSploit itself from GitHub
  pocs <cve>           Search PoCs for a specific CVE
  cve stats            Show CVE cache statistics

{Colors.CYAN}─── Module System ───{Colors.RESET}
  search <query>       Search modules by name, CVE, or description
  use <module_name>    Load a module for use
  show [options|info]  Show module options or info
  set <opt> <val>      Set a module option
  check                Run the check method (vulnerability probe)
  run / exploit        Execute the module
  back                 Unload current module
  reload modules       Reload all modules from disk
  list [category]      List available modules

{Colors.CYAN}─── Target Management ───{Colors.RESET}
  targets              List all targets
  targets add <host>   Add a target
  targets rm <host>    Remove a target
  targets show <host>  Show target details

{Colors.CYAN}─── Scanning ───{Colors.RESET}
  scan <host> [ports]  TCP port scan
  http <url>           HTTP GET request

{Colors.CYAN}─── Payloads ───{Colors.RESET}
  payloads [name]      Show available payloads / generate one
  listener <port>      Start a listener on a port

{Colors.CYAN}─── Sessions ───{Colors.RESET}
  sessions             List all sessions
  sessions -i <id>     Interact with a session
  sessions -k <id>     Kill a session

{Colors.CYAN}─── Strix AI Scanner ───{Colors.RESET}
  strix <target>       Run Strix AI security scan against a target
  strix status         Check Strix installation status
  strix config --key K Configure your Strix API key

{Colors.CYAN}─── System ───{Colors.RESET}
  shell <command>      Run a shell command
  deactivate / logout  Deactivate this device and free your license seat
  clear                Clear the screen
  banner               Show the banner
""")

    def do_exit(self, arg):
        """Exit Nova."""
        print(f"\n{Colors.GREEN}See you next time, Nirbhik. Stay sharp.{Colors.RESET}")
        self.target_manager.save()
        self.session_manager.save()
        self._running = False
        return True

    def do_quit(self, arg):
        return self.do_exit(arg)

    def do_clear(self, arg):
        """Clear the screen."""
        os.system("clear")

    def do_banner(self, arg):
        """Show the SnakeSploit banner."""
        print(BANNER)

    def do_shell(self, arg):
        """Run a shell command. Usage: shell <command>"""
        if not arg:
            print("Usage: shell <command>")
            return
        os.system(arg)

    def do_deactivate(self, arg):
        """Deactivate this device and free your license seat. Usage: deactivate"""
        if not self._license_mgr:
            print(f"{Colors.YELLOW}[!] No license manager available.{Colors.RESET}")
            return
        result = self._license_mgr.deactivate()
        if result.get("success", True):
            print(f"{Colors.GREEN}[+] Device deactivated. License seat freed.{Colors.RESET}")
            print(f"{Colors.GREEN}[+] Exiting SnakeSploit.{Colors.RESET}")
            self._running = False
            self.target_manager.save()
            self.session_manager.save()
            return True
        else:
            print(f"{Colors.YELLOW}[!] {result.get('message', 'Deactivation failed')}{Colors.RESET}")

    def do_logout(self, arg):
        """Alias for deactivate — frees your license seat. Usage: logout"""
        return self.do_deactivate(arg)

    # ──────────────────────────────────────────
    # Strix commands
    # ──────────────────────────────────────────

    def do_strix(self, arg):
        """Strix AI security scanner. Usage:
  strix <target>         Scan a target (URL or IP)
  strix config --key K   Set your Strix API key
  strix config --remove  Remove Strix API key
  strix status           Check Strix installation and config"""
        from core.strix import StrixEngine
        strix = StrixEngine()

        args = arg.strip().split()
        if not args:
            print(f"\n{Colors.BOLD}Strix AI Security Scanner{Colors.RESET}")
            print(f"  Usage:")
            print(f"    {Colors.CYAN}strix <target>{Colors.RESET}         Run a scan against a target")
            print(f"    {Colors.CYAN}strix config --key K{Colors.RESET}   Set your Strix API key")
            print(f"    {Colors.CYAN}strix status{Colors.RESET}          Check installation status")
            print()
            return

        if args[0] == "config" and len(args) >= 3 and args[1] == "--key":
            api_key = args[2]
            result = strix.set_api_key(api_key)
            if result["success"]:
                print(f"{Colors.GREEN}[+] {result['message']}{Colors.RESET}")
            else:
                print(f"{Colors.RED}[-] {result['message']}{Colors.RESET}")
            return

        if args[0] == "config" and "--remove" in args:
            result = strix.remove_api_key()
            print(f"{Colors.YELLOW}[!] {result['message']}{Colors.RESET}")
            return

        if args[0] == "status":
            status = strix.get_status()
            print(f"\n{Colors.BOLD}Strix Status{Colors.RESET}")
            print(f"  Installed:     {Colors.GREEN}Yes{Colors.RESET} at {status['runner_path']}" if status["installed"] else f"  Installed:     {Colors.RED}No{Colors.RESET}")
            print(f"  API Key:       {Colors.GREEN}Configured{Colors.RESET}" if status["has_api_key"] else f"  API Key:       {Colors.RED}Not set{Colors.RESET}")
            print(f"  Last Updated:  {status.get('last_updated', 'never')}")
            if not status["installed"]:
                print(f"\n  {Colors.YELLOW}[!] Strix is not installed on this system.{Colors.RESET}")
                print(f"      Install it at ~/.strix/ run-strix.sh")
            return

        # Default: scan a target
        target = arg.strip()
        if not target.startswith("http://") and not target.startswith("https://"):
            # Could be an IP or hostname — probe with http/https
            target = f"https://{target}"

        print(f"\n{Colors.CYAN}[*] Strix scan initiated for: {target}{Colors.RESET}\n")
        result = strix.scan(target)

        print()
        if result["success"]:
            print(f"{Colors.GREEN}[+] Scan completed in {result.get('elapsed_seconds', 0)}s{Colors.RESET}")
            print(f"{Colors.GREEN}[+] Full output saved to: {result.get('log_path', 'N/A')}{Colors.RESET}")
            print(f"\n{Colors.BOLD}Results:{Colors.RESET}")
            print(result.get("output", "No output")[:2000])
        else:
            print(f"{Colors.RED}[-] Scan failed: {result.get('error', 'Unknown error')}{Colors.RESET}")

        # Add target to database
        host = target.split("://")[-1].split("/")[0]
        t = self.target_manager.add(host)
        t.notes["strix_scanned"] = True
        t.notes["strix_last_scan"] = result.get("timestamp", "")
        self.target_manager.save()

    # ──────────────────────────────────────────
    # Update system commands
    # ──────────────────────────────────────────

    def do_update_self(self, arg):
        """Update SnakeSploit itself from GitHub. Usage: update-self"""
        import subprocess
        repo_dir = os.path.dirname(os.path.abspath(__file__))
        print(f"{Colors.CYAN}[*] Updating SnakeSploit from GitHub...{Colors.RESET}")
        try:
            result = subprocess.run(
                ["git", "pull"],
                cwd=repo_dir,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                output = result.stdout.strip()
                if "Already up to date" in output:
                    print(f"{Colors.GREEN}[+] Already up to date!{Colors.RESET}")
                else:
                    print(f"{Colors.GREEN}[+] Updated successfully!{Colors.RESET}")
                    for line in output.split("\n")[:5]:
                        if line.strip():
                            print(f"     {line}")
                    print(f"{Colors.YELLOW}[!] Restart SnakeSploit to use the latest version.{Colors.RESET}")
            else:
                print(f"{Colors.RED}[-] Update failed: {result.stderr[:200]}{Colors.RESET}")
        except FileNotFoundError:
            print(f"{Colors.RED}[-] Git not found. Install git to use self-update.{Colors.RESET}")
        except subprocess.TimeoutExpired:
            print(f"{Colors.RED}[-] Update timed out.{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[-] Update failed: {e}{Colors.RESET}")

    def do_update(self, arg):
        """Fetch CVEs from NVD. Usage: update [days] or update full [days]"""
        args = arg.split()
        days = 7
        full = False

        if args and args[0] == "full":
            full = True
            if len(args) > 1:
                try:
                    days = int(args[1])
                except ValueError:
                    pass
        else:
            if args:
                try:
                    days = int(args[0])
                except ValueError:
                    pass

        if full:
            print(f"{Colors.CYAN}[*] Running full update pipeline (last {days} days)...{Colors.RESET}")
            results = self.auto_updater.run_full_update(days_back=days)
            print(f"\n{Colors.GREEN}[+] Complete: {results['new_cves']} CVEs, "
                  f"{results['new_pocs']} PoCs, {results['new_modules']} modules{Colors.RESET}")
        else:
            print(f"{Colors.CYAN}[*] Fetching CVEs from last {days} days...{Colors.RESET}")
            count = self.cve_updater.fetch_recent(days_back=days)
            stats = self.cve_updater.get_statistics()
            print(f"\n{Colors.GREEN}[+] Fetched {count} new CVEs{Colors.RESET}")
            print(f"    Total cached: {stats['total_cves']}")
            print(f"    Critical: {stats['critical']} | High: {stats['high']} | "
                  f"Medium: {stats['medium']} | Low: {stats['low']}")
            print(f"    With PoCs: {stats['with_pocs']}")

    def do_cve(self, arg):
        """CVE commands: 'cve stats' for statistics."""
        args = arg.split()
        if not args or args[0] == "stats":
            stats = self.cve_updater.get_statistics()
            print(f"\n{Colors.BOLD}CVE Cache Statistics:{Colors.RESET}")
            print(f"  Total CVEs:    {stats['total_cves']}")
            print(f"  Critical:      {stats['critical']}")
            print(f"  High:          {stats['high']}")
            print(f"  Medium:        {stats['medium']}")
            print(f"  Low:           {stats['low']}")
            print(f"  With PoCs:     {stats['with_pocs']}")
            print(f"  Without PoCs:  {stats['without_pocs']}")
            print(f"  Last fetch:    {stats['last_fetch'] or 'Never'}")
        elif args[0] == "search" and len(args) > 1:
            query = " ".join(args[1:])
            print(f"{Colors.CYAN}[*] Searching CVEs for '{query}'...{Colors.RESET}")
            count = self.cve_updater.fetch_by_keywords([query])
            print(f"{Colors.GREEN}[+] Found {count} new CVEs{Colors.RESET}")

    def do_pocs(self, arg):
        """Search for PoCs for a CVE. Usage: pocs CVE-XXXX-XXXXX"""
        if not arg:
            print("Usage: pocs CVE-XXXX-XXXXX")
            return
        cve_id = arg.strip().upper()
        print(f"{Colors.CYAN}[*] Searching PoCs for {cve_id}...{Colors.RESET}")
        results = self.poc_scraper.search_all(cve_id)
        if not results:
            print(f"{Colors.YELLOW}[!] No PoCs found for {cve_id}{Colors.RESET}")
            return
        print(f"\n{Colors.GREEN}[+] Found {len(results)} PoCs:{Colors.RESET}")
        for i, poc in enumerate(results, 1):
            source = poc.get("source", "unknown")
            title = poc.get("title", "No title")
            url = poc.get("url", "")
            stars = poc.get("stars", 0)
            print(f"\n  {Colors.BOLD}{i}. [{source.upper()}]{Colors.RESET} {title}")
            print(f"     URL:   {Colors.DIM}{url}{Colors.RESET}")
            if stars:
                print(f"     Stars: {stars}")

    # ──────────────────────────────────────────
    # Module system commands
    # ──────────────────────────────────────────

    def do_list(self, arg):
        """List modules. Usage: list [category]"""
        if arg:
            category = arg.strip()
            if category in self.module_manager.categories:
                print(f"\n{Colors.BOLD}Modules in '{category}':{Colors.RESET}")
                for path in self.module_manager.categories[category]:
                    name = os.path.splitext(os.path.basename(path))[0]
                    print(f"  {name}")
                return
            # Search in loaded modules
            matches = [(n, m) for n, m in self.module_manager.modules.items()
                       if category.lower() in n.lower()]
            if matches:
                print(f"\n{Colors.BOLD}Matching modules:{Colors.RESET}")
                for name, mod in sorted(matches):
                    cves = ", ".join(mod.metadata.cve_ids) if mod.metadata.cve_ids else ""
                    cve_str = f" [{Colors.RED}{cves}{Colors.RESET}]" if cves else ""
                    print(f"  {Colors.CYAN}{name}{Colors.RESET}{cve_str}")
                    print(f"    {mod.metadata.description[:80]}")
            else:
                print(f"{Colors.YELLOW}[!] No modules found matching '{category}'{Colors.RESET}")
            return

        # Full listing
        print(f"\n{Colors.BOLD}Available Modules ({len(self.module_manager.modules)}):{Colors.RESET}")
        for cat, paths in sorted(self.module_manager.categories.items()):
            print(f"\n  {Colors.CYAN}{cat}:{Colors.RESET}")
            for path in paths:
                name = os.path.splitext(os.path.basename(path))[0]
                print(f"    └─ {name}")

    def do_search(self, arg):
        """Search modules by name or CVE. Usage: search <query>"""
        if not arg:
            print("Usage: search <query>")
            return
        results = self.module_manager.search(arg)
        if not results:
            print(f"{Colors.YELLOW}[!] No modules found for '{arg}'{Colors.RESET}")
            return
        print(f"\n{Colors.GREEN}[+] {len(results)} modules found:{Colors.RESET}")
        for name, meta in sorted(results):
            cves = ", ".join(meta.cve_ids) if meta.cve_ids else ""
            cve_str = f" [{Colors.RED}{cves}{Colors.RESET}]" if cves else ""
            print(f"\n  {Colors.CYAN}{name}{Colors.RESET}{cve_str}")
            print(f"    {meta.description[:100]}")

    def do_use(self, arg):
        """Load a module. Usage: use <module_name_or_path>"""
        if not arg:
            print("Usage: use <module_name>")
            return

        name = arg.strip()

        # Try loading by full name
        if name in self.module_manager.modules:
            mod = self.module_manager.modules[name]
            # Create fresh instance to avoid state bleed
            try:
                fresh = type(mod)()
                self._active_module = fresh
                self._active_module_name = name
                print(f"{Colors.GREEN}[+] Using module: {name}{Colors.RESET}")
                print(f"    {fresh.metadata.description}")
                if fresh.metadata.cve_ids:
                    print(f"    CVEs: {', '.join(fresh.metadata.cve_ids)}")
                return
            except Exception as e:
                print(f"{Colors.YELLOW}[!] Could not create fresh instance: {e}")
                print(f"{Colors.GREEN}[+] Using cached instance instead{Colors.RESET}")
                self._active_module = mod
                self._active_module_name = name
                return

        # Try searching
        results = self.module_manager.search(name)
        if len(results) == 1:
            name_match, mod = results[0]
            # Use the module instance directly (from discover/load), don't re-instantiate
            self._active_module = mod
            self._active_module_name = name_match
            print(f"{Colors.GREEN}[+] Using module: {name_match}{Colors.RESET}")
            return

        if results:
            print(f"{Colors.YELLOW}[!] Multiple matches. Be more specific:{Colors.RESET}")
            for n, m in results:
                print(f"  {Colors.CYAN}{n}{Colors.RESET}")
            return

        # Try loading from generated modules directory
        gen_dir = os.path.expanduser("~/snakesploit/data/modules_generated")
        if os.path.isdir(gen_dir):
            for f in os.listdir(gen_dir):
                if f.endswith(".py") and name in f:
                    path = os.path.join(gen_dir, f)
                    mod = self.module_manager.load_module(path)
                    if mod:
                        mod_name = f"generated/{name}"
                        self._active_module = mod
                        self._active_module_name = mod_name
                        print(f"{Colors.GREEN}[+] Using generated module: {mod_name}{Colors.RESET}")
                        return

        print(f"{Colors.RED}[-] Module '{name}' not found{Colors.RESET}")

    def do_back(self, arg):
        """Unload the current module."""
        if self._active_module:
            self._active_module.cleanup()
        self._active_module = None
        self._active_module_name = ""
        print(f"{Colors.GREEN}[+] Unloaded module{Colors.RESET}")

    def do_show(self, arg):
        """Show module info/options. Usage: show [options|info]"""
        if not self._active_module:
            print(f"{Colors.YELLOW}[!] No active module. Use 'use <module>' first.{Colors.RESET}")
            return

        arg = arg.strip().lower() if arg else "info"

        if arg == "info" or arg == "i":
            m = self._active_module.metadata
            print(f"\n{Colors.BOLD}Module: {self._active_module_name}{Colors.RESET}")
            print(f"  Description:  {m.description}")
            print(f"  Author:       {m.author}")
            print(f"  Version:      {m.version}")
            print(f"  Type:         {m.module_type}")
            print(f"  Platform:     {m.platform}")
            print(f"  Arch:         {m.arch}")
            print(f"  Rank:         {m.rank}")
            if m.cve_ids:
                print(f"  CVEs:         {', '.join(m.cve_ids)}")
            if m.references:
                print(f"  References:")
                for ref in m.references[:3]:
                    print(f"    └─ {ref}")
            if m.privileged:
                print(f"  Privileged:   Yes")

        elif arg == "options" or arg == "o":
            print(f"\n{Colors.BOLD}Module Options ({self._active_module_name}):{Colors.RESET}")
            opts = self._active_module.options
            if not opts:
                print("  (none set)")
            else:
                print(f"  {'Name':<20} {'Value':<30} {'Required':<10}")
                print(f"  {'─'*20} {'─'*30} {'─'*10}")
                shown = set()
                for req in self._active_module.required_options:
                    val = opts.get(req, "")
                    print(f"  {req:<20} {str(val):<30} {'yes':<10}")
                    shown.add(req)
                for k, v in opts.items():
                    if k not in shown:
                        print(f"  {k:<20} {str(v):<30} {'no':<10}")
            print()

            print(f"  Required: {', '.join(self._active_module.required_options)}")

    def do_set(self, arg):
        """Set a module option. Usage: set <OPTION> <value>"""
        if not self._active_module:
            print(f"{Colors.YELLOW}[!] No active module.{Colors.RESET}")
            return
        parts = shlex.split(arg)
        if len(parts) < 2:
            print("Usage: set <OPTION> <value>")
            return
        opt = parts[0].upper()
        val = " ".join(parts[1:])
        self._active_module.options[opt] = val
        print(f"{Colors.GREEN}[+] {opt} => {val}{Colors.RESET}")

    def do_check(self, arg):
        """Run non-destructive vulnerability check on target."""
        if not self._active_module:
            print(f"{Colors.YELLOW}[!] No active module.{Colors.RESET}")
            return
        try:
            self._active_module.validate()
            print(f"{Colors.CYAN}[*] Checking target...{Colors.RESET}")
            result = self._active_module.check()
            if result:
                print(f"{Colors.GREEN}[+] Target appears VULNERABLE{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}[!] Target does not appear vulnerable{Colors.RESET}")
        except RuntimeError as e:
            print(f"{Colors.RED}[-] {e}{Colors.RESET}")

    def do_run(self, arg):
        """Execute the active module. Usage: run or exploit"""
        if not self._active_module:
            print(f"{Colors.YELLOW}[!] No active module.{Colors.RESET}")
            return
        self._execute_module()

    def do_exploit(self, arg):
        """Alias for 'run'"""
        self.do_run(arg)

    def _execute_module(self):
        """Execute the active module with output handling."""
        try:
            self._active_module.validate()
            print(f"{Colors.CYAN}[*] Running module {self._active_module_name}...{Colors.RESET}")
            start = time.time()
            result = self._active_module.run()
            elapsed = time.time() - start

            print(f"\n{Colors.GREEN}[+] Module completed in {elapsed:.2f}s{Colors.RESET}")

            # Add target to database
            host = self._active_module.options.get("RHOSTS", "")
            if host:
                target = self.target_manager.add(host)
                cves = self._active_module.metadata.cve_ids
                for cve in cves:
                    target.add_vulnerability(
                        cve_id=cve,
                        description=self._active_module.metadata.description,
                        source="SnakeSploit",
                        module=self._active_module_name,
                    )
                self.target_manager.save()

        except RuntimeError as e:
            print(f"{Colors.RED}[-] Error: {e}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[-] Unexpected error: {e}{Colors.RESET}")

    def do_reload(self, arg):
        """Reload modules from disk. Usage: reload modules"""
        if arg == "modules":
            count = self.module_manager.reload_all()
            print(f"{Colors.GREEN}[+] Reloaded {count} modules{Colors.RESET}")
        else:
            print("Usage: reload modules")

    # ──────────────────────────────────────────
    # Target management
    # ──────────────────────────────────────────

    def do_targets(self, arg):
        """Manage targets. Usage: targets [add|rm|show] <host>"""
        args = arg.split()
        if not args:
            # List all targets
            targets = self.target_manager.all()
            if not targets:
                print(f"{Colors.YELLOW}[!] No targets in database{Colors.RESET}")
                return
            print(f"\n{Colors.BOLD}Targets:{Colors.RESET}")
            print(f"  {'Host':<20} {'OS':<15} {'Services':<10} {'Vulns':<6}")
            print(f"  {'─'*20} {'─'*15} {'─'*10} {'─'*6}")
            for t in targets:
                print(f"  {t.host:<20} {t.os:<15} {len(t.services):<10} {len(t.vulnerabilities):<6}")
            print(f"\n  Total: {len(targets)}")
            return

        if args[0] == "add" and len(args) > 1:
            host = args[1]
            self.target_manager.add(host)
            self.target_manager.save()
            print(f"{Colors.GREEN}[+] Added target: {host}{Colors.RESET}")

        elif args[0] == "rm" and len(args) > 1:
            host = args[1]
            self.target_manager.remove(host)
            self.target_manager.save()
            print(f"{Colors.GREEN}[+] Removed target: {host}{Colors.RESET}")

        elif args[0] == "show" and len(args) > 1:
            host = args[1]
            target = self.target_manager.get(host)
            if not target:
                print(f"{Colors.YELLOW}[!] Target not found: {host}{Colors.RESET}")
                return
            print(f"\n{Colors.BOLD}Target: {target.host}{Colors.RESET}")
            print(f"  Hostname:   {target.hostname or 'N/A'}")
            print(f"  OS:         {target.os}")
            print(f"  First Seen: {target.first_seen}")
            print(f"  Last Seen:  {target.last_seen}")
            if target.services:
                print(f"\n  {Colors.BOLD}Services:{Colors.RESET}")
                print(f"  {'Port':<8} {'Protocol':<10} {'Service':<15} {'Banner':<40}")
                print(f"  {'─'*8} {'─'*10} {'─'*15} {'─'*40}")
                for port in sorted(target.services.keys()):
                    svc = target.services[port]
                    print(f"  {port:<8} {svc.protocol:<10} {svc.service:<15} {svc.banner[:40]:<40}")
            if target.vulnerabilities:
                print(f"\n  {Colors.BOLD}Vulnerabilities:{Colors.RESET}")
                for v in target.vulnerabilities:
                    print(f"  [{Colors.RED}{v['cve_id']}{Colors.RESET}] {v['description'][:60]}")
        else:
            print("Usage: targets [add|rm|show] <host>")

    # ──────────────────────────────────────────
    # Scanning
    # ──────────────────────────────────────────

    def do_scan(self, arg):
        """TCP port scan. Usage: scan <host> [port1,port2,...]"""
        args = arg.split()
        if not args:
            print("Usage: scan <host> [port1,port2,...]")
            return

        host = args[0]
        ports = None
        if len(args) > 1:
            try:
                ports = [int(p) for p in args[1].split(",")]
            except ValueError:
                print(f"{Colors.RED}[-] Invalid port list{Colors.RESET}")
                return

        print(f"{Colors.CYAN}[*] Scanning {host}...{Colors.RESET}")
        results = PortScanner.scan(host, ports)

        if not results:
            print(f"{Colors.YELLOW}[!] No open ports found{Colors.RESET}")
            return

        print(f"\n{Colors.GREEN}[+] Found {len(results)} open ports:{Colors.RESET}")
        print(f"  {'Port':<8} {'State':<10}")
        print(f"  {'─'*8} {'─'*10}")
        for r in results:
            print(f"  {r['port']:<8} {Colors.GREEN}{r['state']:<10}{Colors.RESET}")

        # Add to target database
        target = self.target_manager.add(host)
        for r in results:
            from core.target import Service
            target.add_service(Service(port=r["port"], state=r["state"]))
        self.target_manager.save()

    def do_http(self, arg):
        """HTTP GET request. Usage: http <url>"""
        if not arg:
            print("Usage: http <url>")
            return
        result = HTTPClient.get(arg.strip())
        if "error" in result:
            print(f"{Colors.RED}[-] Error: {result['error']}{Colors.RESET}")
            return
        print(f"{Colors.GREEN}[+] Status: {result['status']}{Colors.RESET}")
        print(f"  Headers: {len(result.get('headers', {}))} keys")
        body = result.get("text", "")
        if len(body) > 500:
            print(f"  Body: {len(body)} chars (showing first 500)")
            print(f"  {body[:500]}...")
        else:
            print(f"  Body: {body}")

    # ──────────────────────────────────────────
    # Payloads
    # ──────────────────────────────────────────

    def do_payloads(self, arg):
        """Generate payloads. Usage: payloads [type] LHOST=x LPORT=y"""
        if not arg:
            print(f"\n{Colors.BOLD}Available Payloads:{Colors.RESET}")
            payloads = [
                ("linux_reverse", "Bash reverse shell over /dev/tcp"),
                ("python_reverse", "Python reverse shell"),
                ("nc_reverse", "Netcat reverse shell"),
                ("powershell_reverse", "PowerShell reverse shell (Windows)"),
                ("perl_reverse", "Perl reverse shell"),
                ("python_bind", "Python bind shell"),
                ("php_reverse", "PHP reverse shell"),
            ]
            print(f"  {'Name':<22} {'Description':<50}")
            print(f"  {'─'*22} {'─'*50}")
            for name, desc in payloads:
                print(f"  {Colors.CYAN}{name:<22}{Colors.RESET} {desc:<50}")
            print(f"\n  Usage: payloads <name> LHOST=<ip> LPORT=<port> [encode=true]")
            return

        # Parse: payloads <name> LHOST=x LPORT=y
        parts = shlex.split(arg)
        name = parts[0]
        lhost = "127.0.0.1"
        lport = 4444
        encode = False

        for p in parts[1:]:
            if "=" in p:
                k, v = p.split("=", 1)
                if k.upper() == "LHOST":
                    lhost = v
                elif k.upper() == "LPORT":
                    lport = int(v)
                elif k.upper() == "ENCODE" and v.lower() == "true":
                    encode = True

        try:
            payload = PayloadGenerator.generate(name, lhost, lport, encode)
            print(f"\n{Colors.GREEN}[+] Generated {name} payload{Colors.RESET}")
            print(f"    LHOST:  {payload.lhost}")
            print(f"    LPORT:  {payload.lport}")
            print(f"    Size:   {payload.size} bytes")
            print(f"    Encoded: {payload.encoded}")
            print(f"\n{Colors.BOLD}Payload:{Colors.RESET}")
            print(f"  {Colors.DIM}{payload.code}{Colors.RESET}")
            print()
        except ValueError as e:
            print(f"{Colors.RED}[-] {e}{Colors.RESET}")

    # ──────────────────────────────────────────
    # Listener
    # ──────────────────────────────────────────

    def do_listener(self, arg):
        """Start a reverse shell listener. Usage: listener <port>"""
        if not arg:
            print("Listener ports: active sessions")
            active = self.session_manager.list_active()
            if active:
                for sid, s in active.items():
                    print(f"  {sid} on port {s.target_port} ({s.target_host})")
            else:
                print("  No active listeners")
            return

        try:
            port = int(arg)
        except ValueError:
            print(f"{Colors.RED}[-] Invalid port{Colors.RESET}")
            return

        # Check if a listener is already running on this port
        for sid, s in self.session_manager.list_active().items():
            if s.target_port == port and s.session_type == "reverse":
                print(f"{Colors.YELLOW}[!] Listener already active on port {port} (session {sid}){Colors.RESET}")
                return

        thread = threading.Thread(
            target=self._listener_thread,
            args=(port,),
            daemon=True
        )
        thread.start()
        print(f"{Colors.GREEN}[+] Listener started on port {port}{Colors.RESET}")
        print(f"    Waiting for incoming connections...")

    def _listener_thread(self, port: int):
        """Background thread for the listener."""
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("0.0.0.0", port))
            server.listen(5)
            server.settimeout(1.0)

            while self._running:
                try:
                    conn, addr = server.accept()
                    print(f"\n{Colors.GREEN}[+] Connection from {addr[0]}:{addr[1]}{Colors.RESET}")

                    session = self.session_manager.create_session(
                        session_type="reverse",
                        target_host=addr[0],
                        target_port=addr[1],
                        conn=conn,
                        platform="unknown",
                    )
                    print(f"{Colors.GREEN}[+] Session {session.id} created{Colors.RESET}")
                    print(f"    Use 'sessions -i {session.id}' to interact")

                    # Start interaction in background
                    thread = threading.Thread(
                        target=self._session_interaction_loop,
                        args=(session,),
                        daemon=True,
                    )
                    thread.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"\n{Colors.RED}[-] Listener error: {e}{Colors.RESET}")
            server.close()
        except Exception as e:
            print(f"\n{Colors.RED}[-] Could not start listener: {e}{Colors.RESET}")

    def _session_interaction_loop(self, session):
        """Background loop to receive session data."""
        import select
        while not session.dead and self._running:
            try:
                data = session.interact()
                if data:
                    print(f"\n{Colors.MAGENTA}[{session.id}]{Colors.RESET} {data.strip()}")
                    self.prompt = f"{Colors.GREEN}snakesploit{Colors.RESET} > "
            except Exception:
                session.dead = True
                break

    # ──────────────────────────────────────────
    # Session management
    # ──────────────────────────────────────────

    def do_sessions(self, arg):
        """Manage sessions. Usage: sessions | sessions -i <id> | sessions -k <id>"""
        args = arg.split()

        if not args:
            sessions = self.session_manager.sessions
            if not sessions:
                print(f"{Colors.YELLOW}[!] No sessions{Colors.RESET}")
                return
            print(f"\n{Colors.BOLD}Active Sessions:{Colors.RESET}")
            print(f"  {'ID':<12} {'Type':<12} {'Target':<25} {'State':<10}")
            print(f"  {'─'*12} {'─'*12} {'─'*25} {'─'*10}")
            for sid, s in sorted(sessions.items()):
                state = f"{Colors.GREEN}active{Colors.RESET}" if not s.dead else f"{Colors.DIM}dead{Colors.RESET}"
                print(f"  {sid:<12} {s.session_type:<12} {s.target_host}:{s.target_port:<15} {state}")
            return

        if args[0] == "-i" and len(args) > 1:
            session_id = args[1]
            session = self.session_manager.get(session_id)
            if not session:
                print(f"{Colors.RED}[-] Session not found: {session_id}{Colors.RESET}")
                return
            print(f"{Colors.GREEN}[+] Interacting with session {session_id}{Colors.RESET}")
            print(f"{Colors.YELLOW}[!] Type 'exit' to return to Nova{Colors.RESET}\n")
            self._interact_with_session(session)

        elif args[0] == "-k" and len(args) > 1:
            session_id = args[1]
            self.session_manager.close_session(session_id)
            print(f"{Colors.RED}[-] Session {session_id} killed{Colors.RESET}")

    def _interact_with_session(self, session):
        """Interactive session mode."""
        self.prompt = f"{Colors.MAGENTA}[{session.id}]{Colors.RESET} > "
        while not session.dead:
            try:
                user_input = input(self.prompt)
                if user_input.lower() in ("exit", "quit", "back"):
                    break
                session.send(user_input)
                time.sleep(0.3)
                output = session.recv(timeout=2.0)
                if output:
                    print(output.strip())
            except (KeyboardInterrupt, EOFError):
                break
        self.prompt = f"{Colors.GREEN}snakesploit{Colors.RESET} > "

    # ──────────────────────────────────────────
    # Empty line / default
    # ──────────────────────────────────────────

    def emptyline(self):
        pass

    def default(self, line):
        print(f"{Colors.YELLOW}[!] Unknown command: {line}. Type 'help'{Colors.RESET}")

    # ──────────────────────────────────────────
    # Startup
    # ──────────────────────────────────────────

    def run(self):
        """Start the console loop."""
        try:
            self.cmdloop()
        except KeyboardInterrupt:
            print(f"\n\n{Colors.GREEN}Goodbye, Nirbhik.{Colors.RESET}")
            self.target_manager.save()
            self.session_manager.save()
            self._running = False


def main():
    console = NovaConsole()
    console.run()


if __name__ == "__main__":
    main()