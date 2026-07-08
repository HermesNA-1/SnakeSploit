"""
SnakeSploit Auto-Module Generator — creates exploit/poc modules from CVE data.
Generates Python modules that try to reproduce PoCs against targets.
"""

import json
import os
import re
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

# Import CVE / PoC components
# NOTE: Must come before AutoUpdater since it references them
from .cve_fetcher import CVEUpdater, PoCScraper


MODULE_TEMPLATE = '''"""
SnakeSploit Auto-Generated Module
CVE: {cve_id}
Source: {source}
Generated: {generated}
Description: {description}
"""

from core.module import NovaModule, ModuleMetadata
import socket
import json
import urllib.request


class Module(NovaModule):
    """Auto-generated module for {cve_id}"""

    metadata = ModuleMetadata(
        name="{module_name}",
        description="{description}",
        author="Nova Auto-Generator",
        version="1.0",
        cve_ids=["{cve_id}"],
        references={references},
        rank="average",
        module_type="auxiliary",
        platform="{platform}",
        arch="{arch}",
    )

    required_options = ["RHOSTS", "RPORT"]

    def check(self) -> bool:
        """Probe the target to see if it responds."""
        host = self.options.get("RHOSTS", "127.0.0.1")
        port = int(self.options.get("RPORT", 80))
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((host, port))
            data = s.recv(1024)
            s.close()
            self.print_good(f"HOST:PORT is open")
            return True
        except Exception as e:
            self.print_error(f"Could not connect: ERROR")
            return False

    def run(self) -> dict:
        """Execute the exploit/PoC for {cve_id}.

        NOTE: This is an auto-generated stub. For a real exploit,
        replace this method with the actual PoC code.
        """
        host = self.options.get("RHOSTS", "127.0.0.1")
        port = int(self.options.get("RPORT", 80))
        ssl = self.options.get("SSL", "false").lower() == "true"
        protocol = "https" if ssl else "http"

        self.print_status(f"Target: HOST:PORT (PROTOCOL)")
        self.print_status(f"CVE: {cve_id}")
        self.print_status(f"Description: {desc_short}...")

        # TODO: Replace with actual PoC code
        # Check references for exploit code:
        # {poc_urls}

        self.print_warning("This is an auto-generated stub module.")
        self.print_warning("Replace the run() method with the actual PoC.")

        return {{
            "cve": "{cve_id}",
            "target": f"HOST:PORT",
            "status": "stub - needs PoC implementation",
        }}
'''


class ModuleGenerator:
    """Generates Nova exploit/aux modules from CVE + PoC data."""

    def __init__(self):
        self.output_dir = os.path.expanduser("~/snakesploit/data/modules_generated")
        os.makedirs(self.output_dir, exist_ok=True)
        self.manifest_path = os.path.join(self.output_dir, "manifest.json")
        self._load_manifest()

    def _load_manifest(self):
        if os.path.exists(self.manifest_path):
            with open(self.manifest_path) as f:
                self.manifest = json.load(f)
        else:
            self.manifest = {"generated": [], "total": 0}

    def _save_manifest(self):
        with open(self.manifest_path, "w") as f:
            json.dump(self.manifest, f, indent=2)

    def _sanitize_name(self, cve_id: str, description: str) -> str:
        """Create a clean module name from CVE and description."""
        keywords = description.lower().split()[:4]
        safe_kw = []
        for kw in keywords:
            kw = re.sub(r'[^a-z0-9_-]', '', kw)
            if kw and len(kw) > 2:
                safe_kw.append(kw)
        if safe_kw:
            name = "_".join(safe_kw[:3])
        else:
            name = cve_id.lower().replace("-", "_")
        return f"{cve_id.lower()}_{name}"[:64]

    def _determine_platform(self, cpe_matches: List[str], description: str) -> str:
        """Guess platform from CPE strings or description."""
        desc_lower = description.lower()
        for cpe in cpe_matches:
            if "windows" in cpe.lower():
                return "windows"
            if "linux" in cpe.lower():
                return "linux"
            if "apple" in cpe.lower() or "mac_os" in cpe.lower():
                return "osx"
        if any(w in desc_lower for w in ["windows", "win", "iis", "exchange", "sharepoint"]):
            return "windows"
        if any(w in desc_lower for w in ["linux", "apache", "nginx", "unix", "ssh"]):
            return "linux"
        if any(w in desc_lower for w in ["web", "cms", "wordpress", "joomla", "drupal"]):
            return "php"
        return "multi"

    def _determine_arch(self, platform: str) -> str:
        arch_map = {
            "windows": "x64",
            "linux": "x64",
            "osx": "x64",
            "php": "cmd",
            "multi": "cmd",
        }
        return arch_map.get(platform, "cmd")

    def generate_module(self, cve_data: dict, pocs: List[dict] = None) -> Optional[str]:
        """
        Generate a module file from CVE data.
        Returns module name if successful, None otherwise.
        """
        cve_id = cve_data.get("id", "CVE-XXXX-XXXX")
        description = cve_data.get("description", "No description available.")
        score = cve_data.get("score", 0.0)
        cpe = cve_data.get("cpe_matches", [])
        refs = cve_data.get("references", [])

        if cve_id in self.manifest["generated"]:
            return None

        module_name = self._sanitize_name(cve_id, description)
        platform = self._determine_platform(cpe, description)
        arch = self._determine_arch(platform)

        ref_urls = [r.get("url", "") for r in refs if r.get("url")]
        if pocs:
            for poc in pocs:
                ref_urls.append(poc.get("url", ""))

        poc_urls_str = "\n        # ".join(ref_urls) if ref_urls else "No PoC URLs found"
        references_str = json.dumps(ref_urls[:5])
        desc_short = description[:100]

        # Sanitize for Python source code safety (escape quotes, strip newlines)
        description_safe = description[:200].replace("'", "\\'").replace('"', '\\"').replace("\n", " ").replace("\r", " ").strip()
        desc_short_safe = desc_short.replace("'", "\\'").replace('"', '\\"').replace("\n", " ").replace("\r", " ").strip()

        content = MODULE_TEMPLATE.format(
            cve_id=cve_id,
            source="NVD API / SnakeSploit PoC Scraper",
            generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            description=description_safe,
            desc_short=desc_short_safe,
            module_name=module_name,
            references=references_str,
            platform=platform,
            arch=arch,
            poc_urls=poc_urls_str,
        )

        filename = f"{module_name}.py"
        filepath = os.path.join(self.output_dir, filename)

        with open(filepath, "w") as f:
            f.write(content)

        if pocs:
            poc_info = []
            for poc in pocs:
                poc_info.append({
                    "source": poc.get("source", ""),
                    "url": poc.get("url", ""),
                    "title": poc.get("title", ""),
                    "stars": poc.get("stars", 0),
                })
            info_path = os.path.join(self.output_dir, f"{module_name}_pocs.json")
            with open(info_path, "w") as f:
                json.dump(poc_info, f, indent=2)

        self.manifest["generated"].append(cve_id)
        self.manifest["total"] = len(self.manifest["generated"])
        self._save_manifest()

        return module_name

    def generate_all(self, cve_list: List[dict], poc_db: List[dict] = None) -> int:
        """Generate modules for all CVEs. Returns count of new modules."""
        new_count = 0
        poc_by_cve = {}
        if poc_db:
            for p in poc_db:
                cve_id = p.get("cve_id", "")
                if cve_id not in poc_by_cve:
                    poc_by_cve[cve_id] = []
                poc_by_cve[cve_id].append(p)

        for cve in cve_list:
            cve_id = cve.get("id", "")
            if cve_id in self.manifest["generated"]:
                continue
            pocs = poc_by_cve.get(cve_id, [])
            module_name = self.generate_module(cve, pocs)
            if module_name:
                print(f"  [+] Generated module: {module_name}")
                new_count += 1

        return new_count

    def get_statistics(self) -> dict:
        return {
            "total_generated": len(self.manifest["generated"]),
            "output_dir": self.output_dir,
        }


class AutoUpdater:
    """Orchestrates the full auto-update pipeline:
    1. Fetch recent CVEs from NVD
    2. Search for PoCs
    3. Generate modules
    """

    def __init__(self):
        self.cve_updater = CVEUpdater()
        self.poc_scraper = PoCScraper()
        self.module_generator = ModuleGenerator()

    def run_full_update(self, days_back: int = 3, max_cves: int = 50) -> dict:
        """Run the complete update pipeline."""
        results = {"new_cves": 0, "new_pocs": 0, "new_modules": 0, "errors": []}

        print("=== Nova Auto-Update Pipeline ===")
        print(f"[*] Fetching CVEs from last {days_back} days...")

        try:
            results["new_cves"] = self.cve_updater.fetch_recent(days_back=days_back, limit=max_cves)
        except Exception as e:
            results["errors"].append(f"CVE fetch error: {e}")

        print("[*] Searching for PoCs...")
        cves_without_pocs = self.cve_updater.get_cves_without_pocs()[:max_cves]
        try:
            results["new_pocs"] = self.poc_scraper.scan_all_cves_for_pocs(cves_without_pocs)
        except Exception as e:
            results["errors"].append(f"PoC search error: {e}")

        print("[*] Generating modules...")
        priority_cves = (
            self.cve_updater.get_cves_by_severity("CRITICAL")[:20] +
            self.cve_updater.get_cves_by_severity("HIGH")[:20] +
            self.cve_updater.get_cves_by_severity("MEDIUM")[:10]
        )

        try:
            results["new_modules"] = self.module_generator.generate_all(priority_cves, self.poc_scraper.index)
        except Exception as e:
            results["errors"].append(f"Module generation error: {e}")

        print("\n=== Update Complete ===")
        print(f"  New CVEs: {results['new_cves']}")
        print(f"  New PoCs: {results['new_pocs']}")
        print(f"  New Modules: {results['new_modules']}")
        if results["errors"]:
            print(f"  Errors: {len(results['errors'])}")

        return results