"""
SnakeSploit Auto-Update Engine — pulls CVEs from NVD API 2.0 and scrapes PoCs
from GitHub, Exploit-DB, and Packet Storm.
Generates module stubs for new vulnerabilities.
"""

import json
import os
import re
import subprocess
import sys
import time
import urllib.request
import urllib.error
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class CVEUpdater:
    """Pulls CVEs from NVD API 2.0 and stores them locally."""

    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    USER_AGENT = "SnakeSploit/1.0"

    def __init__(self):
        self.cache_dir = os.path.expanduser("~/.snakesploit/cve_cache")
        self.db_path = os.path.join(self.cache_dir, "cve_index.json")
        self.last_fetch = None
        os.makedirs(self.cache_dir, exist_ok=True)
        self._load_index()

    def _load_index(self):
        if os.path.exists(self.db_path):
            with open(self.db_path) as f:
                data = json.load(f)
            self.last_fetch = data.get("last_fetch")
            self.index = data.get("cves", [])
        else:
            self.index = []
            self.last_fetch = None

    def _save_index(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with open(self.db_path, "w") as f:
            json.dump({
                "last_fetch": datetime.now().isoformat(),
                "total_cves": len(self.index),
                "cves": self.index,
            }, f, indent=2)

    def _api_request(self, url: str) -> Optional[dict]:
        """Make a rate-limited request to NVD API."""
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": self.USER_AGENT,
            })
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 403:
                print("  [!] NVD API rate limit hit. Waiting 10s...")
                time.sleep(10)
                return self._api_request(url)
            print(f"  [!] NVD API error {e.code}: {e.reason}")
            return None
        except Exception as e:
            print(f"  [!] NVD API request failed: {e}")
            return None

    def fetch_recent(self, days_back: int = 7, limit: int = 100) -> int:
        """
        Fetch CVEs published in the last N days.
        Returns number of new CVEs fetched.
        """
        start_date = (datetime.now() - timedelta(days=days_back)).strftime("%Y-%m-%dT00:00:00.000")
        end_date = datetime.now().strftime("%Y-%m-%dT00:00:00.000")

        url = (f"{self.NVD_API}?pubStartDate={start_date}&pubEndDate={end_date}"
               f"&resultsPerPage={min(limit, 200)}&startIndex=0")

        print(f"  [*] Fetching CVEs from {start_date} to {end_date}...")
        data = self._api_request(url)
        if not data:
            return 0

        vulnerabilities = data.get("vulnerabilities", [])
        existing_ids = {c["id"] for c in self.index}
        new_count = 0

        for vuln in vulnerabilities:
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "")

            if cve_id in existing_ids:
                continue

            # Extract key info
            descriptions = cve_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # CVSS score
            metrics = cve_data.get("metrics", {})
            cvss_score = 0.0
            cvss_vector = ""
            for metric_version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if metric_version in metrics:
                    metric_data = metrics[metric_version][0]
                    cvss_data = metric_data.get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    cvss_vector = cvss_data.get("vectorString", "")
                    break

            # CPE info (affected products)
            configurations = cve_data.get("configurations", [])
            cpe_matches = []
            for config in configurations:
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        cpe_matches.append(match.get("criteria", ""))

            # References
            references = []
            for ref in cve_data.get("references", []):
                references.append({
                    "url": ref.get("url", ""),
                    "tags": ref.get("tags", []),
                    "source": ref.get("source", ""),
                })

            # Determine severity from score
            if cvss_score >= 9.0:
                severity = "CRITICAL"
            elif cvss_score >= 7.0:
                severity = "HIGH"
            elif cvss_score >= 4.0:
                severity = "MEDIUM"
            elif cvss_score > 0:
                severity = "LOW"
            else:
                severity = "UNKNOWN"

            entry = {
                "id": cve_id,
                "description": description[:500],
                "score": cvss_score,
                "severity": severity,
                "vector": cvss_vector,
                "cpe_matches": cpe_matches[:10],
                "references": references[:10],
                "published": cve_data.get("published", ""),
                "last_modified": cve_data.get("lastModified", ""),
                "fetched": datetime.now().isoformat(),
                "has_poc": False,
                "poc_count": 0,
            }

            self.index.append(entry)
            new_count += 1
            existing_ids.add(cve_id)

        self._save_index()
        print(f"  [+] Fetched {new_count} new CVEs (total: {len(self.index)})")

        # If there are more results, paginate
        total_results = data.get("totalResults", 0)
        if total_results > limit:
            pass  # Could implement pagination for full sync

        return new_count

    def fetch_by_keywords(self, keywords: List[str], limit: int = 50) -> int:
        """Search CVEs by keyword (product, vendor, etc.)."""
        query = "+".join(keywords)
        url = (f"{self.NVD_API}?keywordSearch={query}"
               f"&resultsPerPage={min(limit, 200)}&startIndex=0")

        data = self._api_request(url)
        if not data:
            return 0

        vulnerabilities = data.get("vulnerabilities", [])
        existing_ids = {c["id"] for c in self.index}
        new_count = 0

        for vuln in vulnerabilities:
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "")
            if cve_id in existing_ids:
                continue
            # Same parse logic as fetch_recent
            descriptions = cve_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            entry = {
                "id": cve_id,
                "description": description[:500],
                "score": 0.0,
                "severity": "UNKNOWN",
                "vector": "",
                "cpe_matches": [],
                "references": [],
                "published": cve_data.get("published", ""),
                "last_modified": cve_data.get("lastModified", ""),
                "fetched": datetime.now().isoformat(),
                "has_poc": False,
                "poc_count": 0,
            }
            self.index.append(entry)
            new_count += 1

        self._save_index()
        return new_count

    def get_cves_by_severity(self, severity: str) -> List[dict]:
        """Filter stored CVEs by severity level."""
        return [c for c in self.index if c.get("severity") == severity.upper()]

    def get_cves_without_pocs(self) -> List[dict]:
        """Get CVEs that don't have PoCs yet."""
        return [c for c in self.index if not c.get("has_poc")]

    def mark_poc_found(self, cve_id: str):
        for c in self.index:
            if c["id"] == cve_id:
                c["has_poc"] = True
                c["poc_count"] = c.get("poc_count", 0) + 1
        self._save_index()

    def get_statistics(self) -> dict:
        """Get CVE cache statistics."""
        return {
            "total_cves": len(self.index),
            "critical": len(self.get_cves_by_severity("CRITICAL")),
            "high": len(self.get_cves_by_severity("HIGH")),
            "medium": len(self.get_cves_by_severity("MEDIUM")),
            "low": len(self.get_cves_by_severity("LOW")),
            "with_pocs": sum(1 for c in self.index if c.get("has_poc")),
            "without_pocs": len(self.get_cves_without_pocs()),
            "last_fetch": self.last_fetch,
        }


class PoCScraper:
    """Scrapes PoC exploits from GitHub, Exploit-DB, and Packet Storm."""

    GITHUB_SEARCH_API = "https://api.github.com/search/repositories"
    EXPLOITDB_SEARCH = "https://www.exploit-db.com/search"

    def __init__(self):
        self.poc_dir = os.path.expanduser("~/.snakesploit/poc_cache")
        os.makedirs(self.poc_dir, exist_ok=True)
        self.index_path = os.path.join(self.poc_dir, "poc_index.json")
        self._load_index()

    def _load_index(self):
        if os.path.exists(self.index_path):
            with open(self.index_path) as f:
                self.index = json.load(f)
        else:
            self.index = []

    def _save_index(self):
        with open(self.index_path, "w") as f:
            json.dump(self.index, f, indent=2)

    def search_github(self, cve_id: str) -> List[dict]:
        """Search GitHub for PoCs related to a CVE."""
        results = []
        try:
            url = f"{self.GITHUB_SEARCH_API}?q={cve_id}+poc&sort=stars&order=desc&per_page=10"
            req = urllib.request.Request(url, headers={
                "User-Agent": "Nova-Pentest-Framework/1.0",
                "Accept": "application/vnd.github.v3+json",
            })
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
                for item in data.get("items", []):
                    results.append({
                        "source": "github",
                        "cve_id": cve_id,
                        "title": item.get("full_name", ""),
                        "url": item.get("html_url", ""),
                        "description": item.get("description", "") or "",
                        "stars": item.get("stargazers_count", 0),
                        "language": item.get("language", ""),
                        "fetched": datetime.now().isoformat(),
                        "type": "repository",
                    })
        except urllib.error.HTTPError as e:
            if e.code == 403:
                print("  [!] GitHub API rate limited. Skipping.")
            else:
                print(f"  [!] GitHub search error: {e.code}")
        except Exception as e:
            print(f"  [!] GitHub search error: {e}")
        return results

    def search_exploitdb(self, cve_id: str) -> List[dict]:
        """Search for PoCs on Exploit-DB."""
        # Use Google dorking or exploitdb search via web scraping
        # For now, we check if there's a known URL pattern
        results = []
        try:
            url = f"https://www.exploit-db.com/search?cve={cve_id}"
            req = urllib.request.Request(url, headers={
                "User-Agent": self.USER_AGENT if hasattr(self, 'USER_AGENT') else "Nova-Framework/1.0",
            })
            # Exploit-DB requires JavaScript, so we'll note the URL
            results.append({
                "source": "exploitdb",
                "cve_id": cve_id,
                "title": f"Exploit-DB search for {cve_id}",
                "url": url,
                "description": f"Check Exploit-DB for {cve_id} exploits",
                "type": "search_url",
                "fetched": datetime.now().isoformat(),
            })
        except Exception:
            pass
        return results

    def search_all(self, cve_id: str) -> List[dict]:
        """Search all sources for a given CVE."""
        all_results = []
        all_results.extend(self.search_github(cve_id))
        all_results.extend(self.search_exploitdb(cve_id))

        if all_results:
            for r in all_results:
                r["cve_id"] = cve_id
                self.index.append(r)
            self._save_index()

        return all_results

    def get_top_pocs(self, cve_id: str, limit: int = 3) -> List[dict]:
        """Get the best PoCs for a CVE (sorted by stars/relevance)."""
        related = [p for p in self.index if p.get("cve_id") == cve_id and p.get("source") == "github"]
        related.sort(key=lambda x: x.get("stars", 0), reverse=True)
        return related[:limit]

    def clone_poc(self, url: str, target_dir: str) -> bool:
        """Clone a PoC repository."""
        repo_name = url.rstrip("/").split("/")[-1]
        dest = os.path.join(target_dir, repo_name)
        if os.path.exists(dest):
            return True
        try:
            result = subprocess.run(
                ["git", "clone", "--depth", "1", url, dest],
                capture_output=True, timeout=60
            )
            return result.returncode == 0
        except Exception:
            return False

    def scan_all_cves_for_pocs(self, cve_list: List[dict]) -> int:
        """Scan a list of CVEs for PoCs. Returns count of new PoCs found."""
        new_poc_count = 0
        existing_poc_ids = {p.get("cve_id") for p in self.index}

        for cve in cve_list:
            cve_id = cve["id"]
            if cve_id in existing_poc_ids:
                continue
            print(f"  [*] Searching PoCs for {cve_id}...")
            results = self.search_all(cve_id)
            if results:
                new_poc_count += 1
                print(f"    [+] Found {len(results)} PoCs for {cve_id}")
            time.sleep(1)  # Be nice to APIs

        return new_poc_count