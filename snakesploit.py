#!/usr/bin/env python3
"""
SnakeSploit — Python-Powered Exploit Framework
======================================
Auto-pulls CVEs from NVD, scrapes PoCs from GitHub/Exploit-DB,
and generates exploit modules automatically.

Usage:
  ./nova.py           ─ Interactive console
  ./nova.py --update  ─ Run update pipeline (fetch CVEs + PoCs)
  ./nova.py --help    ─ Show options
"""

import argparse
import os
import sys

# Ensure we can import from the nova package
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main():
    parser = argparse.ArgumentParser(
        description="SnakeSploit — Python-Powered Exploit Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  snakesploit                     Start interactive console
  snakesploit --update            Fetch recent CVEs and PoCs
  snakesploit --update --days 14  Fetch last 14 days of CVEs
  snakesploit --update --full     Full pipeline: CVEs → PoCs → module gen
  snakesploit --cve stats         Show CVE cache statistics
  snakesploit --module-list       List all available modules
  snakesploit --gen-cves          Generate modules from all cached CVEs
        """
    )
    parser.add_argument("--update", action="store_true", help="Run CVE/PoC update")
    parser.add_argument("--days", type=int, default=7, help="Days back for CVEs")
    parser.add_argument("--full", action="store_true", help="Full update pipeline")
    parser.add_argument("--cve", choices=["stats", "search"], help="CVE operations")
    parser.add_argument("--cve-query", type=str, help="CVE search query")
    parser.add_argument("--module-list", action="store_true", help="List modules")
    parser.add_argument("--gen-cves", action="store_true", help="Generate modules from CVEs")
    parser.add_argument("--search", type=str, help="Search modules")
    parser.add_argument("--non-interactive", action="store_true", help="Don't start console")

    args = parser.parse_args()

    # Run update pipeline
    if args.update:
        from updater.module_generator import AutoUpdater
        updater = AutoUpdater()
        results = updater.run_full_update(
            days_back=args.days,
        ) if args.full else updater.cve_updater.fetch_recent(days_back=args.days)

        if not args.non_interactive:
            print("\nStarting console...")
            from console import NovaConsole
            NovaConsole().run()
        return

    # CVE operations
    if args.cve:
        from updater.cve_fetcher import CVEUpdater
        updater = CVEUpdater()
        if args.cve == "stats":
            stats = updater.get_statistics()
            print(f"\nCVE Cache Statistics:")
            for k, v in stats.items():
                print(f"  {k}: {v}")
        elif args.cve == "search" and args.cve_query:
            count = updater.fetch_by_keywords([args.cve_query])
            print(f"Fetched {count} CVEs")

        if not args.non_interactive:
            print("\nStarting console...")
            from console import NovaConsole
            NovaConsole().run()
        return

    # List modules
    if args.module_list:
        from core.module import ModuleManager
        mm = ModuleManager()
        mm.discover()
        count = sum(len(v) for v in mm.categories.values())
        print(f"\nFound {count} modules:")
        for cat, paths in sorted(mm.categories.items()):
            print(f"\n  {cat}:")
            for path in paths:
                name = os.path.splitext(os.path.basename(path))[0]
                print(f"    └─ {name}")

        if not args.non_interactive:
            print("\nStarting console...")
            from console import NovaConsole
            NovaConsole().run()
        return

    # Generate modules from cached CVEs
    if args.gen_cves:
        from updater.module_generator import ModuleGenerator
        from updater.cve_fetcher import CVEUpdater, PoCScraper
        cve = CVEUpdater()
        poc = PoCScraper()
        gen = ModuleGenerator()

        cves = cve.index
        print(f"Generating modules from {len(cves)} cached CVEs...")
        count = gen.generate_all(cves, poc.index)
        print(f"Generated {count} new modules (total: {gen.manifest['total']})")

        if not args.non_interactive:
            print("\nStarting console...")
            from console import NovaConsole
            NovaConsole().run()
        return

    # Search modules
    if args.search:
        from core.module import ModuleManager
        mm = ModuleManager()
        mm.discover()
        for cat, paths in mm.categories.items():
            for path in paths:
                mm.load_module(path)
        results = mm.search(args.search)
        if results:
            print(f"\nFound {len(results)} modules:")
            for name, meta in sorted(results):
                cves = ", ".join(meta.cve_ids) if meta.cve_ids else ""
                print(f"\n  {name}" + (f" [{cves}]" if cves else ""))
                print(f"    {meta.description[:80]}")
        else:
            print(f"No modules found for '{args.search}'")

        if not args.non_interactive:
            print("\nStarting console...")
            from console import SnakeSploitConsole
            SnakeSploitConsole().run()
        return

    # Default: start console
    from console import SnakeSploitConsole
    SnakeSploitConsole().run()


if __name__ == "__main__":
    main()