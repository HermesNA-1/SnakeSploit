"""
SnakeSploit Module System — Base classes for all modules.
Each module: exploit, payload, auxiliary scanner, post-exploitation.
"""

import importlib.util
import inspect
import json
import os
import sys
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ModuleMetadata:
    """Metadata every Nova module must define."""
    name: str
    description: str
    author: str = "Nova Framework"
    version: str = "1.0"
    cve_ids: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    rank: str = "normal"  # excellent, great, good, normal, average, low, manual
    module_type: str = "exploit"  # exploit, payload, auxiliary, post
    platform: str = "generic"  # windows, linux, osx, multi, generic
    arch: str = "generic"  # x86, x64, arm, python, cmd, generic
    privileged: bool = False
    disclosure_date: Optional[str] = None
    added_date: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d"))


class NovaModule:
    """Base class for all Nova modules."""

    metadata: ModuleMetadata = None
    options: Dict[str, Any] = {}  # RHOSTS, RPORT, SSL, etc.
    required_options: List[str] = []

    def __init__(self):
        self.options = {}
        self._results = {}
        self._session = None
        self.verify_metadata()

    def verify_metadata(self):
        if self.metadata is None:
            raise ValueError(f"Module {self.__class__.__name__} must define `metadata`")

    def setup(self, **kwargs):
        """Set module options from kwargs or interactive."""
        for k, v in kwargs.items():
            self.options[k.upper()] = v
        return self

    def validate(self) -> bool:
        """Check required options are set."""
        missing = [r for r in self.required_options if r not in self.options or not self.options[r]]
        if missing:
            raise RuntimeError(f"Missing required options: {', '.join(missing)}")
        return True

    def check(self) -> bool:
        """Check if target is vulnerable (non-destructive probe)."""
        return False

    def run(self) -> Dict[str, Any]:
        """Main execution — override in subclasses."""
        raise NotImplementedError("Subclasses must implement run()")

    def cleanup(self):
        """Tear down any connections or temp files."""
        pass

    def report(self) -> Dict[str, Any]:
        """Return structured result."""
        return {
            "module": self.metadata.name,
            "target": self.options.get("RHOSTS", "unknown"),
            "result": self._results,
        }

    # --- utility methods for module authors ---

    def print_status(self, msg: str):
        print(f"  [*] {msg}")

    def print_good(self, msg: str):
        print(f"  [+] {msg}")

    def print_error(self, msg: str):
        print(f"  [-] {msg}")

    def print_warning(self, msg: str):
        print(f"  [!] {msg}")

    def store_loot(self, data: str, filename: str) -> str:
        """Save loot data to disk."""
        loot_dir = os.path.expanduser("~/.snakesploit/loot")
        os.makedirs(loot_dir, exist_ok=True)
        path = os.path.join(loot_dir, filename)
        with open(path, "w") as f:
            f.write(data)
        self.print_good(f"Loot stored: {path}")
        return path


class ModuleManager:
    """Discovers, loads, and manages modules."""

    def __init__(self, module_dirs: List[str] = None):
        self.modules: Dict[str, NovaModule] = {}
        self.categories: Dict[str, list] = {}
        self.module_dirs = module_dirs or [
            os.path.expanduser("~/snakesploit/modules/exploits"),
            os.path.expanduser("~/snakesploit/modules/aux"),
            os.path.expanduser("~/snakesploit/modules/payloads"),
            os.path.expanduser("~/snakesploit/data/modules_generated"),
        ]
        self._loaded = False

    def discover(self):
        """Walk module directories and index all .py files."""
        self.modules = {}
        self.categories = {}

        for mod_dir in self.module_dirs:
            if not os.path.isdir(mod_dir):
                continue
            # Use the directory basename as the category (e.g. 'aux', 'exploits')
            dir_category = os.path.basename(mod_dir.rstrip("/")) or "root"
            for root, dirs, files in os.walk(mod_dir):
                for f in files:
                    if f.endswith(".py") and not f.startswith("_"):
                        module_path = os.path.join(root, f)
                        rel_path = os.path.relpath(module_path, mod_dir)
                        # Use subdirector within category if nested
                        subdir = os.path.dirname(rel_path)
                        category = f"{dir_category}/{subdir}" if subdir else dir_category
                        if category not in self.categories:
                            self.categories[category] = []
                        self.categories[category].append(module_path)

        self._loaded = True
        total = sum(len(v) for v in self.categories.values())
        return total

    def load_module(self, module_path: str) -> Optional[NovaModule]:
        """Load a single module file and return an instance."""
        try:
            spec = importlib.util.spec_from_file_location(
                f"nova_mod_{hashlib.md5(module_path.encode()).hexdigest()}",
                module_path
            )
            if spec is None or spec.loader is None:
                return None
            mod = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = mod
            spec.loader.exec_module(mod)

            for name, obj in inspect.getmembers(mod):
                if (inspect.isclass(obj) and issubclass(obj, NovaModule)
                        and obj is not NovaModule):
                    instance = obj()
                    module_name = f"{instance.metadata.module_type}/{instance.metadata.name}"
                    self.modules[module_name] = instance
                    return instance
        except Exception as e:
            print(f"  [!] Failed to load {module_path}: {e}")
        return None

    def search(self, query: str) -> List[tuple]:
        """Search modules by name, CVE, or description.
        Returns list of (full_module_name, NovaModule_instance)."""
        results = []
        query = query.lower()
        for name, mod in self.modules.items():
            meta = mod.metadata
            if (query in meta.name.lower() or
                query in meta.description.lower() or
                any(query in cve.lower() for cve in meta.cve_ids)):
                results.append((name, mod))
        return results

    def get_module(self, name: str) -> Optional[NovaModule]:
        """Get module by its full name."""
        return self.modules.get(name)

    def reload_all(self):
        """Reload all modules from disk."""
        self.modules = {}
        self.discover()
        for cat, paths in self.categories.items():
            for path in paths:
                self.load_module(path)
        return len(self.modules)