"""
SnakeSploit Target Management — track targets, open ports, services, vulnerabilities.
"""

import json
import os
import socket
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


@dataclass
class Service:
    port: int
    protocol: str = "tcp"
    service: str = "unknown"
    banner: str = ""
    version: str = ""
    state: str = "open"

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "banner": self.banner,
            "version": self.version,
            "state": self.state,
        }


@dataclass
class Target:
    host: str
    hostname: str = ""
    os: str = "unknown"
    os_cpe: str = ""
    services: Dict[int, Service] = field(default_factory=dict)
    vulnerabilities: List[dict] = field(default_factory=list)
    notes: Dict[str, Any] = field(default_factory=dict)
    first_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now().isoformat())

    def add_service(self, service: Service):
        self.services[service.port] = service
        self.last_seen = datetime.now().isoformat()

    def add_vulnerability(self, cve_id: str, description: str, source: str = "manual",
                          score: float = 0.0, module: str = ""):
        self.vulnerabilities.append({
            "cve_id": cve_id,
            "description": description,
            "source": source,
            "score": score,
            "module": module,
            "date": datetime.now().isoformat(),
        })
        self.last_seen = datetime.now().isoformat()

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "hostname": self.hostname,
            "os": self.os,
            "os_cpe": self.os_cpe,
            "services": {str(k): v.to_dict() for k, v in self.services.items()},
            "vulnerabilities": self.vulnerabilities,
            "notes": self.notes,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }

    @staticmethod
    def from_dict(data: dict) -> "Target":
        t = Target(host=data["host"])
        t.hostname = data.get("hostname", "")
        t.os = data.get("os", "unknown")
        t.os_cpe = data.get("os_cpe", "")
        t.vulnerabilities = data.get("vulnerabilities", [])
        t.notes = data.get("notes", {})
        t.first_seen = data.get("first_seen", "")
        t.last_seen = data.get("last_seen", "")
        for port_str, svc_data in data.get("services", {}).items():
            svc = Service(**svc_data)
            t.services[int(port_str)] = svc
        return t

    @staticmethod
    def resolve_host(target_str: str) -> str:
        """Resolve hostname to IP if needed."""
        # Strip port if present
        host = target_str.split(":")[0]
        try:
            socket.getaddrinfo(host, None)
            return host
        except socket.gaierror:
            return host  # Return as-is, might be IP


class TargetManager:
    """Manages the target database."""

    def __init__(self):
        self.targets: Dict[str, Target] = {}
        self._db_path = os.path.expanduser("~/.snakesploit/targets.json")

    def add(self, host: str) -> Target:
        if host not in self.targets:
            self.targets[host] = Target(host=host)
        return self.targets[host]

    def get(self, host: str) -> Optional[Target]:
        return self.targets.get(host)

    def remove(self, host: str):
        self.targets.pop(host, None)

    def all(self) -> List[Target]:
        return list(self.targets.values())

    def search(self, query: str) -> List[Target]:
        query = query.lower()
        results = []
        for t in self.targets.values():
            if (query in t.host.lower() or query in t.hostname.lower()
                    or query in t.os.lower()):
                results.append(t)
            # Check services
            for svc in t.services.values():
                if query in svc.service.lower():
                    results.append(t)
                    break
        return results

    def vulnerable_hosts(self) -> List[Target]:
        return [t for t in self.targets.values() if t.vulnerabilities]

    def summary(self) -> dict:
        return {
            "total_targets": len(self.targets),
            "total_services": sum(len(t.services) for t in self.targets.values()),
            "total_vulnerabilities": sum(len(t.vulnerabilities) for t in self.targets.values()),
            "vulnerable_hosts": len(self.vulnerable_hosts()),
        }

    def save(self):
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
        data = {host: t.to_dict() for host, t in self.targets.items()}
        with open(self._db_path, "w") as f:
            json.dump(data, f, indent=2)

    def load(self):
        if os.path.exists(self._db_path):
            with open(self._db_path) as f:
                data = json.load(f)
            for host, tdata in data.items():
                self.targets[host] = Target.from_dict(tdata)