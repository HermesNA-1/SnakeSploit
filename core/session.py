"""
SnakeSploit Session Handling — manage active sessions (reverse shells, bind shells, etc.)
"""

import json
import os
import socket
import threading
import subprocess
import time
from datetime import datetime
from typing import Dict, Optional, Any, Callable
from dataclasses import dataclass, field


@dataclass
class NovaSession:
    """Represents an active session (shell, meterpreter-like, etc.)"""
    id: str
    session_type: str  # shell, meterpreter, bind, reverse
    target_host: str
    target_port: int
    local_port: int = 0
    platform: str = "unknown"
    transport: str = "tcp"
    first_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    last_active: str = field(default_factory=lambda: datetime.now().isoformat())
    dead: bool = False
    _conn: Any = None
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _buffer: str = ""

    def send(self, data: str) -> bool:
        """Send data to the session."""
        if self.dead or not self._conn:
            return False
        try:
            self._conn.send((data + "\n").encode())
            self.last_active = datetime.now().isoformat()
            return True
        except Exception:
            self.dead = True
            return False

    def recv(self, timeout: float = 2.0) -> str:
        """Receive data from the session."""
        if self.dead or not self._conn:
            return ""

        self._conn.settimeout(timeout)
        try:
            data = self._conn.recv(65535).decode(errors="replace")
            self._buffer += data
            self.last_active = datetime.now().isoformat()
            return data
        except socket.timeout:
            return ""
        except Exception:
            self.dead = True
            return ""

    def interact(self) -> str:
        """Interactive read with no timeout — blocks until data."""
        if self.dead or not self._conn:
            return ""
        try:
            self._conn.settimeout(None)
            data = self._conn.recv(65535).decode(errors="replace")
            self.last_active = datetime.now().isoformat()
            return data
        except Exception:
            self.dead = True
            return ""

    def close(self):
        """Close the session connection."""
        self.dead = True
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.session_type,
            "target": f"{self.target_host}:{self.target_port}",
            "platform": self.platform,
            "first_seen": self.first_seen,
            "last_active": self.last_active,
            "dead": self.dead,
        }


class SessionManager:
    """Manages all active and dead sessions."""

    def __init__(self):
        self.sessions: Dict[str, NovaSession] = {}
        self._counter = 0
        self._db_path = os.path.expanduser("~/.snakesploit/sessions.json")

    def create_session(self, session_type: str, target_host: str,
                       target_port: int, conn: Any = None,
                       platform: str = "unknown") -> NovaSession:
        self._counter += 1
        session_id = f"{session_type[:3]}_{self._counter}"
        session = NovaSession(
            id=session_id,
            session_type=session_type,
            target_host=target_host,
            target_port=target_port,
            platform=platform,
            _conn=conn,
        )
        self.sessions[session_id] = session
        self.save()
        return session

    def get(self, session_id: str) -> Optional[NovaSession]:
        return self.sessions.get(session_id)

    def close_session(self, session_id: str):
        if session_id in self.sessions:
            self.sessions[session_id].close()

    def list_active(self) -> Dict[str, NovaSession]:
        return {k: v for k, v in self.sessions.items() if not v.dead}

    def list_dead(self) -> Dict[str, NovaSession]:
        return {k: v for k, v in self.sessions.items() if v.dead}

    def summary(self) -> dict:
        return {
            "total": len(self.sessions),
            "active": len(self.list_active()),
            "dead": len(self.list_dead()),
        }

    def save(self):
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
        data = {k: v.to_dict() for k, v in self.sessions.items()}
        with open(self._db_path, "w") as f:
            json.dump(data, f, indent=2)

    def load(self):
        if os.path.exists(self._db_path):
            with open(self._db_path) as f:
                data = json.load(f)
            for sid, sdata in data.items():
                s = NovaSession(
                    id=sdata["id"],
                    session_type=sdata["type"],
                    target_host=sdata.get("target", "unknown").split(":")[0],
                    target_port=int(sdata.get("target", ":0").split(":")[1] or 0),
                    platform=sdata.get("platform", "unknown"),
                    dead=sdata.get("dead", True),
                )
                self.sessions[sid] = s