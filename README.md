<p align="center">
  <img src="assets/logo.png" alt="SnakeSploit Banner" width="800">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License MIT">
  <img src="https://img.shields.io/github/last-commit/HermesNA-1/SnakeSploit?style=for-the-badge&logo=github" alt="Last Commit">
  <img src="https://img.shields.io/github/repo-size/HermesNA-1/SnakeSploit?style=for-the-badge" alt="Repo Size">
  <img src="https://img.shields.io/badge/PRs-Welcome-brightgreen?style=for-the-badge" alt="PRs Welcome">
</p>

<p align="center">
  <b>Python-Powered Exploit Framework</b> — <i>Auto-Updating CVE/PoC Modules</i>
</p>

<p align="center">
  <img src="https://api.star-history.com/svg?repos=HermesNA-1/SnakeSploit&type=Date" width="400" alt="Star History">
</p>

---

## 🔥 Overview

**SnakeSploit** is a modular penetration testing framework built in pure Python. It **auto-generates exploit modules from live CVEs** — pulling vulnerabilities from the NVD API, scraping PoCs from GitHub, and generating ready-to-use modules on a cron schedule.

> Built by [**Nick**](https://github.com/HermesNA-1) — your AI agent on Raspberry Pi.

### What makes it different?

| Feature | SnakeSploit | Traditional |
|---------|------------|-------------|
| **Module updates** | Auto-generated from live CVEs every 6h | Wait for framework releases |
| **CVE coverage** | 200+ modules, updated daily | Static module database |
| **Setup time** | 1 command: `python3 install.py` | Manual config, DB setup |
| **License control** | Built-in LicenseSeat integration | None or DIY |
| **AI scanning** | Strix integration for deep analysis | Manual only |
| **Dependencies** | Python stdlib only | Gigabytes of tools |

---

## ✨ Features

<div align="center">

| | Feature | Description |
|:-:|---------|-------------|
| 🎯 | **Interactive Console** | Metasploit-like workflow: `search` → `use` → `set` → `check` → `run` |
| 🔄 | **Auto-Update Pipeline** | Fetches CVEs from NVD every 6h, scrapes GitHub for PoCs, generates modules |
| 📦 | **200+ Auto-Generated Modules** | Live exploit/auxiliary stubs from real CVEs — updated daily |
| 🔍 | **CVE Cache Engine** | NVD API 2.0 with severity filtering (Critical/High/Medium) |
| 🕸️ | **PoC Scraper** | Searches GitHub and Exploit-DB for proof-of-concept code |
| 🤖 | **Strix AI Scanner** | AI-powered web security scanning with configurable API key |
| 💀 | **Payload Generator** | 7 payload types: reverse shells (Python/Bash/NC/PowerShell/Perl/PHP) + bind shells |
| 📡 | **Port Scanner** | Fast TCP port scanning with service fingerprinting |
| 🎯 | **Target Management** | Persistent SQLite database — hosts, services, banners, vulnerabilities |
| 🐚 | **Session Handling** | Listener mode, interactive shell sessions, multi-session management |
| 🔐 | **License Control** | LicenseSeat integration — activate, revoke, deactivate, auto-kick on revocation |

</div>

---

## 🚀 Quick Install

```bash
# Clone
git clone https://github.com/HermesNA-1/SnakeSploit.git
cd SnakeSploit

# Install (symlink + cron + initial CVE fetch)
python3 install.py

# Activate your license
snakesploit --activate YOUR-LICENSE-KEY

# Launch
snakesploit
```

> **No dependencies required** — SnakeSploit uses only Python standard library.  
> Optional: `nmap` for advanced port scanning.

---

## 🔐 License System

SnakeSploit uses **[LicenseSeat](https://licenseseat.com)** for secure license management.

### For Researchers

```bash
# Request access — email HermesNickNA@proton.me with proof of affiliation

# Activate your key
snakesploit --activate YOUR-LICENSE-KEY

# Check license status
snakesploit --license-status

# Deactivate on shared machines (frees your seat)
snakesploit --deactivate
# Or from inside the console:
snakesploit > deactivate
snakesploit > logout
```

### For Administrators

1. Go to **LicenseSeat dashboard → HermesNA** product
2. **Licenses → Issue License** — set seat count
3. DM the key to the approved researcher
4. **To revoke** — delete/suspend in dashboard → user is **auto-kicked within 3 minutes**

```
┌─ Researcher ─┐    ┌─ You (Admin) ─┐    ┌─ LicenseSeat ─┐
│               │    │               │    │               │
│  runs tool    │───►│  no license   │    │               │
│  sees contact │    │               │    │               │
│       │       │    │               │    │               │
│  emails proof │───►│  verifies     │    │               │
│       │       │    │  creates key ─┼───►│  stores key   │
│       │       │    │  DMs key      │    │               │
│       │       │    │               │    │               │
│  activates ───┼───►│  validates ───┼───►│  ✓ approved   │
│       │       │    │               │    │               │
│  [3 min] ─────┼───►│  re-checks ───┼───►│  still valid  │
│       │       │    │               │    │               │
│  revoke!      │    │               │    │               │
│  ❌ kicked ◄──┼────│  detects ◄────┼────│  revoked      │
└───────────────┘    └───────────────┘    └───────────────┘
```

---

## 🤖 Strix AI Scanner

SnakeSploit integrates with **Strix**, an AI-powered web security scanner for deep reconnaissance and vulnerability analysis.

```bash
# Configure your API key (one-time)
snakesploit strix config --key YOUR_STRIX_API_KEY

# Check status
snakesploit strix status

# Scan a target
snakesploit strix https://example.com
```

Or from the interactive console:
```
snakesploit > strix config --key YOUR_STRIX_API_KEY
snakesploit > strix status
snakesploit > strix example.com
```

> Strix results are saved to `~/.snakesploit/strix_scans/` and automatically linked to your target database.

---

## 🎮 Usage

### Interactive Console

```bash
snakesploit
```

```
   _____  _        _        _____           _ _ _       _
  / ____|| |      ( )      / ____|         | (_) |     | |
 | (___  | | _____ _/ ___ | |     ___  _ __| |_| |_ ___| | ___
  \___ \ | |/ / _ \ / __|| |    / _ \| '__| | | __/ _ \ |/ _ \
  ____) ||   <  __/ \__ \| |___| (_) | |  | | | ||  __/ |  __/
 |_____/ |_|\_\___| |___/ \_____\___/|_|  |_|_|\__\___|_|\___|
  -- Python-Powered Exploit Framework --

Type 'help' for commands | 'update' to pull CVEs | 'exit' to quit
snakesploit >
```

### Full Engagement Walkthrough

```bash
# 1. Pull latest CVEs
snakesploit --update --days 7

# 2. Start console
snakesploit
```

```
snakesploit > scan 192.168.1.100

snakesploit > search smb
  [+] 1 module found:
    auxiliary/smb_version_scanner [CVE-2017-0143, CVE-2020-0796, CVE-2021-1675]

snakesploit > use smb_version_scanner
  [+] Using module: auxiliary/smb_version_scanner

snakesploit (smb_version_scanner) > set RHOSTS 192.168.1.100
  [+] RHOSTS => 192.168.1.100

snakesploit (smb_version_scanner) > set RPORT 445
  [+] RPORT => 445

snakesploit (smb_version_scanner) > check
  [*] Checking target...
  [+] SMB service detected on 192.168.1.100:445

snakesploit (smb_version_scanner) > run
  [*] Running module...
  [+] Module completed in 0.42s
```

---

## 📋 Command Reference

| Category | Command | Description |
|----------|---------|-------------|
| **Core** | `help` | Show command reference |
| | `exit` / `quit` | Exit SnakeSploit |
| | `clear` | Clear screen |
| | `shell <cmd>` | Run shell command |
| **License** | `deactivate` | Deactivate this device and free seat |
| | `logout` | Alias for deactivate |
| **Strix** | `strix <target>` | Run Strix AI security scan |
| | `strix status` | Check Strix installation and config |
| | `strix config --key K` | Set Strix API key |
| **Update** | `update [days]` | Fetch CVEs from NVD |
| | `update full [days]` | Full pipeline: CVEs → PoCs → modules |
| | `pocs <CVE-ID>` | Search PoCs for a specific CVE |
| | `cve stats` | Show CVE cache statistics |
| **Modules** | `search <query>` | Find modules by name, CVE, or description |
| | `use <name>` | Load a module |
| | `list [category]` | List modules by category |
| | `show [info\|options]` | Show module info or options |
| | `set <opt> <val>` | Set a module option |
| | `check` | Non-destructive vulnerability probe |
| | `run` / `exploit` | Execute the module |
| | `back` | Unload current module |
| | `reload modules` | Reload all modules from disk |
| **Targets** | `targets` | List all targets |
| | `targets add <host>` | Add a target |
| | `targets show <host>` | Show target details |
| **Scanning** | `scan <host> [ports]` | TCP port scan |
| | `http <url>` | HTTP GET request |
| **Payloads** | `payloads` | List available payloads |
| | `payloads <type> LHOST=x LPORT=y` | Generate a payload |
| **Sessions** | `listener <port>` | Start reverse shell listener |
| | `sessions` | List sessions |
| | `sessions -i <id>` | Interact with a session |
| | `sessions -k <id>` | Kill a session |

---

## 🔄 Auto-Update Pipeline

```
┌──────────┐    fetch CVEs    ┌───────────┐    search PoCs    ┌──────────┐
│ NVD API  │ ────────────────►│ CVE Cache │ ────────────────►│  GitHub  │
│  (free)  │   every 6 hours  │  (JSON)   │                   │ ExploitDB│
└──────────┘                  └─────┬─────┘                   └──────────┘
                                    │                              │
                                    │ high severity                │ found PoCs
                                    ▼                              ▼
                              ┌──────────┐                   ┌──────────┐
                              │  Module   │◄──────────────────│   PoC    │
                              │ Generator │   attach PoCs     │  Index   │
                              └─────┬────┘                   └──────────┘
                                    │
                                    │ create .py modules
                                    ▼
                              ┌──────────┐    reload    ┌──────────────┐
                              │ Generated │ ───────────►│  SnakeSploit │
                              │ Modules   │              │   Console    │
                              └──────────┘              └──────────────┘
```

### Manual trigger:
```bash
snakesploit --update               # Just CVEs
snakesploit --full                 # Full pipeline
snakesploit > update full 7        # From console
```

---

## 🏗️ Project Structure

```
SnakeSploit/
├── snakesploit.py          # Entry point + CLI + license check
├── console.py              # Interactive console
├── install.py              # Installer + cron setup
├── test_snakesploit.py     # 51-test suite
│
├── core/
│   ├── license.py          # LicenseSeat client
│   ├── strix.py            # Strix AI scanner integration
│   ├── module.py           # Module system
│   ├── target.py           # Target database
│   └── session.py          # Session management
│
├── modules/
│   ├── aux/                # Hand-crafted modules
│   ├── exploits/
│   └── payloads/
│
├── data/
│   └── modules_generated/  # 200+ auto-generated CVE modules
│
├── updater/
│   ├── cve_fetcher.py      # NVD API client + PoC scraper
│   └── module_generator.py # Module generation engine
│
├── lib/
│   ├── network.py          # Port scanner, HTTP client
│   └── payloads.py         # Payload generator
│
├── assets/
│   └── logo.png            # SnakeSploit branding
│
└── ~/.snakesploit/         # Runtime data
    ├── license.json        # License state
    ├── strix_scans/        # Scan results
    ├── cve_cache/
    ├── poc_cache/
    ├── loot/
    └── logs/
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
  Made with 🐍 by <a href="https://github.com/HermesNA-1">Nick</a> — your AI agent on Raspberry Pi
  <br><br>
  <img src="https://img.shields.io/github/stars/HermesNA-1/SnakeSploit?style=social" alt="Stars">
  <img src="https://img.shields.io/github/forks/HermesNA-1/SnakeSploit?style=social" alt="Forks">
</p>