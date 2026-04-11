# Personal Firewall

> **Local network monitor + rule engine -- real-time connection scanning, threat intel (15K+ IPs), cryptominer detection, DNS exfil alerts.**
> A free, self-hosted alternative to GlassWire, Little Snitch, and ZoneAlarm for users who want network visibility without the subscription.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Zero Dependencies](https://img.shields.io/badge/deps-zero_(stdlib_only)-brightgreen.svg)]()

---

## What it does

Scans all active network connections on your machine, cross-references them
against threat intelligence feeds (15,000+ malicious IPs from IPsum and
Feodo Tracker), and alerts on cryptominer ports, DNS exfiltration patterns,
lateral movement, and suspicious outbound connections. Runs as a one-shot
scan, continuous monitor, or persistent Windows service.

```
============================================================
  Personal Firewall v1.0
============================================================
[*] Blocked IPs loaded  : 5,000
[*] Connections found   : 121
[*] Active alerts       : 3

[CRITICAL] Threat Intel Match -- 185.220.101.42:443 (Feodo C2)
[HIGH]     Cryptominer Port  -- pool.minexmr.com:3333 (stratum)
[MEDIUM]   DNS Exfiltration  -- high-entropy subdomain queries
```

---

## Why you want this

| | **Personal Firewall** | GlassWire | Little Snitch | ZoneAlarm |
|---|---|---|---|---|
| **Price** | Free (MIT) | $29-$99/yr | $49 | Free (limited) |
| **Runtime deps** | **None** -- pure stdlib | Proprietary | macOS only | Proprietary |
| **Threat intel feeds** | 15K+ IPs (auto-update) | Basic | No | Basic |
| **Cryptominer detection** | Yes | No | No | No |
| **DNS exfil detection** | Yes | No | No | No |
| **Lateral movement alerts** | Yes | No | No | No |
| **Persistent service** | Yes (install.bat) | Always-on | Always-on | Always-on |
| **Cross-platform** | Windows + Mac + Linux | Windows | macOS | Windows |

---

## 60-second quickstart

```bash
git clone https://github.com/CyberEnthusiastic/personal-firewall.git
cd personal-firewall
python firewall.py scan
```

### One-command installer

```bash
./install.sh          # Linux / macOS / WSL / Git Bash
.\install.ps1         # Windows PowerShell
```

---

## How to run

```bash
python firewall.py scan                           # one-time snapshot
python firewall.py monitor                        # continuous (every 30s)
python firewall.py update                         # fetch latest threat intel
start reports\firewall_report.html                # open report (Windows)
open  reports/firewall_report.html                # open report (macOS)
xdg-open reports/firewall_report.html             # open report (Linux)
```

### Persistent Windows service

```batch
install.bat                                       # install as background service
uninstall.bat                                     # remove the service
```

---

## What it detects

| Detection | Severity | What it catches |
|-----------|----------|-----------------|
| Threat intel match | CRITICAL | Connection to known-malicious IP (15K+ feed) |
| Cryptominer port | HIGH | Stratum mining pool connections (3333, 14444) |
| DNS exfiltration | MEDIUM | High-entropy subdomain queries, tunneling |
| Lateral movement | HIGH | Internal connections on admin ports (445, 3389) |
| C2 beaconing | HIGH | Regular-interval callbacks to unknown infra |

---

## How to uninstall

```bash
# Remove Python environment and configs
./uninstall.sh        # Linux / macOS / WSL / Git Bash
.\uninstall.ps1       # Windows PowerShell

# Remove Windows persistent service
uninstall.bat
```

---

## Project layout

```
personal-firewall/
├── firewall.py           # main engine -- scanner, monitor, threat intel matcher
├── report_generator.py   # HTML report builder
├── rules/
│   ├── default_blocks.json   # built-in block rules (ports, patterns)
│   └── threat_intel_ips.json # cached threat intel IP blocklist
├── logs/
│   └── firewall_alerts.jsonl # persistent alert log
├── reports/              # generated HTML reports (gitignored)
├── .vscode/              # extensions.json, settings.json
├── install.sh            # installer (Linux/Mac/WSL)
├── install.ps1           # installer (Windows)
├── install.bat           # Windows persistent service installer
├── uninstall.sh          # uninstaller (Linux/Mac/WSL)
├── uninstall.ps1         # uninstaller (Windows)
├── uninstall.bat         # Windows service uninstaller
├── Dockerfile            # containerized runs
├── requirements.txt      # empty -- pure stdlib
├── LICENSE               # MIT
├── NOTICE                # attribution
├── SECURITY.md           # vulnerability disclosure
└── CONTRIBUTING.md       # how to send PRs
```

---

## License

MIT. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

---

Built by **[Mohith Vasamsetti (CyberEnthusiastic)](https://github.com/CyberEnthusiastic)** as part of the [AI Security Projects](https://github.com/CyberEnthusiastic?tab=repositories) suite.
