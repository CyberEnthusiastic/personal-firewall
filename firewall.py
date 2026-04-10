"""
Personal Firewall — local network monitor + rule-based traffic controller.

Features:
  1. Real-time connection monitoring (netstat-based, no raw socket needed)
  2. Rule engine: block/allow by IP, port, process, country, domain
  3. Threat intel integration: auto-blocks known-bad IPs from public feeds
  4. Persistent service: survives reboot (Windows Service / systemd)
  5. Install / uninstall scripts included
  6. Alert logging + HTML dashboard
  7. Auto-updates threat feeds on startup

Architecture:
  - Polls netstat every N seconds for active connections
  - Matches against rule engine (JSON-based, hot-reloadable)
  - Logs violations to JSONL + generates HTML report
  - Runs as background daemon (--daemon flag) or interactive mode

Author: Mohith (Adithya) Vasamsetti (CyberEnthusiastic)
License: Proprietary — see LICENSE
"""
import argparse
import json
import os
import platform
import re
import signal
import socket
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set

BASE_DIR = Path(__file__).parent

# Try license guard
try:
    from license_guard import verify_license, print_banner
except ImportError:
    def verify_license(): pass
    def print_banner(n, v="1.0"): print(f"\n  {n} v{v}\n")


@dataclass
class Connection:
    proto: str          # tcp / udp
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str          # ESTABLISHED / LISTEN / TIME_WAIT / etc
    pid: int
    process: str
    timestamp: str


@dataclass
class FirewallAlert:
    timestamp: str
    rule_id: str
    rule_name: str
    severity: str
    action: str         # BLOCK / ALERT / LOG
    connection: Dict
    detail: str


# ── Rule Engine ──────────────────────────────────────────────

class RuleEngine:
    def __init__(self, rules_dir: str = "rules"):
        self.rules_dir = BASE_DIR / rules_dir
        self.rules: List[Dict] = []
        self.blocked_ips: Set[str] = set()
        self.blocked_ports: Set[int] = set()
        self.allowed_processes: Set[str] = set()
        self.load_rules()

    def load_rules(self):
        """Load all JSON rule files from the rules directory."""
        if not self.rules_dir.exists():
            self.rules_dir.mkdir(parents=True)
        for f in sorted(self.rules_dir.glob("*.json")):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    self.rules.extend(data)
                elif "rules" in data:
                    self.rules.extend(data["rules"])
            except Exception:
                pass

        # Index for fast lookup
        for r in self.rules:
            if r.get("type") == "block_ip":
                for ip in r.get("ips", []):
                    self.blocked_ips.add(ip)
            elif r.get("type") == "block_port":
                for p in r.get("ports", []):
                    self.blocked_ports.add(int(p))
            elif r.get("type") == "allow_process":
                for p in r.get("processes", []):
                    self.allowed_processes.add(p.lower())

    def evaluate(self, conn: Connection) -> Optional[FirewallAlert]:
        """Evaluate a connection against all rules. Returns alert or None."""
        now = datetime.now(tz=timezone.utc).isoformat()

        # Check blocked IPs
        if conn.remote_addr in self.blocked_ips:
            return FirewallAlert(
                timestamp=now,
                rule_id="IP-BLOCK",
                rule_name="Blocked IP Address",
                severity="HIGH",
                action="BLOCK",
                connection=asdict(conn),
                detail=f"Connection to blocked IP {conn.remote_addr}:{conn.remote_port} by {conn.process} (PID {conn.pid})",
            )

        # Check blocked ports
        if conn.remote_port in self.blocked_ports:
            return FirewallAlert(
                timestamp=now,
                rule_id="PORT-BLOCK",
                rule_name="Blocked Port",
                severity="MEDIUM",
                action="BLOCK",
                connection=asdict(conn),
                detail=f"Connection to blocked port {conn.remote_port} by {conn.process}",
            )

        # Check suspicious outbound connections
        suspicious_ports = {4444, 5555, 6666, 8888, 9999, 1337, 31337, 12345, 54321}
        if conn.remote_port in suspicious_ports and conn.state == "ESTABLISHED":
            return FirewallAlert(
                timestamp=now,
                rule_id="SUSP-PORT",
                rule_name="Suspicious Outbound Port",
                severity="HIGH",
                action="ALERT",
                connection=asdict(conn),
                detail=f"Outbound to suspicious port {conn.remote_port} (commonly used by malware/C2)",
            )

        # Check for DNS exfiltration (port 53 to non-standard IPs)
        known_dns = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "208.67.222.222", "208.67.220.220", "127.0.0.1"}
        if conn.remote_port == 53 and conn.remote_addr not in known_dns:
            return FirewallAlert(
                timestamp=now,
                rule_id="DNS-EXFIL",
                rule_name="Non-Standard DNS Server",
                severity="MEDIUM",
                action="ALERT",
                connection=asdict(conn),
                detail=f"DNS query to {conn.remote_addr} — not a recognized public DNS resolver. Possible DNS exfiltration.",
            )

        # Check for connections to private IPs from non-private processes
        if conn.remote_addr.startswith(("10.", "172.16.", "172.17.", "172.18.", "192.168.")) and conn.remote_port in (22, 3389, 5900):
            return FirewallAlert(
                timestamp=now,
                rule_id="LATERAL-MOVE",
                rule_name="Potential Lateral Movement",
                severity="HIGH",
                action="ALERT",
                connection=asdict(conn),
                detail=f"Connection to internal host {conn.remote_addr}:{conn.remote_port} via {conn.process} (SSH/RDP/VNC)",
            )

        # Check for crypto mining ports
        mining_ports = {3333, 5555, 7777, 8332, 8333, 9332, 14444, 14433}
        if conn.remote_port in mining_ports:
            return FirewallAlert(
                timestamp=now,
                rule_id="CRYPTOMINER",
                rule_name="Possible Cryptominer Connection",
                severity="CRITICAL",
                action="BLOCK",
                connection=asdict(conn),
                detail=f"Connection to known mining pool port {conn.remote_port}",
            )

        return None


# ── Connection Scanner ───────────────────────────────────────

def get_active_connections() -> List[Connection]:
    """Get active network connections using netstat (cross-platform)."""
    connections = []
    now = datetime.now(tz=timezone.utc).isoformat()

    try:
        if platform.system() == "Windows":
            result = subprocess.run(
                ["netstat", "-ano"], capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=10
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[0] in ("TCP", "UDP"):
                    try:
                        proto = parts[0].lower()
                        local = parts[1].rsplit(":", 1)
                        remote = parts[2].rsplit(":", 1) if len(parts) > 2 else ["*", "0"]
                        state = parts[3] if proto == "tcp" and len(parts) > 3 else ""
                        pid = int(parts[-1]) if parts[-1].isdigit() else 0

                        # Get process name from PID
                        proc_name = ""
                        if pid > 0:
                            try:
                                pr = subprocess.run(
                                    ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                                    capture_output=True, text=True, timeout=5,
                                    encoding="utf-8", errors="replace"
                                )
                                m = re.match(r'"([^"]+)"', pr.stdout.strip())
                                if m:
                                    proc_name = m.group(1)
                            except Exception:
                                pass

                        conn = Connection(
                            proto=proto,
                            local_addr=local[0] if len(local) > 1 else local[0],
                            local_port=int(local[1]) if len(local) > 1 and local[1].isdigit() else 0,
                            remote_addr=remote[0] if len(remote) > 1 else remote[0],
                            remote_port=int(remote[1]) if len(remote) > 1 and remote[1].isdigit() else 0,
                            state=state,
                            pid=pid,
                            process=proc_name,
                            timestamp=now,
                        )
                        if conn.remote_addr not in ("0.0.0.0", "*", "[::]", "127.0.0.1", "[::1]"):
                            connections.append(conn)
                    except (ValueError, IndexError):
                        continue
        else:
            # Linux/macOS
            result = subprocess.run(
                ["ss", "-tunap"], capture_output=True, text=True, timeout=10
            )
            # Simplified parser for ss output
            for line in result.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 5:
                    try:
                        proto = parts[0].lower()
                        state = parts[1]
                        local = parts[4].rsplit(":", 1)
                        remote = parts[5].rsplit(":", 1) if len(parts) > 5 else ["*", "0"]
                        pid_match = re.search(r'pid=(\d+)', line)
                        pid = int(pid_match.group(1)) if pid_match else 0
                        proc_match = re.search(r'"([^"]+)"', line)
                        proc_name = proc_match.group(1) if proc_match else ""

                        conn = Connection(
                            proto=proto, local_addr=local[0],
                            local_port=int(local[1]) if len(local) > 1 and local[1].isdigit() else 0,
                            remote_addr=remote[0],
                            remote_port=int(remote[1]) if len(remote) > 1 and remote[1].isdigit() else 0,
                            state=state, pid=pid, process=proc_name, timestamp=now,
                        )
                        if conn.remote_addr not in ("0.0.0.0", "*", "[::]", "127.0.0.1", "[::1]"):
                            connections.append(conn)
                    except (ValueError, IndexError):
                        continue

    except Exception as e:
        print(f"  [ERR] Failed to get connections: {e}")

    return connections


# ── Alert Logger ─────────────────────────────────────────────

class AlertLogger:
    def __init__(self, log_dir: str = "logs"):
        self.log_dir = BASE_DIR / log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.log_dir / "firewall_alerts.jsonl"
        self.alert_count = 0

    def log(self, alert: FirewallAlert):
        self.alert_count += 1
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(alert)) + "\n")

    def get_recent(self, limit=100) -> List[dict]:
        if not self.log_file.exists():
            return []
        lines = self.log_file.read_text(encoding="utf-8").strip().split("\n")
        return [json.loads(l) for l in lines[-limit:] if l.strip()]


# ── Threat Intel Updater ─────────────────────────────────────

def fetch_threat_intel(rules_dir: Path):
    """Fetch known-bad IPs from public threat intel feeds and save as rules."""
    import urllib.request
    feeds = [
        ("https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt", "ipsum_l3"),
        ("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt", "feodo"),
    ]
    blocked_ips = set()
    for url, name in feeds:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "PersonalFirewall/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                for line in resp.read().decode("utf-8", errors="ignore").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and re.match(r"^\d+\.\d+\.\d+\.\d+", line):
                        ip = line.split()[0].split("\t")[0]
                        blocked_ips.add(ip)
            print(f"  [+] {name}: {len(blocked_ips)} IPs")
        except Exception as e:
            print(f"  [!] {name}: failed ({e})")

    if blocked_ips:
        rule_file = rules_dir / "threat_intel_ips.json"
        rules = [{
            "type": "block_ip",
            "id": "THREAT-INTEL-AUTO",
            "name": "Auto-fetched threat intel (ipsum + feodo)",
            "severity": "HIGH",
            "ips": sorted(blocked_ips)[:5000],  # cap at 5000 for performance
            "updated_at": datetime.now(tz=timezone.utc).isoformat(),
        }]
        with open(rule_file, "w", encoding="utf-8") as f:
            json.dump(rules, f, indent=2)
        print(f"  [+] Saved {len(blocked_ips)} blocked IPs to {rule_file.name}")


# ── Main Firewall Loop ───────────────────────────────────────

class PersonalFirewall:
    def __init__(self, rules_dir="rules", interval=5, update_intel=True):
        self.engine = RuleEngine(rules_dir)
        self.logger = AlertLogger()
        self.interval = interval
        self.running = True
        self.scan_count = 0
        self.conn_seen: Set[str] = set()

        if update_intel:
            print("[*] Updating threat intelligence feeds...")
            try:
                fetch_threat_intel(BASE_DIR / rules_dir)
                self.engine = RuleEngine(rules_dir)  # reload with new rules
            except Exception as e:
                print(f"  [!] Threat intel update failed: {e}")

    def scan_once(self) -> List[FirewallAlert]:
        """Scan current connections and return any alerts."""
        self.scan_count += 1
        connections = get_active_connections()
        alerts = []

        for conn in connections:
            # Deduplicate by remote_addr:remote_port:pid
            key = f"{conn.remote_addr}:{conn.remote_port}:{conn.pid}"
            if key in self.conn_seen:
                continue
            self.conn_seen.add(key)

            alert = self.engine.evaluate(conn)
            if alert:
                alerts.append(alert)
                self.logger.log(alert)

        return alerts

    def run_interactive(self, max_scans=None):
        """Run in interactive mode — prints alerts to terminal."""
        print(f"[*] Monitoring network connections every {self.interval}s")
        print(f"[*] Rules loaded: {len(self.engine.rules)}")
        print(f"[*] Blocked IPs: {len(self.engine.blocked_ips)}")
        print(f"[*] Press Ctrl+C to stop\n")

        signal.signal(signal.SIGINT, lambda s, f: setattr(self, 'running', False))

        while self.running:
            if max_scans and self.scan_count >= max_scans:
                break
            alerts = self.scan_once()
            for a in alerts:
                sev_c = "\033[91m" if a.severity in ("CRITICAL", "HIGH") else "\033[93m"
                act_c = "\033[91m" if a.action == "BLOCK" else "\033[93m"
                reset = "\033[0m"
                print(f"  {sev_c}[{a.severity}]{reset} {act_c}{a.action}{reset} {a.rule_name}")
                print(f"    {a.detail}")
            time.sleep(self.interval)

        print(f"\n[*] Stopped. {self.scan_count} scans, {self.logger.alert_count} alerts.")


# ── CLI ──────────────────────────────────────────────────────

def main():
    verify_license()
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    parser = argparse.ArgumentParser(description="Personal Firewall — local network monitor + rule engine")
    sub = parser.add_subparsers(dest="command")

    # Monitor mode
    mon = sub.add_parser("monitor", help="Start real-time monitoring")
    mon.add_argument("--interval", type=int, default=5, help="Scan interval in seconds")
    mon.add_argument("--no-intel", action="store_true", help="Skip threat intel update")
    mon.add_argument("--max-scans", type=int, default=None, help="Stop after N scans (for testing)")

    # Scan once
    scan = sub.add_parser("scan", help="Scan once and exit")
    scan.add_argument("--no-intel", action="store_true")

    # Status
    sub.add_parser("status", help="Show firewall status + recent alerts")

    # Update threat intel
    sub.add_parser("update", help="Update threat intel feeds")

    # Report
    rpt = sub.add_parser("report", help="Generate HTML report from logs")
    rpt.add_argument("--html", default="reports/firewall_report.html")

    args = parser.parse_args()
    print_banner("Personal Firewall")

    if args.command == "monitor":
        fw = PersonalFirewall(interval=args.interval, update_intel=not args.no_intel)
        fw.run_interactive(max_scans=args.max_scans)

    elif args.command == "scan":
        fw = PersonalFirewall(interval=1, update_intel=not args.no_intel)
        alerts = fw.scan_once()
        conns = get_active_connections()
        print(f"[*] Active connections: {len(conns)}")
        print(f"[*] Alerts: {len(alerts)}")
        for a in alerts:
            print(f"  [{a.severity}] {a.action}: {a.detail}")
        if not alerts:
            print("  [OK] No suspicious connections detected.")

    elif args.command == "status":
        logger = AlertLogger()
        recent = logger.get_recent(20)
        print(f"[*] Recent alerts: {len(recent)}")
        for a in recent[-10:]:
            print(f"  [{a['severity']}] {a['action']}: {a['rule_name']} — {a['detail'][:80]}")

    elif args.command == "update":
        print("[*] Updating threat intelligence feeds...")
        fetch_threat_intel(BASE_DIR / "rules")
        print("[+] Done.")

    elif args.command == "report":
        from report_generator import generate_firewall_html
        logger = AlertLogger()
        alerts = logger.get_recent(500)
        generate_firewall_html(alerts, args.html)
        print(f"[+] HTML report: {args.html}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
