"""
Pre-Scripted Demo Alert Generator — 18-Alert Sequence
Team SY-A9 | Shanteshwar

Insurance policy for presentation day.
Sends 18 crafted alerts to POST /api/v1/classify with 3-second delays.
Severity escalates for drama — honeypot trigger is the climax at alert 15.

Usage:
    python demo_alerts.py
    python demo_alerts.py --url https://your-railway-url.app/api/v1/classify
"""

import sys
import time

import requests

# ──────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────

BASE_URL = "http://localhost:8000/api/v1/classify"

# Allow overriding via CLI for Railway / production demo
if len(sys.argv) > 1 and sys.argv[1] == "--url" and len(sys.argv) > 2:
    BASE_URL = sys.argv[2]

DELAY_SECONDS = 3

# ──────────────────────────────────────────────────────────────────────
# 18 Pre-Crafted Alerts (in escalating severity order)
# ──────────────────────────────────────────────────────────────────────

ALERTS = [
    # ── 3 BENIGN — normal business traffic ────────────────────────
    {
        "raw_log": "GET /index.html HTTP/1.1 200",
        "source_ip": "192.168.1.10",
        "dest_ip": "192.168.1.100",
        "port": 80,
        "event_type": "HTTP_REQUEST",
    },
    {
        "raw_log": "DNS query for google.com from 192.168.1.11",
        "source_ip": "192.168.1.11",
        "dest_ip": "8.8.8.8",
        "port": 53,
        "event_type": "DNS_QUERY",
    },
    {
        "raw_log": "Scheduled backup job started by svc_backup",
        "source_ip": "192.168.1.50",
        "dest_ip": "192.168.1.200",
        "port": 445,
        "event_type": "FILE_COPY",
    },

    # ── 3 LOW — port scans and probes ─────────────────────────────
    {
        "raw_log": "SYN scan on ports 21-25 from 203.0.113.50",
        "source_ip": "203.0.113.50",
        "dest_ip": "192.168.1.5",
        "port": 22,
        "event_type": "PORT_SCAN",
    },
    {
        "raw_log": "ICMP sweep from 198.51.100.10",
        "source_ip": "198.51.100.10",
        "dest_ip": "192.168.1.0",
        "port": 0,
        "event_type": "ICMP_PING",
    },
    {
        "raw_log": "HTTP OPTIONS probe on /api",
        "source_ip": "198.51.100.20",
        "dest_ip": "192.168.1.100",
        "port": 8080,
        "event_type": "HTTP_OPTIONS",
    },

    # ── 3 MEDIUM — failed auth attempts ───────────────────────────
    {
        "raw_log": "Failed SSH login for root from 185.100.86.10 (attempt 3/10)",
        "source_ip": "185.100.86.10",
        "dest_ip": "192.168.1.5",
        "port": 22,
        "event_type": "AUTH_FAIL",
    },
    {
        "raw_log": "VPN authentication failure for user admin from 91.108.4.1",
        "source_ip": "91.108.4.1",
        "dest_ip": "192.168.1.1",
        "port": 1194,
        "event_type": "VPN_FAIL",
    },
    {
        "raw_log": "RDP brute force detected — 15 failed attempts in 30s",
        "source_ip": "185.220.100.5",
        "dest_ip": "192.168.1.20",
        "port": 3389,
        "event_type": "RDP_BRUTEFORCE",
    },

    # ── 3 HIGH — lateral movement attempts ────────────────────────
    {
        "raw_log": "SMB connection from WS_3 to APP_SERVER admin$ share",
        "source_ip": "192.168.1.33",
        "dest_ip": "192.168.1.100",
        "port": 445,
        "event_type": "SMB_LATERAL",
        "accessed_path": "\\\\APP_SERVER\\admin$",
    },
    {
        "raw_log": "Unusual process netcat spawned by svchost.exe on WS_2",
        "source_ip": "192.168.1.32",
        "dest_ip": "185.220.101.1",
        "port": 4444,
        "event_type": "PROCESS_SPAWN",
    },
    {
        "raw_log": "Kerberoasting attempt — TGS-REQ for service account from WS_1",
        "source_ip": "192.168.1.31",
        "dest_ip": "192.168.1.10",
        "port": 88,
        "event_type": "KERBEROAST",
    },

    # ── 2 CRITICAL — known-bad IPs ────────────────────────────────
    {
        "raw_log": "Connection to known Tor exit node 185.220.101.47",
        "source_ip": "192.168.1.25",
        "dest_ip": "185.220.101.47",
        "port": 9001,
        "event_type": "C2_CALLBACK",
    },
    {
        "raw_log": "Cobalt Strike beacon detected — characteristic sleep jitter",
        "source_ip": "91.108.56.100",
        "dest_ip": "192.168.1.100",
        "port": 443,
        "event_type": "C2_BEACON",
    },

    # ── 1 HONEYPOT TRIGGER — climax of the demo ──────────────────
    {
        "raw_log": "File open: /etc/db_credentials_prod.conf by process python3 PID 4471",
        "source_ip": "192.168.1.35",
        "dest_ip": "192.168.1.200",
        "port": 5432,
        "event_type": "FILE_READ",
        "accessed_path": "/etc/db_credentials_prod.conf",
    },

    # ── 3 post-honeypot escalation (same source_ip = lateral spread)
    {
        "raw_log": "SMB lateral movement from 192.168.1.35 to DOMAIN_CTRL",
        "source_ip": "192.168.1.35",
        "dest_ip": "192.168.1.10",
        "port": 445,
        "event_type": "SMB_LATERAL",
        "accessed_path": "\\\\DOMAIN_CTRL\\SYSVOL",
    },
    {
        "raw_log": "Credential dump attempt — lsass.exe memory read from 192.168.1.35",
        "source_ip": "192.168.1.35",
        "dest_ip": "192.168.1.10",
        "port": 445,
        "event_type": "CREDENTIAL_DUMP",
    },
    {
        "raw_log": "Data exfiltration — 2.4 GB upload to 185.220.101.47 from 192.168.1.35",
        "source_ip": "192.168.1.35",
        "dest_ip": "185.220.101.47",
        "port": 443,
        "event_type": "DATA_EXFIL",
    },
]

# ──────────────────────────────────────────────────────────────────────
# Runner
# ──────────────────────────────────────────────────────────────────────

def main():
    total = len(ALERTS)
    print(f"=== SOC Demo Alert Generator — {total} alerts ===")
    print(f"Target: {BASE_URL}")
    print(f"Delay:  {DELAY_SECONDS}s between alerts\n")

    for i, alert in enumerate(ALERTS, start=1):
        try:
            resp = requests.post(BASE_URL, json=alert, timeout=60)
            data = resp.json() if resp.ok else {}
            severity = data.get("severity", "???")
            honeypot = " [HONEYPOT]" if data.get("honeypot_triggered") else ""
            print(f"[{i}/{total}] Sent: {severity}{honeypot} — {alert['event_type']}")
        except requests.exceptions.ConnectionError:
            print(f"[{i}/{total}] CONNECTION ERROR — is the API running at {BASE_URL}?")
        except Exception as err:
            print(f"[{i}/{total}] ERROR: {err}")

        if i < total:
            time.sleep(DELAY_SECONDS)

    print(f"\n=== Demo complete — {total} alerts sent ===")


if __name__ == "__main__":
    main()
