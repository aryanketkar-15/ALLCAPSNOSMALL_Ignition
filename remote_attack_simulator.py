"""
FULL SPECTRUM ATTACK SIMULATOR
AI SOC Analyzer — Team SY-A9

Sends a complete 12-alert sequence covering ALL severity levels:
  BENIGN x2 → LOW x2 → MEDIUM x2 → HIGH x2 → CRITICAL x2 → HONEYPOT x2

Each attack waits for the SOC's AI response before moving to the next.

Usage:
  python remote_attack_simulator.py http://10.159.195.53:8000
"""

import sys
import time
import requests

# ── ANSI Colours ──────────────────────────────────────────────────
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
ORANGE  = "\033[38;5;208m"
RED     = "\033[91m"
MAGENTA = "\033[95m"
CYAN    = "\033[96m"
RESET   = "\033[0m"
BOLD    = "\033[1m"

SEV_COLOR = {
    "BENIGN":   GREEN,
    "LOW":      YELLOW,
    "MEDIUM":   ORANGE,
    "HIGH":     RED,
    "CRITICAL": MAGENTA,
    "UNKNOWN":  CYAN,
}

# ── Full Attack Sequence ──────────────────────────────────────────

ATTACKS = [

    # ══════════════════════════════════
    # TIER 1: BENIGN — Normal traffic
    # ══════════════════════════════════
    {
        "tier":  "[ BENIGN ]",
        "color": GREEN,
        "desc":  "Normal web browsing (HTTP GET)",
        "payload": {
            "raw_log":     "GET /index.html HTTP/1.1 200 OK from 10.0.0.10",
            "source_ip":   "10.0.0.10",
            "dest_ip":     "192.168.1.100",
            "port":        80,
            "event_type":  "HTTP_REQUEST",
            "accessed_path": "/index.html",
            "protocol":    "HTTP",
        }
    },
    {
        "tier":  "[ BENIGN ]",
        "color": GREEN,
        "desc":  "Scheduled DNS resolution (google.com)",
        "payload": {
            "raw_log":     "DNS query for google.com resolved successfully",
            "source_ip":   "10.0.0.11",
            "dest_ip":     "8.8.8.8",
            "port":        53,
            "event_type":  "DNS_QUERY",
            "accessed_path": "",
            "protocol":    "UDP",
        }
    },

    # ══════════════════════════════════
    # TIER 2: LOW — Probes & Scans
    # ══════════════════════════════════
    {
        "tier":  "[  LOW   ]",
        "color": YELLOW,
        "desc":  "External Port Scan (SYN Sweep)",
        "payload": {
            "raw_log":     "SYN scan detected on ports 20-25 from 203.0.113.50",
            "source_ip":   "203.0.113.50",
            "dest_ip":     "192.168.1.5",
            "port":        22,
            "event_type":  "PORT_SCAN",
            "accessed_path": "",
            "protocol":    "TCP",
        }
    },
    {
        "tier":  "[  LOW   ]",
        "color": YELLOW,
        "desc":  "ICMP Ping Sweep (Network Discovery)",
        "payload": {
            "raw_log":     "ICMP echo sweep from 198.51.100.10 targeting /24 subnet",
            "source_ip":   "198.51.100.10",
            "dest_ip":     "192.168.1.0",
            "port":        0,
            "event_type":  "ICMP_PING",
            "accessed_path": "",
            "protocol":    "ICMP",
        }
    },

    # ══════════════════════════════════
    # TIER 3: MEDIUM — Failed Auths
    # ══════════════════════════════════
    {
        "tier":  "[ MEDIUM ]",
        "color": ORANGE,
        "desc":  "SSH Brute Force (10 failed attempts)",
        "payload": {
            "raw_log":     "Failed SSH login for root — 10 attempts in 60s from 185.100.86.10",
            "source_ip":   "185.100.86.10",
            "dest_ip":     "192.168.1.5",
            "port":        22,
            "event_type":  "AUTH_FAIL",
            "accessed_path": "",
            "protocol":    "SSH",
        }
    },
    {
        "tier":  "[ MEDIUM ]",
        "color": ORANGE,
        "desc":  "RDP Brute Force (15 failed attempts)",
        "payload": {
            "raw_log":     "RDP brute force detected — 15 failed attempts in 30s from 185.220.100.5",
            "source_ip":   "185.220.100.5",
            "dest_ip":     "192.168.1.20",
            "port":        3389,
            "event_type":  "RDP_BRUTEFORCE",
            "accessed_path": "",
            "protocol":    "RDP",
        }
    },

    # ══════════════════════════════════
    # TIER 4: HIGH — Active Intrusion
    # ══════════════════════════════════
    {
        "tier":  "[  HIGH  ]",
        "color": RED,
        "desc":  "SMB Lateral Movement (WannaCry pattern)",
        "payload": {
            "raw_log":     "SMB share enumeration followed by EternalBlue exploit attempt from 10.0.0.50",
            "source_ip":   "10.0.0.50",
            "dest_ip":     "192.168.1.15",
            "port":        445,
            "event_type":  "SMB_LATERAL",
            "accessed_path": "\\\\FILESERVER\\C$",
            "protocol":    "SMB",
        }
    },
    {
        "tier":  "[  HIGH  ]",
        "color": RED,
        "desc":  "Kerberoasting (AD Privilege Escalation)",
        "payload": {
            "raw_log":     "Multiple TGS Kerberos tickets requested with RC4-HMAC from 10.0.0.55",
            "source_ip":   "10.0.0.55",
            "dest_ip":     "192.168.1.1",
            "port":        88,
            "event_type":  "KERBEROAST",
            "accessed_path": "",
            "protocol":    "KERBEROS",
        }
    },

    # ══════════════════════════════════
    # TIER 5: CRITICAL — Full Compromise
    # ══════════════════════════════════
    {
        "tier":  "[CRITICAL]",
        "color": MAGENTA,
        "desc":  "C2 Beacon — Malware calling home",
        "payload": {
            "raw_log":     "High-frequency beaconing to randomly generated .xyz domains every 5s — C2 callback pattern",
            "source_ip":   "192.168.1.25",
            "dest_ip":     "91.108.4.200",
            "port":        443,
            "event_type":  "C2_BEACON",
            "accessed_path": "",
            "protocol":    "HTTPS",
        }
    },
    {
        "tier":  "[CRITICAL]",
        "color": MAGENTA,
        "desc":  "Data Exfiltration — 50GB outbound SSH",
        "payload": {
            "raw_log":     "Unusually large outbound SSH data transfer of 50GB to unknown external IP 185.234.218.23",
            "source_ip":   "192.168.1.30",
            "dest_ip":     "185.234.218.23",
            "port":        22,
            "event_type":  "DATA_EXFIL",
            "accessed_path": "",
            "protocol":    "SSH",
        }
    },

    # ══════════════════════════════════
    # TIER 6: HONEYPOT TRIGGERS!
    # ══════════════════════════════════
    {
        "tier":  "[HONEYPOT]",
        "color": CYAN,
        "desc":  "🍯 Honeypot: Fake DB Credentials File Accessed!",
        "payload": {
            "raw_log":     "File read: db_credentials_prod — accessed by user 'svc_backup' from 10.0.0.99",
            "source_ip":   "10.0.0.99",
            "dest_ip":     "192.168.1.50",
            "port":        445,
            "event_type":  "FILE_READ",
            "accessed_path": "db_credentials_prod",
            "protocol":    "SMB",
        }
    },
    {
        "tier":  "[HONEYPOT]",
        "color": CYAN,
        "desc":  "🍯 Honeypot: Fake Admin Login Portal Hit!",
        "payload": {
            "raw_log":     "POST /admin/login from 10.0.0.99 — honeypot admin portal accessed",
            "source_ip":   "10.0.0.99",
            "dest_ip":     "192.168.1.100",
            "port":        8080,
            "event_type":  "HTTP_REQUEST",
            "accessed_path": "/admin/login",
            "protocol":    "HTTP",
        }
    },
]

# ─────────────────────────────────────────────────────────────────

def print_banner(target_url):
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}     FULL SPECTRUM ATTACK DEMO — AI SOC ANALYZER{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")
    print(f"  Target : {CYAN}{target_url}{RESET}")
    print(f"  Attacks: {len(ATTACKS)} (BENIGN → LOW → MEDIUM → HIGH → CRITICAL → HONEYPOT)")
    print(f"{BOLD}{'='*60}{RESET}\n")

def main():
    if len(sys.argv) < 2:
        print("Usage: python remote_attack_simulator.py <http://SOC_IP:8000>")
        sys.exit(1)

    base_url = sys.argv[1].rstrip('/')
    endpoint = f"{base_url}/api/v1/classify"
    print_banner(base_url)

    for i, attack in enumerate(ATTACKS, 1):
        tier  = attack["tier"]
        color = attack["color"]
        desc  = attack["desc"]

        print(f"{color}{BOLD}{tier}{RESET} ({i}/{len(ATTACKS)}) {desc}")

        payload = attack["payload"]
        payload["timestamp"] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())

        try:
            response = requests.post(endpoint, json=payload, timeout=70)
            if response.status_code == 200:
                data = response.json()
                sev   = data.get("severity", "UNKNOWN")
                conf  = int(data.get("confidence", 0) * 100)
                state = data.get("playbook_state", "?")
                sev_c = SEV_COLOR.get(sev, RESET)
                honey = " 🍯 HONEYPOT TRIGGERED!" if data.get("honeypot_triggered") else ""
                print(f"         {BOLD}→ Severity:{RESET} {sev_c}{sev}{RESET}  "
                      f"{BOLD}Confidence:{RESET} {conf}%  "
                      f"{BOLD}Playbook:{RESET} {state}{honey}")
            else:
                print(f"         {RED}→ HTTP {response.status_code} — {response.text[:120]}{RESET}")
        except requests.exceptions.Timeout:
            print(f"         {RED}→ Timeout — SOC LLM is still processing (this is normal){RESET}")
        except requests.exceptions.RequestException as e:
            print(f"         {RED}→ Connection error: {e}{RESET}")

        # Pause between attacks (shorter for benign, longer for critical)
        pause = 3 if i <= 4 else 5
        if i < len(ATTACKS):
            print(f"         {BOLD}Waiting {pause}s...{RESET}\n")
            time.sleep(pause)

    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{GREEN}{BOLD}  Demo complete! Check your SOC Dashboard now.{RESET}")
    print(f"{BOLD}{'='*60}{RESET}\n")

if __name__ == "__main__":
    main()
