import os
import json
import ipaddress
from datetime import datetime, timezone, timedelta

# === Event-type semantic mapping ===
EVENT_DESCRIPTIONS = {
    'PORT_SCAN':        ('Network reconnaissance', 'T1046 — Service Discovery via port sweep', 'HIGH'),
    'AUTH_FAIL':        ('Brute-force authentication attempt', 'T1110 — Credential Brute Forcing', 'HIGH'),
    'RDP_BRUTEFORCE':   ('Remote Desktop brute-force attack', 'T1110.001 — Password Guessing via RDP', 'HIGH'),
    'KERBEROAST':       ('Kerberos ticket harvesting', 'T1558.003 — Kerberoasting', 'CRITICAL'),
    'SMB_LATERAL':      ('Lateral movement via SMB shares', 'T1021.002 — Remote Services: SMB', 'CRITICAL'),
    'C2_BEACON':        ('Command & Control beacon heartbeat', 'T1071 — Application Layer Protocol C2', 'CRITICAL'),
    'C2_CALLBACK':      ('Active C2 callback / reverse shell', 'T1071.001 — Web Protocol C2', 'CRITICAL'),
    'FILE_READ':        ('Sensitive file access', 'T1059 — Command & Scripting Interpreter', 'HIGH'),
    'CREDENTIAL_DUMP':  ('OS credential harvesting', 'T1003 — OS Credential Dumping', 'CRITICAL'),
    'DATA_EXFIL':       ('Data exfiltration attempt', 'T1041 — Exfiltration Over C2 Channel', 'CRITICAL'),
    'PROCESS_SPAWN':    ('Suspicious child process', 'T1059.003 — Windows Command Shell', 'HIGH'),
    'ICMP_PING':        ('ICMP host discovery sweep', 'T1018 — Remote System Discovery', 'LOW'),
    'HTTP_REQUEST':     ('Outbound HTTP communication', 'T1071.001 — Web Protocol', 'LOW'),
    'HTTP_OPTIONS':     ('HTTP OPTIONS probe (CORS/API recon)', 'T1071.001 — Web Protocol Enumeration', 'MEDIUM'),
    'DNS_QUERY':        ('DNS lookup to external resolver', 'T1071.004 — DNS Application Layer Protocol', 'LOW'),
    'FILE_COPY':        ('Bulk file copy / staging', 'T1074 — Data Staged for Exfil', 'MEDIUM'),
    'VPN_FAIL':         ('Failed VPN authentication attempt', 'T1133 — External Remote Services', 'MEDIUM'),
    'ICMP_FLOOD':       ('ICMP flood — potential DDoS', 'T1498 — Network Denial of Service', 'HIGH'),
}

INTERNAL_SERVICE_PORTS = {
    21:   'FTP',    22:   'SSH',     23:  'Telnet',
    25:   'SMTP',   53:   'DNS',     80:  'HTTP',
    88:   'Kerberos', 135: 'RPC',   139: 'NetBIOS',
    389:  'LDAP',   443:  'HTTPS',  445: 'SMB',
    636:  'LDAPS',  1433: 'MSSQL', 3306: 'MySQL',
    3389: 'RDP',   5985: 'WinRM', 5986: 'WinRM-SSL',
    8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt',
}

HIGH_RISK_EXTERNAL_RANGES = [
    ('185.220.0.0/14',   'Tor exit node range'),
    ('94.102.0.0/16',    'known C2 hosting AS'),
    ('45.33.0.0/16',     'DigitalOcean VPS (threat actor infra)'),
    ('194.165.0.0/16',   'bulletproof hosting range'),
    ('91.108.0.0/16',    'Telegram / proxy relay range'),
]


class VerificationEngine:
    """
    3-pass Verification Engine for SOC alerts.
    Each pass generates specific, per-alert XAI evidence strings — never generic.
    """

    def __init__(self, kb_path='./data/known_bad_iocs.json'):
        self.kb_path = kb_path
        self._setup_kb()

    def _setup_kb(self):
        os.makedirs(os.path.dirname(self.kb_path), exist_ok=True)
        if not os.path.exists(self.kb_path):
            starter = {
                'bad_ips': ['185.220.101.0/24', '194.165.16.0/24', '45.33.32.0/24', '91.108.4.0/22'],
                'bad_cves': ['CVE-2021-44228', 'CVE-2017-0144', 'CVE-2019-0708'],
                'bad_processes': ['mimikatz', 'psexec', 'cobalt_strike', 'meterpreter', 'netcat']
            }
            with open(self.kb_path, 'w') as f:
                json.dump(starter, f, indent=4)
        with open(self.kb_path, 'r') as f:
            self.kb = json.load(f)

    # ── PASS 1: Structural Integrity ────────────────────────────────────────────
    def _pass_structural(self, alert: dict) -> tuple[int, str]:
        required_fields = ['source_ip', 'event_type', 'raw_log', 'timestamp']
        missing_fields = [f for f in required_fields if not alert.get(f)]

        proto = alert.get('protocol')
        valid_protocols = ['tcp', 'udp', 'icmp', 'http', 'https', 'smb', 'rdp', 'ssh', None]
        if proto is not None and proto.lower() not in [p for p in valid_protocols if p]:
            missing_fields.append(f'protocol={proto}')

        ts = alert.get('timestamp')
        if ts is not None:
            now = datetime.now(timezone.utc)
            try:
                if isinstance(ts, str):
                    dt_ts = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                    if dt_ts.tzinfo is None:
                        dt_ts = dt_ts.replace(tzinfo=timezone.utc)
                elif isinstance(ts, datetime):
                    dt_ts = ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts
                else:
                    dt_ts = None
                if dt_ts and (now - dt_ts > timedelta(hours=24) or dt_ts > now):
                    missing_fields.append('timestamp_out_of_range')
            except (ValueError, TypeError):
                missing_fields.append('timestamp_parse_error')

        src = alert.get('source_ip', '')
        dst = alert.get('dest_ip', '')
        event = alert.get('event_type', 'UNKNOWN')

        if missing_fields:
            detail = ', '.join(missing_fields)
            return 0, (
                f'PASS 1: ⚠ Structural gap — missing/invalid fields: [{detail}]. '
                f'Alert from {src or "unknown"} → {dst or "unknown"} typed as {event} '
                f'requires all fields for full verification.'
            )

        # Build a specific pass-1 sentence
        port = alert.get('port', 'N/A')
        meta = EVENT_DESCRIPTIONS.get(event)
        tactic = meta[1] if meta else f'event_type={event}'
        return 20, (
            f'PASS 1: ✓ Structural integrity confirmed — alert from {src} → {dst}:{port} '
            f'is well-formed. Event typed as {event} ({tactic}).'
        )

    # ── PASS 2: IOC Consistency & Network Behaviour ──────────────────────────────
    def _pass_ioc_consistency(self, alert: dict) -> tuple[int, list[str]]:
        confidence = 0
        evidences = []

        src_ip  = alert.get('source_ip', '')
        dst_ip  = alert.get('dest_ip', '')
        event   = alert.get('event_type', 'UNKNOWN')
        iocs    = alert.get('iocs', {})
        port    = alert.get('port')

        # Normalise port
        try:
            port = int(port) if port is not None else None
        except (ValueError, TypeError):
            port = None

        meta = EVENT_DESCRIPTIONS.get(event)

        # ── 2a. Event-type semantics ──
        if meta:
            desc, tactic, risk = meta
            confidence += 10
            evidences.append(
                f'PASS 2: Event {event} classified as "{desc}" — MITRE ATT&CK {tactic} '
                f'(inherent risk: {risk}). Source {src_ip} → destination {dst_ip}.'
            )

        # ── 2b. Port-based service fingerprint ──
        if port and port in INTERNAL_SERVICE_PORTS:
            svc = INTERNAL_SERVICE_PORTS[port]
            try:
                is_private_dst = ipaddress.IPv4Address(dst_ip).is_private if dst_ip else False
                is_private_src = ipaddress.IPv4Address(src_ip).is_private if src_ip else False
            except (ValueError, ipaddress.AddressValueError):
                is_private_dst = is_private_src = False

            if not is_private_src and is_private_dst:
                # External → internal on sensitive port
                confidence += 30
                evidences.append(
                    f'PASS 2: ⚠ External source {src_ip} targeting internal {svc} service '
                    f'(port {port}) at {dst_ip} — classic ingress attack pattern. '
                    f'Expected traffic direction: internal → external.'
                )
            elif is_private_src and is_private_dst and event not in ('HTTP_REQUEST', 'DNS_QUERY', 'FILE_COPY'):
                # Internal → internal on sensitive port = lateral movement
                confidence += 20
                evidences.append(
                    f'PASS 2: ⚠ East-west traffic — {src_ip} → {dst_ip} on port {port} ({svc}). '
                    f'Internal-to-internal access to {svc} is anomalous for event type {event} — '
                    f'consistent with lateral movement (T1021).'
                )

        # ── 2c. IOC-level lateral movement IPs ──
        lat_ips = iocs.get('lateral_movement', [])
        if lat_ips:
            ip_list = ', '.join(lat_ips[:4]) + (f' +{len(lat_ips)-4} more' if len(lat_ips) > 4 else '')
            confidence += 15
            evidences.append(
                f'PASS 2: ⚠ RFC-1918 private IPs found in payload: [{ip_list}]. '
                f'Presence in log body from {src_ip} indicates active internal network traversal '
                f'— {event} with embedded internal targets is a lateral spread indicator.'
            )

        # ── 2d. External IOC IPs ──
        ext_ips = iocs.get('ipv4', [])
        if ext_ips:
            ip_list = ', '.join(ext_ips[:3]) + (f' +{len(ext_ips)-3} more' if len(ext_ips) > 3 else '')
            confidence += 10
            evidences.append(
                f'PASS 2: External IPs in payload: [{ip_list}]. '
                f'Non-RFC-1918 addresses embedded in a {event} log from {src_ip} '
                f'— possible C2 infrastructure contact or exfiltration endpoint.'
            )

        # ── 2e. Domain names in IOCs ──
        domains = iocs.get('domain', [])
        if domains:
            dom_list = ', '.join(domains[:3]) + (f' +{len(domains)-3} more' if len(domains) > 3 else '')
            confidence += 10
            evidences.append(
                f'PASS 2: Suspicious domains in payload: [{dom_list}]. '
                f'DNS lookups or embedded domains during {event} indicate possible DGA, '
                f'phishing redirect, or C2 domain rotation.'
            )

        # ── 2f. No anomaly found ──
        if not evidences:
            evidences.append(
                f'PASS 2: Network behaviour check — {src_ip} → {dst_ip} on event {event} '
                f'shows no anomalous IOC patterns in payload. Alert confidence driven by event type alone.'
            )

        return min(confidence, 50), evidences

    # ── PASS 3: Threat Intelligence Knowledge Base ───────────────────────────────
    def _pass_knowledge_base(self, alert: dict) -> tuple[int, list[str]]:
        confidence = 0
        evidences = []
        iocs = alert.get('iocs', {})
        event = alert.get('event_type', 'UNKNOWN')
        src_ip = alert.get('source_ip', '')

        bad_ips = self.kb.get('bad_ips', [])
        all_ips = iocs.get('ipv4', []) + [src_ip] if src_ip else iocs.get('ipv4', [])

        for ip in all_ips:
            if not ip:
                continue
            for b_net in bad_ips:
                try:
                    if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(b_net, strict=False):
                        confidence += 30
                        evidences.append(
                            f'PASS 3: 🚨 TI Match — IP {ip} is in threat intelligence feed range {b_net}. '
                            f'This subnet is associated with known malicious infrastructure. '
                            f'Activity type {event} from/to this IP is HIGH confidence malicious.'
                        )
                        break
                except (ValueError, ipaddress.AddressValueError):
                    pass

        # Check high-risk ASN ranges
        for ip in all_ips:
            if not ip:
                continue
            for cidr, label in HIGH_RISK_EXTERNAL_RANGES:
                try:
                    if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(cidr, strict=False):
                        if not any(ip in e for e in evidences):
                            confidence += 20
                            evidences.append(
                                f'PASS 3: ⚠ IP {ip} belongs to {label} ({cidr}). '
                                f'This range is frequently used by threat actors for {event} campaigns.'
                            )
                        break
                except (ValueError, ipaddress.AddressValueError):
                    pass

        # Check CVEs
        bad_cves = [c.upper() for c in self.kb.get('bad_cves', [])]
        for cve in iocs.get('cve', []):
            if cve.upper() in bad_cves:
                confidence += 30
                evidences.append(
                    f'PASS 3: 🚨 CVE Match — {cve} is a known critical exploit in our threat DB. '
                    f'Exploitation of this CVE has been weaponised in the wild and is linked to '
                    f'{event}-type attack chains.'
                )

        # Check processes
        bad_procs = [p.lower() for p in self.kb.get('bad_processes', [])]
        for proc in iocs.get('process', []):
            if proc.lower() in bad_procs:
                confidence += 30
                evidences.append(
                    f'PASS 3: 🚨 Malware Tool Match — process "{proc}" is in known malware/dual-use '
                    f'tool database. Execution during {event} on host {src_ip} is a strong indicator '
                    f'of active compromise or red team activity.'
                )

        # SHA256 hashes in payload
        hashes = iocs.get('sha256', [])
        if hashes:
            evidences.append(
                f'PASS 3: SHA-256 hash(es) found in payload — [{", ".join(hashes[:2])}…]. '
                f'File hashes associated with {event} activity warrant malware sandbox detonation.'
            )
            confidence += 10

        if not evidences:
            evidences.append(
                f'PASS 3: TI lookup — no matches in KB for IPs/CVEs/processes in this {event} alert. '
                f'Alert is not corroborated by threat intelligence feeds; confidence adjusted accordingly.'
            )

        return min(confidence, 60), evidences

    # ── PUBLIC: verify ───────────────────────────────────────────────────────────
    def verify(self, alert: dict, honeypot_boost: int = 0) -> dict:
        total_confidence = 0
        evidence_trail = []

        c1, e1 = self._pass_structural(alert)
        total_confidence += c1
        evidence_trail.append(e1)

        c2, e2_list = self._pass_ioc_consistency(alert)
        total_confidence += c2
        evidence_trail.extend(e2_list)

        c3, e3_list = self._pass_knowledge_base(alert)
        total_confidence += c3
        evidence_trail.extend(e3_list)

        total_confidence += honeypot_boost
        total_confidence = min(total_confidence, 100)

        if total_confidence >= 70:
            status = 'VERIFIED'
        elif 30 <= total_confidence <= 69:
            status = 'UNVERIFIED'
        else:
            status = 'FALSE_POSITIVE'

        return {
            'verification_status': status,
            'confidence_score': total_confidence,
            'evidence_trail': evidence_trail
        }
