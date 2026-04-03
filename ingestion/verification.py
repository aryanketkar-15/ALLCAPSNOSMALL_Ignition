import os
import json
import ipaddress
from datetime import datetime, timezone, timedelta

class VerificationEngine:
    """
    3-pass Verification Engine for SOC alerts.
    Takes extracted parameters and outputs a confidence score and human-readable evidence trail.
    """
    def __init__(self, kb_path='./data/known_bad_iocs.json'):
        self.kb_path = kb_path
        self._setup_kb()
        
    def _setup_kb(self):
        # Create data directory if it's missing
        os.makedirs(os.path.dirname(self.kb_path), exist_ok=True)
        if not os.path.exists(self.kb_path):
            starter_content = {
                'bad_ips': ['185.220.101.0/24', '194.165.16.0/24', '45.33.32.0/24'],
                'bad_cves': ['CVE-2021-44228', 'CVE-2017-0144', 'CVE-2019-0708'],
                'bad_processes': ['mimikatz', 'psexec', 'cobalt_strike', 'meterpreter', 'netcat']
            }
            with open(self.kb_path, 'w') as f:
                json.dump(starter_content, f, indent=4)
        
        with open(self.kb_path, 'r') as f:
            self.kb = json.load(f)
            
    def _pass_structural(self, alert: dict) -> tuple[int, str]:
        missing_fields = []
        required_fields = ['source_ip', 'event_type', 'raw_log', 'timestamp']
        
        for req in required_fields:
            if req not in alert or alert[req] is None:
                missing_fields.append(req)
                
        proto = alert.get('protocol')
        valid_protocols = ['tcp', 'udp', 'icmp', 'http', 'https', 'smb', 'rdp', 'ssh', None]
        if proto not in valid_protocols:
            missing_fields.append(f'invalid_protocol_{proto}')
            
        ts = alert.get('timestamp')
        if ts is not None:
            now = datetime.now(timezone.utc)
            if isinstance(ts, datetime):
                # Ensure it's timezone-aware for comparison
                dt_ts = ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts
                if now - dt_ts > timedelta(hours=24) or dt_ts > now:
                    missing_fields.append('timestamp_not_in_last_24h')
            elif isinstance(ts, str):
                try:
                    dt_ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    if dt_ts.tzinfo is None:
                        dt_ts = dt_ts.replace(tzinfo=timezone.utc)
                    if now - dt_ts > timedelta(hours=24) or dt_ts > now:
                        missing_fields.append('timestamp_not_in_last_24h')
                except ValueError:
                    missing_fields.append('timestamp_parse_error')
                    
        if missing_fields:
            return 0, f'PASS 1: WARN — missing fields: {missing_fields}'
        else:
            return 20, 'PASS 1: Structural check passed — all required fields present'
            
    def _pass_ioc_consistency(self, alert: dict) -> tuple[int, list[str]]:
        confidence = 0
        evidences = []
        
        internal_service_ports = {445: 'SMB', 3389: 'RDP', 1433: 'MSSQL', 22: 'SSH', 5985: 'WinRM'}
        
        dest_ip = alert.get('dest_ip')
        port = alert.get('port')
        
        # Treat port check safely if port is a string
        if port is not None:
            try:
                port = int(port)
            except ValueError:
                port = None

        if dest_ip and port in internal_service_ports:
            try:
                # Check if dest_ip is NOT in RFC 1918 ranges (external)
                is_private = ipaddress.IPv4Address(dest_ip).is_private
                if not is_private:
                    service = internal_service_ports[port]
                    confidence += 30
                    evidences.append(f'PASS 2: External IP {dest_ip} targeting internal service port {port} ({service}) — HIGH confidence lateral movement')
            except (ipaddress.AddressValueError, ValueError):
                pass
                
        iocs = alert.get('iocs', {})
        lat_moves = iocs.get('lateral_movement', [])
        if lat_moves:
            confidence += 15
            evidences.append('PASS 2: Internal IP movement detected — possible lateral spread')
            
        return confidence, evidences
        
    def _pass_knowledge_base(self, alert: dict) -> tuple[int, list[str]]:
        confidence = 0
        evidences = []
        iocs = alert.get('iocs', {})
        
        # Pre-process IPs into networks to allow for both basic prefix match and robust subnet logic
        bad_ips = self.kb.get('bad_ips', [])
        
        for ip in iocs.get('ipv4', []):
            matched = False
            # Basic prefix match logic from prompt + IPAddress robust fallback
            for b_net in bad_ips:
                prefix = b_net.split('.0/')[0] + '.'
                if ip.startswith(prefix):
                    matched = True
                    confidence += 30
                    evidences.append(f'PASS 3: IP {ip} matches known threat range {b_net}')
                    break
                    
                # Robust subnet membership check
                try:
                    if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(b_net, strict=False):
                        if not matched:
                            matched = True
                            confidence += 30
                            evidences.append(f'PASS 3: IP {ip} matches known threat range {b_net}')
                            break
                except ValueError:
                    pass
                
        # Check CVEs
        bad_cves = [c.upper() for c in self.kb.get('bad_cves', [])]
        for cve in iocs.get('cve', []):
            if cve.upper() in bad_cves:
                confidence += 30
                evidences.append(f'PASS 3: CVE {cve} is a known critical vulnerability')
                
        # Check processes
        bad_procs = [p.lower() for p in self.kb.get('bad_processes', [])]
        for proc in iocs.get('process', []):
            if proc.lower() in bad_procs:
                confidence += 30
                evidences.append(f'PASS 3: Process name {proc} matches known malware/tool')
                
        return confidence, evidences

    def verify(self, alert: dict, honeypot_boost: int = 0) -> dict:
        total_confidence = 0
        evidence_trail = []
        
        # Run passes sequentially
        c1, e1 = self._pass_structural(alert)
        total_confidence += c1
        evidence_trail.append(e1)
        
        c2, e2_list = self._pass_ioc_consistency(alert)
        total_confidence += c2
        evidence_trail.extend(e2_list)
        
        c3, e3_list = self._pass_knowledge_base(alert)
        total_confidence += c3
        evidence_trail.extend(e3_list)
        
        # Add honeypot boost
        total_confidence += honeypot_boost
        
        # Cap at 100
        if total_confidence > 100:
            total_confidence = 100
            
        # Map output constraints
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
