import requests
import time

API = 'http://localhost:8000/api/v1/classify'

alerts = [
    {
        'raw_log': 'Normal HTTP request to google.com',
        'source_ip': '10.0.1.5', 'dest_ip': '8.8.8.8',
        'port': 80, 'event_type': 'HTTP_REQUEST',
        'accessed_path': '', 'protocol': 'HTTP',
        'timestamp': '2024-04-03T14:50:00Z'
    },
    {
        'raw_log': 'SSH login failure from external IP',
        'source_ip': '45.12.33.10', 'dest_ip': '192.168.1.20',
        'port': 22, 'event_type': 'SSH_FAIL',
        'accessed_path': '', 'protocol': 'SSH',
        'timestamp': '2024-04-03T14:51:00Z'
    },
    {
        'raw_log': 'RDP connection from internal workstation',
        'source_ip': '192.168.1.8', 'dest_ip': '192.168.1.20',
        'port': 3389, 'event_type': 'RDP_CONNECT',
        'accessed_path': '', 'protocol': 'RDP',
        'timestamp': '2024-04-03T14:52:00Z'
    },
    {
        'raw_log': 'Kerberoasting via SMB lateral movement',
        'source_ip': '192.168.1.8', 'dest_ip': '192.168.1.10',
        'port': 445, 'event_type': 'SMB_LATERAL',
        'accessed_path': '', 'protocol': 'SMB',
        'timestamp': '2024-04-03T14:53:00Z'
    },
    {
        'raw_log': 'db_credentials_prod.conf accessed by unknown process',
        'source_ip': '192.168.1.35', 'dest_ip': '10.0.0.5',
        'port': 0, 'event_type': 'FILE_READ',
        'accessed_path': '/etc/db_credentials_prod.conf',
        'protocol': '',
        'timestamp': '2024-04-03T14:54:00Z'
    },
    {
        'raw_log': 'Tor exit node connection attempt to internal server',
        'source_ip': '185.220.101.1', 'dest_ip': '192.168.1.50',
        'port': 3389, 'event_type': 'RDP_CONNECT',
        'accessed_path': '', 'protocol': 'RDP',
        'timestamp': '2024-04-03T14:55:00Z'
    },
    {
        'raw_log': 'Large data exfiltration to external IP after honeypot hit',
        'source_ip': '192.168.1.35', 'dest_ip': '185.220.101.1',
        'port': 443, 'event_type': 'DATA_EXFIL',
        'accessed_path': '', 'protocol': 'HTTPS',
        'timestamp': '2024-04-03T14:56:00Z'
    },
]

print("=== SOC Demo Alert Injector ===")
print(f"Target: {API}")
print(f"Firing {len(alerts)} alerts...\n")

for i, alert in enumerate(alerts):
    try:
        r = requests.post(API, json=alert, timeout=60)
        data = r.json()
        sev = data.get('severity', '?')
        conf = data.get('confidence', 0)
        blast = data.get('blast_radius', 0)
        honeypot = data.get('honeypot_triggered', False)
        hp_flag = " <<HONEYPOT!>>" if honeypot else ""
        print(f"Alert {i+1:2d}: {sev:8s} | conf={conf:.2f} | blast={blast:.3f}{hp_flag}")
    except Exception as e:
        print(f"Alert {i+1:2d}: ERROR - {e}")
    time.sleep(2)

print("\nAll alerts fired! Check http://localhost:3000")
