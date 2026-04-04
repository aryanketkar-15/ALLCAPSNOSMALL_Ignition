import requests
import json

API = 'http://localhost:8000/api/v1/classify'

alert = {
    'raw_log': 'SSH brute force from external IP',
    'source_ip': '45.12.33.10',
    'dest_ip': '192.168.1.20',
    'port': 22,
    'event_type': 'SSH_FAIL',
    'accessed_path': '',
    'protocol': 'SSH',
    'timestamp': '2024-04-03T14:51:00Z'
}

print("Sending single alert to /classify (60s timeout)...")
try:
    r = requests.post(API, json=alert, timeout=60)
    print(f"Status: {r.status_code}")
    if r.status_code == 200:
        data = r.json()
        print(json.dumps(data, indent=2))
    else:
        print("ERROR:")
        print(r.text[:2000])
except Exception as e:
    print(f"EXCEPTION: {e}")
