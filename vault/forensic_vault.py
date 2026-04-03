import hashlib
import json
import os
import socket
from pathlib import Path
from datetime import datetime, timezone

class ForensicVault:
    def __init__(self, vault_dir: str = 'vault/snapshots'):
        self.vault_dir = Path(vault_dir)
        self.vault_dir.mkdir(parents=True, exist_ok=True)

    def capture_snapshot(self, incident: dict) -> str:
        if 'alert_id' not in incident:
            raise ValueError("Incident missing 'alert_id' key")
            
        timestamp = datetime.now(timezone.utc).isoformat()
        # Replace ':' for filename safety
        safe_timestamp = timestamp.replace(":", "-")
        alert_id = incident['alert_id']
        snapshot_id = f"{alert_id}_{safe_timestamp}"
        
        # Serialise: sort_keys=True is MANDATORY for deterministic hash
        payload = json.dumps(incident, sort_keys=True, default=str)
        
        sha256 = hashlib.sha256(payload.encode('utf-8')).hexdigest()
        
        json_path = self.vault_dir / f"vault_{snapshot_id}.json"
        hash_path = self.vault_dir / f"vault_{snapshot_id}.sha256"
        
        # WORM - Write Once, Read Many. Do not overwrite.
        with open(json_path, 'w', encoding='utf-8') as f:
            f.write(payload)
            
        with open(hash_path, 'w', encoding='utf-8') as f:
            f.write(sha256)
            
        return snapshot_id
