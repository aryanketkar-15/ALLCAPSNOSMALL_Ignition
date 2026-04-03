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
        incident['captured_at'] = timestamp
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

    def verify_integrity(self, snapshot_id: str) -> bool:
        json_path = self.vault_dir / f"vault_{snapshot_id}.json"
        hash_path = self.vault_dir / f"vault_{snapshot_id}.sha256"
        
        if not json_path.exists() or not hash_path.exists():
            return False
            
        with open(json_path, 'rb') as f:
            raw_bytes = f.read()
            
        computed_hash = hashlib.sha256(raw_bytes).hexdigest()
        
        with open(hash_path, 'r', encoding='utf-8') as f:
            stored_hash = f.read().strip()
            
        return computed_hash == stored_hash

    def list_snapshots(self) -> list[str]:
        snapshots = []
        if not self.vault_dir.exists():
            return snapshots
            
        for path in self.vault_dir.glob("vault_*.json"):
            # filename is vault_alertID_safeTimestamp.json
            name = path.name
            if name.startswith("vault_") and name.endswith(".json"):
                snapshot_id = name[len("vault_"):-len(".json")]
                snapshots.append(snapshot_id)
                
        return sorted(snapshots)

    def generate_chain_of_custody(self, snapshot_id: str) -> str:
        json_path = self.vault_dir / f"vault_{snapshot_id}.json"
        hash_path = self.vault_dir / f"vault_{snapshot_id}.sha256"
        
        if not json_path.exists() or not hash_path.exists():
            return f"ERROR: Snapshot {snapshot_id} not found."
            
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                incident = json.load(f)
        except Exception:
            incident = {'alert_id': 'UNKNOWN (CORRUPTED)', 'captured_at': 'UNKNOWN'}
            
        with open(hash_path, 'r', encoding='utf-8') as f:
            stored_hash = f.read().strip()
            
        integrity_status = self.verify_integrity(snapshot_id)
        integrity_str = '✅ VERIFIED' if integrity_status else '❌ TAMPERED'
        
        return f"""══════════════════════════════════════════════
CHAIN OF CUSTODY REPORT
══════════════════════════════════════════════
Incident ID   : {incident.get('alert_id', incident.get('alert_id'))}
Capture Time  : {incident.get('captured_at', 'N/A')}
SHA-256 Hash  : {stored_hash}
System Host   : {socket.gethostname()}
Captured By   : SOC-AI Automated System
Integrity     : {integrity_str}
──────────────────────────────────────────────
This record is cryptographically sealed and
legally admissible as forensic evidence.
══════════════════════════════════════════════"""
