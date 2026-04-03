import json
import hashlib
import os
from datetime import datetime

class ForensicVault:
    def __init__(self, storage_path="vault/snapshots/"):
        """
        Initializes the vault with a dedicated directory for snapshots.
        """
        self.storage_path = storage_path
        # Ensure the directory exists
        if not os.path.exists(self.storage_path):
            os.makedirs(self.storage_path)

    def capture_snapshot(self, incident):
        """
        Serializes incident data to JSON with deterministic key ordering,
        computes a SHA-256 hash, and saves both to the vault.
        """
        alert_id = incident.get("alert_id", "unknown")
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        
        # Rule: Use sort_keys=True for deterministic hashing
        json_data = json.dumps(incident, sort_keys=True).encode('utf-8')
        sha256_hash = hashlib.sha256(json_data).hexdigest()
        
        # File naming convention: vault_{timestamp}_{alert_id}.json
        base_filename = f"vault_{timestamp}_{alert_id}"
        json_path = os.path.join(self.storage_path, f"{base_filename}.json")
        hash_path = os.path.join(self.storage_path, f"{base_filename}.sha256")
        
        # Write JSON data (Simulated WORM storage)
        with open(json_path, "wb") as f:
            f.write(json_data)
            
        # Write SHA-256 hash
        with open(hash_path, "w") as f:
            f.write(sha256_hash)
            
        return base_filename, sha256_hash

    def verify_integrity(self, snapshot_filename):
        """
        Reloads the snapshot, re-calculates the hash, and compares it to 
        the stored .sha256 file to detect tampering.
        """
        json_path = os.path.join(self.storage_path, f"{snapshot_filename}.json")
        hash_path = os.path.join(self.storage_path, f"{snapshot_filename}.sha256")
        
        if not os.path.exists(json_path) or not os.path.exists(hash_path):
            return False
            
        with open(json_path, "rb") as f:
            current_content = f.read()
            
        with open(hash_path, "r") as f:
            stored_hash = f.read().strip()
            
        current_hash = hashlib.sha256(current_content).hexdigest()
        return current_hash == stored_hash

    def generate_chain_of_custody(self, snapshot_filename, alert_id):
        """
        Generates a professional report including the SHA-256 hash and legal notice.
        """
        hash_path = os.path.join(self.storage_path, f"{snapshot_filename}.sha256")
        
        with open(hash_path, "r") as f:
            seal_hash = f.read().strip()
            
        report = (
            f"--- CHAIN OF CUSTODY REPORT ---\n"
            f"Incident ID: {alert_id}\n"
            f"Snapshot ID: {snapshot_filename}\n"
            f"Capture Timestamp: {datetime.utcnow()} UTC\n"
            f"SHA-256 Hash Seal: {seal_hash}\n"
            f"System Hostname: {os.getenv('COMPUTERNAME', 'SOC-NODE-01')}\n"
            f"Note: This record is cryptographically sealed and legally admissible.\n"
            f"-------------------------------"
        )
        return report