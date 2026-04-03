import json
from playbooks.states import PlaybookState
from playbooks.fsm import PlaybookStateMachine
from vault.forensic_vault import ForensicVault
from vault.cacao_exporter import CacaoExporter

def run_response_pipeline(alert: dict) -> dict:
    # 1. Validate required keys
    required_keys = ['alert_id', 'severity', 'src_ip', 'blast_radius']
    for k in required_keys:
        if k not in alert:
            raise ValueError(f"Alert missing required key: {k}")
            
    # 2. Build PlaybookContext
    ctx = {
        'alert_id': alert['alert_id'],
        'severity': alert['severity'],
        'src_ip': alert['src_ip'],
        'blast_radius': alert['blast_radius'],
        'current_state': PlaybookState.ALERT_RECEIVED,
        'actions_log': [],
        'failed_attempts': 0,
        'remediation_attempts': 0
    }
    
    # 3. Run FSM
    fsm = PlaybookStateMachine()
    result = fsm.run(ctx)
    
    # 4. Generate narrative
    narrative = fsm.generate_playbook_narrative(result['actions_log'], result['alert_id'])
    
    # 5. Vault capture
    vault = ForensicVault()
    sid = vault.capture_snapshot(result)
    
    # 6. Read vault_hash
    hash_path = vault.vault_dir / f"vault_{sid}.sha256"
    with open(hash_path, 'r', encoding='utf-8') as f:
        vault_hash = f.read().strip()
        
    # 7. Verify integrity
    integrity = vault.verify_integrity(sid)
    
    # 8. Export CACAO
    exporter = CacaoExporter()
    cacao_path = exporter.export(result['alert_id'], result['actions_log'], narrative)
    
    # 9. Return structured result
    return {
        'alert_id': result['alert_id'],
        'final_state': result['current_state'],
        'actions_log': result['actions_log'],
        'playbook_narrative': narrative,
        'vault_snapshot_id': sid,
        'vault_hash': vault_hash,
        'cacao_path': cacao_path,
        'integrity_verified': integrity
    }

if __name__ == '__main__':
    test_alert = {
        'alert_id': 'TEST-O-001',
        'severity': 'HIGH',
        'src_ip': '10.50.0.9',
        'blast_radius': 75,
        'raw_log': 'Detected unauthorized enumeration'
    }
    
    res = run_response_pipeline(test_alert)
    print(json.dumps(res, indent=2))
