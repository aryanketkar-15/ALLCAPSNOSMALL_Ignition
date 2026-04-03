import json
import os
from vault.cacao_exporter import CacaoExporter
from playbooks.fsm import PlaybookStateMachine
from playbooks.states import PlaybookState

if __name__ == '__main__':
    ctx = {
        'alert_id': 'DEMO-SOC-2024-001',
        'severity': 'CRITICAL',
        'src_ip': '192.168.1.100',
        'blast_radius': 85,
        'current_state': PlaybookState.ALERT_RECEIVED,
        'actions_log': [],
        'failed_attempts': 0,
        'remediation_attempts': 0
    }

    m = PlaybookStateMachine()
    result = m.run(ctx)

    narrative = m.generate_playbook_narrative(result['actions_log'], ctx['alert_id'])

    exporter = CacaoExporter()
    path = exporter.export(ctx['alert_id'], result['actions_log'], narrative)
    
    print(f'Sample CACAO generated: {path}')
    print(f'Workflow steps: {len(json.load(open(path))["workflow"])}')
    
    print(json.dumps(json.load(open(path)), indent=2))
