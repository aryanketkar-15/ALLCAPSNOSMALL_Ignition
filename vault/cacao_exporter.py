import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

class CacaoExporter:
    def __init__(self, output_dir: str = 'vault/cacao'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _build_skeleton(self, incident_id: str, name: str, description: str) -> dict:
        return {
            'type': 'playbook',
            'spec_version': 'cacao-2.0',
            'id': f'playbook--{str(uuid.uuid4())}',
            'name': name,
            'description': description,
            'created': datetime.now(timezone.utc).isoformat(),
            'modified': datetime.now(timezone.utc).isoformat(),
            'created_by': f'identity--{str(uuid.uuid4())}',
            'playbook_types': ['investigation', 'remediation'],
            'workflow_start': 'start--1',
            'workflow': {}
        }

    def _build_start_step(self) -> dict:
        return {'start--1': {'type': 'start', 'on_completion': 'action--1'}}

    def _build_end_step(self, step_id: str) -> dict:
        return {step_id: {'type': 'end'}}

    def export(self, incident_id: str, playbook_actions: list, llm_summary: str = '') -> str:
        skeleton = self._build_skeleton(
            incident_id,
            name=f'SOC Response Playbook \u2014 Incident {incident_id}',
            description=llm_summary or 'Automated SOC response playbook.'
        )
        
        workflow = {}
        workflow.update(self._build_start_step())
        
        n = len(playbook_actions)
        for i, action in enumerate(playbook_actions, 1):
            step_id = f'action--{i}'
            next_id = f'action--{i+1}' if i < n else f'end--{n}'
            
            workflow[step_id] = {
                'type': 'action',
                'name': action.get('action_taken', 'Unknown Action'),
                'description': action.get('reason', ''),
                'executed_at': action.get('timestamp', ''),
                'on_completion': next_id
            }
            
        workflow.update(self._build_end_step(f'end--{n}'))
        skeleton['workflow'] = workflow
        
        output_str = json.dumps(skeleton, indent=2, ensure_ascii=False)
        # Validate JSON integrity natively
        json.loads(output_str)
        
        filepath = self.output_dir / f"incident_{incident_id}.json"
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(output_str)
            
        return str(filepath)

if __name__ == '__main__':
    exporter = CacaoExporter()
    print(json.dumps(exporter._build_skeleton('test', 'test_name', 'test_desc'), indent=2))
