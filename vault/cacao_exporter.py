import json
import uuid
from datetime import datetime
import os

class CacaoExporter:
    def __init__(self, output_dir="vault/cacao/"):
        """
        Initializes the CACAO exporter with a target directory for JSON playbooks.
        """
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def export(self, incident_id, actions_log, llm_summary="Automated Incident Response Playbook"):
        """
        Converts the LangGraph actions_log into an OASIS CACAO 2.0 compliant JSON.
        """
        playbook_id = f"playbook--{uuid.uuid4()}"
        timestamp = datetime.utcnow().isoformat() + "Z"
        
        # Initialize the CACAO root structure
        cacao_pb = {
            "type": "playbook",  # Mandatory field 
            "spec_version": "cacao-2.0",  # Mandatory field 
            "id": playbook_id,
            "name": f"Incident Response Playbook - {incident_id}",
            "description": llm_summary,
            "created": timestamp,
            "modified": timestamp,
            "workflow_start": "step--0",
            "workflow": {}  # Mandatory dictionary 
        }

        # Map each LangGraph FSM action to a CACAO workflow step [cite: 236]
        for i, action in enumerate(actions_log):
            step_id = f"step--{i}"
            next_step = f"step--{i+1}" if i < len(actions_log) - 1 else None
            
            cacao_pb["workflow"][step_id] = {
                "type": "action",
                "name": action.get("action_taken", "Unknown Action"),
                "description": action.get("reason", "No reason provided"),
                "on_completion": next_step if next_step else "step--end"
            }

        # Add the final 'end' step required by the standard [cite: 236]
        cacao_pb["workflow"]["step--end"] = {
            "type": "end"
        }

        # Write to the vault [cite: 237]
        file_path = os.path.join(self.output_dir, f"incident_{incident_id}.json")
        with open(file_path, "w") as f:
            json.dump(cacao_pb, f, indent=4)
            
        return file_path