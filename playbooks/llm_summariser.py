import requests
import json

class LLMSummariser:
    def __init__(self, model_name="llama3:8b", host="http://localhost:11434"):
        """
        Connects to the local Ollama instance for offline AI summarisation.
        """
        self.endpoint = f"{host}/api/generate"
        self.model_name = model_name

    def summarise(self, alert_dict, actions_log):
        """
        Sends the incident data and playbook actions to Llama3 for a 2-sentence executive summary.
        """
        prompt = (
            f"You are a SOC Analyst. Write a brief, 2-sentence executive summary "
            f"of the following security incident and the automated response actions taken.\n"
            f"Incident Severity: {alert_dict.get('severity', 'UNKNOWN')}\n"
            f"Source IP: {alert_dict.get('source_ip', 'UNKNOWN')}\n"
            f"Evidence: {alert_dict.get('evidence_trail', 'N/A')}\n"
            f"Playbook Actions Taken: {json.dumps(actions_log)}"
        )

        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False
        }

        try:
            response = requests.post(self.endpoint, json=payload, timeout=10)
            response.raise_for_status()
            return response.json().get("response", "Summary generation failed.")
        except Exception as e:
            # Failsafe so the main API doesn't crash if the LLM container drops
            return f"SYSTEM_NOTE: LLM summarisation offline. Check port 11434. ({str(e)})"