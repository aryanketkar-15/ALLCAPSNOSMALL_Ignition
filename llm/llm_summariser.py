import json
import time
from typing import Optional

import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3:8b"
TIMEOUT = 30


class LLMSummariser:
    """
    Offline local Ollama inference wrapper for SOC Alert Summarisation.
    """

    def __init__(self, model: str = OLLAMA_MODEL, base_url: str = OLLAMA_URL):
        self.model = model
        self.base_url = base_url
        self._verify_connection()

    def _verify_connection(self) -> None:
        """
        Pings the Ollama root to ensure the daemon is running locally.
        NEVER raises an exception on failure—we must ensure the API stays up.
        """
        # Testing root API endpoint or tags endpoint to check liveness
        test_url = self.base_url.replace("/api/generate", "/")
        try:
            resp = requests.get(test_url, timeout=5)
            if resp.status_code == 200:
                print(f"Ollama connected: {resp.status_code}")
            else:
                print(f"WARNING: Ollama returned status {resp.status_code} — template fallback active")
        except Exception as e:
            print("WARNING: Ollama not reachable — template fallback active")

    def _call_ollama(self, prompt: str) -> Optional[str]:
        """
        Sends a non-streaming completion request. Returns the extracted text or None if failed.
        """
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False
        }
        try:
            resp = requests.post(self.base_url, json=payload, timeout=TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            return data.get("response", "").strip()
        except requests.exceptions.Timeout:
            print("[LLM] Timeout after 30s — using fallback")
            return None
        except Exception as e:
            print(f"[LLM] Error: {e}")
            return None

    def _is_valid_response(self, text: Optional[str]) -> bool:
        """
        Validates whether the returned string is substantial enough for UI display.
        """
        if text is None:
            return False
        if not text.strip():
            return False
        if len(text.strip()) <= 20:
            return False
        return True

    def summarise(self, alert_context: dict) -> str:
        """
        Takes raw alert context, trims it, and queries Ollama for a tactical SOC summary.
        If Ollama fails or the response is invalid, falls back to a template string.
        """
        # Trim alert context to top 5 key fields to save token space
        trimmed_context = {
            "severity": alert_context.get("severity", "UNKNOWN"),
            "event_type": alert_context.get("event_type", "unknown_event"),
            "src_ip": alert_context.get("src_ip", "N/A"),
            "confidence": alert_context.get("confidence", 0.0),
            "top_features": alert_context.get("top_features", ["unknown"]),
        }
        
        prompt = (
            "You are a senior cybersecurity analyst in a Security Operations Centre.\n"
            "Analyse this security alert and provide exactly three things:\n"
            "1. SUMMARY: One sentence describing what happened.\n"
            "2. TECHNIQUE: The most likely MITRE ATT&CK technique name and exactly one ID flag (e.g., T1059 Command Execution).\n"
            "3. ACTION: Exactly one uppercase immediate recommended action tag (e.g., BLOCK_IP, ISOLATE_HOST, QUARANTINE_FILE, SUSPEND_USER).\n"
            "Keep your total response under 120 words. Do not repeat the alert data.\n"
            f"Alert: {json.dumps(trimmed_context)}"
        )

        result = self._call_ollama(prompt)
        
        if self._is_valid_response(result):
            return result
        return self._template_summary(trimmed_context)

    def _template_summary(self, alert_context: dict) -> str:
        """
        Resilient hardcoded fallback summary in case Ollama fails to respond.
        Returns a string natively mimicking the Prompt template.
        """
        severity = alert_context.get("severity", "UNKNOWN")
        event_type = alert_context.get("event_type", "unknown_event")
        src_ip = alert_context.get("src_ip", "N/A")
        
        # safely handle confidence (convert back to percentage out of 100)
        conf_val = alert_context.get("confidence", 0.0)
        try:
            conf_str = f"{float(conf_val) * 100:.0f}"
        except (ValueError, TypeError):
            conf_str = "0"
            
        top_feats = alert_context.get("top_features", ["unknown_pattern"])
        top_feature = top_feats[0] if isinstance(top_feats, list) and len(top_feats) > 0 else "unknown_pattern"

        fallback = (
            f"SUMMARY: A {severity}-severity {event_type} alert was triggered\n"
            f"from {src_ip} with {conf_str}% confidence.\n"
            f"TECHNIQUE: Suspicious activity detected via {top_feature} pattern (T1059).\n"
            f"ACTION: ISOLATE_HOST"
        )
        return fallback
