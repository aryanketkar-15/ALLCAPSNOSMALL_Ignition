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
