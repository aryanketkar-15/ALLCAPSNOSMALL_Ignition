"""
Honeypot Manager — Active Deception System
Threat Intelligence Pillar | Team SY-A9 | Shanteshwar

Zero-false-positive detection: any interaction with a decoy asset is
guaranteed malicious — no legitimate user would ever touch these files.
"""

import os
from datetime import datetime, timezone

import requests


class HoneypotManager:
    """
    Manages a registry of 5 fake (decoy) assets.
    Any interaction with a honeypot asset is a confirmed intrusion indicator.
    """

    def __init__(self):
        self.assets = self._build_registry()

    # ------------------------------------------------------------------
    # Registry
    # ------------------------------------------------------------------

    @staticmethod
    def _build_registry() -> dict:
        """Return the 5-asset honeypot registry keyed by asset_id."""
        return {
            "HP_SALARY_FILE": {
                "asset_id": "HP_SALARY_FILE",
                "asset_type": "fake_file",
                "description": "salary_2024_Q3_final.xlsx",
                "is_triggered": False,
                "trigger_count": 0,
                "last_triggered": None,
            },
            "HP_DB_CRED": {
                "asset_id": "HP_DB_CRED",
                "asset_type": "fake_file",
                "description": "db_credentials_prod.conf",
                "is_triggered": False,
                "trigger_count": 0,
                "last_triggered": None,
            },
            "HP_ADMIN_LOGIN": {
                "asset_id": "HP_ADMIN_LOGIN",
                "asset_type": "fake_endpoint",
                "description": "/admin/login decoy endpoint",
                "is_triggered": False,
                "trigger_count": 0,
                "last_triggered": None,
            },
            "HP_SSH_2222": {
                "asset_id": "HP_SSH_2222",
                "asset_type": "fake_service",
                "description": "Dummy SSH on port 2222",
                "is_triggered": False,
                "trigger_count": 0,
                "last_triggered": None,
            },
            "HP_CLOUD_CONFIG": {
                "asset_id": "HP_CLOUD_CONFIG",
                "asset_type": "fake_file",
                "description": "/backup/cloud_config.json",
                "is_triggered": False,
                "trigger_count": 0,
                "last_triggered": None,
            },
        }

    # ------------------------------------------------------------------
    # Trigger detection
    # ------------------------------------------------------------------

    def check_interaction(self, alert: dict) -> dict:
        """
        Scan an alert for honeypot interactions.

        Parameters
        ----------
        alert : dict
            Keys checked: raw_log, accessed_path, destination_port,
                          event_type, protocol

        Returns
        -------
        dict  { triggered: bool, asset_id: str|None, description: str|None }
        """
        # Safe defaults — never KeyError on missing fields
        raw_log = alert.get("raw_log", "")
        accessed_path = alert.get("accessed_path", "")
        dest_port = alert.get("destination_port", 0)
        event_type = alert.get("event_type", "")
        protocol = alert.get("protocol", "")

        now = datetime.now(timezone.utc).isoformat()

        # --- HP_SALARY_FILE ---
        if "salary_2024" in accessed_path or "salary_2024_Q3" in raw_log:
            return self._trigger("HP_SALARY_FILE", now)

        # --- HP_DB_CRED ---
        if "db_credentials_prod" in accessed_path or "db_credentials_prod" in raw_log:
            return self._trigger("HP_DB_CRED", now)

        # --- HP_ADMIN_LOGIN (path AND event_type must both match) ---
        if "/admin/login" in accessed_path and event_type in (
            "HTTP_REQUEST", "WEB_ACCESS", "GET", "POST",
        ):
            return self._trigger("HP_ADMIN_LOGIN", now)

        # --- HP_SSH_2222 (strict port == 2222, not port 22) ---
        if dest_port == 2222 and protocol in ("SSH", "TCP", "unknown"):
            return self._trigger("HP_SSH_2222", now)

        # --- HP_CLOUD_CONFIG ---
        if "cloud_config" in accessed_path or "cloud_config.json" in raw_log:
            return self._trigger("HP_CLOUD_CONFIG", now)

        # No honeypot matched
        return {"triggered": False, "asset_id": None, "description": None}

    def _trigger(self, asset_id: str, timestamp: str) -> dict:
        """Mark an asset as triggered and return the result dict."""
        asset = self.assets[asset_id]
        asset["is_triggered"] = True          # permanent — never resets
        asset["trigger_count"] += 1
        asset["last_triggered"] = timestamp
        return {
            "triggered": True,
            "asset_id": asset_id,
            "description": asset["description"],
        }

    # ------------------------------------------------------------------
    # CRITICAL override (Prompt 4)
    # ------------------------------------------------------------------

    def apply_honeypot_override(self, alert_result: dict, triggered_asset: dict) -> dict:
        """
        Force-override classification to CRITICAL with 1.0 confidence.
        Appends a zero-false-positive evidence trail entry.

        Parameters
        ----------
        alert_result : dict   — the full classification result dict
        triggered_asset : dict — output from check_interaction()

        Returns
        -------
        dict — the modified alert_result (also mutated in-place)
        """
        alert_result["severity"] = "CRITICAL"
        alert_result["confidence"] = 1.0
        alert_result["honeypot_triggered"] = True
        alert_result["triggered_asset_id"] = triggered_asset["asset_id"]

        # Ensure evidence_trail exists
        if "evidence_trail" not in alert_result:
            alert_result["evidence_trail"] = []

        alert_result["evidence_trail"].append(
            f"HONEYPOT TRIGGERED: {triggered_asset['description']} accessed. "
            f"Zero false positive \u2014 100% fidelity detection. "
            f"Asset: {triggered_asset['asset_id']}"
        )

        return alert_result

    def send_webhook_notification(self, alert_result: dict) -> None:
        """
        Fire an HTTP POST to HONEYPOT_WEBHOOK_URL (env var).
        CRITICAL: failures are logged but NEVER raised.
        """
        url = os.environ.get(
            "HONEYPOT_WEBHOOK_URL", "http://localhost:9999/dummy"
        )

        payload = {
            "event": "HONEYPOT_TRIGGERED",
            "severity": "CRITICAL",
            "asset_id": alert_result.get("triggered_asset_id", "unknown"),
            "alert_id": alert_result.get("alert_id", "unknown"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        try:
            requests.post(url, json=payload, timeout=5)
            print(f"[HONEYPOT] Webhook sent to {url}")
        except Exception as err:
            print(f"[HONEYPOT] Webhook failed (non-fatal): {err}")

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def get_triggered_assets(self) -> list:
        """Return a list of asset_ids that have been triggered."""
        return [
            aid for aid, asset in self.assets.items()
            if asset["is_triggered"]
        ]

    def get_asset_status(self) -> list:
        """Return full status of all assets (useful for the dashboard)."""
        return list(self.assets.values())


# ------------------------------------------------------------------
# Smoke-test
# ------------------------------------------------------------------
if __name__ == "__main__":
    h = HoneypotManager()
    # DB cred test
    r = h.check_interaction({
        "raw_log": "accessed db_credentials_prod.conf",
        "accessed_path": "/etc/db_credentials_prod.conf",
        "destination_port": 0,
        "event_type": "FILE_READ",
        "protocol": "",
    })
    print("DB cred test:", r)
    print("Triggered assets:", h.get_triggered_assets())
