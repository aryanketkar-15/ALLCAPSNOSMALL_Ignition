from enum import Enum
from typing import TypedDict

class PlaybookState(str, Enum):
    ALERT_RECEIVED = "ALERT_RECEIVED"
    INITIAL_TRIAGE = "INITIAL_TRIAGE"
    IP_BLOCKED = "IP_BLOCKED"
    ASN_BLOCKED = "ASN_BLOCKED"
    HOST_ISOLATED = "HOST_ISOLATED"
    ESCALATED_TO_L2 = "ESCALATED_TO_L2"
    RESOLVED = "RESOLVED"
    FAILED_DEFENCE = "FAILED_DEFENCE"

class PlaybookContext(TypedDict):
    alert_id: str
    severity: str          # 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
    src_ip: str
    blast_radius: int      # 0-100
    current_state: PlaybookState
    actions_log: list      # list of dicts
    failed_attempts: int   # default 0
    remediation_attempts: int
