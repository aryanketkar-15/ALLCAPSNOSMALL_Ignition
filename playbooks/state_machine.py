import time
from enum import Enum
from typing import Dict, List, TypedDict, Annotated, Union
from datetime import datetime
from langgraph.graph import StateGraph, END

# [cite: 76, 200] Define playbook states as Python Enums
class PlaybookState(Enum):
    ALERT_RECEIVED = "ALERT_RECEIVED"
    INITIAL_TRIAGE = "INITIAL_TRIAGE"
    IP_BLOCKED = "IP_BLOCKED"
    ASN_BLOCKED = "ASN_BLOCKED"
    HOST_ISOLATED = "HOST_ISOLATED"
    ESCALATED_TO_L2 = "ESCALATED_TO_L2"
    RESOLVED = "RESOLVED"
    FAILED_DEFENCE = "FAILED_DEFENCE"

# [cite: 80, 207] Define the state schema for the graph
class AgentState(TypedDict):
    alert_id: str
    severity: str
    source_ip: str
    blast_radius: float
    current_state: PlaybookState
    actions_log: List[Dict]
    remediation_attempts: int
    last_alert_time: float

class PlaybookStateMachine:
    def __init__(self):
        # [cite: 77, 201] Implement StateGraph
        builder = StateGraph(AgentState)

        # Define Nodes [cite: 201]
        builder.add_node("receive_alert", self.receive_alert)
        builder.add_node("triage", self.triage)
        builder.add_node("block_ip", self.block_ip)
        builder.add_node("block_asn", self.block_asn)
        builder.add_node("escalate", self.escalate)

        # [cite: 78, 201] Define Edges and Logic
        builder.set_entry_point("receive_alert")
        builder.add_edge("receive_alert", "triage")
        
        # [cite: 202, 203] Conditional transitions from Triage
        builder.add_conditional_edges(
            "triage",
            self.triage_routing,
            {
                "block": "block_ip",
                "escalate": "escalate",
                "end": END
            }
        )

        # [cite: 205] IP Block to ASN or Resolve
        builder.add_conditional_edges(
            "block_ip",
            self.check_repetition,
            {
                "asn_escalate": "block_asn",
                "resolve": END
            }
        )

        builder.add_edge("block_asn", END)
        builder.add_edge("escalate", END)

        self.graph = builder.compile()

    def _log_action(self, state: AgentState, to_state: PlaybookState, action: str, reason: str):
        # [cite: 80, 207] Log state transitions
        state['actions_log'].append({
            "timestamp": datetime.utcnow().isoformat(),
            "from_state": state['current_state'].value,
            "to_state": to_state.value,
            "action_taken": action,
            "reason": reason
        })
        state['current_state'] = to_state

    def receive_alert(self, state: AgentState):
        self._log_action(state, PlaybookState.INITIAL_TRIAGE, "Alert Ingestion", "System received new raw SIEM log")
        return state

    def triage_routing(self, state: AgentState):
        # [cite: 78, 202, 203] Routing logic based on severity and blast radius
        if state['severity'] in ["HIGH", "CRITICAL"]:
            return "block"
        elif state['severity'] == "MEDIUM" and state['blast_radius'] > 5.0:
            return "escalate"
        return "end"

    def triage(self, state: AgentState):
        return state

    def block_ip(self, state: AgentState):
        # [cite: 204] Simulate IP Block action
        self._log_action(state, PlaybookState.IP_BLOCKED, f"Blocked IP {state['source_ip']}", "High severity threat detected")
        return state

    def check_repetition(self, state: AgentState):
        # [cite: 78, 205] Simulate self-correction for repeating attackers
        # In a real scenario, this would check the database/cache for timing
        if state.get('is_repeat_attacker', False):
            return "asn_escalate"
        return "resolve"

    def block_asn(self, state: AgentState):
        # [cite: 79, 206] ASN escalation logic
        ip_parts = state['source_ip'].split('.')
        asn_prefix = f"{ip_parts[0]}.{ip_parts[1]}.0.0/16"
        self._log_action(state, PlaybookState.ASN_BLOCKED, f"Blocked ASN {asn_prefix}", "Attacker switched IPs within subnet")
        return state

    def escalate(self, state: AgentState):
        # [cite: 81, 208] Immediate L2 escalation
        self._log_action(state, PlaybookState.ESCALATED_TO_L2, "L2 Escalation", "Medium threat with high blast radius or defense failure")
        return state