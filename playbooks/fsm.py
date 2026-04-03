from langgraph.graph import StateGraph, END
import json
import threading
from datetime import datetime, timezone
from playbooks.states import PlaybookState, PlaybookContext
from playbooks.actions import (
    receive_alert, triage, block_ip, block_asn,
    isolate_host, escalate_l2, resolve, failed_defence
)

def triage_decision(ctx: PlaybookContext) -> str:
    severity = ctx.get('severity', '')
    blast_radius = ctx.get('blast_radius', 0)
    if severity in ('HIGH', 'CRITICAL'):
        return 'block_ip'
    if severity == 'MEDIUM' and blast_radius > 60:
        return 'escalate_l2'
    return 'resolve'

def block_ip_decision(ctx: PlaybookContext) -> str:
    remediation_attempts = ctx.get('remediation_attempts', 0)
    blast_radius = ctx.get('blast_radius', 0)
    if remediation_attempts >= 3:
        return 'failed_defence'
    if blast_radius > 80:
        return 'block_asn'
    return 'resolve'

class PlaybookStateMachine:
    def __init__(self):
        graph = StateGraph(PlaybookContext)
        
        # Add nodes
        graph.add_node("receive_alert", receive_alert)
        graph.add_node("triage", triage)
        graph.add_node("block_ip", block_ip)
        graph.add_node("block_asn", block_asn)
        graph.add_node("isolate_host", isolate_host)
        graph.add_node("escalate_l2", escalate_l2)
        graph.add_node("resolve", resolve)
        graph.add_node("failed_defence", failed_defence)

        # Set entry point
        graph.set_entry_point("receive_alert")

        # Explicit edges
        graph.add_edge("receive_alert", "triage")
        graph.add_edge("block_asn", "resolve")
        graph.add_edge("isolate_host", "resolve")
        graph.add_edge("escalate_l2", END)
        graph.add_edge("failed_defence", END)
        graph.add_edge("resolve", END)
        
        # Conditional edges
        graph.add_conditional_edges("triage", triage_decision)
        graph.add_conditional_edges("block_ip", block_ip_decision)
        
        self.graph = graph.compile()

    def run(self, ctx: PlaybookContext) -> PlaybookContext:
        """Invoke the compiled graph with the provided state."""
        return self.graph.invoke(ctx)

    def generate_playbook_narrative(self, actions_log: list, alert_id: str) -> str:
        if not actions_log:
            return f"Incident {alert_id}: No response actions log."

        start_time = actions_log[0].get('timestamp', 'unknown')
        end_time = actions_log[-1].get('timestamp', 'unknown')
        final_state = actions_log[-1].get('to_state', 'UNKNOWN')

        fallback_narrative = (
            f"Incident {alert_id}: Automated response initiated at {start_time}.\n"
            f"System executed {len(actions_log)} response actions.\n"
            f"Final state: {final_state} at {end_time}."
        )

        try:
            from llm.llm_summariser import LLMSummariser

            result_container = []

            def _call_llm():
                try:
                    res = LLMSummariser().generate_playbook_narrative(actions_log)
                    result_container.append(res)
                except Exception:
                    pass

            t = threading.Thread(target=_call_llm)
            t.start()
            t.join(30.0)

            if t.is_alive() or not result_container:
                return fallback_narrative

            return result_container[0]

        except ImportError:
            return fallback_narrative
        except Exception:
            return fallback_narrative
