from langgraph.graph import StateGraph, END
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
