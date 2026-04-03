from datetime import datetime, timezone
from playbooks.states import PlaybookState, PlaybookContext

def extract_asn_block(ip: str) -> str:
    """Takes an IP like '192.168.1.100' and returns the /16 block '192.168.0.0/16'."""
    parts = ip.split('.')
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.0.0/16"
    return "0.0.0.0/16"

def _record_action(ctx: PlaybookContext, new_state: PlaybookState, action_taken: str, reason: str) -> PlaybookContext:
    action_record = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'from_state': ctx['current_state'],
        'to_state': new_state,
        'action_taken': action_taken,
        'reason': reason
    }
    
    if 'actions_log' not in ctx:
        ctx['actions_log'] = []
    
    ctx['actions_log'].append(action_record)
    ctx['current_state'] = new_state
    return ctx

def receive_alert(ctx: PlaybookContext) -> PlaybookContext:
    return _record_action(
        ctx, 
        PlaybookState.INITIAL_TRIAGE, 
        "Alert received and parsed", 
        "Initial ingestion of alert data."
    )

def triage(ctx: PlaybookContext) -> PlaybookContext:
    severity = ctx.get('severity', '')
    blast_radius = ctx.get('blast_radius', 0)
    
    if severity in ['HIGH', 'CRITICAL']:
        new_state = PlaybookState.IP_BLOCKED
        reason = f"Severity is {severity}."
    elif severity == 'MEDIUM' and blast_radius > 60:
        new_state = PlaybookState.ESCALATED_TO_L2
        reason = f"Severity is MEDIUM with high blast radius ({blast_radius})."
    else:
        # Default fallback if it doesn't meet the blocking/escalation threshold explicitly outlined
        new_state = PlaybookState.RESOLVED
        reason = f"Severity {severity} does not require immediate blocking."
        
    return _record_action(
        ctx, 
        new_state, 
        "Automated triage assessment completed", 
        reason
    )

def block_ip(ctx: PlaybookContext) -> PlaybookContext:
    ctx['remediation_attempts'] = ctx.get('remediation_attempts', 0) + 1
    return _record_action(
        ctx, 
        PlaybookState.IP_BLOCKED, 
        f"Blocked individual IP: {ctx.get('src_ip')}", 
        "Isolation mandated by playbook rules."
    )

def block_asn(ctx: PlaybookContext) -> PlaybookContext:
    ip = ctx.get('src_ip', '')
    subnet = extract_asn_block(ip)
    return _record_action(
        ctx, 
        PlaybookState.ASN_BLOCKED, 
        f"Blocked ASN/subnet: {subnet}", 
        "Attacker rotating IPs inside the same ASN block."
    )

def isolate_host(ctx: PlaybookContext) -> PlaybookContext:
    return _record_action(
        ctx, 
        PlaybookState.HOST_ISOLATED, 
        "Isolated targeted host from network", 
        "Prevent lateral movement."
    )

def escalate_l2(ctx: PlaybookContext) -> PlaybookContext:
    return _record_action(
        ctx, 
        PlaybookState.ESCALATED_TO_L2, 
        "Escalated to human L2 analyst", 
        "Complexity or blast radius exceeds automated playbook capabilities."
    )

def resolve(ctx: PlaybookContext) -> PlaybookContext:
    return _record_action(
        ctx, 
        PlaybookState.RESOLVED, 
        "Incident closed", 
        "Threat mitigated successfully or marked as false positive."
    )

def failed_defence(ctx: PlaybookContext) -> PlaybookContext:
    return _record_action(
        ctx, 
        PlaybookState.FAILED_DEFENCE, 
        "Automated defense failed - triggering immediate L2 PagerDuty alert", 
        "Failed to remediate threat within allowed attempts/parameters."
    )
