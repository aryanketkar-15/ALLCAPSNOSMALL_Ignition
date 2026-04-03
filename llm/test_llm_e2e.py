import sys
sys.path.insert(0, '.')

from llm.llm_summariser import LLMSummariser

def main():
    print("Initiating test_llm_e2e...")
    s = LLMSummariser()

    alert_ctx = {
        'alert_id': 'ALT-2024-001',
        'severity': 'HIGH',
        'event_type': 'privilege_escalation',
        'source_ip': '192.168.1.45',
        'confidence': 0.87,
        'top_features': ['argsNum']
    }
    
    actions_log = [
        {'timestamp': '2024-01-01T22:00:00', 'from_state': 'ALERT_RECEIVED', 'to_state': 'INITIAL_TRIAGE', 'action_taken': 'Alert triaged', 'reason': 'HIGH severity'},
        {'timestamp': '2024-01-01T22:00:05', 'from_state': 'INITIAL_TRIAGE', 'to_state': 'IP_BLOCKED', 'action_taken': 'Blocked 192.168.1.45', 'reason': 'HIGH + blast_radius > 3'},
        {'timestamp': '2024-01-01T22:05:00', 'from_state': 'IP_BLOCKED', 'to_state': 'RESOLVED', 'action_taken': 'Incident resolved', 'reason': 'No further alerts from IP'}
    ]

    print("\n[1/3] Testing Live summarise()...")
    summary = s.summarise(alert_ctx)
    assert len(summary) > 50, f"Summary too short: {len(summary)}"
    # Using uppercase conversion for robust finding of the tag keys or natural text
    keywords = ['ATTACK', 'THREAT', 'SUMMARY', 'HIGH', 'PRIVILEGE']
    assert any(k in summary.upper() for k in keywords), "Summary missing required context keywords"
    print("      -> Live summarize PASSED")

    print("[2/3] Testing Live generate_playbook_narrative()...")
    narrative = s.generate_playbook_narrative(actions_log)
    assert len(narrative) > 50, "Narrative too short"
    print("      -> Live narrative PASSED")

    print("[3/3] Testing Network Breakdown Fallback Resiliency...")
    # Monkeypatch to simulate offline/timeout
    original_call = s._call_ollama
    s._call_ollama = lambda prompt: None  

    fallback_summary = s.summarise(alert_ctx)
    assert len(fallback_summary) > 0 and 'SUMMARY:' in fallback_summary, "Fallback summary corrupted"

    fallback_narrative = s.generate_playbook_narrative(actions_log)
    assert len(fallback_narrative) > 0 and 'INCIDENT NARRATIVE:' in fallback_narrative, "Fallback narrative corrupted"
    
    # Reset Monkeypatch
    s._call_ollama = original_call
    print("      -> Mock Fallbacks PASSED")

    print("\nALL LLM TESTS PASSED")

if __name__ == "__main__":
    main()
