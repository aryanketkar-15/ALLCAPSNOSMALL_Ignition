from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
import time, datetime

# STEP 1 — Corrected imports mapped to exactly what Aryan, Shanteshwar, and Ajaya deployed:
from ingestion.parser import LogParser
from ingestion.ioc_extractor import IOCExtractor
from ingestion.verification import VerificationEngine
# Updated to match Aryan's actual filename:
from classifier.classifier_service import ClassifierService
# Updated to match Shanteshwar's components:
# (Assuming graph, blast_radius exist in knowledge_graph and honeypot_manager exists in honeypot)
# We handle import errors dynamically below if Shanteshwar hasn't fully pushed the classes yet
from playbooks.state_machine import PlaybookStateMachine
from playbooks.llm_summariser import LLMSummariser
from vault.forensics import ForensicVault
from vault.cacao_exporter import CacaoExporter

app = FastAPI(title='SOC AI Classification System', version='1.0.0')

# STEP 2 — CORS middleware (add BEFORE routes)
app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=False,
    allow_methods=['*'],
    allow_headers=['*'],
)

# STEP 3 — Shared state
services = {}
alert_history: List[dict] = []  # in-memory store, last 50 alerts
stats = {
    'total': 0, 
    'severity': {'BENIGN':0, 'LOW':0, 'MEDIUM':0, 'HIGH':0, 'CRITICAL':0},
    'honeypots_triggered': 0, 
    'total_time_ms': 0
}

# STEP 4 — Startup event
@app.on_event('startup')
async def startup():
    print('[STARTUP] Initialising SOC AI Pipeline Services...')
    # Load Rishi's modules
    services['parser'] = LogParser()
    services['ioc'] = IOCExtractor()
    services['verifier'] = VerificationEngine()
    
    # Load Aryan's models (Takes 1.4s)
    try:
        services['classifier'] = ClassifierService()
    except Exception as e:
        print(f"[WARN] Failed to load ClassifierService: {e}. Injecting Mock.")
        services['classifier'] = type('Mock', (), {'predict': lambda s,x: {'severity':'LOW','confidence':0.3,'top_features':[]}})()
        
    # Load Shanteshwar's graphs & honeypots
    try:
        from knowledge_graph.blast_radius import BlastRadiusAnalyser
        services['blast'] = BlastRadiusAnalyser()
    except Exception as e:
        print(f"[WARN] Failed to load BlastRadiusAnalyser: {e}")
        
    try:
        from honeypot.honeypot_manager import HoneypotManager
        services['honeypot'] = HoneypotManager()
    except Exception as e:
        print(f"[WARN] Failed to load HoneypotManager: {e}")
        
    try:
        from knowledge_graph.graph import KnowledgeGraph
        services['kg'] = KnowledgeGraph()
    except Exception as e:
        print(f"[WARN] Failed to load KnowledgeGraph: {e}")

    # Load Ajaya's FSM & Vault
    try:
        services['playbook'] = PlaybookStateMachine()
    except Exception as e:
        print(f"[WARN] Failed to load PlaybookStateMachine: {e}")
        
    try:
        services['llm'] = LLMSummariser()
    except Exception as e:
        print(f"[WARN] Failed to load LLMSummariser: {e}")
        
    try:
        services['vault'] = ForensicVault()
    except Exception as e:
        print(f"[WARN] Failed to load ForensicVault: {e}")
        
    try:
        services['cacao'] = CacaoExporter()
    except Exception as e:
        print(f"[WARN] Failed to load CacaoExporter: {e}")

    print('[STARTUP] All available services loaded successfully into memory.')

# STEP 5 — Pydantic request/response models
class AlertRequest(BaseModel):
    raw_log: str
    source_ip: str
    dest_ip: str
    port: int
    timestamp: str

class AlertResponse(BaseModel):
    alert_id: str
    severity: str
    confidence: float
    evidence_trail: list
    blast_radius: float
    playbook_state: str
    summary: str
    vault_hash: str

# STEP 6 — Health endpoint
@app.get('/health')
async def health():
    return {
        'status': 'ok', 
        'services_loaded': list(services.keys()), 
        'time': datetime.datetime.utcnow().isoformat()
    }


# =====================================================================
# PIPELINE ENDPOINTS
# =====================================================================

def _sanitise(obj):
    """Recursively convert non-JSON-serialisable types to safe primitives."""
    import numpy as np, pandas as pd
    if isinstance(obj, dict):
        return {k: _sanitise(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_sanitise(i) for i in obj]
    elif isinstance(obj, (pd.Timestamp, datetime.datetime)):
        return obj.isoformat()
    elif isinstance(obj, (np.integer,)):
        return int(obj)
    elif isinstance(obj, (np.floating,)):
        return float(obj)
    elif isinstance(obj, (np.bool_,)):
        return bool(obj)
    elif isinstance(obj, (np.ndarray,)):
        return obj.tolist()
    return obj


@app.post('/api/v1/classify', response_model=AlertResponse)
async def classify_alert(request: AlertRequest):
    start = time.perf_counter()

    # Step 1: Parse
    alert = services['parser'].parse({
        'raw_log': request.raw_log,
        'source_ip': request.source_ip,
        'dest_ip': request.dest_ip,
        'port': request.port,
        'timestamp': request.timestamp,
    }, dataset='unsw')  # auto-detect dataset if possible

    # Step 2: IOC Extraction
    import pandas as pd
    df = pd.DataFrame([alert])
    df = services['ioc'].extract_all(df)
    alert = df.iloc[0].to_dict()

    # Step 3: Verification
    verification = services['verifier'].verify(alert)
    alert.update(verification)

    # Step 4: Classification
    classification = services['classifier'].predict(alert)
    alert['severity'] = classification['severity']
    alert['confidence'] = classification['confidence']

    # Step 5: Honeypot Check (may override severity to CRITICAL)
    honeypot_hit = services['honeypot'].check_interaction(alert)
    if honeypot_hit:
        alert['severity'] = 'CRITICAL'
        alert['confidence'] = 1.0
        alert['evidence_trail'].append('HONEYPOT TRIGGERED: 100% fidelity detection — zero false positive possible')
        stats['honeypots_triggered'] += 1

    # Step 6: Blast Radius
    blast_result = services['blast'].calculate(alert.get('source_ip', 'WORKSTATION_1'))
    alert['blast_radius'] = blast_result.get('blast_radius_score', 0.0)

    # Step 7: Playbook
    from playbooks.state_machine import PlaybookState
    state_input = {
        'alert_id': str(alert.get('alert_id', 'none')),
        'severity': alert.get('severity', 'LOW'),
        'source_ip': alert.get('source_ip', '0.0.0.0'),
        'blast_radius': alert.get('blast_radius', 0.0),
        'current_state': PlaybookState.ALERT_RECEIVED,
        'actions_log': [],
        'remediation_attempts': 0,
        'last_alert_time': time.time()
    }
    playbook_result = services['playbook'].graph.invoke(state_input)
    alert['playbook_state'] = playbook_result.get('current_state', PlaybookState.ALERT_RECEIVED).value
    alert['playbook_actions'] = playbook_result.get('actions_log', [])

    # Step 8: Forensic Vault — sanitise first so json.dumps inside vault doesn't choke on Timestamps
    alert = _sanitise(alert)
    vault_filename, vault_hash = services['vault'].capture_snapshot(alert)
    alert['vault_hash'] = vault_hash

    # Step 9: LLM Summary (non-blocking — use asyncio.wait_for with 30s timeout)
    import asyncio
    try:
        # Adjusted to match Ajaya's two-argument signature
        summary = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(None, services['llm'].summarise, alert, alert.get('playbook_actions', [])),
            timeout=30.0
        )
    except asyncio.TimeoutError:
        summary = f'[Template] {alert["severity"]} severity alert — event: {alert.get("event_type", "unknown")} from {alert.get("source_ip","unknown")}'
    except Exception as e:
        summary = f"LLM Summariser failed: {e}"

    # Step 10: CACAO Export (fire and forget — non-blocking)
    try:
        services['cacao'].export(alert['alert_id'], alert.get('playbook_actions', []), summary)
    except Exception as e:
        print(f'[CACAO] Non-fatal export error: {e}')

    elapsed_ms = (time.perf_counter() - start) * 1000
    print(f'[CLASSIFY] {alert["alert_id"]} processed in {elapsed_ms:.0f}ms — severity: {alert["severity"]}')

    # Update stats
    stats['total'] += 1
    stats['severity'][alert['severity']] = stats['severity'].get(alert['severity'], 0) + 1
    stats['total_time_ms'] += elapsed_ms

    # Store in history (keep last 50)
    alert['summary'] = summary
    alert_history.append(alert)
    if len(alert_history) > 50: alert_history.pop(0)

    return AlertResponse(
        alert_id=str(alert['alert_id']),
        severity=alert['severity'],
        confidence=alert['confidence'],
        evidence_trail=alert.get('evidence_trail', []),
        blast_radius=alert.get('blast_radius', 0.0),
        playbook_state=alert.get('playbook_state', 'ALERT_RECEIVED'),
        summary=summary,
        vault_hash=alert.get('vault_hash', ''),
    )


@app.get('/api/v1/alerts')
async def get_alerts():
    return list(reversed(alert_history))
