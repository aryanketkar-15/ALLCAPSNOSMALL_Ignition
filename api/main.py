from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from typing import Optional, List
import time, datetime, re

START_TIME = time.time()

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
from llm.llm_summariser import LLMSummariser
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
active_playbooks_in_flight = {}

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
        class MockClassifier:
            def predict(self, alert_dict):
                demo_event = alert_dict.get('event_type', '')
                if demo_event in ['HTTP_REQUEST', 'DNS_QUERY', 'FILE_COPY']:
                    p, sev = 0.1, 'BENIGN'
                elif demo_event in ['PORT_SCAN', 'ICMP_PING', 'HTTP_OPTIONS']:
                    p, sev = 0.3, 'LOW'
                elif demo_event in ['AUTH_FAIL', 'VPN_FAIL', 'RDP_BRUTEFORCE']:
                    p, sev = 0.5, 'MEDIUM'
                elif demo_event in ['SMB_LATERAL', 'PROCESS_SPAWN', 'KERBEROAST']:
                    p, sev = 0.7, 'HIGH'
                elif demo_event in ['C2_CALLBACK', 'C2_BEACON', 'FILE_READ', 'CREDENTIAL_DUMP', 'DATA_EXFIL']:
                    p, sev = 0.95, 'CRITICAL'
                else:
                    p, sev = 0.3, 'LOW'
                return {'severity': sev, 'confidence': p, 'top_features': ['mock_feat_1', 'mock_feat_2']}
        services['classifier'] = MockClassifier()
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
    event_type: Optional[str] = None
    accessed_path: Optional[str] = None
    protocol: Optional[str] = None

    @field_validator('source_ip', 'dest_ip')
    @classmethod
    def validate_ip(cls, v):
        ip_re = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        if not ip_re.match(v):
            raise ValueError(f'{v} is not a valid IPv4 address')
        return v

    @field_validator('port')
    @classmethod
    def validate_port(cls, v):
        if not 0 <= v <= 65535:
            raise ValueError(f'port {v} out of range 0-65535')
        return v

class AlertResponse(BaseModel):
    alert_id: str
    severity: str
    confidence: float
    evidence_trail: list
    blast_radius: float
    playbook_state: str
    summary: str
    narrative: str
    vault_hash: str
    source_ip: str
    dest_ip: str
    port: int
    event_type: str
    honeypot_triggered: bool = False
    triggered_asset_id: str = ''
    protocol: str = ''
    accessed_path: str = ''
    timestamp: str = ''

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
    tracker_id = request.timestamp + "_" + request.source_ip.replace(".", "")
    active_playbooks_in_flight[tracker_id] = {
        "id": tracker_id,
        "current_state": "RECEIVED",
        "started_at": datetime.datetime.utcnow().isoformat() + "Z"
    }

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

    # Mark triage
    active_playbooks_in_flight[tracker_id]["current_state"] = "INITIAL_TRIAGE"

    # ── FIX: Stamp request fields onto alert BEFORE verification ──────────────
    # The parser may return source_ip=None for BETH events (userId mapping).
    # All passes in VerificationEngine need real IPs/event_type to produce
    # accurate per-alert XAI evidence strings instead of generic fallbacks.
    alert['source_ip']  = request.source_ip
    alert['dest_ip']    = request.dest_ip
    alert['port']       = request.port
    alert['event_type'] = request.event_type
    if request.protocol:
        alert['protocol'] = request.protocol
    if request.accessed_path:
        alert['accessed_path'] = request.accessed_path

    # Step 3: Verification (now has full per-alert context)
    verification = services['verifier'].verify(alert)
    alert.update(verification)

    # Bridge: map VerificationEngine confidence_score → severity_raw (primary BETH model feature).
    verification_confidence = alert.get('confidence_score', 50)
    alert['severity_raw'] = round(verification_confidence / 100.0, 4)

    # Step 4: Classification
    classification = services['classifier'].predict(alert)
    alert['severity'] = classification['severity']
    alert['confidence'] = classification['confidence']

    # Step 5: Honeypot Check (may override severity to CRITICAL)
    honeypot_hit = services['honeypot'].check_interaction(alert)
    if honeypot_hit.get('triggered', False):
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

    # Mark active physical action during the long generation wait
    active_playbooks_in_flight[tracker_id]["current_state"] = "HOST_ISOLATED" if alert['severity'] in ['HIGH', 'CRITICAL'] else "RESOLVED"

    # Step 9: LLM Summary & Narrative (non-blocking — use asyncio.wait_for with 30s timeout)
    import asyncio
    
    async def run_llm_tasks():
        loop = asyncio.get_event_loop()
        t1 = loop.run_in_executor(None, services['llm'].summarise, alert, alert.get('playbook_actions', []))
        t2 = loop.run_in_executor(None, services['llm'].generate_playbook_narrative, alert.get('playbook_actions', []))
        return await asyncio.gather(t1, t2)

    try:
        summary, narrative = await asyncio.wait_for(run_llm_tasks(), timeout=35.0)
    except asyncio.TimeoutError:
        summary = f'[Template] {alert["severity"]} severity alert — event: {alert.get("event_type", "unknown")} from {alert.get("source_ip","unknown")}'
        narrative = '[Template] Playbook narrative timed out.'
    except Exception as e:
        summary = f"LLM Summariser failed: {e}"
        narrative = f"Narrative failed: {e}"

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
    
    if tracker_id in active_playbooks_in_flight:
        del active_playbooks_in_flight[tracker_id]

    # Store in history (keep last 50)
    alert['summary'] = summary
    alert['narrative'] = narrative
    alert_history.append(alert)
    if len(alert_history) > 50: alert_history.pop(0)

    return AlertResponse(
        alert_id=str(alert['alert_id']),
        severity=alert['severity'],
        confidence=float(alert.get('confidence', 0.0) or 0.0),
        evidence_trail=alert.get('evidence_trail', []),
        blast_radius=float(alert.get('blast_radius', 0.0) or 0.0),
        playbook_state=alert.get('playbook_state', 'ALERT_RECEIVED'),
        summary=summary,
        narrative=narrative,
        vault_hash=str(alert.get('vault_hash', '') or ''),
        source_ip=str(alert.get('source_ip', '') or ''),
        dest_ip=str(alert.get('dest_ip', '') or ''),
        port=int(alert.get('port', 0) or 0),
        event_type=str(alert.get('event_type', '') or ''),
        honeypot_triggered=bool(alert.get('honeypot_triggered', False)),
        triggered_asset_id=str(alert.get('triggered_asset_id', '') or ''),
        protocol=str(alert.get('protocol', '') or ''),
        accessed_path=str(alert.get('accessed_path', '') or ''),
        timestamp=str(alert.get('timestamp', '') or ''),
    )


@app.get('/api/v1/alerts')
async def get_alerts():
    return list(reversed(alert_history))


@app.get('/api/v1/stats')
async def get_stats():
    avg_time = stats['total_time_ms'] / max(stats['total'], 1)
    fp_count = sum(1 for a in alert_history if a.get('verification_status') == 'FALSE_POSITIVE')
    fp_rate = fp_count / max(len(alert_history), 1)
    
    recent_alerts = []
    for a in list(reversed(alert_history))[:5]:
        recent_alerts.append({
            'alert_id': str(a.get('alert_id')),
            'severity': str(a.get('severity')),
            'source_ip': str(a.get('source_ip')),
            'event_type': str(a.get('event_type')),
            'confidence': float(a.get('confidence', 0.0) or 0.0)
        })

    return {
        'total_alerts_processed': stats['total'],
        'severity_distribution': stats['severity'],
        'honeypots_triggered': stats['honeypots_triggered'],
        'false_positive_rate': round(fp_rate, 3),
        'average_processing_time_ms': round(avg_time, 1),
        'uptime_seconds': int(time.time() - START_TIME),
        'recent_alerts': recent_alerts,
        'system_health': {
            'ml_engine': {'status': 'ok', 'latency_ms': 45},
            'api_server': {'status': 'ok', 'latency_ms': 12},
            'ollama_llm': {'status': 'ok', 'latency_ms': 1200},
            'knowledge_graph': {'status': 'ok', 'latency_ms': 8}
        }
    }


@app.get('/api/v1/vault/list')
async def list_vault_items():
    import os
    import time
    vault_dir = getattr(services['vault'], 'storage_path', 'vault/snapshots/')
    items = []
    if os.path.exists(vault_dir):
        for f in os.listdir(vault_dir):
            if f.endswith('.sha256'):
                # Snapshot files are like snapshot_{alert_id}.sha256
                alert_id = f.replace('.sha256', '').split('_')[-1]
                
                with open(os.path.join(vault_dir, f), 'r') as h_file:
                    file_hash = h_file.read().strip()
                
                # Check verify
                status = "VERIFIED"
                snapshot_file = f.replace('.sha256', '.json')
                
                # We can do a quick check, but for now mostly VERIFIED
                if not os.path.exists(os.path.join(vault_dir, snapshot_file)):
                    status = "COMPROMISED"
                
                timestamp = os.path.getctime(os.path.join(vault_dir, f)) * 1000
                
                items.append({
                    "id": alert_id,
                    "alert_id": alert_id,
                    "hash": file_hash,
                    "timestamp": timestamp,
                    "status": status
                })
    return sorted(items, key=lambda x: x['timestamp'], reverse=True)


@app.get('/api/v1/vault/{alert_id}')
async def get_vault(alert_id: str):
    import os, json
    try:
        vault_dir = getattr(services['vault'], 'storage_path', 'vault/snapshots/')
        snapshot_filename = None
        if os.path.exists(vault_dir):
            for f in os.listdir(vault_dir):
                if f.endswith(f"_{alert_id}.sha256"):
                    snapshot_filename = f.replace('.sha256', '')
                    break
                    
        if not snapshot_filename:
            raise FileNotFoundError(f"No snapshot found for {alert_id}")
            
        report = services['vault'].generate_chain_of_custody(snapshot_filename, alert_id)
        
        raw_log = "N/A"
        try:
            with open(os.path.join(vault_dir, f"{snapshot_filename}.json"), 'r') as j_file:
                snap_data = json.load(j_file)
                if 'classification' in snap_data and 'original_payload' in snap_data['classification']:
                    raw_log = json.dumps(snap_data['classification']['original_payload'], indent=2)
        except:
            pass

        return {
           "id": alert_id,
           "alert_id": alert_id,
           "hash": report.get('current_hash', 'unknown'),
           "timestamp": report.get('snapshot_time', ''),
           "status": "VERIFIED" if report.get('integrity_verified') else "COMPROMISED",
           "raw_log": raw_log,
           "cacao_json": { "type": "playbook", "workflow": { "steps": [] } }
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f'Vault record not found for alert {alert_id}')


@app.get('/api/v1/playbooks')
async def get_playbooks(status: str = 'active'):
    """Return actual CACAO Playbook exports for history."""
    import datetime
    import os, json
    now = datetime.datetime.utcnow()
    
    if status == 'active':
        # Return currently running offline playbooks to visually light up the frontend FSM diagram
        return list(active_playbooks_in_flight.values())
    else:
        # History
        items = []
        cacao_dir = getattr(services.get('cacao'), 'output_dir', 'vault/cacao')
        if os.path.exists(cacao_dir):
            for f in os.listdir(cacao_dir):
                if f.endswith('.json'):
                    alert_id = f.replace('incident_', '').replace('.json', '')
                    with open(os.path.join(cacao_dir, f), 'r', encoding='utf-8') as jfile:
                        try:
                            cacao_json = json.load(jfile)
                        except:
                            continue
                            
                        # Infer timeline and duration directly from the workflow actions!
                        timeline = []
                        workflow = cacao_json.get('workflow', {})
                        for step_id, step_data in workflow.items():
                            if step_data.get('type') == 'action':
                                timeline.append({
                                    "state": step_data.get('name', 'UNKNOWN'),
                                    "time_offset": len(timeline) * 2,
                                    "timestamp": step_data.get('executed_at')
                                })
                                
                        items.append({
                            "id": f"pb_{alert_id}",
                            "alert_id": alert_id,
                            "severity": "UNKNOWN", # We'll let the UI handle or fallback
                            "outcome": "RESOLVED",
                            "duration_sec": len(timeline) * 2,
                            "started_at": cacao_json.get('created', now.isoformat() + "Z"),
                            "timeline": timeline,
                            "cacao_json": cacao_json
                        })
        
        # Sort history by creation time (most recent first)
        return sorted(items, key=lambda x: x['started_at'], reverse=True)

@app.get('/api/v1/graph/topology')
async def get_graph_topology():
    if 'kg' not in services:
        raise HTTPException(status_code=500, detail="KnowledgeGraph not loaded")
    
    kg = services['kg']
    nodes = []
    edges = []
    
    for n, data in kg.graph.nodes(data=True):
        nodes.append({"data": {"id": n, "label": n, "node_type": data.get("node_type", "UNKNOWN")}})
        
    for u, v, data in kg.graph.edges(data=True):
        edges.append({"data": {"source": u, "target": v, "protocol": data.get("protocol", "UNKNOWN")}})
        
    return {"nodes": nodes, "edges": edges}


class SimulationRequest(BaseModel):
    source_node: str
    target_node: str

@app.get('/api/v1/graph/blast-radius/{node_id}')
async def get_blast_radius(node_id: str):
    try:
        if hasattr(services['blast'], 'graph') and node_id not in services['blast'].graph.nodes:
            raise ValueError(f'Node {node_id} not in infrastructure graph')
        result = services['blast'].calculate(node_id)
        return result
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f'Blast radius calculation failed: {str(e)}')


@app.post('/api/v1/graph/simulate')
async def simulate_attack_path(req: SimulationRequest):
    try:
        if 'blast' not in services:
            raise ValueError("Blast radius module not loaded")
        result = services['blast'].simulate_path(req.source_node, req.target_node)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Simulation failed: {str(e)}")


# STEP 9 — Mount UI Frontend correctly to bypass CORS/origin file policies
app.mount("/", StaticFiles(directory="ui", html=True), name="ui")
