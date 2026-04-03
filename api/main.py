from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
import time, datetime

# Track API startup time for uptime calculation
startup_time = time.time()

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
        print(f"[WARN] Failed to load ClassifierService: {e}")
        
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
    timestamp: str = ''
    event_type: str = ''
    accessed_path: str = ''
    protocol: str = ''

class AlertResponse(BaseModel):
    alert_id: str
    severity: str
    confidence: float
    evidence_trail: list
    blast_radius: float
    playbook_state: str
    summary: str
    vault_hash: str

class StatsResponse(BaseModel):
    total_alerts_processed: int
    severity_distribution: dict
    honeypots_triggered: int
    false_positive_rate: float
    average_processing_time_ms: float
    uptime_seconds: int

# STEP 6 — Health endpoint
@app.get('/health')
async def health():
    return {
        'status': 'ok', 
        'services_loaded': list(services.keys()), 
        'time': datetime.datetime.utcnow().isoformat()
    }

# ══════════════════════════════════════════════════════════════
# STEP 7 — Shanteshwar's Phase 6 endpoints (Prompts 6 & 7)
# ══════════════════════════════════════════════════════════════

@app.get('/api/v1/stats', response_model=StatsResponse)
async def get_stats():
    """Live system statistics — powers the dashboard right panel."""
    total = stats['total']
    sev = stats['severity']
    benign_count = sev.get('BENIGN', 0)
    fp_rate = round((benign_count / total * 100), 1) if total > 0 else 0.0
    avg_time = round(stats['total_time_ms'] / total, 2) if total > 0 else 0.0

    return StatsResponse(
        total_alerts_processed=total,
        severity_distribution={
            'BENIGN': sev.get('BENIGN', 0),
            'LOW': sev.get('LOW', 0),
            'MEDIUM': sev.get('MEDIUM', 0),
            'HIGH': sev.get('HIGH', 0),
            'CRITICAL': sev.get('CRITICAL', 0),
        },
        honeypots_triggered=stats['honeypots_triggered'],
        false_positive_rate=fp_rate,
        average_processing_time_ms=avg_time,
        uptime_seconds=int(time.time() - startup_time),
    )


@app.get('/api/v1/vault/{alert_id}')
async def get_vault(alert_id: str):
    """Forensic vault — chain of custody report for a processed alert."""
    vault_svc = services.get('vault')
    if vault_svc is None:
        raise HTTPException(status_code=503, detail='ForensicVault service not loaded')

    # Check if snapshot exists
    try:
        integrity_ok = vault_svc.verify_integrity(alert_id)
    except (FileNotFoundError, KeyError, Exception):
        raise HTTPException(status_code=404, detail={
            'error': 'SNAPSHOT_NOT_FOUND',
            'alert_id': alert_id,
        })

    if not integrity_ok:
        raise HTTPException(status_code=409, detail={
            'error': 'VAULT_TAMPERED',
            'alert_id': alert_id,
            'message': 'Snapshot integrity check failed — file may have been modified',
        })

    try:
        report = vault_svc.generate_chain_of_custody(alert_id)
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse(content=report, media_type='text/plain')
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get('/api/v1/graph/blast-radius/{node_id}')
async def get_blast_radius(node_id: str, include_paths: bool = True):
    """Blast radius query for a given infrastructure node."""
    blast_svc = services.get('blast')
    if blast_svc is None:
        raise HTTPException(status_code=503, detail='BlastRadiusAnalyser service not loaded')

    # Unknown node check
    if node_id not in blast_svc.graph:
        raise HTTPException(status_code=404, detail={
            'error': 'NODE_NOT_FOUND',
            'node_id': node_id,
            'available_nodes': list(blast_svc.graph.nodes()),
        })

    result = blast_svc.calculate(node_id)

    if not include_paths:
        result.pop('affected_nodes', None)
        result.pop('path_to_nearest_critical', None)

    return result


@app.get('/api/v1/alerts')
async def get_alerts():
    """Return the last 50 processed alerts."""
    return alert_history[-50:]
