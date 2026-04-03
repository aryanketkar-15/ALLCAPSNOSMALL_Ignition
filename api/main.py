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
