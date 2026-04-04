<div align="center">

<br/>

```
 █████╗ ██╗         ███████╗ ██████╗  ██████╗
██╔══██╗██║         ██╔════╝██╔═══██╗██╔════╝
███████║██║         ███████╗██║   ██║██║
██╔══██║██║         ╚════██║██║   ██║██║
██║  ██║███████╗    ███████║╚██████╔╝╚██████╗
╚═╝  ╚═╝╚══════╝   ╚══════╝ ╚═════╝  ╚═════╝
```

# **ALLCAPSNOSMALL — Ignition**
### *Autonomous SOC AI · Real-Time Threat Detection · CACAO Playbook Orchestration*

<br/>

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev)
[![LangGraph](https://img.shields.io/badge/LangGraph-Agentic_FSM-FF6B6B?style=for-the-badge)](https://langchain-ai.github.io/langgraph/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-GradientBoosting-F7931E?style=for-the-badge&logo=scikitlearn&logoColor=white)](https://scikit-learn.org)
[![License](https://img.shields.io/badge/License-Academic_Research-00FF88?style=for-the-badge)](LICENSE)

<br/>

> **Ignition** is a production-grade, fully autonomous Security Operations Centre (SOC) AI platform.  
> It ingests raw network logs, classifies threats in real time using trained ML models, enriches alerts with  
> explainable AI (XAI) evidence chains, orchestrates CACAO 2.0 playbooks via a LangGraph finite-state machine,  
> and visualises the entire blast radius across a live infrastructure knowledge graph — all within a single unified dashboard.

<br/>

---

</div>

## 📋 Table of Contents

- [Overview](#-overview)
- [Key Capabilities](#-key-capabilities)
- [System Architecture](#-system-architecture)
- [Module Breakdown](#-module-breakdown)
  - [Ingestion Pipeline](#1--ingestion-pipeline)
  - [ML Classifier Engine](#2--ml-classifier-engine)
  - [Knowledge Graph & Blast Radius](#3--knowledge-graph--blast-radius-analyser)
  - [Honeypot Deception System](#4--honeypot-deception-system)
  - [CACAO Playbook Orchestrator](#5--cacao-20-playbook-orchestrator)
  - [LLM Summariser](#6--llm-ai-analyst)
  - [Forensic Vault](#7--forensic-vault)
  - [REST API Backend](#8--rest-api-backend)
  - [React SOC Dashboard](#9--react-soc-dashboard)
- [Tech Stack](#-tech-stack)
- [Getting Started](#-getting-started)
- [API Reference](#-api-reference)
- [Dataset Support](#-dataset-support)
- [Security Architecture](#-security-architecture)
- [Contributors](#-contributors)

---

## 🔍 Overview

**Ignition** addresses a critical gap in modern cybersecurity: the human analyst bottleneck. Traditional SOC platforms flood operators with thousands of unranked alerts per day, causing alert fatigue and missed critical threats. This platform autonomously:

1. **Ingests** raw SIEM/network logs from any network environment
2. **Enriches** every alert with multi-pass IOC extraction and threat intelligence correlation
3. **Classifies** each alert using a trained GradientBoosting ML model (BETH & UNSW-NB15 datasets)
4. **Generates** per-alert XAI evidence trails explaining *exactly why* each alert was flagged
5. **Orchestrates** response via an autonomous LangGraph FSM executing CACAO 2.0 playbooks
6. **Detects** zero-false-positive honeypot interactions from decoy assets
7. **Seals** all evidence in a cryptographic forensic vault with SHA-256 chain of custody
8. **Visualises** threat blast radius and infrastructure attack paths in a real-time graph

---

## ⚡ Key Capabilities

| Capability | Detail |
|---|---|
| 🧠 **ML Threat Classification** | GradientBoosting on BETH dataset · 5-tier severity (BENIGN → CRITICAL) · sub-100ms inference |
| 🔍 **3-Pass XAI Verification** | Structural integrity → IOC consistency → Threat Intelligence KB · per-alert evidence strings |
| 🕸️ **Knowledge Graph** | NetworkX infrastructure graph · pre-computed all-pairs Dijkstra · O(1) blast radius lookup |
| 🍯 **Honeypot Detection** | 5 decoy assets · zero-false-positive guarantee · webhook escalation |
| 🤖 **Agentic Playbook FSM** | LangGraph StateGraph · 8-state CACAO 2.0 orchestration · autonomous IP/ASN blocking |
| 💬 **LLM Analyst** | Ollama (Llama 3) narrative generation · template fallback when offline |
| 🔒 **Forensic Vault** | SHA-256 snapshot sealing · chain-of-custody reports · tamper detection |
| 📡 **Real-Time Dashboard** | React + Vite · live polling · severity filters · XAI drawer · playbook FSM diagram |
| 🎯 **Attack Simulator** | Cross-network remote attack simulation · 15 event types · realistic IP rotation |

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         ALLCAPSNOSMALL IGNITION — System Flow                   │
└─────────────────────────────────────────────────────────────────────────────────┘

     RAW LOG / SIEM ALERT
           │
           ▼
  ┌─────────────────┐
  │  Log Parser     │  ← Normalises BETH / UNSW-NB15 / custom formats
  │  ingestion/     │    Maps fields: source_ip, dest_ip, port, event_type
  └────────┬────────┘
           │
           ▼
  ┌─────────────────┐
  │  IOC Extractor  │  ← Vectorised regex: IPv4, IPv6, SHA-256, CVE, URL, Domain
  │  ingestion/     │    False-positive filter: private IPs → lateral_movement
  └────────┬────────┘
           │
           ▼
  ┌─────────────────────────────────────────────────────────────┐
  │                3-Pass Verification Engine                    │
  │  Pass 1: Structural Integrity (field presence, timestamp)    │
  │  Pass 2: IOC Consistency (port/service fingerprint, east-west│
  │           traffic, MITRE ATT&CK tactic mapping)             │
  │  Pass 3: Threat Intel KB (bad IPs, CVEs, malware processes)  │
  └────────┬────────────────────────────────────────────────────┘
           │  XAI Evidence Trail (per-alert strings)
           ▼
  ┌─────────────────┐    ┌──────────────────┐    ┌──────────────────────┐
  │  ML Classifier  │    │  Honeypot Check  │    │  Blast Radius        │
  │  GradientBoost  │    │  5 decoy assets  │    │  NetworkX graph +    │
  │  BETH dataset   │    │  0% false pos.   │    │  all-pairs Dijkstra  │
  └────────┬────────┘    └────────┬─────────┘    └──────────┬───────────┘
           │                      │                          │
           └──────────────────────┴──────────────────────────┘
                                  │
                                  ▼
                     ┌────────────────────────┐
                     │  CACAO Playbook FSM    │  ← LangGraph StateGraph
                     │  ALERT_RECEIVED        │
                     │    → INITIAL_TRIAGE    │
                     │    → IP_BLOCKED        │
                     │    → ASN_BLOCKED       │
                     │    → HOST_ISOLATED     │
                     │    → ESCALATED_TO_L2   │
                     │    → RESOLVED          │
                     └────────────┬───────────┘
                                  │
                     ┌────────────▼───────────┐
                     │  LLM Summariser        │  ← Ollama Llama 3 / template fallback
                     │  + CACAO 2.0 Exporter  │
                     └────────────┬───────────┘
                                  │
                     ┌────────────▼───────────┐
                     │  Forensic Vault        │  ← SHA-256 sealing, chain-of-custody
                     └────────────┬───────────┘
                                  │
                     ┌────────────▼───────────┐
                     │  FastAPI REST API      │  ← Port 8000
                     │  /api/v1/classify      │
                     │  /api/v1/alerts        │
                     │  /api/v1/stats         │
                     │  /api/v1/playbooks     │
                     │  /api/v1/vault/*       │
                     │  /api/v1/graph/*       │
                     └────────────┬───────────┘
                                  │
                     ┌────────────▼───────────┐
                     │  React SOC Dashboard   │  ← Port 3000 (Vite)
                     │  Live Alerts · Overview│
                     │  Playbooks · Graph     │
                     │  Forensic Vault        │
                     └────────────────────────┘
```

---

## 📦 Module Breakdown

### 1. 📥 Ingestion Pipeline
**`ingestion/`**

| File | Role |
|---|---|
| `parser.py` | Normalises raw log dicts into a unified `AlertSchema`. Supports BETH (UNIX syscall) and UNSW-NB15 (network flow) formats. |
| `ioc_extractor.py` | Vectorised named-group regex extraction of IPv4, IPv6, SHA-256, MD5, CVE IDs, URLs, and domains from raw logs using pandas `str.extractall()`. Separates RFC-1918 private IPs into `lateral_movement` bucket. |
| `verification.py` | **3-Pass XAI Engine** — generates unique, per-alert human-readable evidence strings. Pass 1: structural integrity. Pass 2: MITRE ATT&CK tactic mapping + port/service fingerprinting + direction analysis. Pass 3: threat intelligence KB lookup (bad IPs, CVEs, malware tools). |
| `schema.py` | Pydantic schema for unified alert representation. |

**Design Principle:** No row-level Python loops — all extraction is vectorised through pandas for maximum throughput (targets < 2s for 10,000 rows).

---

### 2. 🧠 ML Classifier Engine
**`classifier/`**

The ML engine trains and serves a **GradientBoosting** classifier on real-world intrusion datasets. It outputs a 5-tier severity classification and an attack probability confidence score.

| File | Role |
|---|---|
| `train.py` | End-to-end training runner. Supports `--dataset beth` or `--dataset unsw`. |
| `dataset_loader.py` | Loads and validates BETH / UNSW-NB15 CSVs with schema enforcement. |
| `feature_pipeline.py` | Feature engineering: encoding, train/val/test split, StandardScaler, SMOTE oversampling for class imbalance. |
| `model_trainer.py` | Trains GradientBoosting + alternatives, selects best by validation AUC, saves artifacts. |
| `classifier_service.py` | **Production inference wrapper** — loads `model.pkl`, `scaler.pkl`, `encoders.pkl` ONCE at startup. Sub-100ms `predict()` method. |
| `artifacts/` | `model.pkl`, `scaler.pkl`, `encoders.pkl`, `feature_importance.json`, `model_name.txt` |

**Severity Mapping:**

| Probability | Severity |
|---|---|
| 0.00 – 0.20 | ![BENIGN](https://img.shields.io/badge/BENIGN-388bfd?style=flat-square) |
| 0.20 – 0.40 | ![LOW](https://img.shields.io/badge/LOW-00ff88?style=flat-square&labelColor=000) |
| 0.40 – 0.60 | ![MEDIUM](https://img.shields.io/badge/MEDIUM-ffd700?style=flat-square&labelColor=000) |
| 0.60 – 0.80 | ![HIGH](https://img.shields.io/badge/HIGH-ff8c00?style=flat-square) |
| 0.80 – 1.00 | ![CRITICAL](https://img.shields.io/badge/CRITICAL-ff4444?style=flat-square) |

---

### 3. 🕸️ Knowledge Graph & Blast Radius Analyser
**`knowledge_graph/`**

Models the enterprise infrastructure as a weighted directed graph. Every compromised node's blast radius is scored by its Dijkstra distance to critical assets.

| File | Role |
|---|---|
| `graph.py` | `KnowledgeGraph` class — builds a NetworkX digraph from `infra_graph.graphml`. Nodes: workstations, servers, databases, gateways. Edges: protocol-weighted connections. |
| `blast_radius.py` | `BlastRadiusAnalyser` — pre-computes **all-pairs Dijkstra** at startup for O(1) query-time blast radius. Scores proximity to critical assets. Supports `simulate_path(source, target)` for attack path simulation. |
| `infra_graph.graphml` | GraphML definition of the enterprise network topology. |

**Blast Radius Score Formula:**
```
score = Σ ( 1 / (distance_to_critical_node + 1) ) for all critical nodes reachable
```
Higher score = compromised node is closer to more critical assets = higher danger.

---

### 4. 🍯 Honeypot Deception System
**`honeypot/`**

A **zero-false-positive** detection layer using 5 strategically placed decoy assets. Any interaction is a guaranteed intrusion indicator — no legitimate user ever touches these files.

| Honeypot Asset | Type | Trigger Condition |
|---|---|---|
| `HP_SALARY_FILE` | Fake file | `salary_2024_Q3_final.xlsx` access |
| `HP_DB_CRED` | Fake file | `db_credentials_prod.conf` access |
| `HP_ADMIN_LOGIN` | Fake endpoint | HTTP request to `/admin/login` |
| `HP_SSH_2222` | Fake service | TCP connection to port 2222 |
| `HP_CLOUD_CONFIG` | Fake file | `/backup/cloud_config.json` access |

When triggered: severity is **force-overridden to CRITICAL** with `confidence = 1.0`, and a webhook notification is fired to `HONEYPOT_WEBHOOK_URL`.

---

### 5. 🤖 CACAO 2.0 Playbook Orchestrator
**`playbooks/`**

Implements an autonomous response FSM using **LangGraph `StateGraph`**. Each state transition is logged with timestamps, creating a full audit trail exported as a CACAO 2.0 JSON playbook.

```
ALERT_RECEIVED
    │
    ▼
INITIAL_TRIAGE
    │
    ├─── severity=HIGH/CRITICAL ──► IP_BLOCKED
    │                                   │
    │                              repeat? ──► ASN_BLOCKED ──► RESOLVED
    │                                   │
    │                                   └────────────────────► RESOLVED
    │
    ├─── severity=MEDIUM + blast_radius > 5 ──► ESCALATED_TO_L2 ──► END
    │
    └─── severity=LOW/BENIGN ──► END (RESOLVED)
```

| File | Role |
|---|---|
| `state_machine.py` | `PlaybookStateMachine` — compiles and executes the LangGraph FSM. |
| `states.py` | `PlaybookState` enum definitions. |
| `actions.py` | Individual action handlers: block_ip, block_asn, isolate_host, escalate. |
| `fsm.py` | Routing logic and conditional edge definitions. |

---

### 6. 💬 LLM AI Analyst
**`llm/`**

Integrates **Ollama (Llama 3)** locally for human-readable threat narrative generation. Falls back gracefully to template-based summaries when Ollama is not running.

- `summarise(alert, playbook_actions)` — generates a structured threat summary (SUMMARY, TECHNIQUE, ACTION)
- `generate_playbook_narrative(actions_log)` — writes a natural-language description of the playbook execution timeline
- **Timeout:** 35 seconds max — non-blocking via `asyncio.wait_for`

---

### 7. 🔒 Forensic Vault
**`vault/`**

Every processed alert is cryptographically sealed for tamper-evident evidence preservation.

| File | Role |
|---|---|
| `forensics.py` | `ForensicVault` — captures JSON snapshots and seals them with SHA-256. |
| `cacao_exporter.py` | Exports CACAO 2.0 JSON playbooks to `vault/cacao/`. |
| `forensic_vault.py` | Chain-of-custody report generator — verifies snapshot integrity on demand. |
| `snapshots/` | Immutable `.json` + `.sha256` file pairs per alert. |
| `cacao/` | CACAO 2.0 playbook exports per incident. |

---

### 8. 🌐 REST API Backend
**`api/main.py`** — FastAPI application on port `8000`

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Service health check — lists all loaded modules |
| `/api/v1/classify` | POST | Full classification pipeline — returns `AlertResponse` |
| `/api/v1/alerts` | GET | Last 50 processed alerts (reverse chronological) |
| `/api/v1/stats` | GET | System statistics — severity distribution, uptime, avg latency |
| `/api/v1/playbooks` | GET | Active (`?status=active`) or history playbooks |
| `/api/v1/vault/list` | GET | All forensic vault snapshots |
| `/api/v1/vault/{alert_id}` | GET | Full chain-of-custody report for an alert |
| `/api/v1/graph/topology` | GET | Infrastructure graph nodes and edges |
| `/api/v1/graph/blast-radius/{node_id}` | GET | Blast radius score for a node |
| `/api/v1/graph/simulate` | POST | Simulate attack path between two nodes |

---

### 9. 🖥️ React SOC Dashboard
**`ui/ai-soc-analyzer/`** — Vite + React 19 + TypeScript on port `3000`

| Page | Description |
|---|---|
| **Overview** | System metrics, severity distribution charts, recent alert feed, live statistics |
| **Live Alerts** | Real-time alert table with severity filters, IP search, and XAI detail drawer |
| **Playbooks** | CACAO 2.0 orchestration — active playbook live cards, FSM diagram (ReactFlow), execution history, JSON viewer |
| **Graph View** | Interactive Cytoscape.js infrastructure graph with blast radius and attack path simulation |
| **Forensic Vault** | Cryptographic snapshot browser with chain-of-custody reports and CACAO export download |

**Technology Highlights:**
- `@xyflow/react` — FSM state diagram with live animated edges
- `cytoscape` + `cytoscape-cola` — force-directed infrastructure graph
- `recharts` — severity distribution and timeline charts
- `react-force-graph-2d` — network topology visualisation
- TailwindCSS v4 + custom dark theme (GitHub dark palette)

---

## 🛠️ Tech Stack

### Backend
| Technology | Purpose |
|---|---|
| **Python 3.11+** | Core runtime |
| **FastAPI** | Async REST API with automatic OpenAPI docs |
| **Uvicorn** | ASGI server with hot-reload |
| **LangGraph** | Agentic FSM playbook orchestration |
| **scikit-learn** | GradientBoosting classifier, StandardScaler |
| **imbalanced-learn** | SMOTE oversampling for class imbalance |
| **NetworkX** | Infrastructure knowledge graph + Dijkstra |
| **pandas / numpy** | Vectorised IOC extraction and feature engineering |
| **Ollama (Llama 3)** | Local LLM for threat narrative generation |
| **cryptography** | SHA-256 forensic vault sealing |
| **Pydantic** | Request/response validation schemas |

### Frontend
| Technology | Purpose |
|---|---|
| **React 19** | UI framework |
| **Vite 6** | Dev server and bundler |
| **TypeScript** | Type safety |
| **TailwindCSS v4** | Utility-first styling |
| **@xyflow/react** | FSM playbook diagram |
| **Cytoscape.js** | Interactive network graph |
| **Recharts** | Data visualisation charts |
| **Lucide React** | Icon system |
| **React Router v7** | Client-side navigation |

---

## 🚀 Getting Started

### Prerequisites

- Python 3.11+
- Node.js 20+
- [Ollama](https://ollama.ai) (optional — for live LLM summaries)

### 1. Clone and Set Up Environment

```bash
git clone https://github.com/ALLCAPSNOSMALL/ALLCAPSNOSMALL_Ignition.git
cd ALLCAPSNOSMALL_Ignition

# Create and activate virtual environment
python -m venv soc_env
.\soc_env\Scripts\activate          # Windows
# source soc_env/bin/activate       # Linux/macOS

# Install Python dependencies
pip install -r requirements.txt
```

### 2. Train the ML Model (or use pre-trained artifacts)

Pre-trained artifacts are included in `classifier/artifacts/`. To retrain:

```bash
# Train on BETH dataset (recommended)
python classifier/train.py --dataset beth

# Or train on UNSW-NB15
python classifier/train.py --dataset unsw
```

### 3. Start the Backend

```bash
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

The API will be live at `http://localhost:8000`  
Interactive docs: `http://localhost:8000/docs`

### 4. Start the Frontend

```bash
cd ui/ai-soc-analyzer
npm install
npm run dev
```

Dashboard available at `http://localhost:3000`

### 5. Start Ollama (Optional — for live AI summaries)

```bash
ollama serve
ollama pull llama3
```

### 6. Run the Attack Simulator

```bash
# Simulate a cross-network multi-stage attack
python remote_attack_simulator.py
```

This fires 15+ realistic attack events (PORT_SCAN → KERBEROAST → C2_BEACON → DATA_EXFIL) against the running API, populating the dashboard with a full attack chain demonstration.

---

## 📡 API Reference

### `POST /api/v1/classify`

**Request Body:**
```json
{
  "raw_log": "FILE_READ accessed /etc/passwd from 10.0.0.99",
  "source_ip": "10.0.0.99",
  "dest_ip": "192.168.1.50",
  "port": 445,
  "timestamp": "2026-04-04T08:45:01",
  "event_type": "FILE_READ",
  "accessed_path": "/etc/passwd",
  "protocol": "SMB"
}
```

**Response:**
```json
{
  "alert_id": "0721a732-da7f-49...",
  "severity": "CRITICAL",
  "confidence": 0.95,
  "evidence_trail": [
    "PASS 1: ✓ Structural integrity confirmed — alert from 10.0.0.99 → 192.168.1.50:445...",
    "PASS 2: Event FILE_READ classified as 'Sensitive file access' — MITRE ATT&CK T1059...",
    "PASS 3: TI lookup — IP matches known threat intel range..."
  ],
  "blast_radius": 2.4,
  "playbook_state": "HOST_ISOLATED",
  "summary": "A critical file read event has been detected...",
  "narrative": "Autonomous playbook executed: IP blocked at 08:45:02...",
  "vault_hash": "48950d3e51c4250cc593eb6b5116b9d3f9347790909bea6d082f...",
  "honeypot_triggered": false
}
```

---

## 📊 Dataset Support

| Dataset | Description | Features |
|---|---|---|
| **BETH** | UNIX syscall and process traces from real enterprise hosts | `severity_raw`, `event_type`, `processName` |
| **UNSW-NB15** | Network flow dataset with 9 attack categories | `dur`, `sbytes`, `dbytes`, `proto`, `service`, `state`, + 14 more |

Datasets should be placed in `data/` as `.csv` files. The dataset loader auto-detects column schemas and validates required features before training.

---

## 🛡️ Security Architecture

```
┌─────────────────────────────────────────────────────┐
│              Defence-in-Depth Stack                 │
├─────────────────────────────────────────────────────┤
│  Layer 1 — Detection    ML Classifier (5 tiers)     │
│  Layer 2 — Enrichment   3-Pass XAI Verification     │
│  Layer 3 — Deception    Zero-FP Honeypot System     │
│  Layer 4 — Response     Autonomous CACAO FSM        │
│  Layer 5 — Evidence     SHA-256 Forensic Vault      │
│  Layer 6 — Visibility   Real-Time SOC Dashboard     │
└─────────────────────────────────────────────────────┘
```

**MITRE ATT&CK Coverage:**

| Tactic | Techniques Detected |
|---|---|
| Reconnaissance | T1046 (Port Scan), T1018 (Remote System Discovery) |
| Credential Access | T1110 (Brute Force), T1558.003 (Kerberoasting), T1003 (OS Credential Dump) |
| Lateral Movement | T1021.002 (SMB/Windows Admin Shares) |
| Command & Control | T1071 (Application Layer Protocol), T1071.001 (Web Protocols) |
| Exfiltration | T1041 (Exfiltration Over C2), T1074 (Data Staged) |
| Execution | T1059 (Command & Scripting Interpreter) |

---

## 🗂️ Project Structure

```
ALLCAPSNOSMALL_Ignition/
│
├── api/                        # FastAPI backend
│   └── main.py                 # Routes, pipeline orchestration, startup
│
├── ingestion/                  # Log processing pipeline
│   ├── parser.py               # Multi-format log normaliser
│   ├── ioc_extractor.py        # Vectorised IOC regex engine
│   ├── verification.py         # 3-pass XAI verification engine
│   └── schema.py               # Alert schema
│
├── classifier/                 # ML threat classification
│   ├── train.py                # Training entry point
│   ├── dataset_loader.py       # BETH/UNSW data loader
│   ├── feature_pipeline.py     # Feature engineering + SMOTE
│   ├── model_trainer.py        # Model training + selection
│   ├── classifier_service.py   # Production inference wrapper
│   └── artifacts/              # model.pkl, scaler.pkl, encoders.pkl
│
├── knowledge_graph/            # Infrastructure graph
│   ├── graph.py                # KnowledgeGraph (NetworkX)
│   ├── blast_radius.py         # BlastRadiusAnalyser (pre-computed Dijkstra)
│   └── infra_graph.graphml     # Network topology definition
│
├── honeypot/                   # Deception system
│   └── honeypot_manager.py     # 5-asset decoy registry + trigger logic
│
├── playbooks/                  # CACAO playbook orchestration
│   ├── state_machine.py        # LangGraph FSM
│   ├── states.py               # PlaybookState enum
│   ├── actions.py              # Action handlers
│   └── fsm.py                  # Routing + conditional edges
│
├── llm/                        # LLM integration
│   └── llm_summariser.py       # Ollama Llama 3 / template fallback
│
├── vault/                      # Forensic evidence preservation
│   ├── forensics.py            # ForensicVault (SHA-256 sealing)
│   ├── cacao_exporter.py       # CACAO 2.0 JSON exporter
│   ├── snapshots/              # Immutable alert snapshots
│   └── cacao/                  # CACAO playbook exports
│
├── ui/ai-soc-analyzer/         # React SOC Dashboard
│   ├── src/pages/              # Overview, LiveAlerts, Playbooks, GraphView, ForensicVault
│   ├── src/components/         # Shared UI components
│   └── src/services/api.js     # API client
│
├── remote_attack_simulator.py  # Cross-network attack simulation
├── demo_alerts.py              # Batch demo alert injection
├── requirements.txt            # Python dependencies
└── README.md                   # This file
```

---

## 👥 Contributors

This platform was designed and built by **Team SY-A9** as part of the ALLCAPSNOSMALL research initiative.

<br/>

<table align="center">
  <tr>
    <td align="center" width="220">
      <br/>
      <b>Shanteshwar</b>
      <br/><br/>
      <sub>
        <b>Knowledge Graph & Threat Intelligence</b><br/><br/>
        Infrastructure KnowledgeGraph (NetworkX) · BlastRadiusAnalyser (pre-computed Dijkstra) · Honeypot Deception System (5 decoy assets, zero-FP guarantee) · XAI 3-Pass Verification Engine · IOC extraction pipeline · API integration layer
      </sub>
    </td>
    <td align="center" width="220">
      <br/>
      <b>Aryan</b>
      <br/><br/>
      <sub>
        <b>ML Classification Engine</b><br/><br/>
        GradientBoosting classifier · Feature pipeline (encoding + SMOTE) · BETH & UNSW-NB15 dataset loading · Model training & selection · Production inference wrapper (ClassifierService) · 5-tier severity mapping · Model artifacts
      </sub>
    </td>
    <td align="center" width="220">
      <br/>
      <b>Rishi</b>
      <br/><br/>
      <sub>
        <b>Ingestion & Log Processing</b><br/><br/>
        Multi-format log parser (BETH / UNSW-NB15) · Vectorised IOC extractor (named-group regex) · RFC-1918 lateral movement classification · Alert schema (Pydantic) · Dataset validation pipeline · Throughput benchmarking
      </sub>
    </td>
    <td align="center" width="220">
      <br/>
      <b>Ajaya</b>
      <br/><br/>
      <sub>
        <b>Playbooks, LLM & Vault</b><br/><br/>
        LangGraph CACAO 2.0 FSM · 8-state autonomous playbook orchestration · Ollama Llama 3 LLM integration · Threat narrative generation · ForensicVault (SHA-256 chain-of-custody) · CACAO 2.0 JSON exporter · React SOC Dashboard
      </sub>
    </td>
  </tr>
</table>

<br/>

---

<div align="center">

**Built with autonomy. Defended by intelligence. Sealed in cryptographic evidence.**

<br/>

```
  ██████╗ ███████╗███████╗███████╗███╗   ██╗██████╗ ███████╗██████╗
  ██╔══██╗██╔════╝██╔════╝██╔════╝████╗  ██║██╔══██╗██╔════╝██╔══██╗
  ██║  ██║█████╗  █████╗  █████╗  ██╔██╗ ██║██║  ██║█████╗  ██║  ██║
  ██║  ██║██╔══╝  ██╔══╝  ██╔══╝  ██║╚██╗██║██║  ██║██╔══╝  ██║  ██║
  ██████╔╝███████╗██║     ███████╗██║ ╚████║██████╔╝███████╗██████╔╝
  ╚═════╝ ╚══════╝╚═╝     ╚══════╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═════╝
```

*Team SY-A9 · ALLCAPSNOSMALL Research Initiative · 2026*

</div>
