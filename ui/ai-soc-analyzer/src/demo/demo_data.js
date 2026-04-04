export const MOCK_STATS = {
   total_alerts_processed: 14502,
   average_processing_time_ms: 124,
   honeypots_triggered: 3,
   severity_distribution: { CRITICAL: 12, HIGH: 45, MEDIUM: 300, LOW: 14145, BENIGN: 0 },
   system_health: {
      ml_engine: { status: 'ok', latency_ms: 45 },
      api_server: { status: 'ok', latency_ms: 12 },
      ollama_llm: { status: 'slow', latency_ms: 1200 },
      knowledge_graph: { status: 'ok', latency_ms: 8 }
   },
   trend_data: Array.from({length: 12}, (_, i) => ({
      time: `-${(12-i)*5}m`, 
      CRITICAL: Math.floor(Math.random()*5), 
      HIGH: Math.floor(Math.random()*15), 
      MEDIUM: Math.floor(Math.random()*30), 
      LOW: Math.floor(Math.random()*100), 
      BENIGN: 0
   })),
   timeline_bars: Array.from({length: 60}, (_, i) => ({
      minute: `-${60-i}m`, 
      max_severity: Math.random() > 0.8 ? 'CRITICAL' : (Math.random() > 0.5 ? 'HIGH' : 'LOW'), 
      count: Math.floor(Math.random()*40)
   })),
   recent_alerts: [
      { alert_id: 'mock-1', severity: 'CRITICAL', source_ip: '45.33.12.9', event_type: 'RANSOMWARE_BEHAVIOR', confidence: 0.99 },
      { alert_id: 'mock-2', severity: 'HIGH', source_ip: '192.168.1.10', event_type: 'LATERAL_MOVEMENT', confidence: 0.85 },
      { alert_id: 'mock-3', severity: 'HONEYPOT', source_ip: '10.0.0.5', event_type: 'HONEYPOT_ACCESS', confidence: 1.0 },
   ]
};

export const MOCK_ALERTS = [
   { alert_id: 'alt-a1', severity: 'CRITICAL', source_ip: '45.33.12.9', dest_ip: '10.0.0.100', event_type: 'RANSOMWARE_BEHAVIOR', confidence: 0.98, timestamp: new Date().toISOString(), summary: "High confidence ransomware encryption behavior observed.", evidence_trail: ["Multiple file extensions renamed to .locked", "High volume of shadow copy deletions"] },
   { alert_id: 'alt-hp1', severity: 'CRITICAL', source_ip: '8.8.8.8', dest_ip: '10.0.0.99', event_type: 'HONEYPOT_ACCESS', confidence: 1.0, timestamp: new Date(Date.now()-1000).toISOString(), honeypot_triggered: true, summary: "Attacker interacted with fake SSH service.", evidence_trail: ["Login attempt on honeypot port 22"] },
   { alert_id: 'alt-b2', severity: 'HIGH', source_ip: '192.168.1.10', dest_ip: '10.0.0.50', event_type: 'PORT_SCAN', confidence: 0.85, timestamp: new Date(Date.now()-5000).toISOString() },
];

export const MOCK_PLAYBOOKS = [
   { id: 'pb-1', alert_id: 'alt-a1', severity: 'CRITICAL', current_state: 'ESCALATED', started_at: new Date(Date.now() - 120000).toISOString(), duration_sec: 120, outcome: 'PENDING' },
   { id: 'pb-2', alert_id: 'alt-b2', severity: 'HIGH', current_state: 'RESOLVED', started_at: new Date(Date.now() - 500000).toISOString(), duration_sec: 45, outcome: 'RESOLVED',
     timeline: [{state: 'RECEIVED', time_offset: 0}, {state: 'INITIAL_TRIAGE', time_offset: 2}, {state: 'IP_BLOCKED', time_offset: 40}, {state: 'RESOLVED', time_offset: 45}],
     cacao_json: { type: "playbook", name: "Auto-Block High Risk", workflow: { steps: [] } }
   }
];

export const MOCK_GRAPH = {
   nodes: [
      { data: { id: 'WS_1', label: 'Workstation 1', node_type: 'WORKSTATION' } },
      { data: { id: 'SRV_1', label: 'App Server', node_type: 'SERVER' } },
      { data: { id: 'DB_PROD', label: 'Prod DB', node_type: 'DATABASE' } },
      { data: { id: 'DC_1', label: 'Domain Controller', node_type: 'DOMAIN_CONTROLLER' } },
      { data: { id: 'GW_EXT', label: 'Internet Gateway', node_type: 'INTERNET_GATEWAY' } },
      { data: { id: 'HP_1', label: 'Honeypot Alpha', node_type: 'HONEYPOT' } },
      { data: { id: 'CORE_ASSET', label: 'Payment Gateway', node_type: 'CRITICAL_ASSET' } }
   ],
   edges: [
      { data: { id: 'e1', source: 'GW_EXT', target: 'WS_1', protocol: 'HTTPS' } },
      { data: { id: 'e2', source: 'WS_1', target: 'SRV_1', protocol: 'RDP' } },
      { data: { id: 'e3', source: 'SRV_1', target: 'DB_PROD', protocol: 'SQL' } },
      { data: { id: 'e4', source: 'SRV_1', target: 'DC_1', protocol: 'LDAP' } },
      { data: { id: 'e5', source: 'DC_1', target: 'CORE_ASSET', protocol: 'RPC' } },
      { data: { id: 'e6', source: 'WS_1', target: 'HP_1', protocol: 'SMB' } },
   ]
};

export const MOCK_VAULT = [
   { id: 'v-1', alert_id: 'alt-a1', hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', status: 'VERIFIED', timestamp: new Date(Date.now()-100000).toISOString() },
   { id: 'v-2', alert_id: 'alt-c9', hash: 'f8d3b55288fc...', status: 'COMPROMISED', timestamp: new Date(Date.now()-500000).toISOString() },
];
