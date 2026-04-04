import { MOCK_STATS, MOCK_ALERTS, MOCK_PLAYBOOKS, MOCK_GRAPH, MOCK_VAULT } from '../demo/demo_data';

const BASE = `http://${window.location.hostname}:8000/api/v1`;

let isMockMode = false;
let failedAttempts = 0;

const fetchWithFallback = async (url, mockData) => {
  try {
     const r = await fetch(url);
     if (!r.ok) throw new Error(`HTTP error ${r.status}`);
     const data = await r.json();
     
     if (isMockMode) {
       isMockMode = false;
       window.dispatchEvent(new Event('toggleLiveMode'));
     }
     failedAttempts = 0;
     return data;
  } catch (err) {
     failedAttempts++;
     if (!isMockMode) {
        isMockMode = true; 
        window.dispatchEvent(new Event('toggleMockMode'));
     }
     // Artificial delay for realism
     await new Promise(res => setTimeout(res, 200));
     return mockData;
  }
};

export const api = {
  stats: () => fetchWithFallback(`${BASE}/stats`, MOCK_STATS),
  alerts: (after) => fetchWithFallback(`${BASE}/alerts${after?`?after=${after}`:''}`, MOCK_ALERTS),
  playbooks: (status) => {
     if (status === 'active') return fetchWithFallback(`${BASE}/playbooks?status=${status}`, MOCK_PLAYBOOKS.filter(p => p.outcome === 'PENDING'));
     return fetchWithFallback(`${BASE}/playbooks?status=${status}`, MOCK_PLAYBOOKS.filter(p => p.outcome !== 'PENDING'));
  },
  graph: () => fetchWithFallback(`${BASE}/graph/topology`, MOCK_GRAPH),
  blastRadius: (id) => fetchWithFallback(`${BASE}/graph/blast-radius/${id}`, {
      source_id: id, score: 75, path_to_nearest_critical: [id, 'SRV_1', 'CORE_ASSET']
  }),
  simulate: async (source, target) => {
      try {
          const res = await fetch(`${BASE}/graph/simulate`, {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({source_node: source, target_node: target})
          });
          return await res.json();
      } catch (err) {
          console.error("simulate error", err);
          return { hops: 0, path: [], risk_exposure: 0 };
      }
  },
  vault: () => fetchWithFallback(`${BASE}/vault/list`, MOCK_VAULT),
  vaultItem: (id) => fetchWithFallback(`${BASE}/vault/${id}`, {
      id, alert_id: 'alt-mock', hash: 'e3b0c4...', timestamp: new Date().toISOString(), status: 'VERIFIED',
      raw_log: 'source_ip=10.0.0.1 dest=192.168.1.1 msg="Mock demo"'
  }),
};
