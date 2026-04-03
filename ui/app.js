/**
 * SOC AI Dashboard — Client-Side Logic
 * Team SY-A9 | Shanteshwar (Data Viz Lead)
 *
 * Polls GET /api/v1/alerts every 5 seconds.
 * Polls GET /api/v1/stats every 5 seconds.
 * Submits alerts via POST /api/v1/classify.
 */

const API_BASE = window.location.origin;
const POLL_INTERVAL = 5000;

let allAlerts = [];
let selectedAlertId = null;

// ══════════════════════════════════════════════════════════════
// POLLING
// ══════════════════════════════════════════════════════════════

async function fetchAlerts() {
  try {
    const res = await fetch(`${API_BASE}/api/v1/alerts`);
    if (!res.ok) throw new Error(res.statusText);
    const data = await res.json();
    setApiOnline(true);

    // Detect new alerts
    const prevCount = allAlerts.length;
    allAlerts = data;
    renderAlertFeed(prevCount);

    if (selectedAlertId) {
      const selected = allAlerts.find(a => a.alert_id === selectedAlertId);
      if (selected) renderDetail(selected);
    }
  } catch (e) {
    setApiOnline(false);
  }
}

async function fetchStats() {
  try {
    const res = await fetch(`${API_BASE}/api/v1/stats`);
    if (!res.ok) return;
    const s = await res.json();
    renderStats(s);
  } catch (_) { /* silent */ }
}

// ══════════════════════════════════════════════════════════════
// RENDER: Alert Feed (Left Panel)
// ══════════════════════════════════════════════════════════════

function renderAlertFeed(prevCount) {
  const list = document.getElementById('alert-list');
  document.getElementById('alert-count').textContent = allAlerts.length;

  if (allAlerts.length === 0) {
    list.innerHTML = '<div class="empty-state">Waiting for alerts...</div>';
    return;
  }

  // Rishi's API already returns newest-first
  list.innerHTML = allAlerts.map((a, i) => {
    const sev = (a.severity || 'UNKNOWN').toLowerCase();
    const isNew = i >= prevCount;
    const isHoneypot = a.honeypot_triggered;
    const isSelected = a.alert_id === selectedAlertId;

    return `
      <div class="alert-item ${isNew ? 'new' : ''} ${isHoneypot ? 'honeypot' : ''} ${isSelected ? 'selected' : ''}"
           onclick="selectAlert('${a.alert_id}')">
        <div class="sev-dot ${sev}"></div>
        <div class="alert-info">
          <div class="event-type">${isHoneypot ? '🍯 ' : ''}${a.event_type || a.raw_log?.substring(0, 40) || 'Alert'}</div>
          <div class="alert-meta">${a.source_ip || '?'} → ${a.dest_ip || '?'}</div>
        </div>
        <span class="alert-sev-tag ${sev}">${a.severity || '?'}</span>
      </div>`;
  }).join('');
}

// ══════════════════════════════════════════════════════════════
// RENDER: Alert Detail (Center Panel)
// ══════════════════════════════════════════════════════════════

function selectAlert(id) {
  selectedAlertId = id;
  const alert = allAlerts.find(a => a.alert_id === id);
  if (alert) renderDetail(alert);
  renderAlertFeed(allAlerts.length); // refresh selection highlight
}

function renderDetail(a) {
  const el = document.getElementById('alert-detail');
  const sev = (a.severity || 'UNKNOWN').toLowerCase();
  const confidence = (a.confidence || 0) * 100;

  // Severity color
  const sevColors = {
    critical: 'var(--sev-critical)',
    high: 'var(--sev-high)',
    medium: 'var(--sev-medium)',
    low: 'var(--sev-low)',
    benign: 'var(--sev-benign)',
  };
  const sevColor = sevColors[sev] || 'var(--text-muted)';

  // Evidence trail
  let evidenceHTML = '';
  if (a.evidence_trail && a.evidence_trail.length > 0) {
    evidenceHTML = a.evidence_trail.map(e => {
      const isHP = typeof e === 'string' && e.includes('HONEYPOT');
      return `<div class="evidence-item ${isHP ? 'honeypot-evidence' : ''}">${e}</div>`;
    }).join('');
  } else {
    evidenceHTML = '<div class="evidence-item">No evidence trail available</div>';
  }

  el.innerHTML = `
    <div class="detail-section">
      <h3>Classification</h3>
      <div class="detail-row">
        <span class="label">Alert ID</span>
        <span class="value">${a.alert_id || '—'}</span>
      </div>
      <div class="detail-row">
        <span class="label">Severity</span>
        <span class="value" style="color:${sevColor}; font-weight:700">${a.severity || '—'}</span>
      </div>
      <div class="detail-row">
        <span class="label">Confidence</span>
        <span class="value">${confidence.toFixed(1)}%</span>
      </div>
      <div class="confidence-bar">
        <div class="confidence-fill" style="width:${confidence}%; background:${sevColor}"></div>
      </div>
    </div>

    <div class="detail-section">
      <h3>Network</h3>
      <div class="detail-row">
        <span class="label">Source IP</span>
        <span class="value">${a.source_ip || '—'}</span>
      </div>
      <div class="detail-row">
        <span class="label">Dest IP</span>
        <span class="value">${a.dest_ip || '—'}</span>
      </div>
      <div class="detail-row">
        <span class="label">Port</span>
        <span class="value">${a.port || '—'}</span>
      </div>
    </div>

    <div class="detail-section">
      <h3>Blast Radius</h3>
      <div class="detail-row">
        <span class="label">Score</span>
        <span class="value">${a.blast_radius ?? '—'}</span>
      </div>
      <div class="detail-row">
        <span class="label">Playbook State</span>
        <span class="value">${a.playbook_state || '—'}</span>
      </div>
    </div>

    ${a.honeypot_triggered ? `
    <div class="detail-section">
      <h3>🍯 Honeypot Detection</h3>
      <div class="detail-row">
        <span class="label">Triggered Asset</span>
        <span class="value" style="color:var(--sev-critical)">${a.triggered_asset_id || 'YES'}</span>
      </div>
      <div class="detail-row">
        <span class="label">Confidence</span>
        <span class="value" style="color:var(--sev-critical)">100% — Zero False Positive</span>
      </div>
    </div>` : ''}

    <div class="detail-section">
      <h3>Evidence Trail</h3>
      ${evidenceHTML}
    </div>

    ${a.summary ? `
    <div class="detail-section">
      <h3>LLM Summary</h3>
      <div class="evidence-item">${a.summary}</div>
    </div>` : ''}

    ${a.narrative ? `
    <div class="detail-section">
      <h3>📖 Playbook Narrative</h3>
      <div class="evidence-item">${a.narrative}</div>
    </div>` : ''}

    ${a.vault_hash ? `
    <div class="detail-section">
      <h3>Forensic Vault</h3>
      <div class="detail-row">
        <span class="label">SHA-256</span>
        <span class="value" style="font-size:10px; word-break:break-all">${a.vault_hash}</span>
      </div>
    </div>` : ''}
  `;
}

// ══════════════════════════════════════════════════════════════
// RENDER: Stats (Right Panel)
// ══════════════════════════════════════════════════════════════

function renderStats(s) {
  document.getElementById('stat-total').textContent = s.total_alerts_processed;
  document.getElementById('stat-honeypots').textContent = s.honeypots_triggered;
  document.getElementById('stat-fpr').textContent = s.false_positive_rate.toFixed(1) + '%';
  document.getElementById('stat-avg-time').textContent = s.average_processing_time_ms.toFixed(0) + 'ms';

  // Uptime
  const mins = Math.floor(s.uptime_seconds / 60);
  const secs = s.uptime_seconds % 60;
  document.getElementById('uptime-display').textContent =
    `Uptime: ${mins}m ${secs}s`;

  // Severity bars
  const dist = s.severity_distribution || {};
  const total = s.total_alerts_processed || 1;
  const tiers = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'BENIGN'];

  tiers.forEach(tier => {
    const count = dist[tier] || 0;
    const pct = (count / total) * 100;
    const barEl = document.getElementById('bar-' + tier.toLowerCase());
    const countEl = document.getElementById('count-' + tier.toLowerCase());
    if (barEl) barEl.style.width = pct + '%';
    if (countEl) countEl.textContent = count;
  });
}

// ══════════════════════════════════════════════════════════════
// STATUS INDICATOR
// ══════════════════════════════════════════════════════════════

function setApiOnline(online) {
  const pill = document.getElementById('api-status');
  const text = document.getElementById('status-text');
  if (online) {
    pill.classList.remove('offline');
    text.textContent = 'API Online';
  } else {
    pill.classList.add('offline');
    text.textContent = 'API Offline';
  }
}

// ══════════════════════════════════════════════════════════════
// SUBMIT ALERT
// ══════════════════════════════════════════════════════════════

document.getElementById('alert-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = document.getElementById('submit-btn');
  btn.classList.add('loading');
  btn.textContent = 'Classifying...';

  const payload = {
    raw_log:    document.getElementById('input-raw-log').value,
    source_ip:  document.getElementById('input-src-ip').value || '0.0.0.0',
    dest_ip:    document.getElementById('input-dst-ip').value || '0.0.0.0',
    port:       parseInt(document.getElementById('input-port').value) || 0,
    event_type: document.getElementById('input-event-type').value || '',
    timestamp:  new Date().toISOString(),
  };

  try {
    const res = await fetch(`${API_BASE}/api/v1/classify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (res.ok) {
      const data = await res.json();
      // Immediately add to feed
      allAlerts.push(data);
      renderAlertFeed(allAlerts.length - 1);
      selectAlert(data.alert_id);
    }
  } catch (err) {
    console.error('Submit error:', err);
  }

  btn.classList.remove('loading');
  btn.textContent = 'Classify Alert';
  document.getElementById('alert-form').reset();
});

// ══════════════════════════════════════════════════════════════
// INIT
// ══════════════════════════════════════════════════════════════

fetchAlerts();
fetchStats();

setInterval(fetchAlerts, POLL_INTERVAL);
setInterval(fetchStats, POLL_INTERVAL);
