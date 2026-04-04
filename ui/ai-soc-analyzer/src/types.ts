// ══════════════════════════════════════════════════════
// SOC AI Dashboard — Type Definitions
// Matches the FastAPI AlertResponse schema exactly.
// ══════════════════════════════════════════════════════

export interface Alert {
  // Core API fields (from POST /api/v1/classify)
  alert_id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'BENIGN';
  confidence: number;
  evidence_trail: string[];
  blast_radius: number;
  playbook_state: string;
  summary: string;
  narrative: string;
  vault_hash: string;

  // Request fields stored on alert
  source_ip: string;
  dest_ip: string;
  port: number;
  protocol?: string;
  event_type?: string;
  raw_log?: string;
  timestamp?: string;
  accessed_path?: string;

  // Honeypot detection
  honeypot_triggered?: boolean;
  triggered_asset_id?: string;

  // UI computed fields
  id: string;              // alias for alert_id (for component compat)
  title: string;           // derived from event_type or raw_log
  status: string;          // derived from playbook_state

  // Playbook steps derived from playbook_state
  playbookSteps: PlaybookStep[];

  // Related entities
  relatedEntities: {
    attackerHost: string;
    targetAccount: string;
    payloadHash: string;
  };

  // Chain of custody from vault
  chainOfCustody?: {
    node: string;
    method: string;
    time: string;
  };
}

export interface PlaybookStep {
  id: string;
  label: string;
  status: 'completed' | 'active' | 'pending' | 'error';
  icon: string;
}

export interface StatsResponse {
  total_alerts_processed: number;
  severity_distribution: {
    BENIGN: number;
    LOW: number;
    MEDIUM: number;
    HIGH: number;
    CRITICAL: number;
  };
  honeypots_triggered: number;
  false_positive_rate: number;
  average_processing_time_ms: number;
  uptime_seconds?: number;
}

export interface BlastRadiusResponse {
  blast_radius_score: number;
  affected_nodes: string[];
  path_to_nearest_critical: string[];
  movement_pattern: string;
  nearest_critical_node: string;
  nearest_critical_distance: number;
}

export interface VaultSnapshot {
  snapshot_id: string;
  verified: boolean;
  filename: string;
}

// ── Helpers ────────────────────────────────────────────

/**
 * Converts a raw API response alert into the enriched Alert type
 * the UI components use.
 */
export function normaliseAlert(raw: Record<string, unknown>): Alert {
  const alertId = String(raw.alert_id || raw.id || 'UNKNOWN');
  const severity = (raw.severity as Alert['severity']) || 'LOW';
  const playbookState = String(raw.playbook_state || 'ALERT_RECEIVED');
  const honeypotTriggered = Boolean(raw.honeypot_triggered);
  const eventType = String(raw.event_type || '');
  const rawLog = String(raw.raw_log || '');

  // Derive a readable title
  const title = honeypotTriggered
    ? `🍯 Honeypot: ${raw.triggered_asset_id || eventType || 'Decoy Asset Accessed'}`
    : eventType || rawLog.substring(0, 60) || alertId;

  // Map playbook state to a human status
  const statusMap: Record<string, string> = {
    ALERT_RECEIVED: 'New',
    TRIAGING: 'Triaging',
    INVESTIGATING: 'Investigating',
    ESCALATED: 'Escalated',
    CONTAINMENT: 'Containment',
    REMEDIATION: 'Remediation',
    RESOLVED: 'Resolved',
    FAILED_DEFENCE: 'Failed Defence',
  };
  const status = statusMap[playbookState] || playbookState;

  // Build playbook steps from the state machine
  const allStates = [
    'ALERT_RECEIVED', 'TRIAGING', 'INVESTIGATING',
    'ESCALATED', 'CONTAINMENT', 'REMEDIATION', 'RESOLVED'
  ];
  const currentIdx = allStates.indexOf(playbookState);
  const playbookSteps: PlaybookStep[] = allStates.map((state, idx) => ({
    id: String(idx),
    label: (statusMap[state] || state).replace(/_/g, ' '),
    status: idx < currentIdx ? 'completed'
           : idx === currentIdx ? 'active'
           : 'pending',
    icon: getIconForState(state),
  }));

  // Evidence trail
  const evidenceTrail = (raw.evidence_trail as string[]) || [];

  return {
    alert_id: alertId,
    id: alertId,
    severity,
    confidence: Number(raw.confidence ?? 0),
    evidence_trail: evidenceTrail,
    blast_radius: Number(raw.blast_radius ?? 0),
    playbook_state: playbookState,
    summary: String(raw.summary || ''),
    narrative: String(raw.narrative || ''),
    vault_hash: String(raw.vault_hash || ''),
    source_ip: String(raw.source_ip || '0.0.0.0'),
    dest_ip: String(raw.dest_ip || '0.0.0.0'),
    port: Number(raw.port ?? 0),
    protocol: String(raw.protocol || ''),
    event_type: eventType,
    raw_log: rawLog,
    timestamp: String(raw.timestamp || new Date().toISOString()),
    accessed_path: String(raw.accessed_path || ''),
    honeypot_triggered: honeypotTriggered,
    triggered_asset_id: String(raw.triggered_asset_id || ''),
    title,
    status,
    playbookSteps,
    relatedEntities: {
      attackerHost: String(raw.source_ip || 'Unknown'),
      targetAccount: String(raw.event_type || raw.dest_ip || 'Unknown'),
      payloadHash: String(
        raw.vault_hash
          ? (raw.vault_hash as string).substring(0, 16) + '...'
          : raw.accessed_path || 'N/A'
      ),
    },
    chainOfCustody: raw.vault_hash ? {
      node: 'SOC-NODE-01 (Forensic Vault)',
      method: 'SHA-256 WORM Snapshot',
      time: new Date().toUTCString(),
    } : undefined,
  };
}

function getIconForState(state: string): string {
  switch (state) {
    case 'ALERT_RECEIVED':   return 'Target';
    case 'TRIAGING':         return 'Mask';
    case 'INVESTIGATING':    return 'Search';
    case 'ESCALATED':        return 'ShieldAlert';
    case 'CONTAINMENT':      return 'ShieldAlert';
    case 'REMEDIATION':      return 'Save';
    case 'RESOLVED':         return 'CheckCircle2';
    default:                 return 'CheckCircle2';
  }
}
