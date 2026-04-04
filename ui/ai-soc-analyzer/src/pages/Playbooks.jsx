import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import { api } from '../services/api';
import { ReactFlow, Controls, Background, useNodesState, useEdgesState } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { ChevronDown, ChevronRight, Copy, Download, Clock, CheckCircle2, AlertTriangle, Zap, Activity } from 'lucide-react';

// === FSM CONSTANTS ===
const STATES = [
  'RECEIVED', 'INITIAL_TRIAGE', 'IP_BLOCKED', 'ASN_BLOCKED',
  'HOST_ISOLATED', 'ESCALATED', 'RESOLVED', 'FAILED'
];

const SEVERITY_COLORS = {
  CRITICAL: '#ff4444', HIGH: '#ff8c00', MEDIUM: '#ffd700', LOW: '#00ff88', BENIGN: '#388bfd', UNKNOWN: '#8b949e'
};

const NODE_STYLE_BASE = {
  background: '#161b22',
  color: '#8b949e',
  border: '1.5px solid #30363d',
  borderRadius: '6px',
  padding: '8px 12px',
  fontSize: '11px',
  fontFamily: "'JetBrains Mono', monospace",
  fontWeight: '600',
};

const initialNodes = [
  { id: 'RECEIVED',      data: { label: '⬤ RECEIVED' },      position: { x: 0,   y: 100 }, style: { ...NODE_STYLE_BASE }, sourcePosition: 'right', targetPosition: 'left' },
  { id: 'INITIAL_TRIAGE',data: { label: '⬤ TRIAGE' },        position: { x: 180, y: 100 }, style: { ...NODE_STYLE_BASE }, sourcePosition: 'right', targetPosition: 'left' },
  { id: 'IP_BLOCKED',    data: { label: '⬤ IP_BLOCKED' },    position: { x: 360, y: 20  }, style: { ...NODE_STYLE_BASE }, sourcePosition: 'right', targetPosition: 'left' },
  { id: 'ASN_BLOCKED',   data: { label: '⬤ ASN_BLOCKED' },   position: { x: 540, y: 20  }, style: { ...NODE_STYLE_BASE }, sourcePosition: 'right', targetPosition: 'left' },
  { id: 'HOST_ISOLATED', data: { label: '⬤ ISOLATED' },      position: { x: 360, y: 180 }, style: { ...NODE_STYLE_BASE }, sourcePosition: 'right', targetPosition: 'left' },
  { id: 'ESCALATED',    data: { label: '⬤ ESCALATED' },      position: { x: 540, y: 180 }, style: { ...NODE_STYLE_BASE }, sourcePosition: 'right', targetPosition: 'left' },
  { id: 'RESOLVED',     data: { label: '✓ RESOLVED' },        position: { x: 720, y: 100 }, style: { ...NODE_STYLE_BASE, color: '#00ff88', borderColor: '#00ff8844' }, sourcePosition: 'right', targetPosition: 'left' },
  { id: 'FAILED',       data: { label: '✕ FAILED' },          position: { x: 260, y: -80 }, style: { ...NODE_STYLE_BASE, color: '#ff4444', borderColor: '#ff444444' }, sourcePosition: 'right', targetPosition: 'left' },
];

const edgeDef = { type: 'smoothstep', style: { stroke: '#30363d', strokeWidth: 1.5 } };
const initialEdges = [
  { id: 'e1', source: 'RECEIVED',      target: 'INITIAL_TRIAGE', ...edgeDef },
  { id: 'e2', source: 'INITIAL_TRIAGE',target: 'IP_BLOCKED',     ...edgeDef },
  { id: 'e3', source: 'IP_BLOCKED',    target: 'ASN_BLOCKED',    ...edgeDef },
  { id: 'e4', source: 'ASN_BLOCKED',   target: 'RESOLVED',       ...edgeDef },
  { id: 'e5', source: 'INITIAL_TRIAGE',target: 'HOST_ISOLATED',  ...edgeDef },
  { id: 'e6', source: 'HOST_ISOLATED', target: 'ESCALATED',      ...edgeDef },
  { id: 'e7', source: 'ESCALATED',     target: 'RESOLVED',       ...edgeDef },
  { id: 'e8', source: 'INITIAL_TRIAGE',target: 'FAILED',         ...edgeDef },
  { id: 'e9', source: 'IP_BLOCKED',    target: 'FAILED',         ...edgeDef },
];

// === LIVE TIMER ===
function LiveTimer({ startTime }) {
  const [elapsed, setElapsed] = useState(0);
  useEffect(() => {
    const start = new Date(startTime).getTime();
    const iv = setInterval(() => setElapsed(Math.floor((Date.now() - start) / 1000)), 1000);
    return () => clearInterval(iv);
  }, [startTime]);
  const m = Math.floor(elapsed / 60).toString().padStart(2, '0');
  const s = (elapsed % 60).toString().padStart(2, '0');
  const color = elapsed > 900 ? '#ff4444' : elapsed > 300 ? '#ffd700' : '#00ff88';
  return (
    <span className="font-mono text-sm font-bold" style={{ color }}>
      {m}:{s}
    </span>
  );
}

// === SYNTAX HIGHLIGHTED JSON ===
const SyntaxJson = ({ jsonString }) => {
  if (!jsonString) return null;
  const html = jsonString
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/(\".*?\"(?=\s*:))/g, '<span style="color:#79b8ff">$1</span>')
    .replace(/:\s*(\".*?\")/g, ': <span style="color:#9ecbff">$1</span>')
    .replace(/\b(true|false|null)\b/g, '<span style="color:#f97583">$1</span>')
    .replace(/:\s*(-?\d+(?:\.\d+)?)/g, ': <span style="color:#f8c555">$1</span>');
  return <pre className="text-[11px] leading-relaxed font-mono overflow-auto h-full" dangerouslySetInnerHTML={{ __html: html }} />;
};

// === SEVERITY BADGE ===
const SevBadge = ({ sev }) => {
  const color = SEVERITY_COLORS[sev] || SEVERITY_COLORS.UNKNOWN;
  return (
    <span
      className="px-2 py-0.5 rounded text-[10px] font-bold font-mono uppercase tracking-wide"
      style={{ color, background: `${color}22`, border: `1px solid ${color}55` }}
    >
      {sev || 'UNKNOWN'}
    </span>
  );
};

// === OUTCOME BADGE ===
const OutcomeBadge = ({ outcome }) => {
  const map = {
    RESOLVED:  { color: '#00ff88', icon: <CheckCircle2 size={11} /> },
    ESCALATED: { color: '#ffd700', icon: <AlertTriangle size={11} /> },
    FAILED:    { color: '#ff4444', icon: <AlertTriangle size={11} /> },
  };
  const cfg = map[outcome] || { color: '#8b949e', icon: null };
  return (
    <span
      className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold font-mono"
      style={{ color: cfg.color, background: `${cfg.color}18`, border: `1px solid ${cfg.color}44` }}
    >
      {cfg.icon}{outcome || 'UNKNOWN'}
    </span>
  );
};

// === MAIN COMPONENT ===
export default function Playbooks() {
  const [activePlaybooks, setActivePlaybooks]   = useState([]);
  const [historyPlaybooks, setHistoryPlaybooks] = useState([]);
  const [expandedRowIds, setExpandedRowIds]     = useState(new Set());
  const [selectedCacao, setSelectedCacao]       = useState(null);
  const [copyFlash, setCopyFlash]               = useState(false);

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  // Poll active playbooks
  useEffect(() => {
    const fetch = async () => { try { setActivePlaybooks(await api.playbooks('active') || []); } catch {} };
    fetch();
    const iv = setInterval(fetch, 3000);
    return () => clearInterval(iv);
  }, []);

  // Fetch history once
  useEffect(() => {
    const fetch = async () => {
      try {
        const data = await api.playbooks('history') || [];
        setHistoryPlaybooks(data);
        if (data.length && !selectedCacao && data[0].cacao_json)
          setSelectedCacao(JSON.stringify(data[0].cacao_json, null, 2));
      } catch {}
    };
    fetch();
  }, []);

  // Update FSM diagram
  useEffect(() => {
    if (activePlaybooks.length) {
      const activeState = activePlaybooks[0].current_state;
      setNodes(nds => nds.map(n => {
        const isActive   = n.id === activeState;
        const isResolved = n.id === 'RESOLVED';
        const isFailed   = n.id === 'FAILED';
        let style = { ...NODE_STYLE_BASE };
        if (isActive)   style = { ...style, background: 'rgba(0,255,136,0.12)', color: '#00ff88', border: '2px solid #00ff88', boxShadow: '0 0 14px rgba(0,255,136,0.35)' };
        else if (isResolved) style = { ...style, color: '#00ff88', borderColor: '#00ff8844' };
        else if (isFailed)   style = { ...style, color: '#ff4444', borderColor: '#ff444444' };
        return { ...n, style };
      }));
      setEdges(eds => eds.map(e => ({
        ...e,
        animated: e.target === activeState,
        style: {
          stroke: e.target === activeState ? '#00ff88' : e.target === 'FAILED' ? '#ff4444' : '#30363d',
          strokeWidth: e.target === activeState ? 2.5 : 1.5,
        }
      })));
    } else {
      setNodes(nds => nds.map(n => ({ ...n, style: { ...NODE_STYLE_BASE } })));
      setEdges(eds => eds.map(e => ({ ...e, animated: false, style: { stroke: '#30363d', strokeWidth: 1.5 } })));
    }
  }, [activePlaybooks]);

  const toggleRow = (pb) => {
    setExpandedRowIds(prev => {
      const next = new Set(prev);
      next.has(pb.id) ? next.delete(pb.id) : next.add(pb.id);
      return next;
    });
    if (pb.cacao_json) setSelectedCacao(JSON.stringify(pb.cacao_json, null, 2));
  };

  const copyCacao = () => {
    if (!selectedCacao) return;
    navigator.clipboard.writeText(selectedCacao).catch(() => {
      const el = document.createElement('textarea');
      el.value = selectedCacao;
      document.body.appendChild(el); el.select(); document.execCommand('copy'); document.body.removeChild(el);
    });
    setCopyFlash(true);
    setTimeout(() => setCopyFlash(false), 1500);
  };

  const downloadCacao = () => {
    if (!selectedCacao) return;
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([selectedCacao], { type: 'application/json' }));
    a.download = 'cacao_playbook.json';
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
  };

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        height: '100%',
        width: '100%',
        background: '#0d1117',
        overflow: 'hidden',
      }}
    >
      {/* ── PAGE HEADER ── */}
      <div style={{
        padding: '16px 24px 12px',
        borderBottom: '1px solid #30363d',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexShrink: 0,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <Zap size={18} color="#00ff88" />
          <span style={{ fontFamily: 'Inter, sans-serif', fontWeight: 700, fontSize: 16, color: '#e6edf3', letterSpacing: '-0.01em' }}>
            Playbook Orchestrator
          </span>
          <span style={{
            fontSize: 10, fontFamily: 'JetBrains Mono, monospace', color: '#00ff88',
            background: 'rgba(0,255,136,0.1)', border: '1px solid rgba(0,255,136,0.3)',
            borderRadius: 4, padding: '2px 8px', fontWeight: 700, letterSpacing: 1,
          }}>
            CACAO 2.0
          </span>
        </div>
        <div style={{ display: 'flex', gap: 16, alignItems: 'center' }}>
          <span style={{ fontSize: 11, fontFamily: 'JetBrains Mono, monospace', color: '#8b949e' }}>
            Active: <span style={{ color: activePlaybooks.length ? '#00ff88' : '#8b949e' }}>{activePlaybooks.length}</span>
          </span>
          <span style={{ fontSize: 11, fontFamily: 'JetBrains Mono, monospace', color: '#8b949e' }}>
            History: <span style={{ color: '#e6edf3' }}>{historyPlaybooks.length}</span>
          </span>
        </div>
      </div>

      {/* ── SCROLLABLE BODY ── */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '16px 24px 24px', display: 'flex', flexDirection: 'column', gap: 16 }}>

        {/* ── ACTIVE PLAYBOOK CARDS ── */}
        {activePlaybooks.length > 0 && (
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
              <div style={{ width: 7, height: 7, borderRadius: '50%', background: '#00ff88', boxShadow: '0 0 6px #00ff88', animation: 'pulse 1.5s infinite' }} />
              <span style={{ fontSize: 11, fontFamily: 'JetBrains Mono, monospace', color: '#8b949e', textTransform: 'uppercase', letterSpacing: 1.5 }}>
                Active Playbooks
              </span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 12 }}>
              {activePlaybooks.map(pb => {
                const idx = STATES.indexOf(pb.current_state);
                return (
                  <div key={pb.id} style={{
                    background: '#161b22', border: '1px solid #30363d', borderRadius: 8,
                    padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: 12,
                    boxShadow: '0 0 20px rgba(0,255,136,0.05)',
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: '#8b949e', background: '#30363d', borderRadius: 4, padding: '2px 8px' }}>
                        {pb.alert_id?.slice(0, 18)}…
                      </span>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 9, fontFamily: 'JetBrains Mono, monospace', color: '#00ff88', background: 'rgba(0,255,136,0.1)', border: '1px solid rgba(0,255,136,0.3)', borderRadius: 4, padding: '2px 8px', fontWeight: 700, letterSpacing: 1 }}>
                        <span style={{ width: 5, height: 5, borderRadius: '50%', background: '#00ff88', display: 'inline-block' }} />
                        LIVE
                      </div>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div>
                        <div style={{ fontSize: 10, color: '#8b949e', fontFamily: 'JetBrains Mono, monospace', marginBottom: 2 }}>State</div>
                        <div style={{ fontSize: 12, fontFamily: 'JetBrains Mono, monospace', color: '#00ff88', fontWeight: 700 }}>{pb.current_state}</div>
                      </div>
                      <div style={{ textAlign: 'right' }}>
                        <div style={{ fontSize: 10, color: '#8b949e', fontFamily: 'JetBrains Mono, monospace', marginBottom: 2 }}>Elapsed</div>
                        <LiveTimer startTime={pb.started_at} />
                      </div>
                    </div>
                    {/* Progress bar */}
                    <div>
                      <div style={{ display: 'flex', gap: 3, height: 4, borderRadius: 99, overflow: 'hidden' }}>
                        {STATES.slice(0, -1).map((st, i) => (
                          <div key={st} style={{
                            flex: 1, height: '100%', borderRadius: 99,
                            background: i < idx ? '#00ff88' : i === idx ? '#ffd700' : '#30363d',
                            transition: 'background 0.3s',
                          }} />
                        ))}
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 4, fontSize: 8, fontFamily: 'JetBrains Mono, monospace', color: '#8b949e' }}>
                        <span>RECEIVED</span><span>RESOLVED</span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {activePlaybooks.length === 0 && (
          <div style={{
            border: '1px dashed #30363d', borderRadius: 8, background: '#161b22',
            padding: '14px 20px', display: 'flex', alignItems: 'center', gap: 10,
            flexShrink: 0,
          }}>
            <Activity size={14} color="#8b949e" />
            <span style={{ fontSize: 12, fontFamily: 'JetBrains Mono, monospace', color: '#8b949e' }}>No active playbooks right now.</span>
          </div>
        )}

        {/* ── FSM DIAGRAM ── */}
        <div style={{
          background: '#161b22', border: '1px solid #30363d', borderRadius: 8,
          height: 220, flexShrink: 0, position: 'relative',
        }}>
          <div style={{
            position: 'absolute', top: 10, left: 14, zIndex: 10,
            fontSize: 10, fontFamily: 'JetBrains Mono, monospace', color: '#8b949e',
            textTransform: 'uppercase', letterSpacing: 1.5, background: '#161b22',
            padding: '0 6px',
          }}>
            Autonomic FSM Diagram
          </div>
          <ReactFlow
            nodes={nodes} edges={edges}
            onNodesChange={onNodesChange} onEdgesChange={onEdgesChange}
            fitView fitViewOptions={{ padding: 0.25 }}
            attributionPosition="bottom-right"
            proOptions={{ hideAttribution: true }}
          >
            <Background variant="dots" gap={16} size={0.8} color="#30363d" />
            <Controls
              style={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 6 }}
              showInteractive={false}
            />
          </ReactFlow>
        </div>

        {/* ── HISTORY + CACAO GRID ── */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: '1fr 420px',
          gap: 16,
          flex: 1,
          minHeight: 0,
        }}>
          {/* ── HISTORY TABLE ── */}
          <div style={{
            background: '#161b22', border: '1px solid #30363d', borderRadius: 8,
            display: 'flex', flexDirection: 'column', overflow: 'hidden',
            minHeight: 320,
          }}>
            {/* Table header bar */}
            <div style={{
              padding: '10px 16px', borderBottom: '1px solid #30363d',
              display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0,
            }}>
              <span style={{ fontSize: 11, fontFamily: 'JetBrains Mono, monospace', color: '#8b949e', textTransform: 'uppercase', letterSpacing: 1.5 }}>
                Execution History
              </span>
              <span style={{
                fontSize: 10, fontFamily: 'JetBrains Mono, monospace', color: '#8b949e',
                background: '#30363d', borderRadius: 4, padding: '1px 8px',
              }}>
                {historyPlaybooks.length} records
              </span>
            </div>

            {/* Scrollable table */}
            <div style={{ flex: 1, overflowY: 'auto', overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                <thead>
                  <tr style={{ background: '#0d1117', position: 'sticky', top: 0, zIndex: 5 }}>
                    <th style={{ width: 28, padding: '8px 8px', borderBottom: '1px solid #30363d' }}></th>
                    <th style={{ padding: '8px 12px', borderBottom: '1px solid #30363d', textAlign: 'left', fontSize: 10, fontFamily: 'JetBrains Mono, monospace', color: '#8b949e', textTransform: 'uppercase', letterSpacing: 1, fontWeight: 600 }}>Alert ID</th>
                    <th style={{ padding: '8px 12px', borderBottom: '1px solid #30363d', textAlign: 'left', fontSize: 10, fontFamily: 'JetBrains Mono, monospace', color: '#8b949e', textTransform: 'uppercase', letterSpacing: 1, fontWeight: 600 }}>Severity</th>
                    <th style={{ padding: '8px 12px', borderBottom: '1px solid #30363d', textAlign: 'left', fontSize: 10, fontFamily: 'JetBrains Mono, monospace', color: '#8b949e', textTransform: 'uppercase', letterSpacing: 1, fontWeight: 600 }}>Duration</th>
                    <th style={{ padding: '8px 12px', borderBottom: '1px solid #30363d', textAlign: 'left', fontSize: 10, fontFamily: 'JetBrains Mono, monospace', color: '#8b949e', textTransform: 'uppercase', letterSpacing: 1, fontWeight: 600 }}>Outcome</th>
                    <th style={{ padding: '8px 12px', borderBottom: '1px solid #30363d', textAlign: 'left', fontSize: 10, fontFamily: 'JetBrains Mono, monospace', color: '#8b949e', textTransform: 'uppercase', letterSpacing: 1, fontWeight: 600 }}>Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {historyPlaybooks.length === 0 && (
                    <tr>
                      <td colSpan={6} style={{ textAlign: 'center', padding: '32px', color: '#8b949e', fontSize: 12, fontFamily: 'JetBrains Mono, monospace' }}>
                        No history yet. Run an attack simulation to generate playbooks.
                      </td>
                    </tr>
                  )}
                  {historyPlaybooks.map((pb, i) => {
                    const isExpanded = expandedRowIds.has(pb.id);
                    return (
                      <React.Fragment key={pb.id}>
                        <tr
                          onClick={() => toggleRow(pb)}
                          style={{
                            cursor: 'pointer',
                            borderBottom: '1px solid #21262d',
                            background: isExpanded ? '#0d1117' : (i % 2 === 0 ? '#161b22' : '#12171e'),
                            transition: 'background 0.15s',
                          }}
                          onMouseEnter={e => e.currentTarget.style.background = '#1c2128'}
                          onMouseLeave={e => e.currentTarget.style.background = isExpanded ? '#0d1117' : (i % 2 === 0 ? '#161b22' : '#12171e')}
                        >
                          <td style={{ padding: '8px 8px', color: '#8b949e', verticalAlign: 'middle' }}>
                            {isExpanded ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
                          </td>
                          <td style={{ padding: '8px 12px', fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: '#e6edf3', verticalAlign: 'middle', whiteSpace: 'nowrap', maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                            {pb.alert_id}
                          </td>
                          <td style={{ padding: '8px 12px', verticalAlign: 'middle' }}>
                            <SevBadge sev={pb.severity} />
                          </td>
                          <td style={{ padding: '8px 12px', fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: '#8b949e', verticalAlign: 'middle' }}>
                            {pb.duration_sec}s
                          </td>
                          <td style={{ padding: '8px 12px', verticalAlign: 'middle' }}>
                            <OutcomeBadge outcome={pb.outcome} />
                          </td>
                          <td style={{ padding: '8px 12px', fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: '#8b949e', verticalAlign: 'middle', whiteSpace: 'nowrap' }}>
                            {new Date(pb.started_at).toLocaleString()}
                          </td>
                        </tr>
                        {isExpanded && (
                          <tr style={{ background: '#0d1117', borderBottom: '1px solid #21262d' }}>
                            <td colSpan={6} style={{ padding: '12px 16px' }}>
                              <div style={{ fontSize: 10, fontFamily: 'JetBrains Mono, monospace', color: '#8b949e', marginBottom: 8, textTransform: 'uppercase', letterSpacing: 1 }}>
                                Execution Timeline
                              </div>
                              <div style={{ display: 'flex', alignItems: 'center', gap: 0, overflowX: 'auto', paddingBottom: 4 }}>
                                {pb.timeline && pb.timeline.length > 0 ? pb.timeline.map((step, idx) => (
                                  <React.Fragment key={idx}>
                                    <div style={{
                                      background: '#161b22', border: '1px solid #30363d',
                                      borderRadius: 6, padding: '6px 10px',
                                      display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2,
                                      whiteSpace: 'nowrap', flexShrink: 0,
                                    }}>
                                      <span style={{ fontSize: 10, fontFamily: 'JetBrains Mono, monospace', color: '#00ff88', fontWeight: 700 }}>{step.state}</span>
                                      {step.time_offset !== undefined && (
                                        <span style={{ fontSize: 9, color: '#8b949e' }}>+{step.time_offset}s</span>
                                      )}
                                    </div>
                                    {idx < pb.timeline.length - 1 && (
                                      <div style={{ width: 28, height: 1, background: 'linear-gradient(90deg, #30363d, #00ff8844)', flexShrink: 0, position: 'relative' }}>
                                        <div style={{ position: 'absolute', right: -4, top: -3, width: 6, height: 6, borderTop: '1px solid #30363d', borderRight: '1px solid #30363d', transform: 'rotate(45deg)' }} />
                                      </div>
                                    )}
                                  </React.Fragment>
                                )) : (
                                  <span style={{ fontSize: 11, color: '#8b949e', fontFamily: 'JetBrains Mono, monospace' }}>No timeline data available.</span>
                                )}
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* ── CACAO JSON VIEWER ── */}
          <div style={{
            background: '#161b22', border: '1px solid #30363d', borderRadius: 8,
            display: 'flex', flexDirection: 'column', overflow: 'hidden',
            minHeight: 320,
          }}>
            {/* Header */}
            <div style={{
              padding: '10px 14px', borderBottom: '1px solid #30363d',
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              flexShrink: 0,
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontSize: 11, fontFamily: 'JetBrains Mono, monospace', color: '#8b949e', textTransform: 'uppercase', letterSpacing: 1.5 }}>
                  CACAO Export
                </span>
                <span style={{
                  fontSize: 9, fontFamily: 'JetBrains Mono, monospace', color: '#388bfd',
                  background: 'rgba(56,139,253,0.1)', border: '1px solid rgba(56,139,253,0.3)',
                  borderRadius: 4, padding: '1px 6px', fontWeight: 700,
                }}>JSON</span>
              </div>
              <div style={{ display: 'flex', gap: 4 }}>
                <button
                  onClick={copyCacao}
                  title="Copy JSON"
                  style={{
                    background: copyFlash ? 'rgba(0,255,136,0.15)' : 'transparent',
                    border: `1px solid ${copyFlash ? '#00ff88' : '#30363d'}`,
                    borderRadius: 5, padding: '4px 8px', cursor: 'pointer',
                    color: copyFlash ? '#00ff88' : '#8b949e', display: 'flex', alignItems: 'center', gap: 4,
                    fontSize: 10, fontFamily: 'JetBrains Mono, monospace', transition: 'all 0.2s',
                  }}
                >
                  <Copy size={11} />
                  {copyFlash ? 'Copied!' : 'Copy'}
                </button>
                <button
                  onClick={downloadCacao}
                  title="Download JSON"
                  style={{
                    background: 'transparent', border: '1px solid #30363d',
                    borderRadius: 5, padding: '4px 8px', cursor: 'pointer',
                    color: '#8b949e', display: 'flex', alignItems: 'center', gap: 4,
                    fontSize: 10, fontFamily: 'JetBrains Mono, monospace', transition: 'all 0.2s',
                  }}
                  onMouseEnter={e => { e.currentTarget.style.borderColor = '#00ff88'; e.currentTarget.style.color = '#00ff88'; }}
                  onMouseLeave={e => { e.currentTarget.style.borderColor = '#30363d'; e.currentTarget.style.color = '#8b949e'; }}
                >
                  <Download size={11} />
                  Export
                </button>
              </div>
            </div>

            {/* JSON body */}
            <div style={{
              flex: 1, background: '#0d1117', padding: '12px 14px',
              overflowY: 'auto', overflowX: 'auto',
            }}>
              {selectedCacao ? (
                <SyntaxJson jsonString={selectedCacao} />
              ) : (
                <div style={{
                  height: '100%', display: 'flex', flexDirection: 'column',
                  alignItems: 'center', justifyContent: 'center',
                  color: '#8b949e', fontSize: 12, fontFamily: 'JetBrains Mono, monospace',
                  gap: 8,
                }}>
                  <Download size={20} color="#30363d" />
                  <span>Click a row to load CACAO export</span>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
