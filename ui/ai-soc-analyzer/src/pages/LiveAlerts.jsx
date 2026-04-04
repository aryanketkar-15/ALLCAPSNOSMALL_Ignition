import React, { useState, useEffect, useRef, useMemo } from 'react';
import { api } from '../services/api';
import { 
  Search, AlertTriangle, ShieldCheck, Download, CheckCircle2, X, Terminal, Copy
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';

const SEVERITY_COLORS = {
  CRITICAL: '#ff4444',
  HIGH: '#ff8c00',
  MEDIUM: '#ffd700',
  LOW: '#00ff88',
  BENIGN: '#388bfd'
};

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'BENIGN'];
const EVENT_TYPES = ['All Types', 'PORT_SCAN', 'AUTH_FAIL', 'LATERAL_MOVEMENT', 'C2_BEACON', 'FILE_READ', 'HTTP_REQUEST', 'HONEYPOT'];

export default function LiveAlerts() {
  const navigate = useNavigate();
  const [alerts, setAlerts] = useState([]);
  const [isLive, setIsLive] = useState(true);
  
  // Filters
  const [sevFilter, setSevFilter] = useState(new Set(SEVERITIES));
  const [typeFilter, setTypeFilter] = useState('All Types');
  const [ipSearch, setIpSearch] = useState('');
  
  // Selection & Drawer
  const [selectedIds, setSelectedIds] = useState(new Set());
  const [drawerAlert, setDrawerAlert] = useState(null);
  const newRowIds = useRef(new Set());
  
  useEffect(() => {
    let interval;
    const fetchAlerts = async () => {
      try {
        const data = await api.alerts();
        if (data && data.length) {
          setAlerts(prev => {
            const existingIds = new Set(prev.map(a => a.alert_id));
            const news = data.filter(a => !existingIds.has(a.alert_id));
            news.forEach(n => newRowIds.current.add(n.alert_id));
            setTimeout(() => {
               news.forEach(n => newRowIds.current.delete(n.alert_id));
            }, 2000);
            
            // Auto open drawer for honeypot
            const honeypotNew = news.find(a => a.honeypot_triggered);
            if (honeypotNew) setTimeout(() => setDrawerAlert(honeypotNew), 300);
            
            const combined = [...news, ...prev].slice(0, 500);
            return combined;
          });
        }
      } catch (err) { console.error('Fetch alerts failed', err); }
    };
    
    fetchAlerts();
    if (isLive) {
      interval = setInterval(fetchAlerts, 5000);
    }
    return () => clearInterval(interval);
  }, [isLive]);

  const toggleSev = (sev) => {
    setSevFilter(prev => {
      const next = new Set(prev);
      next.has(sev) ? next.delete(sev) : next.add(sev);
      return next;
    });
  };

  const toggleSelection = (id, e) => {
    e.stopPropagation();
    setSelectedIds(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  // Filter & Sort
  const filteredAlerts = useMemo(() => {
    return alerts
      .filter(a => sevFilter.has(a.severity))
      .filter(a => typeFilter === 'All Types' || a.event_type === typeFilter)
      .filter(a => !ipSearch || (a.source_ip||'').includes(ipSearch) || (a.dest_ip||'').includes(ipSearch))
      .sort((a, b) => {
        if (a.honeypot_triggered && !b.honeypot_triggered) return -1;
        if (!a.honeypot_triggered && b.honeypot_triggered) return 1;
        return new Date(b.timestamp) - new Date(a.timestamp);
      });
  }, [alerts, sevFilter, typeFilter, ipSearch]);

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text).catch(err => {
      const el = document.createElement('textarea');
      el.value = text;
      document.body.appendChild(el);
      el.select();
      document.execCommand('copy');
      document.body.removeChild(el);
    });
  };

  return (
    <div className="flex flex-col h-full bg-sp-bg overflow-hidden relative">
      <style>{`
        @keyframes slideInGreen {
          from { opacity: 0; background-color: rgba(0, 255, 136, 0.2); }
          to { opacity: 1; background-color: transparent; }
        }
        .row-new { animation: slideInGreen 0.3s ease-out; }
      `}</style>

      {/* FILTER BAR */}
      <div className="bg-sp-surface border-b border-sp-border px-6 py-3 flex flex-wrap items-center gap-4 shrink-0 z-10 sticky top-0">
        <div className="flex items-center gap-2">
          {SEVERITIES.map(sev => (
            <button
              key={sev}
              onClick={() => toggleSev(sev)}
              className={`px-3 py-1 rounded-full text-xs font-mono font-bold transition-colors ${
                sevFilter.has(sev) 
                  ? 'text-black' 
                  : 'bg-transparent border border-sp-border text-sp-muted hover:text-sp-text'
              }`}
              style={{ backgroundColor: sevFilter.has(sev) ? SEVERITY_COLORS[sev] : undefined }}
            >
              {sev}
            </button>
          ))}
        </div>

        <select 
          className="bg-sp-surface border border-sp-border text-sp-text rounded px-3 py-1.5 text-xs font-mono"
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
        >
          {EVENT_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
        </select>

        <div className="relative flex items-center">
          <Search className="w-4 h-4 text-sp-muted absolute left-2 pointer-events-none" />
          <input 
            type="text" 
            placeholder="Filter by IP..." 
            value={ipSearch}
            onChange={(e) => setIpSearch(e.target.value)}
            className="bg-sp-surface border border-sp-border rounded text-xs pl-8 pr-3 py-1.5 focus:border-sp-accent focus:outline-none text-sp-text"
          />
        </div>

        <div className="flex-1"></div>

        <button 
          onClick={() => setIsLive(!isLive)}
          className="flex items-center gap-2 px-3 py-1.5 rounded border border-sp-border bg-sp-surface"
        >
          <div className={`w-2 h-2 rounded-full ${isLive ? 'bg-sp-accent animate-pulse' : 'bg-sp-muted'}`}></div>
          <span className={`text-xs font-bold ${isLive ? 'text-sp-accent' : 'text-sp-muted'}`}>
            {isLive ? 'LIVE' : 'PAUSED'}
          </span>
        </button>
      </div>

      {/* ALERT TABLE */}
      <div className="flex-1 overflow-x-auto overflow-y-auto">
        <table className="w-full text-left text-sm whitespace-nowrap min-w-[800px]">
          <thead className="bg-[#0d1117] text-sp-muted text-xs uppercase sticky top-0 z-10 border-b border-sp-border">
            <tr>
              <th className="px-4 py-3 w-10"></th>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3">Alert ID</th>
              <th className="px-4 py-3">Source IP</th>
              <th className="px-4 py-3">Dest IP</th>
              <th className="px-4 py-3">Event Type</th>
              <th className="px-4 py-3">Confidence</th>
              <th className="px-4 py-3">Time</th>
            </tr>
          </thead>
          <tbody>
            {filteredAlerts.map(a => {
              const isNew = newRowIds.current.has(a.alert_id);
              return (
                <tr 
                  key={a.alert_id}
                  onClick={() => setDrawerAlert(a)}
                  className={`border-b border-sp-border/50 hover:bg-sp-border/30 cursor-pointer transition-colors ${
                    a.honeypot_triggered ? 'bg-[#ff00ff]/10 border-l-4 border-l-[#ff00ff]' : ''
                  } ${isNew ? 'row-new' : ''}`}
                >
                  <td className="px-4 py-3 text-center">
                    <input 
                      type="checkbox" 
                      onChange={(e) => toggleSelection(a.alert_id, e)}
                      checked={selectedIds.has(a.alert_id)}
                      className="accent-sp-accent bg-sp-surface border-sp-border"
                    />
                  </td>
                  <td className="px-4 py-3">
                    {a.honeypot_triggered ? (
                      <span className="rounded-full px-2 py-0.5 text-xs font-mono font-bold bg-[#ff00ff] text-black">HONEYPOT</span>
                    ) : (
                      <span className="rounded-full px-2 py-0.5 text-xs font-mono font-bold" style={{ backgroundColor: `${SEVERITY_COLORS[a.severity]}33`, color: SEVERITY_COLORS[a.severity] }}>
                        {a.severity}
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs">{a.alert_id.substring(0, 16)}...</td>
                  <td className="px-4 py-3 font-mono text-xs">{a.source_ip}</td>
                  <td className="px-4 py-3 font-mono text-xs">{a.dest_ip}</td>
                  <td className="px-4 py-3 text-sp-text text-xs">{a.event_type}</td>
                  <td className="px-4 py-3">
                    <div className="w-24 h-1.5 bg-sp-bg rounded overflow-hidden">
                      <div className="h-full" style={{ width: `${(a.confidence || 0) * 100}%`, backgroundColor: SEVERITY_COLORS[a.severity] }}></div>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-sp-muted text-xs font-mono">
                    {new Date(a.timestamp).toLocaleTimeString()}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* DRAWER */}
      {drawerAlert && (
         <>
           <div className="fixed inset-0 bg-black/50 z-40" onClick={() => setDrawerAlert(null)}></div>
           <div className="fixed right-0 top-0 h-full w-[480px] sm:w-full sm:max-w-md bg-sp-bg border-l border-sp-border z-50 transform transition-transform translate-x-0 flex flex-col shadow-2xl">
              
              <div className="p-4 border-b border-sp-border bg-sp-surface flex items-center justify-between shadow-sm z-10 shrink-0">
                <div className="flex items-center gap-3">
                  <span className="font-mono text-sp-accent text-lg font-bold">{drawerAlert.alert_id.substring(0,8)}</span>
                  <span className="rounded-full px-2 py-0.5 text-[10px] font-mono font-bold" style={{ backgroundColor: SEVERITY_COLORS[drawerAlert.severity], color: 'black' }}>
                    {drawerAlert.severity}
                  </span>
                </div>
                <button onClick={() => setDrawerAlert(null)} className="text-sp-muted hover:text-white p-1">
                  <X size={20} />
                </button>
              </div>
              
              <div className="flex-1 overflow-y-auto p-6 flex flex-col gap-6">
                
                {drawerAlert.honeypot_triggered && (
                  <div className="bg-[#ff00ff]/10 border border-[#ff00ff]/30 p-3 rounded-lg text-[#ff00ff] text-xs font-bold uppercase tracking-wider flex items-center gap-2">
                    <AlertTriangle size={16} className="animate-pulse" /> 🍯 HONEYPOT TRIGGERED — Zero false positive · Confidence: 100%
                  </div>
                )}

                <div>
                   <h4 className="text-[10px] font-mono text-sp-muted uppercase mb-3 border-b border-sp-border pb-1">Classification Details</h4>
                   <div className="grid grid-cols-2 gap-4">
                     {[
                       ['Source IP', drawerAlert.source_ip],
                       ['Dest IP', drawerAlert.dest_ip],
                       ['Port', String(drawerAlert.port || 'N/A')],
                       ['Protocol', drawerAlert.protocol || 'N/A'],
                       ['Event Type', drawerAlert.event_type || 'N/A'],
                       ['Timestamp', new Date(drawerAlert.timestamp).toLocaleString()]
                     ].map(([label, val]) => (
                       <div key={label}>
                         <div className="text-[10px] text-sp-muted uppercase tracking-wider mb-1">{label}</div>
                         <div className="font-mono text-sp-text text-sm truncate" title={val}>{val}</div>
                       </div>
                     ))}
                   </div>
                </div>

                <div>
                  <div className="flex justify-between items-end mb-1">
                    <h4 className="text-[10px] font-mono text-sp-muted uppercase">Confidence Score</h4>
                    <span className="text-xs font-mono font-bold" style={{ color: SEVERITY_COLORS[drawerAlert.severity] }}>
                      {((drawerAlert.confidence || 0) * 100).toFixed(1)}%
                    </span>
                  </div>
                  <div className="w-full h-3 bg-sp-surface rounded-full overflow-hidden border border-sp-border">
                    <div className="h-full rounded-full transition-all duration-1000" style={{ width: `${(drawerAlert.confidence||0) * 100}%`, backgroundColor: SEVERITY_COLORS[drawerAlert.severity] }}></div>
                  </div>
                </div>

                {drawerAlert.evidence_trail && drawerAlert.evidence_trail.length > 0 && (
                  <div>
                    <h4 className="text-[10px] font-mono text-sp-muted uppercase mb-3 border-b border-sp-border pb-1">
                      Why this was flagged — XAI Evidence Trail
                    </h4>
                    <div className="flex flex-col gap-2">
                      {drawerAlert.evidence_trail.map((ev, i) => {
                        const passMatch = ev.match(/^PASS\s+(\d)/i);
                        const passNum = passMatch ? passMatch[1] : null;
                        const isThreat = ev.includes('\ud83d\udea8') || ev.includes('TI Match') || ev.includes('Malware') || ev.includes('CVE Match') || ev.includes('HONEYPOT');
                        const isWarn   = ev.includes('\u26a0') || ev.includes('WARN') || ev.includes('missing') || ev.includes('anomal') || ev.includes('lateral') || ev.includes('lateral spread') || ev.includes('East-west');
                        const passColors = { '1': '#388bfd', '2': '#ffd700', '3': '#ff8c00' };
                        const badgeColor = passNum ? (passColors[passNum] || '#8b949e') : '#8b949e';
                        const dotColor   = isThreat ? '#ff4444' : isWarn ? '#ffd700' : '#00ff88';
                        const text = ev.replace(/^PASS\s+\d:\s*/i, '');
                        return (
                          <div
                            key={i}
                            style={{
                              background: isThreat ? 'rgba(255,68,68,0.06)' : isWarn ? 'rgba(255,215,0,0.05)' : 'rgba(0,255,136,0.03)',
                              border: `1px solid ${isThreat ? '#ff444422' : isWarn ? '#ffd70022' : '#30363d'}`,
                              borderRadius: 6, padding: '8px 10px',
                              display: 'flex', gap: 8, alignItems: 'flex-start',
                            }}
                          >
                            {passNum && (
                              <span style={{
                                fontSize: 9, fontFamily: 'JetBrains Mono, monospace', fontWeight: 700,
                                color: badgeColor, background: `${badgeColor}22`,
                                border: `1px solid ${badgeColor}55`,
                                borderRadius: 4, padding: '1px 5px',
                                flexShrink: 0, marginTop: 2, whiteSpace: 'nowrap',
                              }}>
                                PASS {passNum}
                              </span>
                            )}
                            <div style={{
                              width: 6, height: 6, borderRadius: '50%',
                              background: dotColor, flexShrink: 0, marginTop: 5,
                              boxShadow: `0 0 4px ${dotColor}88`,
                            }} />
                            <span style={{
                              fontSize: 11, lineHeight: 1.6,
                              color: isThreat ? '#ff9999' : isWarn ? '#e6c873' : '#c9d1d9',
                              fontFamily: 'Inter, sans-serif',
                            }}>
                              {text}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                <div>
                  <h4 className="text-[10px] font-mono text-sp-muted uppercase mb-2 border-b border-sp-border pb-1 flex items-center gap-1">
                    🤖 AI Analysis (Llama 3)
                  </h4>
                  <div className="bg-sp-surface p-3 rounded-lg border border-sp-border">
                    {drawerAlert.summary ? (
                       <p className="italic text-sp-muted text-sm leading-relaxed">{drawerAlert.summary}</p>
                    ) : (
                       <p className="italic text-sp-muted text-sm flex items-center gap-2">
                         <div className="w-3 h-3 border-2 border-sp-accent border-r-transparent rounded-full animate-spin"></div> Generating...
                       </p>
                    )}
                  </div>
                </div>

                <div>
                  <h4 className="text-[10px] font-mono text-sp-muted uppercase mb-3 border-b border-sp-border pb-1">Forensic Vault</h4>
                  <div className="flex items-center justify-between bg-sp-surface p-2 rounded border border-sp-border mb-2">
                     <span className="font-mono text-xs text-sp-text truncate">{drawerAlert.vault_hash || 'Pending validation...'}</span>
                     <button onClick={() => copyToClipboard(drawerAlert.vault_hash)} className="p-1.5 hover:bg-sp-bg rounded text-sp-muted hover:text-sp-accent transition-colors" title="Copy Hash">
                       <Copy size={14} />
                     </button>
                  </div>
                  <button onClick={() => navigate('/vault')} className="text-sp-accent text-xs font-mono hover:underline inline-flex flex items-center gap-1">
                    View chain of custody &rarr;
                  </button>
                </div>
              </div>
           </div>
         </>
      )}

      {/* BULK ACTIONS BAR */}
      <div className={`fixed bottom-0 left-64 right-0 bg-sp-surface border-t border-sp-border px-6 py-4 flex items-center justify-between transition-transform duration-200 z-30 ${selectedIds.size > 0 ? 'translate-y-0' : 'translate-y-full'}`}>
        <div className="flex items-center gap-3">
          <span className="bg-sp-accent text-black font-bold font-mono px-2 py-0.5 rounded text-sm">{selectedIds.size}</span>
          <span className="text-sp-text font-bold text-sm">alerts selected</span>
        </div>
        <div className="flex items-center gap-3">
          <button className="flex items-center gap-2 bg-[#1f6feb] hover:bg-[#388bfd] text-white px-4 py-1.5 rounded text-sm font-bold transition-colors">
            <Download size={16} /> Export CACAO JSON
          </button>
          <button className="flex items-center gap-2 bg-sp-bg border border-sp-border hover:border-sp-accent text-sp-text px-4 py-1.5 rounded text-sm font-bold transition-colors">
            <CheckCircle2 size={16} className="text-sp-accent" /> Mark Resolved
          </button>
          <button onClick={() => setSelectedIds(new Set())} className="text-sp-muted hover:text-white px-2 py-1.5 text-sm">
            Clear Selection
          </button>
        </div>
      </div>
    </div>
  );
}
