/**
 * SOC AI Analyzer Dashboard — App.tsx
 * Connected to FastAPI backend at http://localhost:8000
 * Team SY-A9 | Shanteshwar (Data Viz Lead)
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  LayoutDashboard,
  Bell,
  ShieldAlert,
  Wand2,
  Share2,
  Lock,
  Search,
  HelpCircle,
  History,
  Target,
  ShieldCheck,
  Save,
  Plus,
  Terminal,
  Download,
  CheckCircle2,
  AlertTriangle,
  Info,
  Maximize2,
  ChevronRight,
  RefreshCw,
  Wifi,
  WifiOff,
  Activity,
  TrendingUp,
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { cn } from './lib/utils';
import { Alert, StatsResponse, VaultSnapshot, normaliseAlert } from './types';

// ── API Config ─────────────────────────────────────────
const API_BASE = 'http://localhost:8000';
const POLL_INTERVAL = 5000;

// ── App ────────────────────────────────────────────────
export default function App() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [vaultSnapshots, setVaultSnapshots] = useState<VaultSnapshot[]>([]);
  const [isApiOnline, setIsApiOnline] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [mobileView, setMobileView] = useState<'list' | 'detail'>('list');

  // Form state
  const [formData, setFormData] = useState({
    raw_log: '',
    source_ip: '192.168.1.1',
    dest_ip: '10.0.0.1',
    port: '80',
    event_type: '',
    accessed_path: '',
    protocol: 'TCP',
  });

  const selectedAlert = alerts.find(a => a.id === selectedAlertId) || alerts[0] || null;

  // ── Polling ─────────────────────────────────────────
  const fetchAlerts = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/v1/alerts`);
      if (!res.ok) throw new Error();
      const data = await res.json();
      setIsApiOnline(true);
      const normalised = data.map(normaliseAlert);
      setAlerts(normalised);
      // Auto-select newest alert when list is empty
      if (!selectedAlertId && normalised.length > 0) {
        setSelectedAlertId(normalised[0].id);
      }
    } catch {
      setIsApiOnline(false);
    }
  }, [selectedAlertId]);

  const fetchStats = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/v1/stats`);
      if (!res.ok) return;
      const data: StatsResponse = await res.json();
      setStats(data);
    } catch { /* silent */ }
  }, []);

  const fetchVaultSnapshots = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/v1/vault/list`);
      if (!res.ok) return;
      const data = await res.json();
      setVaultSnapshots(data.snapshots || []);
    } catch { /* silent */ }
  }, []);

  useEffect(() => {
    fetchAlerts();
    fetchStats();
    fetchVaultSnapshots();
    const t1 = setInterval(fetchAlerts, POLL_INTERVAL);
    const t2 = setInterval(fetchStats, POLL_INTERVAL);
    return () => { clearInterval(t1); clearInterval(t2); };
  }, []);

  // ── Submit Alert ─────────────────────────────────────
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.raw_log.trim() && !formData.event_type.trim()) return;
    setIsSubmitting(true);

    try {
      const res = await fetch(`${API_BASE}/api/v1/classify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          raw_log: formData.raw_log,
          source_ip: formData.source_ip || '192.168.1.1',
          dest_ip: formData.dest_ip || '10.0.0.1',
          port: parseInt(formData.port) || 80,
          event_type: formData.event_type,
          accessed_path: formData.accessed_path,
          protocol: formData.protocol,
          timestamp: new Date().toISOString(),
        }),
      });

      if (res.ok) {
        const raw = await res.json();
        const alert = normaliseAlert(raw);
        setAlerts(prev => [alert, ...prev]);
        setSelectedAlertId(alert.id);
        setFormData(f => ({ ...f, raw_log: '', event_type: '', accessed_path: '' }));
        if (window.innerWidth < 768) setMobileView('detail');
        // Refresh vault list after new alert
        setTimeout(fetchVaultSnapshots, 2000);
      }
    } catch (err) {
      console.error('Submit error:', err);
    }
    setIsSubmitting(false);
  };

  // ── Severity Helpers ─────────────────────────────────
  const getSeverityColor = (severity: Alert['severity']) => {
    switch (severity) {
      case 'CRITICAL': return 'bg-error text-white shadow-[0_0_15px_rgba(255,77,77,0.4)]';
      case 'HIGH':     return 'bg-secondary text-white';
      case 'MEDIUM':   return 'bg-tertiary text-black';
      case 'LOW':      return 'bg-primary text-black';
      case 'BENIGN':   return 'bg-green-500/80 text-white';
      default:         return 'bg-surface-highest text-white';
    }
  };

  const getSeverityBorderColor = (severity: Alert['severity']) => {
    switch (severity) {
      case 'CRITICAL': return 'border-l-4 border-red-500';
      case 'HIGH':     return 'border-l-4 border-orange-400';
      case 'MEDIUM':   return 'border-l-4 border-yellow-400';
      case 'LOW':      return 'border-l-4 border-blue-400';
      case 'BENIGN':   return 'border-l-4 border-green-500';
      default:         return '';
    }
  };

  // Uptime formatter
  const formatUptime = (seconds: number) => {
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    return `${m}m ${s}s`;
  };

  const totalAlerts = stats?.total_alerts_processed || 0;

  return (
    <div className="flex h-screen overflow-hidden bg-background flex-col md:flex-row">
      {/* ── Sidebar (Desktop) ── */}
      <aside className="hidden md:flex w-20 hover:w-64 bg-surface-lowest border-r border-outline-variant/10 flex-col py-6 transition-all duration-300 group z-50">
        <div className="px-6 mb-10 flex items-center overflow-hidden">
          <div className="w-8 h-8 bg-primary rounded flex items-center justify-center shrink-0">
            <ShieldAlert className="w-5 h-5 text-background" />
          </div>
          <div className="ml-4 opacity-0 group-hover:opacity-100 transition-opacity duration-300 whitespace-nowrap">
            <div className="font-headline font-bold text-sm tracking-tighter uppercase">AI SOC Analyzer</div>
            <div className="text-[0.6rem] text-outline tracking-widest uppercase">Team SY-A9</div>
          </div>
        </div>

        <nav className="flex-1 space-y-1">
          <SidebarItem icon={<LayoutDashboard size={20} />} label="Overview" />
          <SidebarItem icon={<Bell size={20} />} label="Live Alerts" badge={alerts.length} />
          <SidebarItem icon={<ShieldAlert size={20} />} label="Investigations" active />
          <SidebarItem icon={<Wand2 size={20} />} label="Playbooks" />
          <SidebarItem icon={<Share2 size={20} />} label="Graph View" />
          <SidebarItem icon={<Lock size={20} />} label="Forensics Vault" badge={vaultSnapshots.length} />
        </nav>

        <div className="mt-auto px-6 space-y-4">
          <div className="opacity-0 group-hover:opacity-100 transition-opacity">
            <div className={cn("flex items-center gap-2 text-[0.65rem] font-bold",
              isApiOnline ? "text-green-400" : "text-red-400")}>
              {isApiOnline ? <Wifi size={12} /> : <WifiOff size={12} />}
              {isApiOnline ? "API Online" : "API Offline"}
            </div>
            {stats && (
              <div className="text-[0.6rem] text-outline mt-1">
                Uptime: {formatUptime(stats.uptime_seconds || 0)}
              </div>
            )}
          </div>
          <SidebarItem icon={<HelpCircle size={20} />} label="Support" />
          <SidebarItem icon={<History size={20} />} label="Logs" />
        </div>
      </aside>

      {/* ── Main Content ── */}
      <main className="flex-1 flex flex-col min-w-0 relative h-full">

        {/* Top Bar */}
        <header className="h-14 bg-background/60 backdrop-blur-xl border-b border-outline-variant/10 flex items-center justify-between px-4 md:px-6 z-40 shrink-0">
          <div className="flex items-center gap-4 md:gap-8">
            <div className="md:hidden w-8 h-8 bg-primary rounded flex items-center justify-center shrink-0">
              <ShieldAlert className="w-5 h-5 text-background" />
            </div>
            <span className="font-headline font-bold text-primary text-lg md:text-xl tracking-tighter uppercase truncate">
              AI SOC Analyzer
            </span>
            <nav className="hidden lg:flex items-center gap-6 text-sm">
              <a href="#" className="text-outline hover:text-white transition-colors">Dashboard</a>
              <a href="#" className="text-outline hover:text-white transition-colors">Alerts</a>
              <a href="#" className="text-white">Investigations</a>
              <a href="#" className="text-outline hover:text-white transition-colors">Threat Intel</a>
            </nav>
          </div>

          <div className="flex items-center gap-2 md:gap-4">
            {/* API Status Pill */}
            <div className={cn(
              "hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-full text-[0.65rem] font-bold border",
              isApiOnline
                ? "bg-green-500/10 border-green-500/30 text-green-400"
                : "bg-red-500/10 border-red-500/30 text-red-400"
            )}>
              {isApiOnline ? <Wifi size={10} /> : <WifiOff size={10} />}
              {isApiOnline ? "LIVE" : "OFFLINE"}
            </div>

            {/* Stats Chips */}
            {stats && (
              <div className="hidden lg:flex items-center gap-3">
                <StatChip label="Alerts" value={stats.total_alerts_processed} />
                <StatChip label="Honeypots" value={stats.honeypots_triggered} danger />
                <StatChip label="Avg Time" value={`${stats.average_processing_time_ms.toFixed(0)}ms`} />
              </div>
            )}

            <button
              onClick={() => { fetchAlerts(); fetchStats(); }}
              className="p-2 rounded-lg hover:bg-surface-low transition-colors text-outline hover:text-white"
              title="Refresh"
            >
              <RefreshCw size={16} />
            </button>

            <div className="relative hidden sm:flex items-center bg-surface-low px-3 py-1.5 rounded-lg border border-outline-variant/20">
              <Search className="w-4 h-4 text-outline mr-2" />
              <input
                type="text"
                placeholder="Search..."
                className="bg-transparent border-none text-xs focus:ring-0 text-white w-24 md:w-32 p-0"
              />
            </div>
            <Bell className="w-5 h-5 text-outline cursor-pointer hover:text-primary transition-colors" />
          </div>
        </header>

        {/* Workspace */}
        <div className="flex-1 flex overflow-hidden p-3 md:p-4 gap-4 relative">

          {/* ── Left: Alert List + Submit Form ── */}
          <section className={cn(
            "w-full md:w-80 flex flex-col gap-3 overflow-hidden transition-all duration-300 shrink-0",
            mobileView === 'detail' ? "hidden md:flex" : "flex"
          )}>
            <div className="flex items-center justify-between">
              <h2 className="font-headline font-medium text-lg">Investigations</h2>
              <div className="flex items-center gap-2">
                {stats && (
                  <span className="text-[0.6rem] bg-primary/10 text-primary px-2 py-0.5 rounded-full font-bold">
                    {stats.total_alerts_processed} total
                  </span>
                )}
                <span className="text-[0.6rem] text-outline font-bold tracking-widest uppercase">Live</span>
              </div>
            </div>

            {/* Stats Bar (mini severity distribution) */}
            {stats && stats.total_alerts_processed > 0 && (
              <div className="flex gap-0.5 h-1 rounded-full overflow-hidden">
                {(['CRITICAL','HIGH','MEDIUM','LOW','BENIGN'] as const).map(sev => {
                  const count = stats.severity_distribution[sev] || 0;
                  const pct = (count / stats.total_alerts_processed) * 100;
                  const colors = {
                    CRITICAL: 'bg-red-500',
                    HIGH: 'bg-orange-400',
                    MEDIUM: 'bg-yellow-400',
                    LOW: 'bg-blue-400',
                    BENIGN: 'bg-green-500',
                  };
                  return pct > 0 ? (
                    <div
                      key={sev}
                      className={cn("h-full transition-all duration-700", colors[sev])}
                      style={{ width: `${pct}%` }}
                      title={`${sev}: ${count}`}
                    />
                  ) : null;
                })}
              </div>
            )}

            {/* Alert List */}
            <div className="flex-1 overflow-y-auto no-scrollbar space-y-2">
              {alerts.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-full gap-3 py-12 text-center">
                  <Activity className="text-outline w-8 h-8 animate-pulse" />
                  <p className="text-[0.65rem] text-outline uppercase tracking-widest">
                    {isApiOnline ? 'No alerts yet — submit one below' : 'API Offline — start uvicorn'}
                  </p>
                </div>
              ) : (
                alerts.map(alert => (
                  <motion.div
                    key={alert.id}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    onClick={() => {
                      setSelectedAlertId(alert.id);
                      if (window.innerWidth < 768) setMobileView('detail');
                    }}
                    className={cn(
                      "p-3 rounded-lg border transition-all cursor-pointer",
                      getSeverityBorderColor(alert.severity),
                      selectedAlertId === alert.id
                        ? "bg-surface-highest border-primary/50 shadow-lg"
                        : "bg-surface-low border-outline-variant/10 hover:bg-surface-high",
                      alert.honeypot_triggered && "shadow-[0_0_8px_rgba(239,68,68,0.2)]"
                    )}
                  >
                    <div className="flex justify-between items-start mb-1">
                      <span className={cn(
                        "text-[0.6rem] font-bold tracking-tighter uppercase",
                        selectedAlertId === alert.id ? "text-primary" : "text-outline"
                      )}>
                        {alert.id}
                      </span>
                      <span className={cn(
                        "px-1.5 py-0.5 text-[0.55rem] font-bold rounded",
                        getSeverityColor(alert.severity)
                      )}>
                        {alert.severity}
                      </span>
                    </div>
                    <h3 className={cn(
                      "text-xs font-semibold mb-1 line-clamp-2",
                      selectedAlertId === alert.id ? "text-white" : "text-on-surface-variant"
                    )}>
                      {alert.title}
                    </h3>
                    <div className="flex items-center justify-between">
                      <span className="text-[0.6rem] text-outline font-mono">{alert.source_ip}</span>
                      <span className="text-[0.6rem] text-outline italic">{alert.status}</span>
                    </div>
                    {alert.honeypot_triggered && (
                      <div className="mt-1.5 text-[0.55rem] text-red-400 font-bold uppercase tracking-widest flex items-center gap-1">
                        🍯 Honeypot Triggered — Zero FP
                      </div>
                    )}
                    {alert.blast_radius > 0 && (
                      <div className="mt-1 flex items-center gap-1">
                        <div className="h-1 flex-1 bg-surface-lowest rounded-full overflow-hidden">
                          <div
                            className={cn("h-full rounded-full",
                              alert.blast_radius > 1.0 ? "bg-red-500" :
                              alert.blast_radius > 0.5 ? "bg-orange-400" : "bg-primary"
                            )}
                            style={{ width: `${Math.min(alert.blast_radius * 50, 100)}%` }}
                          />
                        </div>
                        <span className="text-[0.55rem] text-outline">BR: {alert.blast_radius.toFixed(2)}</span>
                      </div>
                    )}
                  </motion.div>
                ))
              )}
            </div>

            {/* Submit Alert Form */}
            <div className="pt-3 border-t border-outline-variant/10">
              <form onSubmit={handleSubmit} className="space-y-2">
                <p className="text-[0.6rem] text-outline uppercase font-bold tracking-widest">Submit Alert to API</p>
                <textarea
                  value={formData.raw_log}
                  onChange={e => setFormData(f => ({ ...f, raw_log: e.target.value }))}
                  placeholder="Paste raw SIEM log here... (e.g. salary_2024_Q3_final.xlsx)"
                  className="w-full h-16 bg-surface-lowest border border-outline-variant/20 rounded p-2 text-[0.65rem] text-white focus:ring-1 focus:ring-primary focus:border-primary resize-none"
                />
                <div className="grid grid-cols-2 gap-1.5">
                  <input
                    value={formData.source_ip}
                    onChange={e => setFormData(f => ({ ...f, source_ip: e.target.value }))}
                    placeholder="Source IP"
                    className="bg-surface-lowest border border-outline-variant/20 rounded p-1.5 text-[0.65rem] text-white focus:ring-1 focus:ring-primary"
                  />
                  <input
                    value={formData.dest_ip}
                    onChange={e => setFormData(f => ({ ...f, dest_ip: e.target.value }))}
                    placeholder="Dest IP"
                    className="bg-surface-lowest border border-outline-variant/20 rounded p-1.5 text-[0.65rem] text-white focus:ring-1 focus:ring-primary"
                  />
                  <input
                    value={formData.port}
                    onChange={e => setFormData(f => ({ ...f, port: e.target.value }))}
                    placeholder="Port"
                    type="number"
                    className="bg-surface-lowest border border-outline-variant/20 rounded p-1.5 text-[0.65rem] text-white focus:ring-1 focus:ring-primary"
                  />
                  <input
                    value={formData.event_type}
                    onChange={e => setFormData(f => ({ ...f, event_type: e.target.value }))}
                    placeholder="Event Type"
                    className="bg-surface-lowest border border-outline-variant/20 rounded p-1.5 text-[0.65rem] text-white focus:ring-1 focus:ring-primary"
                  />
                </div>
                <input
                  value={formData.accessed_path}
                  onChange={e => setFormData(f => ({ ...f, accessed_path: e.target.value }))}
                  placeholder="Accessed Path (e.g. /etc/db_credentials_prod.conf)"
                  className="w-full bg-surface-lowest border border-outline-variant/20 rounded p-1.5 text-[0.65rem] text-white focus:ring-1 focus:ring-primary"
                />
                <button
                  type="submit"
                  disabled={isSubmitting || !isApiOnline}
                  className="w-full py-2 bg-primary text-background text-[0.65rem] font-bold uppercase tracking-widest rounded-lg hover:brightness-110 active:scale-95 transition-all disabled:opacity-40 flex items-center justify-center gap-2"
                >
                  {isSubmitting ? (
                    <><div className="w-3 h-3 border-2 border-background border-t-transparent rounded-full animate-spin" /> Classifying...</>
                  ) : (
                    <><Plus size={12} /> Submit for Classification</>
                  )}
                </button>
              </form>
            </div>
          </section>

          {/* ── Center: Alert Detail ── */}
          <section className={cn(
            "flex-1 overflow-y-auto no-scrollbar flex flex-col gap-4 transition-all duration-300",
            mobileView === 'list' ? "hidden md:flex" : "flex"
          )}>
            <button
              onClick={() => setMobileView('list')}
              className="md:hidden flex items-center gap-2 text-primary font-bold text-xs uppercase tracking-widest mb-2"
            >
              <ChevronRight className="rotate-180" size={16} /> Back to List
            </button>

            {!selectedAlert ? (
              <div className="flex-1 flex flex-col items-center justify-center gap-4 text-center">
                <ShieldCheck size={48} className="text-outline/30" />
                <p className="text-outline text-sm">No alert selected</p>
                <p className="text-[0.65rem] text-outline/50">Submit an alert or wait for the API to return data</p>
              </div>
            ) : (
              <AnimatePresence mode="wait">
                <motion.div
                  key={selectedAlert.id}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  className="space-y-4"
                >
                  {/* Honeypot Critical Banner */}
                  {selectedAlert.honeypot_triggered && (
                    <motion.div
                      initial={{ scale: 0.95 }}
                      animate={{ scale: 1 }}
                      className="p-4 bg-red-500/10 border border-red-500/40 rounded-lg flex items-center gap-4"
                    >
                      <AlertTriangle className="text-red-400 shrink-0 animate-pulse" />
                      <div>
                        <p className="text-sm font-bold text-red-400 uppercase tracking-wider">
                          🍯 Honeypot Triggered — 100% Fidelity Detection
                        </p>
                        <p className="text-[0.65rem] text-red-400/70 mt-0.5">
                          Asset: {selectedAlert.triggered_asset_id} — Zero False Positive. Confidence: {(selectedAlert.confidence * 100).toFixed(0)}%
                        </p>
                      </div>
                    </motion.div>
                  )}

                  {/* Forensic Snapshot */}
                  <div className="glass-panel p-4 md:p-6 rounded-xl relative overflow-hidden">
                    <div className="absolute top-0 right-0 p-4 opacity-5 hidden sm:block">
                      <ShieldCheck size={120} />
                    </div>
                    <div className="relative z-10">
                      <div className="flex items-center gap-3 mb-4">
                        <div className="px-3 py-1 bg-primary/10 border border-primary/30 text-primary font-bold text-[0.65rem] uppercase tracking-widest">
                          Forensic Evidence Snapshot
                        </div>
                        <div className="h-px flex-1 bg-outline-variant/30 hidden sm:block" />
                        <div className={cn(
                          "px-2 py-0.5 text-[0.6rem] font-bold rounded uppercase",
                          getSeverityColor(selectedAlert.severity)
                        )}>
                          {selectedAlert.severity}
                        </div>
                      </div>

                      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 md:gap-6">
                        <div className="space-y-3">
                          <div>
                            <p className="text-[0.65rem] text-outline uppercase font-bold tracking-wider mb-1">Incident ID</p>
                            <p className="font-headline text-xl font-bold">{selectedAlert.id}</p>
                          </div>
                          <div>
                            <p className="text-[0.65rem] text-outline uppercase font-bold tracking-wider mb-1">SHA-256 Vault Hash</p>
                            <p className="font-mono text-[0.6rem] break-all bg-surface-lowest p-2 rounded border border-outline-variant/10">
                              {selectedAlert.vault_hash || 'Not yet vaulted'}
                              {selectedAlert.honeypot_triggered && (
                                <span className="text-red-400 ml-2 uppercase font-bold block sm:inline"> (DECOY ASSET)</span>
                              )}
                            </p>
                          </div>
                          <div>
                            <p className="text-[0.65rem] text-outline uppercase font-bold tracking-wider mb-1">Confidence</p>
                            <div className="flex items-center gap-2">
                              <div className="flex-1 h-2 bg-surface-lowest rounded-full overflow-hidden">
                                <div
                                  className={cn("h-full rounded-full transition-all duration-700",
                                    selectedAlert.confidence >= 0.8 ? "bg-red-500" :
                                    selectedAlert.confidence >= 0.5 ? "bg-orange-400" : "bg-primary"
                                  )}
                                  style={{ width: `${selectedAlert.confidence * 100}%` }}
                                />
                              </div>
                              <span className="text-xs font-mono font-bold">{(selectedAlert.confidence * 100).toFixed(1)}%</span>
                            </div>
                          </div>
                          <div>
                            <p className="text-[0.65rem] text-outline uppercase font-bold tracking-wider mb-1">Blast Radius Score</p>
                            <div className="flex items-center gap-2">
                              <div className="flex-1 h-2 bg-surface-lowest rounded-full overflow-hidden">
                                <div
                                  className={cn("h-full rounded-full transition-all duration-700",
                                    selectedAlert.blast_radius > 1.0 ? "bg-red-500" :
                                    selectedAlert.blast_radius > 0.5 ? "bg-orange-400" : "bg-primary"
                                  )}
                                  style={{ width: `${Math.min(selectedAlert.blast_radius * 50, 100)}%` }}
                                />
                              </div>
                              <span className="text-xs font-mono font-bold">{selectedAlert.blast_radius.toFixed(4)}</span>
                            </div>
                          </div>
                        </div>

                        <div className="space-y-3">
                          {selectedAlert.chainOfCustody && (
                            <div className="p-3 bg-surface-high/50 border border-primary/10 rounded-lg">
                              <p className="text-[0.65rem] text-outline uppercase font-bold tracking-wider mb-2">Chain of Custody</p>
                              <div className="flex items-center gap-3">
                                <div className="w-8 h-8 bg-primary/20 rounded flex items-center justify-center shrink-0">
                                  <Terminal className="text-primary w-4 h-4" />
                                </div>
                                <div className="min-w-0">
                                  <p className="text-xs font-bold truncate">{selectedAlert.chainOfCustody.node}</p>
                                  <p className="text-[0.6rem] text-outline truncate">
                                    {selectedAlert.chainOfCustody.method} · {selectedAlert.chainOfCustody.time}
                                  </p>
                                </div>
                              </div>
                            </div>
                          )}

                          {/* Network Details */}
                          <div className="p-3 bg-surface-high/50 border border-outline-variant/10 rounded-lg">
                            <p className="text-[0.65rem] text-outline uppercase font-bold tracking-wider mb-2">Network</p>
                            <div className="grid grid-cols-2 gap-x-4 gap-y-1">
                              {[
                                ['Source IP', selectedAlert.source_ip],
                                ['Dest IP', selectedAlert.dest_ip],
                                ['Port', String(selectedAlert.port)],
                                ['Protocol', selectedAlert.protocol || 'N/A'],
                                ['Playbook State', selectedAlert.playbook_state],
                                ['Event Type', selectedAlert.event_type || 'N/A'],
                              ].map(([label, value]) => (
                                <div key={label}>
                                  <p className="text-[0.55rem] text-outline uppercase">{label}</p>
                                  <p className="text-[0.65rem] font-mono text-white truncate">{value}</p>
                                </div>
                              ))}
                            </div>
                          </div>

                          <div className="flex gap-2">
                            <button className="flex-1 py-2 bg-primary text-background text-[0.65rem] font-bold uppercase tracking-widest rounded-lg hover:brightness-110 active:scale-95 transition-all flex items-center justify-center gap-1">
                              <Download size={12} /> Report
                            </button>
                            <button
                              onClick={() => {
                                const snapId = vaultSnapshots.find(s => s.snapshot_id.includes(selectedAlert.id));
                                if (snapId) alert(snapId.verified ? '✅ Integrity Verified — SHA-256 matches' : '❌ TAMPERED — hash mismatch');
                                else alert('No vault snapshot found for this alert yet');
                              }}
                              className="flex-1 py-2 border border-outline-variant/30 text-white text-[0.65rem] font-bold uppercase tracking-widest rounded-lg hover:bg-surface-highest transition-all"
                            >
                              Verify Chain
                            </button>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Evidence Trail */}
                  {selectedAlert.evidence_trail.length > 0 && (
                    <div className="space-y-2">
                      <h3 className="font-headline font-medium text-sm flex items-center gap-2">
                        <AlertTriangle size={14} className="text-orange-400" /> Evidence Trail
                      </h3>
                      <div className="space-y-1.5">
                        {selectedAlert.evidence_trail.map((ev, i) => {
                          const isHoneypot = ev.includes('HONEYPOT');
                          return (
                            <div
                              key={i}
                              className={cn(
                                "px-3 py-2 rounded border text-[0.65rem] leading-relaxed",
                                isHoneypot
                                  ? "bg-red-500/10 border-red-500/30 text-red-300 font-semibold"
                                  : "bg-surface-low border-outline-variant/10 text-outline"
                              )}
                            >
                              {isHoneypot && '🍯 '}{ev}
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {/* AI Summary */}
                  {selectedAlert.summary && (
                    <div className="space-y-2">
                      <h3 className="font-headline font-medium text-sm flex items-center gap-2">
                        <Wand2 size={14} className="text-primary" /> AI Executive Summary
                      </h3>
                      <div className="bg-surface-low border border-primary/10 rounded-xl p-4 text-sm leading-relaxed text-outline">
                        {selectedAlert.summary}
                      </div>
                    </div>
                  )}

                  {/* Playbook Narrative */}
                  {selectedAlert.narrative && selectedAlert.narrative !== '[Template] Playbook narrative timed out.' && (
                    <div className="space-y-2">
                      <h3 className="font-headline font-medium text-sm flex items-center gap-2">
                        <Info size={14} className="text-blue-400" /> Playbook Narrative
                      </h3>
                      <div className="bg-surface-low border border-blue-500/10 rounded-xl p-4 text-[0.65rem] leading-relaxed text-outline">
                        {selectedAlert.narrative}
                      </div>
                    </div>
                  )}

                  {/* Playbook Flow */}
                  {selectedAlert.playbookSteps.length > 0 && (
                    <div className="space-y-3">
                      <h3 className="font-headline font-medium text-sm">Execution Playbook Flow</h3>
                      <div className="bg-surface-lowest rounded-xl border border-outline-variant/10 p-4 md:p-8 flex items-center justify-center overflow-x-auto no-scrollbar">
                        <div className="flex items-center min-w-max">
                          {selectedAlert.playbookSteps.map((step, idx) => (
                            <React.Fragment key={step.id}>
                              <div className="flex flex-col items-center gap-3 relative">
                                <div className={cn(
                                  "w-10 h-10 md:w-12 md:h-12 rounded-full border-2 flex items-center justify-center transition-all duration-500",
                                  step.status === 'completed' ? "bg-primary/20 border-primary shadow-[0_0_15px_rgba(0,230,118,0.2)]" :
                                  step.status === 'active'    ? "bg-orange-400/20 border-orange-400 animate-pulse shadow-[0_0_15px_rgba(255,140,0,0.2)]" :
                                  "bg-surface-high border-outline-variant"
                                )}>
                                  {getStepIcon(step.icon, step.status, 18)}
                                </div>
                                <div className={cn(
                                  "absolute -bottom-6 whitespace-nowrap text-[0.5rem] font-bold uppercase tracking-widest",
                                  step.status === 'completed' ? "text-primary" :
                                  step.status === 'active'    ? "text-orange-400" : "text-outline"
                                )}>
                                  {step.label}
                                </div>
                              </div>
                              {idx < selectedAlert.playbookSteps.length - 1 && (
                                <div className={cn(
                                  "w-6 md:w-10 h-0.5 mx-2 transition-colors duration-500",
                                  selectedAlert.playbookSteps[idx + 1].status !== 'pending'
                                    ? "bg-primary/30" : "bg-outline-variant/20"
                                )} />
                              )}
                            </React.Fragment>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}
                </motion.div>
              </AnimatePresence>
            )}
          </section>

          {/* ── Right: Stats + Entities + Blast Radius ── */}
          <section className="w-72 hidden xl:flex flex-col gap-4 shrink-0 overflow-y-auto no-scrollbar">

            {/* System Stats */}
            {stats && (
              <div className="space-y-2">
                <h2 className="font-headline font-medium text-sm flex items-center gap-2">
                  <TrendingUp size={14} className="text-primary" /> System Stats
                </h2>
                <div className="grid grid-cols-2 gap-2">
                  <StatCard label="Total Alerts" value={String(stats.total_alerts_processed)} />
                  <StatCard label="Honeypots 🍯" value={String(stats.honeypots_triggered)} danger />
                  <StatCard label="False Positive" value={`${(stats.false_positive_rate * 100).toFixed(1)}%`} />
                  <StatCard label="Avg Time" value={`${stats.average_processing_time_ms.toFixed(0)}ms`} />
                </div>

                {/* Severity Bars */}
                <div className="bg-surface-low border border-outline-variant/10 rounded-xl p-3 space-y-2">
                  <p className="text-[0.6rem] text-outline uppercase font-bold tracking-widest">Severity Distribution</p>
                  {(['CRITICAL','HIGH','MEDIUM','LOW','BENIGN'] as const).map(sev => {
                    const count = stats.severity_distribution[sev] || 0;
                    const pct = totalAlerts > 0 ? (count / totalAlerts) * 100 : 0;
                    const colors = {
                      CRITICAL: 'bg-red-500',
                      HIGH:     'bg-orange-400',
                      MEDIUM:   'bg-yellow-400',
                      LOW:      'bg-blue-400',
                      BENIGN:   'bg-green-500',
                    };
                    return (
                      <div key={sev} className="flex items-center gap-2">
                        <span className="text-[0.55rem] font-bold text-outline uppercase w-14 shrink-0">{sev}</span>
                        <div className="flex-1 h-1.5 bg-surface-lowest rounded-full overflow-hidden">
                          <div
                            className={cn("h-full rounded-full transition-all duration-700", colors[sev])}
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                        <span className="text-[0.6rem] font-mono font-bold text-outline w-5 text-right">{count}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Related Entities */}
            {selectedAlert && (
              <div className="space-y-2">
                <h2 className="font-headline font-medium text-sm">Related Entities</h2>
                <div className="bg-surface-low border border-outline-variant/10 rounded-xl p-3 space-y-2 relative overflow-hidden">
                  <div className="absolute inset-0 opacity-5 pointer-events-none">
                    <div className="w-full h-full" style={{ backgroundImage: 'radial-gradient(circle, #00E676 1px, transparent 1px)', backgroundSize: '20px 20px' }} />
                  </div>
                  <EntityCard label="Attacker Host" value={selectedAlert.relatedEntities.attackerHost} color="text-primary" />
                  <EntityCard label="Target Account" value={selectedAlert.relatedEntities.targetAccount} />
                  <EntityCard
                    label="Payload Hash"
                    value={selectedAlert.relatedEntities.payloadHash}
                    badge={selectedAlert.honeypot_triggered ? "HONEYPOT ASSET" : undefined}
                  />
                  <EntityCard label="Event Type" value={selectedAlert.event_type || 'N/A'} />
                </div>
              </div>
            )}

            {/* Blast Radius */}
            {selectedAlert && (
              <div className="flex-1 flex flex-col gap-2">
                <h2 className="font-headline font-medium text-sm flex items-center gap-2">
                  <Share2 size={14} className="text-primary" /> Blast Radius Graph
                </h2>
                <div className="flex-1 bg-surface-low border border-outline-variant/10 rounded-xl p-3 min-h-[160px] relative overflow-hidden">
                  {/* Visual blast radius display */}
                  <div className="flex flex-col items-center justify-center h-full gap-2">
                    <div
                      className="w-20 h-20 rounded-full border-2 flex items-center justify-center relative"
                      style={{
                        borderColor: selectedAlert.blast_radius > 1.0 ? '#ef4444' :
                                     selectedAlert.blast_radius > 0.5 ? '#fb923c' : '#00E676',
                        boxShadow: `0 0 ${Math.min(selectedAlert.blast_radius * 30, 40)}px ${
                          selectedAlert.blast_radius > 1.0 ? 'rgba(239,68,68,0.3)' :
                          selectedAlert.blast_radius > 0.5 ? 'rgba(251,146,60,0.3)' : 'rgba(0,230,118,0.2)'
                        }`,
                      }}
                    >
                      <div className="text-center">
                        <div className="text-lg font-mono font-bold">{selectedAlert.blast_radius.toFixed(2)}</div>
                        <div className="text-[0.5rem] text-outline uppercase">Blast Score</div>
                      </div>
                    </div>
                    <p className="text-[0.6rem] text-outline text-center">
                      Source Node: <span className="text-white font-mono">{selectedAlert.source_ip}</span>
                    </p>
                    <p className="text-[0.55rem] text-outline/60 text-center">
                      {selectedAlert.blast_radius > 1.0 ? '🔴 Critical blast — multiple assets at risk' :
                       selectedAlert.blast_radius > 0.5 ? '🟠 High impact' :
                       selectedAlert.blast_radius > 0    ? '🟢 Limited spread' :
                       'No blast radius data'}
                    </p>
                  </div>
                  <button className="absolute bottom-2 right-2 px-2 py-1 bg-background/80 backdrop-blur text-[0.55rem] font-bold rounded border border-outline-variant/30 uppercase tracking-widest hover:bg-primary hover:text-background transition-colors flex items-center gap-1">
                    <Maximize2 size={10} /> Expand
                  </button>
                </div>
              </div>
            )}

            {/* Vault Snapshots */}
            {vaultSnapshots.length > 0 && (
              <div className="space-y-2">
                <h2 className="font-headline font-medium text-sm flex items-center gap-2">
                  <Lock size={14} className="text-primary" /> Forensic Vault
                </h2>
                <div className="bg-surface-low border border-outline-variant/10 rounded-xl p-3 space-y-1.5 max-h-48 overflow-y-auto no-scrollbar">
                  {vaultSnapshots.slice(0, 10).map(snap => (
                    <div key={snap.snapshot_id} className="flex items-center gap-2 py-1 border-b border-outline-variant/10 last:border-0">
                      <div className={cn("w-2 h-2 rounded-full shrink-0", snap.verified ? "bg-green-500" : "bg-red-500")} />
                      <span className="text-[0.55rem] font-mono text-outline flex-1 truncate">{snap.snapshot_id}</span>
                      <span className={cn("text-[0.5rem] font-bold uppercase", snap.verified ? "text-green-400" : "text-red-400")}>
                        {snap.verified ? '✓ OK' : '✗ ERR'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </section>
        </div>

        {/* Mobile Bottom Nav */}
        <nav className="md:hidden h-16 bg-surface-lowest border-t border-outline-variant/10 flex items-center justify-around px-4 shrink-0">
          <MobileNavItem icon={<LayoutDashboard size={20} />} active={mobileView === 'list'} onClick={() => setMobileView('list')} />
          <MobileNavItem icon={<Bell size={20} />} />
          <MobileNavItem icon={<ShieldAlert size={20} />} active={mobileView === 'detail'} onClick={() => setMobileView('detail')} />
          <MobileNavItem icon={<Wand2 size={20} />} />
          <MobileNavItem icon={<Activity size={20} />} />
        </nav>

        {/* FAB */}
        <button
          onClick={() => {
            setFormData(f => ({
              ...f,
              raw_log: 'db_credentials_prod.conf accessed from internal host',
              source_ip: '192.168.1.35',
              dest_ip: '10.0.0.5',
              port: '3389',
              event_type: 'FILE_READ',
              accessed_path: '/etc/db_credentials_prod.conf',
            }));
            document.querySelector('textarea')?.focus();
          }}
          className="absolute bottom-20 md:bottom-6 right-4 md:right-6 w-12 h-12 md:w-14 md:h-14 bg-primary rounded-full shadow-2xl shadow-primary/20 flex items-center justify-center text-background hover:scale-110 active:scale-95 transition-transform z-50"
          title="Load demo honeypot payload"
        >
          <Plus size={24} strokeWidth={3} />
        </button>
      </main>
    </div>
  );
}

// ── Sub-components ─────────────────────────────────────

function SidebarItem({ icon, label, active = false, badge }: {
  icon: React.ReactNode; label: string; active?: boolean; badge?: number;
}) {
  return (
    <div className={cn(
      "flex items-center px-6 py-4 cursor-pointer transition-all duration-300 group/nav",
      active ? "bg-surface-low text-primary border-l-4 border-primary" : "text-outline hover:text-white hover:bg-surface-low"
    )}>
      <div className={cn("shrink-0 relative", active && "text-primary")}>
        {icon}
        {badge !== undefined && badge > 0 && (
          <span className="absolute -top-1 -right-1 w-4 h-4 bg-primary text-background text-[0.5rem] font-bold rounded-full flex items-center justify-center">
            {badge > 9 ? '9+' : badge}
          </span>
        )}
      </div>
      <span className="ml-6 opacity-0 group-hover:opacity-100 font-bold text-[0.6875rem] uppercase tracking-[0.05em] whitespace-nowrap transition-opacity duration-300">
        {label}
      </span>
    </div>
  );
}

function MobileNavItem({ icon, active = false, onClick }: {
  icon: React.ReactNode; active?: boolean; onClick?: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={cn("p-2 rounded-lg transition-all", active ? "text-primary bg-primary/10" : "text-outline")}
    >
      {icon}
    </button>
  );
}

function StatCard({ label, value, danger = false }: { label: string; value: string; danger?: boolean }) {
  return (
    <div className={cn(
      "p-2.5 bg-surface-lowest rounded-lg border",
      danger ? "border-red-500/20" : "border-outline-variant/10"
    )}>
      <p className="text-[0.55rem] text-outline uppercase font-bold mb-0.5">{label}</p>
      <p className={cn("text-lg font-mono font-bold", danger ? "text-red-400" : "text-white")}>{value}</p>
    </div>
  );
}

function StatChip({ label, value, danger = false }: { label: string; value: number | string; danger?: boolean }) {
  return (
    <div className={cn(
      "flex flex-col items-center px-3 py-1 rounded-lg border text-center",
      danger ? "border-red-500/20 bg-red-500/5" : "border-outline-variant/10 bg-surface-low"
    )}>
      <span className="text-[0.5rem] text-outline uppercase tracking-wider">{label}</span>
      <span className={cn("text-sm font-mono font-bold", danger ? "text-red-400" : "text-white")}>{value}</span>
    </div>
  );
}

function EntityCard({ label, value, color = "text-white", badge }: {
  label: string; value: string; color?: string; badge?: string;
}) {
  return (
    <div className="p-2.5 bg-surface-lowest border border-outline-variant/10 rounded relative z-10">
      <div className="flex justify-between items-start mb-0.5">
        <p className="text-[0.55rem] text-outline uppercase font-bold">{label}</p>
        {badge && (
          <span className="text-[0.5rem] bg-red-500/20 text-red-400 px-1 rounded border border-red-500/20 font-bold">
            {badge}
          </span>
        )}
      </div>
      <p className={cn("text-xs font-mono truncate", color)}>{value}</p>
    </div>
  );
}

function getStepIcon(icon: string, status: string, size: number = 18) {
  const color = status === 'completed' ? "text-primary" : status === 'active' ? "text-orange-400" : "text-outline";
  switch (icon) {
    case 'Target':      return <Target className={color} size={size} />;
    case 'Mask':        return <Info className={color} size={size} />;
    case 'Search':      return <Search className={color} size={size} />;
    case 'ShieldAlert': return <ShieldAlert className={color} size={size} />;
    case 'Save':        return <Save className={color} size={size} />;
    default:            return <CheckCircle2 className={color} size={size} />;
  }
}
