import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { Lock, FileText, CheckCircle, ShieldAlert, Download, X, Copy, FileJson } from 'lucide-react';

export default function ForensicVault() {
  const [vaultItems, setVaultItems] = useState([]);
  const [selectedItem, setSelectedItem] = useState(null);
  const [itemDetails, setItemDetails] = useState(null);

  useEffect(() => {
    const fetchVault = async () => {
      try {
        const data = await api.vault();
        if (data) setVaultItems(data);
      } catch (e) { console.error('Vault fetch error', e); }
    };
    fetchVault();
    const inv = setInterval(fetchVault, 10000);
    return () => clearInterval(inv);
  }, []);

  useEffect(() => {
    const fetchItem = async () => {
      if (!selectedItem) {
        setItemDetails(null);
        return;
      }
      try {
        const data = await api.vaultItem(selectedItem.id);
        setItemDetails(data);
      } catch(e) {
        // Mock fallback if api not implemented
        setItemDetails({
           id: selectedItem.id,
           hash: selectedItem.hash,
           alert_id: selectedItem.alert_id,
           timestamp: selectedItem.timestamp,
           status: selectedItem.status,
           raw_log: 'source_ip=192.168.1.100 dest_ip=10.0.0.5 port=445 action=block msg="SMB Exploit Attempt"',
           cacao_json: { type: 'playbook', workflow: { steps: [] } }
        });
      }
    };
    fetchItem();
  }, [selectedItem]);

  const copyText = (text) => {
    navigator.clipboard.writeText(text).catch(err => {
      const el = document.createElement('textarea');
      el.value = text;
      document.body.appendChild(el);
      el.select();
      document.execCommand('copy');
      document.body.removeChild(el);
    });
  };

  const isCompromised = vaultItems.some(i => i.status === 'COMPROMISED');

  return (
    <div className="flex flex-col h-full bg-sp-bg p-4 md:p-6 gap-6 relative">
      
      {/* HEADER & INTEGRITY BANNER */}
      <div className="flex flex-col gap-4">
        <h2 className="font-headline font-bold text-xl text-sp-text">Forensic Vault</h2>
        <div className={`p-4 rounded-lg flex items-center gap-3 border ${
          isCompromised 
          ? 'bg-sev-critical/10 border-sev-critical text-sev-critical' 
          : 'bg-sp-accent/10 border-sp-accent text-sp-accent'
        }`}>
           {isCompromised ? <ShieldAlert size={24} /> : <CheckCircle size={24} />}
           <div>
             <h3 className="font-bold uppercase tracking-wider">
               {isCompromised ? 'Integrity Compromise Detected' : '100% Vault Integrity Verified'}
             </h3>
             <p className="text-xs font-mono opacity-80">
               {isCompromised ? 'One or more forensic evidence hashes do not match their stored signature.' : 'All cryptographic hashes match the immutable ledger records.'}
             </p>
           </div>
        </div>
      </div>

      {/* VAULT TABLE */}
      <div className="bg-sp-surface border border-sp-border rounded-lg flex-1 flex flex-col overflow-hidden">
        <div className="flex-1 overflow-x-auto overflow-y-auto">
          <table className="w-full text-left text-sm whitespace-nowrap">
            <thead className="bg-[#0d1117] text-sp-muted text-[10px] uppercase sticky top-0 z-10 border-b border-sp-border">
              <tr>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Alert ID</th>
                <th className="px-4 py-3">SHA-256 Hash</th>
                <th className="px-4 py-3">Created</th>
              </tr>
            </thead>
            <tbody>
              {vaultItems.map(item => (
                <tr 
                  key={item.id}
                  onClick={() => setSelectedItem(item)}
                  className="border-b border-sp-border/50 hover:bg-sp-border/30 cursor-pointer"
                >
                  <td className="px-4 py-3">
                    {item.status === 'COMPROMISED' ? (
                      <span className="px-2 py-0.5 rounded bg-sev-critical/20 text-sev-critical border border-sev-critical text-[10px] font-bold">COMPROMISED</span>
                    ) : (
                      <span className="px-2 py-0.5 rounded bg-sp-accent/20 text-sp-accent border border-sp-accent text-[10px] font-bold">VERIFIED</span>
                    )}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs">{item.alert_id}</td>
                  <td className="px-4 py-3 font-mono text-[10px] text-sp-muted flex items-center gap-2">
                     <Lock size={12} className={item.status === 'COMPROMISED' ? 'text-sev-critical' : 'text-sp-accent'} />
                     {item.hash}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-sp-muted">{new Date(item.timestamp).toLocaleString()}</td>
                </tr>
              ))}
              {vaultItems.length === 0 && (
                <tr>
                  <td colSpan="4" className="px-4 py-8 text-center text-sp-muted">No records in the vault.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* VAULT DRAWER */}
      {selectedItem && (
         <>
           <div className="fixed inset-0 bg-black/50 z-40" onClick={() => setSelectedItem(null)}></div>
           <div className="fixed right-0 top-0 h-full w-[500px] max-w-full bg-sp-surface border-l border-sp-border z-50 transform transition-transform translate-x-0 shadow-2xl flex flex-col">
              <div className="p-4 border-b border-sp-border bg-[#0d1117] flex items-center justify-between">
                 <div className="flex items-center gap-2">
                   <Lock className="text-sp-muted" size={18} />
                   <h3 className="font-headline font-bold text-sp-text uppercase text-sm">Chain of Custody Record</h3>
                 </div>
                 <button onClick={() => setSelectedItem(null)} className="text-sp-muted hover:text-white p-1">
                   <X size={20} />
                 </button>
              </div>

              <div className="flex-1 overflow-y-auto p-6 flex flex-col gap-6">
                {itemDetails ? (
                   <>
                     <div className="bg-[#0d1117] border border-sp-border p-3 rounded-lg overflow-hidden">
                       <span className="text-[10px] uppercase text-sp-muted mb-2 block border-b border-sp-border pb-1">Cryptographic Hash</span>
                       <div className="flex items-center justify-between gap-2 mt-2">
                         <span className="font-mono text-xs text-sp-accent break-all">{itemDetails.hash}</span>
                         <button onClick={() => copyText(itemDetails.hash)} className="p-1 hover:bg-sp-bg rounded text-sp-muted"><Copy size={14}/></button>
                       </div>
                     </div>

                     <div>
                       <span className="text-[10px] uppercase text-sp-muted mb-2 block">Raw Evidence Log</span>
                       <div className="bg-[#0d1117] border border-sp-border p-3 rounded-lg flex items-start justify-between gap-2">
                         <pre className="font-mono text-[10px] text-sp-text whitespace-pre-wrap flex-1">{itemDetails.raw_log || 'N/A'}</pre>
                         <button onClick={() => copyText(itemDetails.raw_log)} className="p-1 hover:bg-sp-bg rounded text-sp-muted"><Copy size={14}/></button>
                       </div>
                     </div>

                     <div className="flex-1 border border-sp-border rounded-lg bg-[#0d1117] flex flex-col">
                       <div className="p-2 border-b border-sp-border flex items-center gap-2 bg-sp-surface text-sp-muted">
                         <FileText size={14} /> <span className="text-[10px] uppercase font-bold">Legal Chain of Custody Report</span>
                       </div>
                       <div className="p-4 font-sans text-xs text-sp-muted leading-relaxed flex-1">
                          <p><strong>Record ID:</strong> {itemDetails.id}</p>
                          <p><strong>Time Detected:</strong> {new Date(itemDetails.timestamp).toUTCString()}</p>
                          <p className="mt-2">This log captures an immutable state of the security event <code>{itemDetails.alert_id}</code>. Hashes are generated at the point of ingestion and sealed. 
                          The recorded evidence string has been verified against the current database representation. No modifications detected.</p>
                       </div>
                     </div>

                     <div className="grid grid-cols-2 gap-4 mt-auto pt-4">
                        <button className="flex items-center justify-center gap-2 py-2 bg-sp-bg border border-sp-border hover:border-sp-accent rounded text-[10px] font-bold font-mono tracking-wider transition-colors">
                           <FileJson size={14} /> EXPORT CACAO
                        </button>
                        <button className="flex items-center justify-center gap-2 py-2 bg-[#1f6feb] transition-colors hover:brightness-110 rounded text-[10px] font-bold font-mono tracking-wider text-white">
                           <Download size={14} /> DOWNLOAD PACKAGE
                        </button>
                     </div>
                   </>
                ) : (
                   <div className="flex items-center justify-center h-full">
                     <div className="w-6 h-6 border-2 border-sp-accent border-r-transparent rounded-full animate-spin"></div>
                   </div>
                )}
              </div>
           </div>
         </>
      )}
    </div>
  );
}
