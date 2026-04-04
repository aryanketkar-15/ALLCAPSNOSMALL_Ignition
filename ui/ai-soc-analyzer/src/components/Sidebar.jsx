import React, { useState, useEffect } from 'react';
import { NavLink } from 'react-router-dom';
import { 
  LayoutDashboard, 
  Bell, 
  Target, 
  Share2, 
  Lock,
  WifiOff,
  Menu,
  ChevronLeft
} from 'lucide-react';

export default function Sidebar() {
  const [isDemo, setIsDemo] = useState(false);
  const [isOpen, setIsOpen] = useState(false); // Collapsed by default

  useEffect(() => {
    const handleMock = () => setIsDemo(true);
    const handleLive = () => setIsDemo(false);
    window.addEventListener('toggleMockMode', handleMock);
    window.addEventListener('toggleLiveMode', handleLive);
    return () => {
      window.removeEventListener('toggleMockMode', handleMock);
      window.removeEventListener('toggleLiveMode', handleLive);
    };
  }, []);

  const getNavClass = ({ isActive }) =>
    `flex items-center gap-4 px-4 py-3 text-sm font-medium transition-colors whitespace-nowrap overflow-hidden ${
      isActive
        ? 'text-sp-accent border-l-2 border-sp-accent bg-sp-accent/5'
        : 'text-sp-muted hover:text-sp-text hover:bg-sp-border/30 border-l-2 border-transparent'
    }`;

  return (
    <aside 
       className={`bg-sp-surface border-r border-sp-border h-screen fixed left-0 top-0 flex flex-col z-50 transition-all duration-300 ${isOpen ? 'w-64 shadow-2xl' : 'w-16'}`}
    >
      <div className={`px-4 py-5 border-b border-sp-border mb-4 flex items-center ${isOpen ? 'justify-between' : 'justify-center'}`}>
        {isOpen && (
           <h1 className="font-headline font-bold text-sp-accent tracking-tighter uppercase text-xl truncate ml-2">
             AI SOC Analyzer
           </h1>
        )}
        <button 
           onClick={() => setIsOpen(!isOpen)} 
           className="text-sp-muted hover:text-white p-1 rounded hover:bg-sp-border/50 shrink-0"
        >
           {isOpen ? <ChevronLeft size={20} /> : <Menu size={20} />}
        </button>
      </div>
      
      {isOpen && isDemo && (
        <div className="mx-4 mb-4 flex items-center gap-1.5 bg-sev-medium/20 border border-sev-medium text-sev-medium px-2 py-2 rounded text-[10px] font-bold uppercase font-mono">
          <WifiOff size={12} className="shrink-0" />
          <span>API Offline</span>
        </div>
      )}

      <nav className="flex-1 flex flex-col gap-1 overflow-hidden">
        <NavLink to="/" className={getNavClass} title="Overview">
          <LayoutDashboard size={20} className="shrink-0 ml-1" />
          {isOpen && <span>Overview</span>}
        </NavLink>
        <NavLink to="/alerts" className={getNavClass} title="Live Alerts">
          <Bell size={20} className="shrink-0 ml-1" />
          {isOpen && <span>Live Alerts</span>}
        </NavLink>
        <NavLink to="/playbooks" className={getNavClass} title="Playbooks">
          <Target size={20} className="shrink-0 ml-1" />
          {isOpen && <span>Playbooks</span>}
        </NavLink>
        <NavLink to="/graph" className={getNavClass} title="Graph View">
          <Share2 size={20} className="shrink-0 ml-1" />
          {isOpen && <span>Graph View</span>}
        </NavLink>
        <NavLink to="/vault" className={getNavClass} title="Forensic Vault">
          <Lock size={20} className="shrink-0 ml-1" />
          {isOpen && <span>Forensic Vault</span>}
        </NavLink>
      </nav>
      
      <div className="p-4 border-t border-sp-border text-center overflow-hidden whitespace-nowrap">
         {isOpen ? (
            <span className="text-[9px] text-sp-muted font-mono uppercase">AI SOC Platform v2.0-rc</span>
         ) : (
            <span className="text-[9px] text-sp-muted font-mono text-center block">V2</span>
         )}
      </div>
    </aside>
  );
}
