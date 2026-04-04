import React, { Suspense, Component } from 'react';
import { Routes, Route } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Overview from './pages/Overview';
import LiveAlerts from './pages/LiveAlerts';
import Playbooks from './pages/Playbooks';
import GraphView from './pages/GraphView';
import ForensicVault from './pages/ForensicVault';
import { AlertOctagon } from 'lucide-react';

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

class ErrorBoundary extends Component<{ children: React.ReactNode }, ErrorBoundaryState> {
  state: ErrorBoundaryState = {
    hasError: false,
    error: null
  };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center h-full w-full bg-sp-bg text-sp-text p-6">
          <AlertOctagon size={48} className="text-sev-critical mb-4" />
          <h2 className="text-xl font-bold mb-2">Component Crashed</h2>
          <pre className="bg-sp-surface p-4 rounded text-xs text-sev-critical max-w-2xl overflow-auto border border-sev-critical/30">
             {this.state.error?.toString()}
          </pre>
          <button 
             onClick={() => window.location.reload()}
             className="mt-6 px-4 py-2 bg-sp-surface border border-sp-border hover:border-sp-accent rounded font-mono text-sm"
          >
             Reload Application
          </button>
        </div>
      );
    }
    return (this.props as any).children;
  }
}

const LoadingSkeleton = () => (
  <div className="p-6 w-full h-full flex flex-col gap-6 animate-pulse">
    <div className="h-8 bg-sp-surface w-48 rounded"></div>
    <div className="flex gap-4">
       {[1,2,3,4,5].map(i => <div key={i} className="flex-1 h-24 bg-sp-surface rounded"></div>)}
    </div>
    <div className="h-64 bg-sp-surface rounded w-full"></div>
  </div>
);

export default function App() {
  return (
    <div className="flex h-screen overflow-hidden bg-sp-bg">
      <Sidebar />
        <main className="flex-1 ml-16 h-full relative flex flex-col transition-all duration-300 overflow-hidden">
        <ErrorBoundary>
           <Suspense fallback={<LoadingSkeleton />}>
             <Routes>
               <Route path="/" element={<Overview />} />
               <Route path="/alerts" element={<LiveAlerts />} />
               <Route path="/playbooks" element={<Playbooks />} />
               <Route path="/graph" element={<GraphView />} />
               <Route path="/vault" element={<ForensicVault />} />
             </Routes>
           </Suspense>
        </ErrorBoundary>
      </main>
    </div>
  );
}
