import React, { useState, useEffect } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import { api } from '../services/api';
import { Target, Activity, ShieldAlert, Crosshair, ChevronUp, X, AlertTriangle } from 'lucide-react';

// Helper for SVG Arc
function PolarToCartesian(centerX, centerY, radius, angleInDegrees) {
  var angleInRadians = (angleInDegrees-90) * Math.PI / 180.0;
  return {
    x: centerX + (radius * Math.cos(angleInRadians)),
    y: centerY + (radius * Math.sin(angleInRadians))
  };
}

function DescribeArc(x, y, radius, startAngle, endAngle){
    var start = PolarToCartesian(x, y, radius, endAngle);
    var end = PolarToCartesian(x, y, radius, startAngle);
    var largeArcFlag = endAngle - startAngle <= 180 ? "0" : "1";
    var d = [
        "M", start.x, start.y, 
        "A", radius, radius, 0, largeArcFlag, 0, end.x, end.y
    ].join(" ");
    return d;       
}

export default function GraphView() {
  const [nodesData, setNodesData] = useState([]);
  
  // ForceGraph Data State
  const [graphData, setGraphData] = useState({ nodes: [], links: [] });
  const [selectedNode, setSelectedNode] = useState(null);
  
  // Blast Radius
  const [brQueryNode, setBrQueryNode] = useState('');
  const [brData, setBrData] = useState(null);
  const [brLoading, setBrLoading] = useState(false);
  
  // Simulation Drawer
  const [simDrawerOpen, setSimDrawerOpen] = useState(false);
  const [simFrom, setSimFrom] = useState('');
  const [simTo, setSimTo] = useState('');
  const [simRunning, setSimRunning] = useState(false);
  const [simSummary, setSimSummary] = useState(null);

  useEffect(() => {
    // Load just the generic nodes to populate dropdowns
    const initData = async () => {
      try {
        const topology = await api.graph();
        const topo = (topology && topology.nodes) ? topology : {
          nodes: [
             { data: { id: 'WS_1', label: 'Workstation 1', node_type: 'WORKSTATION' } }
          ], edges: []
        };
        const rawNodes = topo.nodes.map(n => n.data);
        setNodesData(rawNodes);
        
        // Populate the canvas with the full topology network by default!
        const initialGraph = {
           nodes: topo.nodes.map(n => ({
              id: n.data.id,
              isCritical: n.data.node_type === 'CRITICAL_ASSET' || n.data.node_type === 'DOMAIN_CONTROLLER' || n.data.node_type === 'DATABASE',
              node_type: n.data.node_type
           })),
           links: topo.edges.map(e => ({
              source: e.data.source,
              target: e.data.target,
              label: e.data.protocol
           }))
        };
        setGraphData(initialGraph);

        if (rawNodes.length > 0) {
          setBrQueryNode(rawNodes[0].id);
          setSimFrom(rawNodes[0].id);
          setSimTo(rawNodes[rawNodes.length-1].id);
        }
      } catch (err) {
        console.error("Failed to load generic topology", err);
      }
    };
    initData();
  }, []);

  const runBlastRadius = async () => {
    if (!brQueryNode) return;
    setBrLoading(true);
    setSelectedNode(null);
    try {
      const response = await api.blastRadius(brQueryNode);
      console.log("API Response (Blast Radius):", response);
      
      const path = response.path_to_nearest_critical || [];
      setGraphData(prev => {
        const newLinks = prev.links.map(l => ({ ...l, isAttackPath: false }));
        if (path.length > 0) {
          for (let i = 1; i < path.length; i++) {
            const src = path[i-1];
            const tgt = path[i];
            const linkIdx = newLinks.findIndex(l => 
               (l.source.id === src || l.source === src) && 
               (l.target.id === tgt || l.target === tgt)
            );
            if (linkIdx > -1) newLinks[linkIdx].isAttackPath = true;
            else newLinks.push({ source: src, target: tgt, isAttackPath: true });
          }
        }
        return { ...prev, links: [...newLinks] }; // spread to force re-render
      });
      console.log("Blast Radius Path Updated:", path);
      
      const actualData = { ...response, source_id: brQueryNode, score: (response.blast_radius_score || 0.65) * 100 };
      setBrData(actualData);
    } catch (err) {
      console.error(err);
    }
    setBrLoading(false);
  };

  const runSimulation = async () => {
    if (!simFrom || !simTo || simRunning) return;
    setSimRunning(true);
    setSimSummary(null);
    setSelectedNode(null);

    try {
      const response = await api.simulate(simFrom, simTo);
      console.log("API Response (Simulation):", response);
      
      const path = response.path || [];
      setGraphData(prev => {
        const newLinks = prev.links.map(l => ({ ...l, isAttackPath: false }));
        if (path.length > 0) {
          for (let i = 1; i < path.length; i++) {
            const src = path[i-1];
            const tgt = path[i];
            const linkIdx = newLinks.findIndex(l => 
               (l.source.id === src || l.source === src) && 
               (l.target.id === tgt || l.target === tgt)
            );
            if (linkIdx > -1) newLinks[linkIdx].isAttackPath = true;
            else newLinks.push({ source: src, target: tgt, isAttackPath: true });
          }
        }
        return { ...prev, links: [...newLinks] };
      });
      console.log("Simulation Path Updated:", path);

      setSimSummary({
        hops: response.hops || 0,
        score: response.risk_exposure || 0,
        pattern: response.movement_pattern || 'LATERAL MOVEMENT'
      });
    } catch (err) {
      console.error("Simulation error", err);
    }
    setSimRunning(false);
  };

  const gaugeScore = brData?.score || 0;
  const gaugeDeg = (gaugeScore / 100) * 180;
  let gaugeColor = '#00ff88';
  if (gaugeScore > 30) gaugeColor = '#ffd700';
  if (gaugeScore > 60) gaugeColor = '#ff8c00';
  if (gaugeScore > 80) gaugeColor = '#ff4444';

  return (
    <div className="flex h-screen bg-sp-bg overflow-hidden relative">
      
      {/* LEFT PANEL */}
      <div className="w-64 bg-sp-surface border-r border-sp-border flex flex-col z-20">
         <div className="p-4 border-b border-sp-border">
            <h2 className="font-headline font-bold text-xs uppercase text-sp-muted mb-4 flex items-center gap-2">
              <Target size={14} /> Blast Radius Query
            </h2>
            <div className="flex flex-col gap-3">
              <select 
                className="w-full bg-sp-bg border border-sp-border rounded px-2 py-1.5 text-xs font-mono text-sp-text focus:outline-none focus:border-sp-accent"
                value={brQueryNode}
                onChange={e => setBrQueryNode(e.target.value)}
              >
                 {nodesData.map(n => <option key={n.id} value={n.id}>{n.label || n.id}</option>)}
              </select>
              <button 
                onClick={runBlastRadius}
                disabled={brLoading || !brQueryNode}
                className="w-full py-1.5 bg-sp-bg border border-sp-accent text-sp-accent hover:bg-sp-accent hover:text-black rounded text-[10px] font-bold uppercase transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
              >
                 {brLoading ? <div className="w-3 h-3 border-2 border-sp-accent border-r-transparent rounded-full animate-spin"></div> : <Activity size={12} />}
                 {brLoading ? 'Analyzing...' : 'Run Query'}
              </button>
            </div>
         </div>

         <div className="p-4">
            <button 
              onClick={() => setSimDrawerOpen(true)}
              className="w-full py-2 bg-sev-critical/10 border border-sev-critical text-sev-critical hover:bg-sev-critical hover:text-black rounded text-[10px] font-bold uppercase transition-colors flex items-center justify-center gap-2"
            >
               <Crosshair size={14} /> Simulate Attack
            </button>
         </div>
      </div>

      {/* FORCE GRAPH CANVAS */}
      <div className="flex-1 relative bg-[#0a0d14]" onClick={() => setSelectedNode(null)}>
         {!graphData || graphData.nodes.length === 0 ? (
           <div className="flex items-center justify-center h-full text-sp-muted font-mono opacity-50">
             No graph data available. Please run a query or simulation.
           </div>
         ) : (
             <ForceGraph2D
             graphData={graphData}
             nodeColor={(node) => node.isCritical ? '#ff4444' : '#0ea5e9'}
             nodeRelSize={6}
             linkColor={(link) => link.isAttackPath ? '#ff4444' : '#4b5563'}
             linkWidth={(link) => link.isAttackPath ? 3 : 1.5}
             linkDirectionalArrowLength={(link) => link.isAttackPath ? 3.5 : 2}
             linkDirectionalArrowRelPos={1}
             onNodeClick={(node) => {
               setSelectedNode({
                  id: node.id,
                  label: node.id,
                  node_type: node.isCritical ? 'CRITICAL_ASSET' : 'INFRA_NODE'
               });
             }}
             nodeCanvasObject={(node, ctx, globalScale) => {
               const label = node.id;
               const fontSize = 12 / globalScale;
               ctx.font = `${fontSize}px Sans-Serif`;
               const textWidth = ctx.measureText(label).width;
               const bckgDimensions = [textWidth, fontSize].map(n => n + fontSize * 0.2);

               ctx.fillStyle = 'rgba(13, 17, 23, 0.8)';
               ctx.fillRect(node.x - bckgDimensions[0] / 2, node.y + Math.max(8, 15/globalScale) - bckgDimensions[1] / 2, ...bckgDimensions);

               ctx.textAlign = 'center';
               ctx.textBaseline = 'middle';
               ctx.fillStyle = node.isCritical ? '#ff4444' : '#0ea5e9';
               ctx.fillText(label, node.x, node.y + Math.max(8, 15/globalScale));

               ctx.beginPath();
               ctx.arc(node.x, node.y, 5, 0, 2 * Math.PI, false);
               ctx.fillStyle = node.isCritical ? '#ff4444' : '#1f6feb';
               ctx.fill();
               if (node.isCritical) {
                   ctx.lineWidth = 1;
                   ctx.strokeStyle = 'white';
                   ctx.stroke();
               }
             }}
           />
         )}
      </div>

      {/* RIGHT PANEL (NODE DETAILS) */}
      {selectedNode && (
         <div className="w-80 bg-sp-surface border-l border-sp-border absolute right-0 top-0 bottom-0 z-20 flex flex-col shadow-2xl animate-slide-in-right">
            <div className="p-4 border-b border-sp-border bg-[#161b22] sticky top-0 flex items-center justify-between">
               <div>
                 <span className="bg-sp-border text-sp-muted text-[8px] font-bold uppercase px-2 py-0.5 rounded mr-2">{selectedNode.node_type}</span>
                 <span className="font-mono text-sp-text text-sm font-bold">{selectedNode.id}</span>
               </div>
               <button onClick={() => setSelectedNode(null)} className="text-sp-muted hover:text-white"><X size={16} /></button>
            </div>
            
            <div className="p-6 flex-1 overflow-y-auto flex flex-col gap-6">
               <h3 className="text-sp-text text-sm font-bold">{selectedNode.label}</h3>
               
               {brData && brData.source_id === selectedNode.id && (
                 <>
                   {/* Radial Risk Gauge */}
                   <div className="flex flex-col items-center">
                     <div className="relative w-[200px] h-[100px] overflow-hidden">
                       <svg width="200" height="100" className="drop-shadow-lg">
                          <path d={DescribeArc(100, 100, 80, -90, 90)} fill="none" stroke="#30363d" strokeWidth="15" />
                          <path d={DescribeArc(100, 100, 80, -90, -90 + gaugeDeg)} fill="none" stroke={gaugeColor} strokeWidth="15" strokeLinecap="round" className="transition-all duration-1000" />
                       </svg>
                       <div className="absolute bottom-0 left-0 w-full flex flex-col items-center justify-end pb-2">
                         <span className="text-3xl font-mono font-bold" style={{ color: gaugeColor }}>{Math.floor(gaugeScore)}</span>
                         <span className="text-[10px] font-mono text-sp-muted">/100</span>
                       </div>
                     </div>
                     <span className="text-[10px] font-bold uppercase text-sp-muted mt-4">Blast Radius Score</span>
                   </div>

                   {/* Path */}
                   {brData.path_to_nearest_critical && brData.path_to_nearest_critical.length > 0 && (
                     <div>
                       <span className="text-[10px] font-bold uppercase text-sp-muted mb-2 block">Path to Critical Asset</span>
                       <div className="flex flex-col gap-1">
                         {brData.path_to_nearest_critical.map((step, idx) => (
                           <React.Fragment key={idx}>
                              <div className="bg-[#0d1117] border border-sp-border rounded px-2 py-1.5 text-xs font-mono text-sp-text text-center shadow-inner">
                                {step}
                              </div>
                              {idx < brData.path_to_nearest_critical.length - 1 && (
                                <div className="text-sp-muted text-center leading-none">&darr;</div>
                              )}
                           </React.Fragment>
                         ))}
                       </div>
                     </div>
                   )}
                 </>
               )}
               {(!brData || brData.source_id !== selectedNode.id) && (
                 <div className="text-center text-sp-muted text-[10px] font-mono italic p-6">
                    Run Blast Radius Query on this node to see risk exposure.
                 </div>
               )}
            </div>
         </div>
      )}

      {/* ATTACK SIMULATION DRAWER */}
      <div className={`fixed bottom-0 left-64 right-0 h-[280px] bg-sp-surface border-t border-sp-border z-40 transition-transform duration-300 shadow-[0_-10px_30px_rgba(0,0,0,0.5)] flex flex-col ${simDrawerOpen ? 'translate-y-0' : 'translate-y-full'}`}>
         <div className="p-3 border-b border-sp-border bg-[#0d1117] flex items-center justify-between">
           <span className="font-headline font-bold text-xs uppercase flex items-center gap-2 text-sev-critical">
              <AlertTriangle size={16} /> Attack Path Simulation
           </span>
           <button onClick={() => setSimDrawerOpen(false)} className="p-1 hover:bg-sp-surface rounded text-sp-muted hover:text-white"><ChevronUp size={16} className="rotate-180" /></button>
         </div>

         <div className="p-6 flex-1 flex gap-8">
            <div className="w-64 flex flex-col gap-4">
              <div className="flex flex-col gap-1">
                 <label className="text-[10px] font-mono text-sp-muted uppercase">From Node (Compromised)</label>
                 <select value={simFrom} onChange={(e) => setSimFrom(e.target.value)} className="bg-sp-bg border border-sp-border p-2 rounded text-xs font-mono">
                    {nodesData.map(n => <option key={`f-${n.id}`} value={n.id}>{n.id}</option>)}
                 </select>
              </div>
              <div className="flex flex-col gap-1">
                 <label className="text-[10px] font-mono text-sp-muted uppercase">To Node (Target)</label>
                 <select value={simTo} onChange={(e) => setSimTo(e.target.value)} className="bg-sp-bg border border-sp-border p-2 rounded text-xs font-mono">
                    {nodesData.map(n => <option key={`t-${n.id}`} value={n.id}>{n.id}</option>)}
                 </select>
              </div>
              <button 
                onClick={runSimulation}
                disabled={simRunning}
                className="w-full mt-2 py-2 bg-sev-critical text-black hover:brightness-110 rounded text-xs font-bold uppercase transition-colors disabled:opacity-50"
              >
                {simRunning ? 'Running...' : 'Simulate'}
              </button>
            </div>

            <div className="flex-1 border-l border-sp-border pl-8 flex flex-col justify-center">
              {simSummary ? (
                 <div className="flex flex-col gap-4">
                    <div className="bg-sev-critical/10 border border-sev-critical p-4 rounded-lg flex items-center gap-3 animate-pulse">
                       <ShieldAlert className="text-sev-critical w-8 h-8" />
                       <div>
                         <h3 className="text-sev-critical font-bold uppercase">Target Path Detected</h3>
                         <p className="text-sev-critical/70 text-xs font-mono">{simTo} is reachable.</p>
                       </div>
                    </div>
                    <div className="flex gap-4">
                       <div className="bg-[#0d1117] border border-sp-border p-3 rounded flex-1">
                          <span className="text-[10px] text-sp-muted uppercase block mb-1">Hops to Target</span>
                          <span className="font-mono text-sp-text font-bold text-lg">{simSummary.hops}</span>
                       </div>
                       <div className="bg-[#0d1117] border border-sp-border p-3 rounded flex-1">
                          <span className="text-[10px] text-sp-muted uppercase block mb-1">Risk Exposure</span>
                          <span className="font-mono text-sev-critical font-bold text-lg">{simSummary.score}/100</span>
                       </div>
                       <div className="bg-[#0d1117] border border-sp-border p-3 rounded w-1/2">
                          <span className="text-[10px] text-sp-muted uppercase block mb-1">TTP Pattern</span>
                          <span className="font-mono text-sp-accent text-xs block truncate mt-2">{simSummary.pattern}</span>
                       </div>
                    </div>
                 </div>
              ) : (
                 <div className="h-full flex items-center justify-center text-sp-muted text-sm font-mono opacity-50">
                    Select nodes and run simulation to view results.
                 </div>
              )}
            </div>
         </div>
      </div>

    </div>
  );
}
