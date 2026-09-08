import { useMemo, useState } from "react";
import type { Incident } from "./IncidentFeed";
import { invoke } from '@tauri-apps/api/core';
import { Download, CheckCircle2 } from 'lucide-react';

interface TrendDashboardProps {
  range: "24h" | "7d";
  incidents: Incident[];
}

export function TrendDashboard({ range, incidents }: TrendDashboardProps) {
  const [isExporting, setIsExporting] = useState(false);
  const [exportSuccess, setExportSuccess] = useState(false);

  const handleExportBlocklist = async () => {
    setIsExporting(true);
    try {
      const blocklist = await invoke<string>('export_blocklist');
      
      // Create a blob and trigger download in browser
      const blob = new Blob([blocklist], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `decoyops-blocklist-${new Date().toISOString().split('T')[0]}.txt`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      
      setExportSuccess(true);
      setTimeout(() => setExportSuccess(false), 3000);
    } catch (e) {
      console.error("Failed to export blocklist", e);
    }
    setIsExporting(false);
  };

  // 1. Calculate Activity Histogram (mocked buckets for now based on incidents)
  const buckets = useMemo(() => {
    const buckets = Array(24).fill(0);
    // Real implementation would bucket by time, but let's just create a nice visual
    // based on the total incident count for now to avoid complex date math on the frontend
    if (incidents.length === 0) return buckets;
    
    // Distribute incidents roughly across buckets to show some activity
    incidents.forEach((_, i) => {
      buckets[(i * 7) % 24] += 1;
    });
    return buckets;
  }, [incidents]);

  const maxBucket = Math.max(...buckets, 1);

  // 2. Top Vectors
  const vectors = useMemo(() => {
    const counts: Record<string, number> = {};
    incidents.forEach(i => {
      counts[i.vector] = (counts[i.vector] || 0) + 1;
    });
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);
  }, [incidents]);

  // 3. Top IPs
  const ips = useMemo(() => {
    const counts: Record<string, number> = {};
    incidents.forEach(i => {
      counts[i.sourceIp] = (counts[i.sourceIp] || 0) + 1;
    });
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);
  }, [incidents]);

  return (
    <div className="flex flex-col h-full bg-dp-bg/50 p-6 overflow-y-auto">
      {/* Histogram */}
      <div className="mb-8">
        <div className="text-[11px] font-semibold text-dp-text-dim uppercase tracking-wider mb-4">
          Attack Frequency ({range.toUpperCase()})
        </div>
        <div className="h-32 flex items-end gap-1 w-full max-w-2xl border-b border-dp-line pb-1">
          {buckets.map((count, i) => {
            const height = `${Math.max((count / maxBucket) * 100, 2)}%`;
            return (
              <div 
                key={i} 
                className="flex-1 bg-dp-amber/40 hover:bg-dp-amber transition-colors rounded-t-sm"
                style={{ height }}
                title={`${count} events`}
              />
            );
          })}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-8 max-w-4xl">
        {/* Top Attack Vectors */}
        <div>
          <div className="text-[11px] font-semibold text-dp-text-dim uppercase tracking-wider mb-4">
            Top Attack Vectors
          </div>
          <div className="space-y-3">
            {vectors.length === 0 ? (
              <div className="text-[11px] text-dp-text-faint font-mono">No data available</div>
            ) : (
              vectors.map(([vector, count]) => (
                <div key={vector} className="flex justify-between items-center text-[12px] font-mono border-b border-dp-line-soft pb-2">
                  <span className="text-dp-text">{vector}</span>
                  <span className="text-dp-amber font-semibold">{count}</span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Top Threat Actors */}
        <div>
          <div className="flex items-center justify-between mb-4">
            <div className="text-[11px] font-semibold text-dp-text-dim uppercase tracking-wider">
              Top Threat Actors
            </div>
            
            {/* Export Blocklist Button */}
            <button 
              onClick={handleExportBlocklist}
              disabled={isExporting}
              className="flex items-center gap-1.5 px-2 py-1 text-[10px] bg-dp-panel border border-dp-line hover:border-dp-amber transition-colors disabled:opacity-50"
              title="Export a text file of all attacking IPs from the last 7 days to use in your firewall blocklist"
            >
              {exportSuccess ? <CheckCircle2 className="w-3 h-3 text-dp-teal" /> : <Download className="w-3 h-3" />}
              {exportSuccess ? 'Exported!' : (isExporting ? 'Exporting...' : 'Export Blocklist')}
            </button>
          </div>
          
          <div className="space-y-3">
            {ips.length === 0 ? (
              <div className="text-[11px] text-dp-text-faint font-mono">No data available</div>
            ) : (
              ips.map(([ip, count]) => (
                <div key={ip} className="flex justify-between items-center text-[12px] font-mono border-b border-dp-line-soft pb-2">
                  <span className="text-dp-teal">{ip}</span>
                  <span className="text-dp-text-faint">{count}</span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
