import { useState, useMemo } from "react";
import { Terminal, Download, Maximize2, Minimize2, Search } from "lucide-react";
import { SessionReplay } from "../SessionReplay";
import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";
import { writeTextFile } from "@tauri-apps/plugin-fs";

export interface Incident {
  id: number;
  sessionId?: number;
  time: string;
  sourceIp: string;
  vector: string;
  detail: string;
  status: "CAPTURED" | "CONTAINED";
  mitreTtp?: string;
  ttyLogPath?: string;
  geo_lat?: number;
  geo_lon?: number;
}

interface IncidentFeedProps {
  incidents: Incident[];
  isMaximized?: boolean;
  onToggleMaximize?: () => void;
}

export function IncidentFeed({ incidents, isMaximized, onToggleMaximize }: IncidentFeedProps) {
  const [replayPath, setReplayPath] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");

  const filteredIncidents = useMemo(() => {
    if (!searchQuery) return incidents;
    const lowerQuery = searchQuery.toLowerCase();
    return incidents.filter((inc) => 
      inc.sourceIp.toLowerCase().includes(lowerQuery) ||
      inc.vector.toLowerCase().includes(lowerQuery) ||
      inc.detail.toLowerCase().includes(lowerQuery) ||
      (inc.mitreTtp && inc.mitreTtp.toLowerCase().includes(lowerQuery))
    );
  }, [incidents, searchQuery]);

  const handleExport = async (sessionId: number, format: "stix" | "markdown") => {
    try {
      const defaultPath = format === "stix" ? `incident_${sessionId}.stix.json` : `incident_${sessionId}.md`;
      const filters = format === "stix" 
        ? [{ name: "STIX 2.1 JSON", extensions: ["json"] }] 
        : [{ name: "Markdown", extensions: ["md"] }];

      const savePath = await save({
        defaultPath,
        filters,
      });

      if (!savePath) return;

      const reportContent: string = await invoke(
        format === "stix" ? "generate_stix_report" : "generate_markdown_report", 
        { sessionId }
      );
      
      await writeTextFile(savePath, reportContent);
    } catch (e) {
      console.error(`Failed to export ${format}:`, e);
      alert(`Export failed: ${e}`);
    }
  };

  return (
    <div className="flex flex-col min-h-0 h-full relative">
      <div className="flex items-center justify-between px-5 py-3.5 border-b border-dp-line-soft glass-header">
        <div>
          <div className="text-[13px] font-semibold text-dp-text tracking-wide uppercase">Incident Feed</div>
          <div className="text-[11px] text-dp-text-faint mt-0.5">
            {incidents.length > 0 ? `${incidents.length} events, most recent first` : "Waiting for events…"}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button 
            onClick={async () => {
              try {
                const savePath = await save({
                  defaultPath: "decoyops_full_feed_export.csv",
                  filters: [{ name: "CSV Files", extensions: ["csv"] }]
                });
                if (!savePath) return;
                const csvData: string = await invoke("export_all_incidents_csv");
                await writeTextFile(savePath, csvData);
              } catch (err) {
                console.error("Export all failed:", err);
                alert("Failed to export: " + err);
              }
            }}
            className="flex items-center gap-1.5 px-2 py-1 text-[11px] font-mono text-dp-text-dim hover:text-dp-text border border-dp-line hover:border-dp-line-soft rounded transition-colors"
            title="Export Full Incident Database to CSV"
          >
            <Download className="w-3.5 h-3.5" />
            Export All
          </button>
          {onToggleMaximize && (
            <button 
              onClick={onToggleMaximize}
              className="text-dp-text-dim hover:text-dp-text transition-colors p-1"
              title={isMaximized ? "Minimize Feed" : "Maximize Feed"}
            >
              {isMaximized ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
            </button>
          )}
        </div>
      </div>
      
      {/* Search Bar */}
      <div className="px-5 py-2.5 border-b border-dp-line-soft bg-dp-panel-raised/30 shrink-0">
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-dp-text-dim" />
          <input
            type="text"
            placeholder="Filter by IP, Event Type, or MITRE TTP..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-[#0a0a0a] border border-dp-line rounded pl-8 pr-3 py-1.5 text-[11.5px] font-mono text-dp-text placeholder:text-dp-text-faint focus:outline-none focus:border-dp-teal/50 transition-colors"
          />
        </div>
      </div>

      <div className="flex-1 overflow-y-auto">
        {filteredIncidents.length === 0 ? (
          <div className="flex items-center justify-center h-full">
            <div className="text-center space-y-2">
              <div className="font-mono text-[11px] text-dp-text-faint">No incidents recorded</div>
              <div className="font-mono text-[10px] text-dp-text-faint">Deploy a decoy to start capturing attacks</div>
            </div>
          </div>
        ) : (
          filteredIncidents.map((inc) => (
            <div key={inc.id} className="grid grid-cols-[135px_1fr_auto] gap-3 px-5 py-3 border-b border-dp-line-soft items-start hover:bg-dp-teal/5 transition-colors group">
              <div className="font-mono text-[10.5px] text-dp-text-faint pt-0.5 flex items-center">
                <span className="text-dp-text-dim/60 mr-1.5 font-bold">#{inc.id}</span>
                {inc.time}
              </div>
              <div className="min-w-0 overflow-hidden">
                <div className="flex flex-wrap items-center gap-2">
                  <div className="text-[12.5px] font-medium text-dp-text group-hover:text-dp-teal transition-colors truncate">{inc.vector}</div>
                  {inc.mitreTtp && (
                    <span className="font-mono text-[9px] px-1.5 py-0.5 h-fit border border-dp-amber-dim text-dp-amber bg-dp-amber/5 rounded-sm whitespace-nowrap shadow-[0_0_10px_rgba(245,158,11,0.1)] shrink-0">
                      {inc.mitreTtp}
                    </span>
                  )}
                </div>
                <div className="font-mono text-[11px] text-dp-text-dim mt-0.5 truncate">{inc.sourceIp} · <span className="text-dp-text-faint">{inc.detail}</span></div>
              </div>
              <div className="flex flex-col items-end gap-1.5">
                <span className={`font-mono text-[9.5px] px-2 py-0.5 rounded-sm h-fit border whitespace-nowrap shadow-sm ${
                  inc.status === "CONTAINED"
                    ? "border-dp-teal-dim text-dp-teal bg-dp-teal/10 shadow-dp-teal/20"
                    : "border-dp-red-dim text-dp-red bg-dp-red/10 shadow-dp-red/20"
                }`}>
                  {inc.status}
                </span>
                {inc.ttyLogPath && (
                  <button 
                    onClick={() => setReplayPath(inc.ttyLogPath!)}
                    className="flex items-center gap-1 font-mono text-[9.5px] px-1.5 py-0.5 border border-dp-line text-dp-text-dim hover:text-dp-teal hover:border-dp-teal/50 hover:bg-dp-teal/10 transition-all rounded-sm"
                  >
                    <Terminal className="w-3 h-3" />
                    REPLAY
                  </button>
                )}
                {inc.sessionId !== undefined && (
                  <div className="flex items-center gap-1 opacity-60 group-hover:opacity-100 transition-opacity">
                    <button 
                      onClick={() => handleExport(inc.sessionId!, "markdown")}
                      className="flex items-center gap-1 font-mono text-[9.5px] px-1.5 py-0.5 border border-dp-line text-dp-text-dim hover:text-dp-amber hover:border-dp-amber/50 hover:bg-dp-amber/10 transition-all rounded-sm"
                      title="Export Markdown Report"
                    >
                      <Download className="w-3 h-3" />
                      MD
                    </button>
                    <button 
                      onClick={() => handleExport(inc.sessionId!, "stix")}
                      className="flex items-center gap-1 font-mono text-[9.5px] px-1.5 py-0.5 border border-dp-line text-dp-text-dim hover:text-dp-amber hover:border-dp-amber/50 hover:bg-dp-amber/10 transition-all rounded-sm"
                      title="Export STIX 2.1 Bundle"
                    >
                      <Download className="w-3 h-3" />
                      STIX
                    </button>
                  </div>
                )}
              </div>
            </div>
          ))
        )}
      </div>
      
      {replayPath && (
        <SessionReplay 
          logPath={replayPath} 
          onClose={() => setReplayPath(null)} 
        />
      )}
    </div>
  );
}
