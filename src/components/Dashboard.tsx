import { useState } from "react";
import { KpiStrip } from "./dashboard/KpiStrip";
import { ThreatMap } from "./dashboard/ThreatMap";
import { TrendDashboard } from "./dashboard/TrendDashboard";
import { IncidentFeed, type Incident } from "./dashboard/IncidentFeed";
import { IocPanel } from "./dashboard/IocPanel";
import type { useDecoyOps } from "../lib/useDecoyOps";

interface DashboardProps {
  ops: ReturnType<typeof useDecoyOps>;
}

export function Dashboard({ ops }: DashboardProps) {
  const { counters, decoys, incidentFeed } = ops;
  const [timeRange, setTimeRange] = useState<"live" | "24h" | "7d">("live");
  const [isFeedMaximized, setIsFeedMaximized] = useState(false);
  const [isIocMaximized, setIsIocMaximized] = useState(false);

  const activeDecoysCount = decoys.filter((d) => d.state === "running").length;

  // Transform real EventRow[] into Incident[] for the feed
  const incidents: Incident[] = incidentFeed.map((e) => {
    const ts = e.timestamp;
    // Database provides YYYY-MM-DD HH:MM:SS. We want to show date and time.
    const timePart = ts.includes("T") ? ts.replace("T", " ").substring(0, 19) : ts.substring(0, 19);
    let extraContext = "";
    if (e.raw_data) {
      try {
        const raw = JSON.parse(e.raw_data);
        if (e.event_type === "cowrie.command.input" && raw.input) {
          extraContext = ` ➔ "${raw.input}"`;
        } else if (e.event_type.includes("login") && raw.username) {
          extraContext = ` ➔ ${raw.username}:${raw.password || '***'}`;
        } else if (e.event_type === "cowrie.session.file_download" && raw.url) {
          extraContext = ` ➔ downloaded: ${raw.url}`;
        } else if (e.event_type === "cowrie.session.file_upload" && raw.filename) {
          extraContext = ` ➔ uploaded: ${raw.filename}`;
        }
      } catch (_) {
        // ignore JSON parse errors
      }
    }

    return {
      id: e.id,
      sessionId: e.session_id,
      time: timePart,
      sourceIp: e.source_ip ?? "unknown",
      vector: e.attack_vector ?? e.event_type,
      detail: `${e.container_id.substring(0, 12)} · ${e.event_type}${extraContext}`,
      status: e.event_type.toLowerCase().includes("capture") ? "CAPTURED" as const : "CONTAINED" as const,
      mitreTtp: e.mitre_ttp,
      ttyLogPath: e.tty_log_path,
      geo_lat: e.geo_lat,
      geo_lon: e.geo_lon,
    };
  });

  return (
    <div className="flex flex-col overflow-hidden h-full bg-transparent">
      <KpiStrip
        items={[
          {
            label: "Active Decoys",
            value: counters?.active_decoys ?? 0,
            delta: `${decoys.length} registered`,
          },
          {
            label: "Active Sessions",
            value: counters?.active_sessions ?? 0,
            delta: `${counters?.total_events ?? 0} total events`,
            tone: (counters?.active_sessions ?? 0) > 0 ? "amber" : "default",
            deltaTone: (counters?.active_sessions ?? 0) > 0 ? "up" : "default",
          },
          {
            label: "Unique Threat Actors",
            value: counters?.unique_actors ?? 0,
            delta: "all-time unique IPs",
          },
          {
            label: "Payloads Captured",
            value: counters?.payloads_captured ?? 0,
            delta: "hash-only VT by default",
            tone: (counters?.payloads_captured ?? 0) > 0 ? "red" : "default",
          },
        ]}
      />
      <div className={`flex-1 flex flex-col lg:grid min-h-0 overflow-hidden p-5 gap-5 ${
        (isFeedMaximized || isIocMaximized) ? "lg:grid-cols-1" : "lg:grid-cols-[1.35fr_420px]"
      }`}>
        {!(isFeedMaximized || isIocMaximized) && (
          <div className="glass-panel flex flex-col overflow-hidden min-h-[400px] lg:min-h-0 rounded-xl">
          <div className="flex items-center justify-between px-5 py-3.5 border-b border-dp-line-soft glass-header">
            <div>
              <div className="text-[13px] font-semibold tracking-wide text-dp-text uppercase">
                {timeRange === "live" ? "Live Threat Map" : `${timeRange.toUpperCase()} Threat Trends`}
              </div>
              <div className="text-[11px] text-dp-text-faint mt-0.5">
                {timeRange === "live" ? "Real-time geographical attack origins" : "Historical attack frequency and vectors"}
              </div>
            </div>
            <div className="flex gap-1.5">
              {(["live", "24h", "7d"] as const).map((r) => (
                <button
                  key={r}
                  onClick={() => setTimeRange(r)}
                  className={`font-mono text-[10.5px] px-2.5 py-1 border transition-colors ${
                    timeRange === r
                      ? "text-dp-amber border-dp-amber-dim bg-dp-panel-raised"
                      : "text-dp-text-dim border-dp-line bg-dp-panel-raised hover:text-dp-text"
                  }`}
                >
                  {r.toUpperCase()}
                </button>
              ))}
            </div>
          </div>
          {timeRange === "live" ? (
            <div className="flex-1 relative bg-dp-bg/30 min-h-0">
              <ThreatMap incidents={incidents} activeDecoysCount={activeDecoysCount} />
            </div>
          ) : (
            <div className="flex-1 relative bg-dp-bg/30 min-h-0 overflow-auto">
              <TrendDashboard range={timeRange} incidents={incidents} />
            </div>
          )}
        </div>
        )}
        <div className="flex flex-col gap-5 min-h-0 overflow-hidden">
          {!isIocMaximized && (
            <div className="glass-panel rounded-xl flex flex-col flex-1 min-h-0 overflow-hidden">
              <IncidentFeed 
                incidents={incidents} 
                isMaximized={isFeedMaximized}
                onToggleMaximize={() => setIsFeedMaximized(!isFeedMaximized)}
              />
            </div>
          )}
          {!isFeedMaximized && ops.iocs && (
            <div className={`glass-panel rounded-xl flex flex-col ${isIocMaximized ? 'flex-1' : 'h-[250px] shrink-0'} overflow-hidden`}>
              <IocPanel 
                iocs={ops.iocs} 
                isMaximized={isIocMaximized}
                onToggleMaximize={() => setIsIocMaximized(!isIocMaximized)}
              />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
