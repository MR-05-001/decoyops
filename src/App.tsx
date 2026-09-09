import { useState, useEffect } from "react";
import { Radar, Boxes, ShieldAlert, Settings2, BookOpen, X } from "lucide-react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Dashboard } from "./components/Dashboard";
import { Decoys } from "./components/Decoys";
import { Quarantine } from "./components/Quarantine";
import { Settings } from "./components/Settings";
import { Guide } from "./components/Guide";
import { useDecoyOps } from "./lib/useDecoyOps";
import { DependencyCheckModal, DependenciesStatus } from "./components/DependencyCheckModal";

function nowStamp(): string {
  const d = new Date();
  const pad = (n: number) => n.toString().padStart(2, "0");
  return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}

function App() {
  const [currentTab, setCurrentTab] = useState("dashboard");
  const [clock, setClock] = useState(nowStamp());
  const [hostOs, setHostOs] = useState("unknown");
  const [depsReady, setDepsReady] = useState(false);
  const [depsStatus, setDepsStatus] = useState<DependenciesStatus | null>(null);
  const ops = useDecoyOps();

  // Theme logic
  useEffect(() => {
    const savedTheme = localStorage.getItem("decoyops_theme") || "cyberpunk";
    document.body.setAttribute("data-theme", savedTheme);
  }, []);

  useEffect(() => {
    const id = setInterval(() => setClock(nowStamp()), 1000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    invoke<string>("get_os").then(setHostOs).catch(console.error);
  }, []);

  const [toasts, setToasts] = useState<{id: number, msg: string}[]>([]);

  useEffect(() => {
    const unlisten = listen<string>("telemetry-warning", (e) => {
      const id = Date.now();
      setToasts(prev => [...prev, { id, msg: e.payload }]);
      setTimeout(() => {
        setToasts(prev => prev.filter(t => t.id !== id));
      }, 15000);
    });
    return () => {
      unlisten.then(f => f());
    };
  }, []);

  const navItems = [
    { id: "dashboard", icon: Radar, label: "Command Center", count: null },
    { id: "decoys", icon: Boxes, label: "Fleet", count: ops.counters?.active_decoys ?? 0 },
    { id: "quarantine", icon: ShieldAlert, label: "Quarantine", count: ops.counters?.payloads_captured ?? 0 },
    { id: "settings", icon: Settings2, label: "Settings", count: null },
  ];

  const dockerConnected = ops.error === null;

  return (
    <>
      {!depsReady && <DependencyCheckModal onReady={() => setDepsReady(true)} setDeps={setDepsStatus} />}
      {depsReady && (
        <div className="grid grid-cols-[220px_1fr] grid-rows-[60px_1fr] h-screen text-dp-text font-sans bg-transparent">
      {/* ── Top Bar ── */}
      <div className="col-span-2 flex items-center justify-between px-6 glass-header z-10">
        <div className="flex items-center gap-2.5">
          <div className="text-dp-amber relative flex items-center justify-center w-7 h-7">
            <div className="absolute inset-0 bg-dp-amber/30 blur-[8px] rounded-full animate-pulse-slow" />
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="relative z-10 drop-shadow-[0_0_2px_rgba(245,158,11,0.8)]">
              <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
              <path d="M8 12s1.5-3 4-3 4 3 4 3-1.5 3-4 3-4-3-4-3" />
              <circle cx="12" cy="12" r="1" fill="currentColor" />
            </svg>
          </div>
          <div>
            <div className="font-semibold text-[14.5px]">DecoyOps</div>
            <div className="font-mono text-[11px] text-dp-text-faint">
              {currentTab === "dashboard" ? "COMMAND CENTER" :
               currentTab === "decoys" ? "FLEET MANAGEMENT" :
               currentTab === "quarantine" ? "FORENSIC INSPECTOR" :
               currentTab === "deploy" ? "DEPLOYMENT WIZARD" :
               "CONFIGURATION"}
            </div>
          </div>
        </div>
        
        {/* Toast Notifications */}
        <div className="fixed bottom-6 right-6 z-50 flex flex-col gap-3">
          {toasts.map(t => (
            <div key={t.id} className="bg-dp-bg/95 border border-dp-red shadow-lg flex items-start gap-3 backdrop-blur-md max-w-md p-4 shadow-[0_0_15px_rgba(244,63,94,0.15)]">
              <ShieldAlert className="w-5 h-5 text-dp-red shrink-0 mt-0.5" />
              <div className="text-[13px] text-dp-text leading-relaxed font-mono">{t.msg}</div>
              <button onClick={() => setToasts(prev => prev.filter(x => x.id !== t.id))} className="text-dp-text-faint hover:text-dp-red ml-auto transition-colors">
                <X className="w-4 h-4" />
              </button>
            </div>
          ))}
        </div>
        <div className="flex items-center gap-5">
          {/* Docker Health */}
          <div className={`flex items-center gap-1.5 font-mono text-[11.5px] px-2.5 py-1 border transition-colors ${
            dockerConnected
              ? "text-dp-teal border-dp-teal-dim bg-dp-teal/10 pulse-glow"
              : "text-dp-red border-dp-red-dim bg-dp-red/10"
          }`}>
            <span className={`w-1.5 h-1.5 rounded-full bg-current ${dockerConnected ? "animate-pulse" : ""}`} />
            {dockerConnected ? "DOCKER CONNECTED" : "DOCKER OFFLINE"}
          </div>
          {/* FRP Tunnel Health */}
          <div className={`flex items-center gap-1.5 font-mono text-[11.5px] px-2.5 py-1 border transition-colors ${
            ops.frpRunning
              ? "text-dp-teal border-dp-teal-dim bg-dp-teal/10 pulse-glow"
              : "text-dp-text-faint border-dp-line-soft bg-dp-bg/50"
          }`}>
            <span className={`w-1.5 h-1.5 rounded-full bg-current ${ops.frpRunning ? "animate-pulse" : ""}`} />
            {ops.frpRunning ? "FRP ACTIVE" : "FRP OFFLINE"}
          </div>
          {/* Airgap Status */}
          <div className="flex items-center gap-1.5 font-mono text-[11.5px] text-dp-teal px-2.5 py-1 border border-dp-teal-dim bg-dp-teal/5">
            <span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse" />
            {hostOs === "windows" ? "EGRESS-DENY: WFP PENDING" : "ALL DECOYS AIR-GAPPED"}
          </div>
          <button onClick={() => setCurrentTab("guide")} className="text-dp-text-dim hover:text-dp-amber transition-colors flex items-center gap-1.5 font-mono text-[11px]" title="Open Guide">
            <BookOpen className="w-4 h-4" /> GUIDE
          </button>
          <div className="font-mono text-[12.5px] text-dp-text-dim">{clock} UTC</div>
        </div>
      </div>

      {/* ── Left Sidebar ── */}
      <div className="glass-panel border-r border-dp-line py-5 flex flex-col z-0">
        <div className="font-mono text-[10.5px] text-dp-text-faint px-5 py-1.5 mt-2.5">MONITOR</div>
        {navItems.slice(0, 3).map((item) => (
          <NavRow
            key={item.id}
            icon={item.icon}
            label={item.label}
            count={item.count}
            active={currentTab === item.id}
            onClick={() => setCurrentTab(item.id)}
          />
        ))}
        <div className="font-mono text-[10.5px] text-dp-text-faint px-5 py-1.5 mt-2.5">CONFIGURE</div>
        {navItems.slice(3).map((item) => (
          <NavRow
            key={item.id}
            icon={item.icon}
            label={item.label}
            count={item.count}
            active={currentTab === item.id}
            onClick={() => setCurrentTab(item.id)}
          />
        ))}
        <div className="mt-auto px-5 py-3 border-t border-dp-line">
          <div className="font-mono text-[10px] text-dp-text-faint">DecoyOps v0.1.0</div>
          <div className="font-mono text-[10px] text-dp-text-faint mt-0.5">{hostOs}</div>
        </div>
      </div>

      {/* ── Main Content ── */}
      <div className="overflow-auto h-full flex flex-col">
        {currentTab === "dashboard" && <Dashboard ops={ops} />}
        {currentTab === "decoys" && <Decoys deps={depsStatus} />}
        {currentTab === "quarantine" && <Quarantine />}
        {currentTab === "deploy" && <Decoys deps={depsStatus} />}
        {currentTab === "guide" && <Guide />}
        {currentTab === "settings" && <Settings />}
      </div>
    </div>
      )}
    </>
  );
}

function NavRow({ icon: Icon, label, count, active, onClick }: {
  icon: typeof Radar;
  label: string;
  count: number | null;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <div
      onClick={onClick}
      className={`flex items-center justify-between px-5 py-2.5 cursor-pointer transition-all duration-200 group ${
        active
          ? "bg-dp-amber/10 border-r-2 border-dp-amber"
          : "hover:bg-dp-text/5 border-r-2 border-transparent"
      }`}
    >
      <div className="flex items-center gap-3">
        <Icon
          className={`w-4 h-4 transition-colors ${
            active ? "text-dp-amber drop-shadow-[0_0_8px_rgba(251,191,36,0.5)]" : "text-dp-text-dim group-hover:text-dp-text"
          }`}
        />
        <span
          className={`text-[13px] font-medium transition-colors ${
            active ? "text-dp-text" : "text-dp-text-dim group-hover:text-dp-text"
          }`}
        >
          {label}
        </span>
      </div>
      {count !== null && count > 0 && (
        <span className={`text-[11px] font-mono ${active ? "text-dp-amber" : "text-dp-text-dim"}`}>
          {count}
        </span>
      )}
    </div>
  );
}

export default App;
