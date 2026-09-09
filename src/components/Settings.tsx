import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Shield, Key, Server, Trash2, CheckCircle, XCircle, Loader2, Monitor, ChevronDown } from "lucide-react";

type SaveStatus = "idle" | "saving" | "saved" | "error";

export function Settings() {
  const [abuseIpdbKey, setAbuseIpdbKey] = useState("");
  const [virusTotalKey, setVirusTotalKey] = useState("");
  
  // Tunnel Settings
  const [ngrokAuthtoken, setNgrokAuthtoken] = useState("");
  const [ngrokBinaryPath, setNgrokBinaryPath] = useState("");
  const [frpServerAddr, setFrpServerAddr] = useState("");
  const [frpAuthToken, setFrpAuthToken] = useState("");
  const [frpBinaryPath, setFrpBinaryPath] = useState("");
  const [frpPortRangeStart, setFrpPortRangeStart] = useState(10000);
  const [frpPortRangeEnd, setFrpPortRangeEnd] = useState(20000);
  
  const [frpRunning, setFrpRunning] = useState(false);
  
  // App Preferences
  const [pollInterval, setPollInterval] = useState("3000");
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [uiTheme, setUiTheme] = useState("cyberpunk");
  
  const [saveStatus, setSaveStatus] = useState<SaveStatus>("idle");
  const [isPurging, setIsPurging] = useState(false);
  const [purgeResult, setPurgeResult] = useState<string | null>(null);
  const [abuseTest, setAbuseTest] = useState<"idle" | "testing" | "ok" | "fail">("idle");
  const [vtTest, setVtTest] = useState<"idle" | "testing" | "ok" | "fail">("idle");

  useEffect(() => {
    // Load app preferences from localStorage
    setPollInterval(localStorage.getItem('app_poll_interval') || "3000");
    setAutoRefresh(localStorage.getItem('app_autorefresh') !== 'false');
    setUiTheme(localStorage.getItem('decoyops_theme') || "cyberpunk");

    const loadKeys = async () => {
      try {
        const [abuseKey, vtKey] = await Promise.all([
          invoke<string>("get_api_key", { service: "abuseipdb" }),
          invoke<string>("get_api_key", { service: "virustotal" }),
        ]);
        setAbuseIpdbKey(abuseKey);
        setVirusTotalKey(vtKey);
        // Load Tunnel Settings
        const tunnelSettings = await invoke<any>("get_tunnel_settings");
        setNgrokAuthtoken(tunnelSettings.ngrok_authtoken);
        setNgrokBinaryPath(tunnelSettings.ngrok_binary_path);
        setFrpServerAddr(tunnelSettings.frp_server_addr);
        setFrpAuthToken(tunnelSettings.frp_auth_token);
        setFrpBinaryPath(tunnelSettings.frp_binary_path);
        setFrpPortRangeStart(tunnelSettings.frp_port_range_start);
        setFrpPortRangeEnd(tunnelSettings.frp_port_range_end);

        // Check if running
        const running = await invoke<boolean>("get_frp_status");
        setFrpRunning(running);
      } catch (e) {
        console.error("Failed to load keys/config:", e);
      }
    };
    loadKeys();
  }, []);

  const handleSave = async () => {
    setSaveStatus("saving");
    try {
      const tasks: Promise<void>[] = [];
      tasks.push(invoke("save_api_key", { service: "abuseipdb", key: abuseIpdbKey }));
      tasks.push(invoke("save_api_key", { service: "virustotal", key: virusTotalKey }));
      // Save Tunnel Settings
      tasks.push(invoke("save_tunnel_settings", { 
        settings: { 
          provider: "frp", // Hardcode back to default since backend still expects it in struct, though unused in logic
          ngrok_authtoken: ngrokAuthtoken,
          ngrok_binary_path: ngrokBinaryPath,
          frp_server_addr: frpServerAddr,
          frp_auth_token: frpAuthToken,
          frp_binary_path: frpBinaryPath,
          frp_port_range_start: Number(frpPortRangeStart),
          frp_port_range_end: Number(frpPortRangeEnd),
        } 
      }));
      
      // Save app preferences
      localStorage.setItem('app_poll_interval', pollInterval);
      localStorage.setItem('app_autorefresh', autoRefresh.toString());
      localStorage.setItem('decoyops_theme', uiTheme);
      document.body.setAttribute('data-theme', uiTheme);
      
      await Promise.all(tasks);
      setSaveStatus("saved");
      setTimeout(() => setSaveStatus("idle"), 3000);
    } catch (e) {
      console.error(e);
      setSaveStatus("error");
      setTimeout(() => setSaveStatus("idle"), 5000);
    }
  };

  const handlePurge = async () => {
    if (!confirm("WARNING: This will permanently delete all historic telemetry and quarantined payloads. This action is irreversible and will be written to the system audit log.")) {
      return;
    }
    setIsPurging(true);
    setPurgeResult(null);
    try {
      await invoke("purge_telemetry");
      setPurgeResult("Telemetry data and quarantined files purged successfully.");
    } catch (e: any) {
      setPurgeResult(`Failed: ${e}`);
    }
    setIsPurging(false);
  };

  const [isResetting, setIsResetting] = useState(false);
  const handleFactoryReset = async () => {
    const confirmMsg = "WARNING: This will permanently delete ALL data, including databases, logs, quarantine, and your API keys from the keychain. This cannot be undone. Are you absolutely sure?";
    if (window.confirm(confirmMsg)) {
      setIsResetting(true);
      try {
        await invoke("factory_reset");
        window.location.reload();
      } catch (e: any) {
        alert(`Factory Reset Failed: ${e}`);
        setIsResetting(false);
      }
    }
  };

  const testAbuseIpdb = async () => {
    setAbuseTest("testing");
    try {
      await invoke("save_api_key", { service: "abuseipdb", key: abuseIpdbKey });
      // Try a lightweight check of 8.8.8.8 to verify the key works
      await invoke("enrich_ip", { ip: "8.8.8.8" });
      setAbuseTest("ok");
    } catch {
      setAbuseTest("fail");
    }
    setTimeout(() => setAbuseTest("idle"), 4000);
  };

  const testVirusTotal = async () => {
    setVtTest("testing");
    try {
      await invoke("save_api_key", { service: "virustotal", key: virusTotalKey });
      // EICAR test hash - known clean test signature
      await invoke("enrich_hash", { hash: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" });
      setVtTest("ok");
    } catch {
      setVtTest("fail");
    }
    setTimeout(() => setVtTest("idle"), 4000);
  };

  const handleStartFrp = async () => {
    try {
      await invoke("start_frp_client");
      setFrpRunning(true);
    } catch (e) {
      alert(`Failed to start FRP: ${e}`);
    }
  };

  const handleStopFrp = async () => {
    try {
      await invoke("stop_frp_client");
      setFrpRunning(false);
    } catch (e) {
      alert(`Failed to stop FRP: ${e}`);
    }
  };

  const inputClass = "w-full bg-dp-bg border border-dp-line px-3 py-2 text-sm font-mono text-dp-text focus:outline-none focus:border-dp-amber transition-colors";

  return (
    <div className="flex-1 overflow-auto p-6">
      <div className="max-w-3xl mx-auto space-y-6">
        <div>
          <h1 className="text-xl font-semibold text-dp-text">Configuration</h1>
          <p className="text-[12px] text-dp-text-faint mt-1">Manage API keys, network settings, and tunneling. All secrets are stored in your OS keyring.</p>
        </div>

        {/* Network & Isolation */}
        <div className="border border-dp-line glass-panel">
          <div className="flex items-center gap-2 px-5 py-3.5 border-b border-dp-line-soft glass-header">
            <Shield className="w-4 h-4 text-dp-amber" />
            <span className="text-[13px] font-semibold text-dp-text">Network & Isolation</span>
          </div>
          <div className="p-5 space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <label className="text-[10px] text-dp-text-faint uppercase tracking-wider font-medium">Default Subnet (CIDR)</label>
                <input type="text" defaultValue="172.20.0.0/16" className={inputClass} />
              </div>
              <div className="space-y-1.5">
                <label className="text-[10px] text-dp-text-faint uppercase tracking-wider font-medium">Firewall Engine</label>
                <div className="relative">
                  <select className={`${inputClass} appearance-none pr-8`} defaultValue="auto">
                    <option value="auto">Auto-detect (Recommended)</option>
                    <option value="nftables">nftables (Linux)</option>
                    <option value="wfp">WFP (Windows — future)</option>
                  </select>
                  <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dp-text-faint pointer-events-none" />
                </div>
              </div>
            </div>
            <div className="flex items-center justify-between p-3 border border-dp-teal-dim bg-dp-teal/5">
              <div>
                <div className="text-[12px] font-medium text-dp-text">Strict Egress-Deny</div>
                <div className="text-[10px] text-dp-text-faint mt-0.5">Block all outbound traffic from decoy containers (HC#3)</div>
              </div>
              <div className="relative inline-flex h-5 w-9 items-center rounded-full bg-dp-teal cursor-pointer">
                <span className="inline-block h-3 w-3 transform rounded-full bg-white translate-x-5" />
              </div>
            </div>
          </div>
        </div>

        {/* Application Preferences */}
        <div className="border border-dp-line glass-panel">
          <div className="flex items-center gap-2 px-5 py-3.5 border-b border-dp-line-soft glass-header">
            <Monitor className="w-4 h-4 text-dp-amber" />
            <span className="text-[13px] font-semibold text-dp-text">Application Preferences</span>
          </div>
          <div className="p-5 space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <label className="text-[10px] text-dp-text-faint uppercase tracking-wider font-medium">Telemetry Polling Interval</label>
                <div className="relative">
                  <select 
                    className={`${inputClass} appearance-none pr-8`}
                    value={pollInterval}
                    onChange={(e) => setPollInterval(e.target.value)}
                  >
                    <option value="1000">Fast (1 second) — High CPU</option>
                    <option value="3000">Normal (3 seconds) — Balanced</option>
                    <option value="10000">Eco (10 seconds) — Low CPU</option>
                  </select>
                  <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dp-text-faint pointer-events-none" />
                </div>
              </div>
              <div className="space-y-1.5">
                <label className="text-[10px] text-dp-text-faint uppercase tracking-wider font-medium">UI Theme</label>
                <div className="relative">
                  <select 
                    className={`${inputClass} appearance-none pr-8`}
                    value={uiTheme}
                    onChange={(e) => {
                      setUiTheme(e.target.value);
                      document.body.setAttribute('data-theme', e.target.value);
                    }}
                  >
                    <option value="cyberpunk">Cyberpunk Glass (Recommended)</option>
                    <option value="classic">Classic Slate (Flat)</option>
                    <option value="minimal">Midnight Minimal (OLED Black)</option>
                  </select>
                  <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dp-text-faint pointer-events-none" />
                </div>
              </div>
            </div>
            
            <div className="flex items-center justify-between p-3 border border-dp-line bg-dp-bg/50">
              <div>
                <div className="text-[12px] font-medium text-dp-text">Auto-Refresh Dashboards</div>
                <div className="text-[10px] text-dp-text-faint mt-0.5">Pause the live telemetry feed completely to investigate specific logs without interruption.</div>
              </div>
              <div 
                className={`relative inline-flex h-5 w-9 items-center rounded-full cursor-pointer transition-colors ${autoRefresh ? "bg-dp-teal" : "bg-dp-line-soft"}`}
                onClick={() => setAutoRefresh(!autoRefresh)}
              >
                <span className={`inline-block h-3 w-3 transform rounded-full bg-white transition-transform ${autoRefresh ? "translate-x-5" : "translate-x-1"}`} />
              </div>
            </div>
          </div>
        </div>

        {/* Threat Intel APIs */}
        <div className="border border-dp-line glass-panel">
          <div className="flex items-center gap-2 px-5 py-3.5 border-b border-dp-line-soft glass-header">
            <Key className="w-4 h-4 text-dp-amber" />
            <span className="text-[13px] font-semibold text-dp-text">Threat Intelligence APIs</span>
          </div>
          <div className="p-5 space-y-4">
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label className="text-[10px] text-dp-text-faint uppercase tracking-wider font-medium">AbuseIPDB API Key</label>
                <button onClick={testAbuseIpdb} disabled={!abuseIpdbKey || abuseTest === "testing"} className="text-[10px] font-mono text-dp-amber hover:text-dp-text transition-colors disabled:opacity-30">
                  {abuseTest === "testing" ? "TESTING…" : abuseTest === "ok" ? "✓ CONNECTED" : abuseTest === "fail" ? "✗ FAILED" : "TEST CONNECTION"}
                </button>
              </div>
              <input type="password" value={abuseIpdbKey} onChange={e => setAbuseIpdbKey(e.target.value)} placeholder="Enter your AbuseIPDB key…" className={inputClass} />
            </div>
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label className="text-[10px] text-dp-text-faint uppercase tracking-wider font-medium">VirusTotal API Key</label>
                <button onClick={testVirusTotal} disabled={!virusTotalKey || vtTest === "testing"} className="text-[10px] font-mono text-dp-amber hover:text-dp-text transition-colors disabled:opacity-30">
                  {vtTest === "testing" ? "TESTING…" : vtTest === "ok" ? "✓ CONNECTED" : vtTest === "fail" ? "✗ FAILED" : "TEST CONNECTION"}
                </button>
              </div>
              <input type="password" value={virusTotalKey} onChange={e => setVirusTotalKey(e.target.value)} placeholder="Enter your VirusTotal key…" className={inputClass} />
            </div>
            <div className="text-[10px] text-dp-text-faint">Keys are stored in the OS keyring. Rate-limited via governor token bucket (HC#6).</div>
          </div>
        </div>

        {/* Reverse Tunneling */}
        <div className="border border-dp-line glass-panel">
          <div className="flex items-center gap-2 px-5 py-3.5 border-b border-dp-line-soft glass-header">
            <Server className="w-4 h-4 text-dp-amber" />
            <span className="text-[13px] font-semibold text-dp-text">Tunnel Configurations</span>
          </div>
          <div className="p-5 space-y-6">
            <div className="space-y-4">
              <div className="text-[12px] font-semibold text-dp-amber mb-2">Ngrok Configuration</div>
              <div className="space-y-1.5">
                <label className="text-[10px] text-dp-text-faint uppercase tracking-wider font-medium">Ngrok Authtoken</label>
                <input type="password" value={ngrokAuthtoken} onChange={e => setNgrokAuthtoken(e.target.value)} placeholder="Stored securely in keyring…" className={inputClass} />
              </div>
              <div className="space-y-1.5">
                <label className="text-[10px] text-dp-text-faint uppercase tracking-wider font-medium">Ngrok Binary Path</label>
                <input type="text" value={ngrokBinaryPath} onChange={e => setNgrokBinaryPath(e.target.value)} placeholder="tools/ngrok/ngrok" className={inputClass} />
              </div>
            </div>

            <div className="space-y-4 pt-4 border-t border-dp-line-soft">
              <div className="text-[12px] font-semibold text-dp-amber mb-2">FRP Configuration (Self-Hosted)</div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label className="text-[10px] text-dp-text-faint uppercase tracking-wider font-medium">FRP Server Address (IP or Host)</label>
                  <input type="text" value={frpServerAddr} onChange={e => setFrpServerAddr(e.target.value)} placeholder="e.g. 203.0.113.5" className={inputClass} />
                </div>
                <div className="space-y-1.5">
                  <label className="text-[10px] text-dp-text-faint uppercase tracking-wider font-medium">TLS Auth Token</label>
                  <input type="password" value={frpAuthToken} onChange={e => setFrpAuthToken(e.target.value)} placeholder="Shared secret token…" className={inputClass} />
                </div>
              </div>
              <div className="space-y-1.5">
                <label className="text-[10px] text-dp-text-faint uppercase tracking-wider font-medium">FRP Binary Path</label>
                <input type="text" value={frpBinaryPath} onChange={e => setFrpBinaryPath(e.target.value)} placeholder="tools/frp/frpc" className={inputClass} />
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label className="text-[10px] text-dp-text-faint uppercase tracking-wider font-medium">Port Range Start</label>
                  <input type="number" value={frpPortRangeStart} onChange={e => setFrpPortRangeStart(Number(e.target.value))} placeholder="10000" className={inputClass} />
                </div>
                <div className="space-y-1.5">
                  <label className="text-[10px] text-dp-text-faint uppercase tracking-wider font-medium">Port Range End</label>
                  <input type="number" value={frpPortRangeEnd} onChange={e => setFrpPortRangeEnd(Number(e.target.value))} placeholder="20000" className={inputClass} />
                </div>
              </div>
              
              <div className="flex items-center justify-between pt-4 border-t border-dp-line-soft">
                <div className="text-[10px] text-dp-text-faint">
                  Global FRP Process Status: <span className={frpRunning ? "text-dp-teal font-semibold" : "text-dp-red font-semibold"}>{frpRunning ? "RUNNING" : "STOPPED"}</span>
                </div>
                <div className="flex gap-2">
                  <button 
                    onClick={handleStartFrp} 
                    disabled={frpRunning}
                    className="px-3 py-1.5 text-[11px] font-mono border border-dp-teal-dim text-dp-teal hover:bg-dp-teal/10 transition-colors disabled:opacity-30"
                  >
                    START GLOBAL CLIENT
                  </button>
                  <button 
                    onClick={handleStopFrp} 
                    disabled={!frpRunning}
                    className="px-3 py-1.5 text-[11px] font-mono border border-dp-red-dim text-dp-red hover:bg-dp-red/10 transition-colors disabled:opacity-30"
                  >
                    STOP CLIENT
                  </button>
                </div>
              </div>
              <div className="text-[10px] text-dp-text-faint">Never point frpc at a public/demo frps server. Config saved to tools/frp/frpc.toml.</div>
            </div>
          </div>
        </div>

        {/* Danger Zone */}
        <div className="border border-dp-red-dim glass-panel">
          <div className="flex items-center gap-2 px-5 py-3.5 border-b border-dp-red-dim glass-header">
            <Trash2 className="w-4 h-4 text-dp-red" />
            <span className="text-[13px] font-semibold text-dp-red">Danger Zone</span>
          </div>
          <div className="p-5">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-[12px] font-medium text-dp-text">Purge Telemetry Data</div>
                <div className="text-[10px] text-dp-text-faint mt-0.5">Permanently delete all event logs and quarantined payloads. Written to audit log.</div>
              </div>
              <button onClick={handlePurge} disabled={isPurging} className="flex items-center gap-2 px-3 py-1.5 text-[11px] font-mono border border-dp-red-dim text-dp-red hover:bg-dp-red/10 transition-colors disabled:opacity-30">
                <Trash2 className="w-3.5 h-3.5" />
                {isPurging ? "PURGING…" : "PURGE DATABASE"}
              </button>
            </div>
            {purgeResult && (
              <div className={`mt-3 text-[11px] font-mono p-2 border ${purgeResult.startsWith("Failed") ? "border-dp-red-dim text-dp-red" : "border-dp-teal-dim text-dp-teal"}`}>
                {purgeResult}
              </div>
            )}
            <div className="flex items-center justify-between mt-4 pt-4 border-t border-dp-red/20">
              <div>
                <div className="text-[12px] font-medium text-dp-text">Factory Reset</div>
                <div className="text-[10px] text-dp-text-faint mt-0.5">Wipe all databases, logs, quarantine, and keychain secrets.</div>
              </div>
              <button onClick={handleFactoryReset} disabled={isResetting} className="flex items-center gap-2 px-3 py-1.5 text-[11px] font-bold bg-dp-red text-white hover:bg-red-600 transition-colors disabled:opacity-30">
                <Trash2 className="w-3.5 h-3.5" />
                {isResetting ? "RESETTING…" : "FACTORY RESET"}
              </button>
            </div>
          </div>
        </div>

        {/* Save Button */}
        <div className="flex items-center justify-end gap-3 pb-8">
          {saveStatus === "saved" && (
            <span className="flex items-center gap-1.5 text-[11px] font-mono text-dp-teal">
              <CheckCircle className="w-3.5 h-3.5" /> Settings saved to keyring
            </span>
          )}
          {saveStatus === "error" && (
            <span className="flex items-center gap-1.5 text-[11px] font-mono text-dp-red">
              <XCircle className="w-3.5 h-3.5" /> Failed to save
            </span>
          )}
          <button
            onClick={handleSave}
            disabled={saveStatus === "saving"}
            className="flex items-center gap-2 px-5 py-2 text-[13px] font-medium bg-dp-amber text-dp-bg hover:opacity-90 transition-opacity disabled:opacity-30"
          >
            {saveStatus === "saving" ? (
              <><Loader2 className="w-4 h-4 animate-spin" /> Saving…</>
            ) : (
              "Save Changes"
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
