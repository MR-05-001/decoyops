import { useState, useEffect } from 'react';
import { Trash2, Plus, Shield, Network, ArrowRight, ArrowLeft, CheckCircle2, AlertTriangle, Server, Info, X, Loader2, ChevronDown, Play, Square, RotateCw } from 'lucide-react';
import { useDecoyOps, DecoyStatus } from '../lib/useDecoyOps';
import { invoke } from '@tauri-apps/api/core';
import { DependenciesStatus } from './DependencyCheckModal';

const TEMPLATES = [
  { id: 'cowrie/cowrie:latest', name: 'Cowrie', desc: 'SSH/Telnet bruteforce trapping', icon: '🐚', ports: '0:2222' },
  { id: 'dinotools/dionaea:latest', name: 'Dionaea', desc: 'SMB/HTTP/FTP/MSSQL malware capture', icon: '🦠', ports: '0:445' },
  { id: 'dtagdevsec/mailoney:latest', name: 'Mailoney', desc: 'SMTP relay / email credential harvesting', icon: '📧', ports: '0:25' },
  { id: 'dtagdevsec/conpot:latest', name: 'Conpot', desc: 'SCADA / ICS / Modbus industrial control decoys', icon: '🏭', ports: '0:502' },
  { id: 'dtagdevsec/elasticpot:latest', name: 'Elasticpot', desc: 'Fake Elasticsearch cluster targeting ransomware', icon: '📊', ports: '0:9200' },
  { id: 'dtagdevsec/endlessh:latest', name: 'Endlessh', desc: 'SSH tarpit that holds attackers open indefinitely', icon: '🕸️', ports: '0:2222' },
  { id: 'custom', name: 'Custom Container', desc: 'Deploy any manual Docker image', icon: '⚙️', ports: '0:80' },
];

export function Decoys({ deps }: { deps?: DependenciesStatus | null }) {
  const { decoys, deployDecoy, terminateDecoy, startDecoy, stopDecoy, restartDecoy, networks, refresh } = useDecoyOps();
  const [hostOs, setHostOs] = useState('unknown');

  useEffect(() => {
    invoke<string>('get_os').then(setHostOs).catch(console.error);
  }, []);

  // Wizard State
  const [wizardStep, setWizardStep] = useState(0);
  const [isDeploying, setIsDeploying] = useState(false);
  const [newDecoyName, setNewDecoyName] = useState('');
  const [newDecoyTemplate, setNewDecoyTemplate] = useState(TEMPLATES[0].id);
  const [customImage, setCustomImage] = useState('');
  const [newDecoyPort, setNewDecoyPort] = useState(TEMPLATES[0].ports);
  const [networkType, setNetworkType] = useState<'new' | 'existing'>('new');
  const [networkName, setNetworkName] = useState('');
  const [isUnmanaged, setIsUnmanaged] = useState(false);
  const [autoRestart, setAutoRestart] = useState(false);
  const [tunnelProvider, setTunnelProvider] = useState<'none' | 'frp' | 'ngrok'>('none');
  const [deployError, setDeployError] = useState<string | null>(null);

  // Network Manager State
  const [isNetworkManagerOpen, setIsNetworkManagerOpen] = useState(false);
  const [isDeletingNetwork, setIsDeletingNetwork] = useState<string | null>(null);

  const handleDeleteNetwork = async (netName: string) => {
    setIsDeletingNetwork(netName);
    try {
      await invoke('delete_network', { networkName: netName });
      await refresh();
    } catch (e: any) {
      alert(`Failed to delete network: ${e}`);
    }
    setIsDeletingNetwork(null);
  };

  const handleDeploy = async () => {
    if (!newDecoyName) return;
    if (newDecoyTemplate === 'custom' && !customImage) {
      setDeployError("Custom container image name cannot be empty.");
      return;
    }
    if (networkType === 'existing' && !networkName) {
      setDeployError("Please select an existing network, or choose 'Create New Network'.");
      return;
    }
    
    setIsDeploying(true);
    setDeployError(null);
    try {
      const actualTemplate = newDecoyTemplate === 'custom' ? customImage : newDecoyTemplate;
      const actualNetworkName = networkType === 'new' ? '' : networkName;
      const selectedTunnel = tunnelProvider === 'none' ? null : tunnelProvider;
      await deployDecoy(newDecoyName, actualTemplate, newDecoyPort, autoRestart, actualNetworkName, isUnmanaged, selectedTunnel);
      setNewDecoyName('');
      setWizardStep(0);
    } catch (e: any) {
      console.error(e);
      setDeployError(e.toString());
    }
    setIsDeploying(false);
  };

  // Details State
  const [expandedDecoy, setExpandedDecoy] = useState<string | null>(null);
  const [decoyDetails, setDecoyDetails] = useState<any | null>(null);
  const [isLoadingDetails, setIsLoadingDetails] = useState(false);

  const handleInspect = async (containerId: string) => {
    if (expandedDecoy === containerId) {
      setExpandedDecoy(null);
      setDecoyDetails(null);
      return;
    }
    setExpandedDecoy(containerId);
    setIsLoadingDetails(true);
    try {
      const details = await invoke('inspect_decoy', { containerId });
      setDecoyDetails(details);
    } catch (e) {
      console.error(e);
    }
    setIsLoadingDetails(false);
  };

  const [isVerifying, setIsVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState<{status: 'success' | 'failed', message: string} | null>(null);
  
  const [isCapturing, setIsCapturing] = useState(false);
  const [captureResult, setCaptureResult] = useState<{status: 'success' | 'failed', message: string} | null>(null);
  const [pcapDuration, setPcapDuration] = useState<number>(30);

  const handleVerifyIsolation = async (containerId: string) => {
    setIsVerifying(true);
    setVerificationResult(null);
    try {
      const output = await invoke<string>('verify_isolation', { containerId });
      // If ping fails completely due to no route/network isolation, it will either return a string with "100% packet loss" or timeout/Network is unreachable.
      if (output.includes("100% packet loss") || output.includes("Network is unreachable") || output.includes("unreachable")) {
        setVerificationResult({ status: 'success', message: 'Egress isolation verified (Ping blocked)' });
      } else {
        setVerificationResult({ status: 'failed', message: 'WARNING: Ping succeeded! Container can reach the internet.' });
      }
    } catch (e: any) {
      // If exec fails (e.g., ping command not found), it's still effectively isolated.
      if (e.toString().includes("ping might not be installed")) {
        setVerificationResult({ status: 'success', message: 'Egress isolation verified (ping executable stripped)' });
      } else {
        setVerificationResult({ status: 'success', message: `Egress isolation verified (Execution blocked: ${e})` });
      }
    }
    setIsVerifying(false);
  };

  const handleCapturePcap = async (containerId: string) => {
    try {
      setIsCapturing(true);
      setCaptureResult(null);

      // Backend now automatically generates a secure file path to prevent arbitrary file overwrites
      const outputPath = await invoke<string>('capture_pcap', { containerId, duration: pcapDuration });
      
      setCaptureResult({ status: 'success', message: `PCAP securely saved to ${outputPath}` });
    } catch (e: any) {
      setCaptureResult({ status: 'failed', message: `Capture failed: ${e}` });
    }
    setIsCapturing(false);
  };

  const selectTemplate = (t: typeof TEMPLATES[0]) => {
    setNewDecoyTemplate(t.id);
    setNewDecoyPort(t.ports);
  };

  const inputClass = "w-full bg-dp-bg border border-dp-line px-3 py-2 text-sm font-mono text-dp-text focus:outline-none focus:border-dp-amber transition-colors";

  return (
    <div className="flex-1 overflow-auto p-6 flex flex-col gap-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-xl font-semibold text-dp-text">Decoy Fleet</h1>
          <p className="text-[12px] text-dp-text-faint mt-1">Attract and detect malicious traffic, providing insights into attack methodologies.</p>
        </div>
        <div className="flex items-center gap-3">
          <button 
            onClick={() => setIsNetworkManagerOpen(true)}
            className="flex items-center gap-2 px-4 py-2 text-[13px] border border-dp-line text-dp-text hover:border-dp-amber transition-colors"
          >
            <Network className="w-4 h-4" /> Manage Networks
          </button>
          <button 
            onClick={() => setWizardStep(1)}
            className="flex items-center gap-2 px-4 py-2 text-[13px] bg-dp-amber text-black font-semibold hover:bg-yellow-400 transition-colors"
          >
            <Plus className="w-4 h-4" /> Deploy New Decoy
          </button>
        </div>
      </div>

      {/* Deployment Wizard */}
      {wizardStep > 0 && (
        <div className="glass-panel rounded-xl">
          {/* Wizard Header */}
          <div className="flex items-center justify-between px-5 py-3.5 border-b border-dp-line-soft glass-header rounded-t-xl">
            <div>
              <div className="text-[13px] font-semibold text-dp-text tracking-wide uppercase">Deployment Wizard</div>
              <div className="text-[11px] text-dp-text-faint mt-0.5">Configure and deploy an isolated honeypot container</div>
            </div>
            <div className="flex gap-1.5">
              {[1, 2, 3].map((s) => (
                <div key={s} className={`h-1.5 w-10 transition-colors ${wizardStep >= s ? "bg-dp-amber" : "bg-dp-line"}`} />
              ))}
            </div>
          </div>
          <div className="p-5">

            {/* STEP 1: TEMPLATE */}
            {wizardStep === 1 && (
              <div className="space-y-5">
                <div className="text-[12px] font-semibold text-dp-text-dim uppercase tracking-wider flex items-center gap-2">
                  <Shield className="w-4 h-4 text-dp-amber" /> Step 1 — Select Template
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {TEMPLATES.map(t => (
                    <div
                      key={t.id}
                      onClick={() => selectTemplate(t)}
                      className={`p-4 border rounded-lg cursor-pointer transition-all hover:-translate-y-0.5 hover:shadow-lg ${
                        newDecoyTemplate === t.id
                          ? "border-dp-teal bg-dp-teal/5 shadow-[0_0_15px_rgba(16,185,129,0.15)]"
                          : "border-dp-line bg-dp-panel-raised hover:border-dp-teal/50"
                      }`}
                    >
                      <div className="flex items-center gap-3 mb-2">
                        <span className="text-xl">{t.icon}</span>
                        <span className="font-semibold text-[13px] text-dp-text">{t.name}</span>
                      </div>
                      <p className="text-[11px] text-dp-text-faint">{t.desc}</p>
                      <div className="font-mono text-[10px] text-dp-text-dim mt-2">Default: {t.ports}</div>
                    </div>
                  ))}
                </div>
                <div className="flex justify-between pt-2">
                  <button onClick={() => setWizardStep(0)} className="flex items-center gap-2 px-4 py-2 text-[13px] border border-dp-line text-dp-text-dim hover:text-dp-text transition-colors">
                    Cancel
                  </button>
                  <button onClick={() => setWizardStep(2)} className="flex items-center gap-2 px-4 py-2 text-[13px] bg-dp-panel-raised border border-dp-line text-dp-text hover:bg-dp-line transition-colors">
                    Next <ArrowRight className="w-4 h-4" />
                  </button>
                </div>
              </div>
            )}

            {/* STEP 2: NETWORK */}
            {wizardStep === 2 && (
              <div className="space-y-5">
                <div className="text-[12px] font-semibold text-dp-text-dim uppercase tracking-wider flex items-center gap-2">
                  <Network className="w-4 h-4 text-dp-amber" /> Step 2 — Network Topology
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 max-w-2xl">
                  {newDecoyTemplate === 'custom' && (
                    <div className="space-y-1.5 md:col-span-2">
                      <label className="text-[11px] font-medium text-dp-text-dim uppercase tracking-wider">Custom Container Image</label>
                      <input type="text" className={inputClass} placeholder="e.g. nginx:latest, myrepo/custom-honeypot:v1" value={customImage} onChange={e => setCustomImage(e.target.value)} />
                    </div>
                  )}
                  <div className="space-y-1.5">
                    <label className="text-[11px] font-medium text-dp-text-dim uppercase tracking-wider">Decoy Name <span className="text-dp-text-faint text-[9px] lowercase">(Alphanumeric, '-', '_')</span></label>
                    <input type="text" className={inputClass} placeholder="e.g. ssh-decoy-01" value={newDecoyName} onChange={e => setNewDecoyName(e.target.value)} />
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-[11px] font-medium text-dp-text-dim uppercase tracking-wider">Port Mapping</label>
                    <input type="text" className={inputClass} placeholder={TEMPLATES.find(t => t.id === newDecoyTemplate)?.ports || "80:80"} value={newDecoyPort} onChange={e => setNewDecoyPort(e.target.value)} />
                  </div>
                  <div className="space-y-1.5 md:col-span-2">
                    <label className="text-[11px] font-medium text-dp-text-dim uppercase tracking-wider">Network Assignment</label>
                    <div className="flex flex-col gap-3 mt-1">
                      <label className="flex items-center gap-3 cursor-pointer">
                        <input 
                          type="radio" 
                          name="network_type" 
                          checked={networkType === 'new'} 
                          onChange={() => setNetworkType('new')}
                          className="accent-dp-amber"
                        />
                        <span className="text-[12px] text-dp-text">Create New Network (Auto-isolated)</span>
                      </label>
                      <label className="flex items-center gap-3 cursor-pointer">
                        <input 
                          type="radio" 
                          name="network_type" 
                          checked={networkType === 'existing'} 
                          onChange={() => setNetworkType('existing')}
                          className="accent-dp-amber"
                        />
                        <span className="text-[12px] text-dp-text">Attach to Existing Managed Network</span>
                      </label>
                      {networkType === 'existing' && (
                        <div className="pl-6 mt-1 relative max-w-sm">
                          <select 
                            className={`${inputClass} appearance-none pr-8 w-full`}
                            value={networkName}
                            onChange={(e) => setNetworkName(e.target.value)}
                          >
                            <option value="">Select a network...</option>
                            {networks?.map(n => <option key={n} value={n}>{n}</option>)}
                          </select>
                          <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dp-text-faint pointer-events-none" />
                        </div>
                      )}
                    </div>
                  </div>
                  <div className="space-y-1.5 mt-2 md:col-span-2">
                    <label className="text-[11px] font-medium text-dp-text-dim uppercase tracking-wider">Public Tunnel Exposure</label>
                    <div className="flex flex-col gap-3 mt-1">
                      <label className="flex items-center gap-3 cursor-pointer">
                        <input 
                          type="radio" 
                          name="tunnel_provider" 
                          checked={tunnelProvider === 'none'} 
                          onChange={() => setTunnelProvider('none')}
                          className="accent-dp-amber"
                        />
                        <span className="text-[12px] text-dp-text">None (Local network only)</span>
                      </label>
                      <label className="flex items-center gap-3 cursor-pointer" title={!deps?.frpc ? "FRP Client not installed" : ""}>
                        <input 
                          type="radio" 
                          name="tunnel_provider" 
                          checked={tunnelProvider === 'frp'} 
                          onChange={() => setTunnelProvider('frp')}
                          disabled={!deps?.frpc}
                          className="accent-dp-amber disabled:opacity-50"
                        />
                        <span className={`text-[12px] ${deps?.frpc ? "text-dp-text" : "text-dp-text-faint"}`}>FRP Tunnel (Self-hosted)</span>
                        {!deps?.frpc && <span className="text-[10px] text-dp-red ml-2 border border-dp-red px-1 py-0.5">Missing Binary</span>}
                      </label>
                      <label className="flex items-center gap-3 cursor-pointer" title={!deps?.ngrok ? "Ngrok not installed" : ""}>
                        <input 
                          type="radio" 
                          name="tunnel_provider" 
                          checked={tunnelProvider === 'ngrok'} 
                          onChange={() => setTunnelProvider('ngrok')}
                          disabled={!deps?.ngrok}
                          className="accent-dp-amber disabled:opacity-50"
                        />
                        <span className={`text-[12px] ${deps?.ngrok ? "text-dp-text" : "text-dp-text-faint"}`}>Ngrok Tunnel (Third-party)</span>
                        {!deps?.ngrok && <span className="text-[10px] text-dp-red ml-2 border border-dp-red px-1 py-0.5">Missing Binary</span>}
                      </label>
                    </div>
                  </div>
                  <div className="space-y-1.5 mt-2 md:col-span-2">
                    <label className="text-[11px] font-medium text-dp-text-dim uppercase tracking-wider">Auto-Restart Policy</label>
                    <div className="flex items-center gap-3 h-[38px] px-3 bg-dp-bg border border-dp-line cursor-pointer max-w-xs" onClick={() => setAutoRestart(!autoRestart)}>
                      <div className={`relative inline-flex h-4 w-8 items-center rounded-full transition-colors ${autoRestart ? "bg-dp-teal" : "bg-dp-line"}`}>
                        <span className={`inline-block h-3 w-3 transform rounded-full bg-white transition ${autoRestart ? "translate-x-4" : "translate-x-0.5"}`} />
                      </div>
                      <span className="text-[12px] text-dp-text-dim">{autoRestart ? "Enabled (backoff)" : "Disabled"}</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 mt-4 pt-4 border-t border-dp-line-soft">
                  <div className="flex items-center gap-3 h-[38px] cursor-pointer" onClick={() => setIsUnmanaged(!isUnmanaged)}>
                    <div className={`relative inline-flex h-4 w-8 items-center rounded-full transition-colors ${isUnmanaged ? "bg-dp-red" : "bg-dp-line"}`}>
                      <span className={`inline-block h-3 w-3 transform rounded-full bg-white transition ${isUnmanaged ? "translate-x-4" : "translate-x-0.5"}`} />
                    </div>
                  </div>
                  <div className="text-[11px] text-dp-text-faint">
                    <span className={`font-semibold ${isUnmanaged ? 'text-dp-red' : ''}`}>Advanced: Use unmanaged network.</span> I understand this bypasses DecoyOps' egress-deny enforcement (HC#3).
                  </div>
                </div>

                <div className="flex justify-between pt-2 mt-4">
                  <button onClick={() => setWizardStep(1)} className="flex items-center gap-2 px-4 py-2 text-[13px] border border-dp-line text-dp-text-dim hover:text-dp-text transition-colors">
                    <ArrowLeft className="w-4 h-4" /> Back
                  </button>
                  <button onClick={() => setWizardStep(3)} disabled={!newDecoyName} className="flex items-center gap-2 px-4 py-2 text-[13px] bg-dp-panel-raised border border-dp-line text-dp-text hover:bg-dp-line transition-colors disabled:opacity-30">
                    Next <ArrowRight className="w-4 h-4" />
                  </button>
                </div>
              </div>
            )}

            {/* STEP 3: REVIEW */}
            {wizardStep === 3 && (
              <div className="space-y-5">
                <div className="text-[12px] font-semibold text-dp-text-dim uppercase tracking-wider flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-dp-amber" /> Step 3 — Review & Egress Firewall
                </div>

                {hostOs === 'windows' ? (
                  <div className="bg-dp-amber/5 border border-dp-amber-dim p-4">
                    <div className="text-dp-amber font-semibold flex items-center gap-2 mb-1 text-[13px]">
                      <AlertTriangle className="w-4 h-4" /> Egress-Deny Not Enforced (Windows)
                    </div>
                    <p className="text-[11px] text-dp-amber/70">
                      Egress-Deny is not enforced on Windows until the WFP backend is implemented (ADR-002). The container will be deployed to an isolated bridge, but outbound egress filtering is currently inactive on this OS.
                    </p>
                  </div>
                ) : (
                  <div className="bg-dp-teal/5 border border-dp-teal-dim p-4">
                    <div className="text-dp-teal font-semibold flex items-center gap-2 mb-1 text-[13px]">
                      <Shield className="w-4 h-4" /> Egress-Deny Airgap Enabled
                    </div>
                    <p className="text-[11px] text-dp-teal/70">
                      DecoyOps will apply strict network isolation to the decoy. Zero network routes to host LAN.
                    </p>
                  </div>
                )}
                
                {isUnmanaged && (
                  <div className="bg-dp-red/5 border border-dp-red-dim p-4">
                    <div className="text-dp-red font-semibold flex items-center gap-2 mb-1 text-[13px]">
                      <AlertTriangle className="w-4 h-4" /> Unmanaged Network Mode Active
                    </div>
                    <p className="text-[11px] text-dp-red/70">
                      DecoyOps will NOT apply egress-deny rules. You must ensure the host network interface is externally isolated, otherwise the decoy can reach your internal LAN.
                    </p>
                  </div>
                )}

                {deployError && (
                  <div className="bg-dp-red/5 border border-dp-red-dim p-4 mt-2">
                    <div className="text-dp-red font-semibold flex items-center gap-2 mb-1 text-[13px]">
                      <AlertTriangle className="w-4 h-4" /> Deployment Failed
                    </div>
                    <p className="text-[11px] text-dp-red/70">{deployError}</p>
                  </div>
                )}

                <div className="grid grid-cols-[120px_1fr] gap-y-2 gap-x-4 text-[12px] bg-dp-bg/50 p-4 border border-dp-line max-w-lg rounded-lg">
                  <div className="text-dp-text-faint uppercase tracking-wider">Template</div>
                  <div className="font-mono text-dp-text">{newDecoyTemplate === 'custom' ? customImage : newDecoyTemplate}</div>
                  <div className="text-dp-text-faint">Name</div>
                  <div className="font-mono text-dp-amber">{newDecoyName}</div>
                  <div className="text-dp-text-faint">Ports</div>
                  <div className="font-mono text-dp-text">{newDecoyPort}</div>
                  <div className="text-dp-text-faint">Network</div>
                  <div className="font-mono text-dp-text">{networkName || `${newDecoyName}-net`} {isUnmanaged && <span className="text-dp-red">(UNMANAGED)</span>}</div>
                  <div className="text-dp-text-faint">Tunnel</div>
                  <div className="font-mono text-dp-text">{tunnelProvider === 'none' ? 'None' : tunnelProvider.toUpperCase()}</div>
                  <div className="text-dp-text-faint">Auto-Restart</div>
                  <div className="font-mono text-dp-text">{autoRestart ? "ON (backoff)" : "OFF"}</div>
                </div>

                <div className="flex justify-between pt-2">
                  <button onClick={() => setWizardStep(2)} className="flex items-center gap-2 px-4 py-2 text-[13px] border border-dp-line text-dp-text-dim hover:text-dp-text transition-colors">
                    <ArrowLeft className="w-4 h-4" /> Back
                  </button>
                  <button onClick={handleDeploy} disabled={isDeploying} className="flex items-center gap-2 px-4 py-2 text-[13px] bg-dp-amber text-dp-bg font-medium hover:opacity-90 transition-opacity disabled:opacity-30">
                    {isDeploying ? "Deploying..." : "Confirm & Deploy"}
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Fleet Table */}
      <div className={`glass-panel rounded-xl ${wizardStep > 0 ? "opacity-40 pointer-events-none" : ""}`}>
        <div className="flex items-center gap-2 px-5 py-3.5 border-b border-dp-line-soft glass-header rounded-t-xl">
          <Server className="w-4 h-4 text-dp-amber pulse-glow" />
          <span className="text-[13px] font-semibold text-dp-text tracking-wide uppercase">Active Fleet</span>
          <span className="ml-auto font-mono text-[11px] text-dp-text-faint">{decoys.length} container{decoys.length !== 1 ? "s" : ""}</span>
        </div>
        {decoys.length === 0 ? (
          <div className="flex items-center justify-center py-16">
            <div className="text-center space-y-1">
              <div className="text-[12px] text-dp-text-faint">No decoys deployed</div>
              <div className="text-[11px] text-dp-text-faint">Deploy one to start capturing attacks</div>
            </div>
          </div>
        ) : (
          <div className="overflow-auto">
            <table className="w-full text-[12.5px]">
              <thead>
                <tr className="border-b border-dp-line-soft">
                  <th className="h-9 px-5 text-left font-medium text-dp-text-faint uppercase text-[10px] tracking-wider">Name</th>
                  <th className="h-9 px-5 text-left font-medium text-dp-text-faint uppercase text-[10px] tracking-wider">Container</th>
                  <th className="h-9 px-5 text-left font-medium text-dp-text-faint uppercase text-[10px] tracking-wider">Tunnel (Public)</th>
                  <th className="h-9 px-5 text-left font-medium text-dp-text-faint uppercase text-[10px] tracking-wider">State</th>
                  <th className="h-9 px-5 text-right font-medium text-dp-text-faint uppercase text-[10px] tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody>
                {decoys.map((decoy: DecoyStatus) => (
                  <tr key={decoy.container_id} className={`border-b border-dp-line-soft transition-colors ${expandedDecoy === decoy.container_id ? 'bg-dp-panel-raised' : 'hover:bg-dp-teal/5'}`}>
                    <td className="px-5 py-3 font-medium text-dp-text">
                      <div className="flex items-center gap-2">
                        {decoy.state === "running" && <span className="w-1.5 h-1.5 rounded-full bg-dp-teal shadow-[0_0_8px_rgba(16,185,129,0.8)] animate-pulse" />}
                        {decoy.name}
                      </div>
                    </td>
                    <td className="px-5 py-3 font-mono text-[11px] text-dp-text-dim">{decoy.container_id.substring(0, 12)}</td>
                    <td className="px-5 py-3 font-mono text-[11px]">
                      {decoy.tunnel_provider ? (
                        decoy.tunnel_public_url ? (
                          <a href={`http://${decoy.tunnel_public_url}`} target="_blank" rel="noreferrer" className="text-dp-amber hover:underline break-all" title="Click to open">
                            {decoy.tunnel_public_url}
                          </a>
                        ) : (
                          <span className="text-dp-text-dim flex items-center gap-1.5"><Loader2 className="w-3 h-3 animate-spin" /> Provisioning...</span>
                        )
                      ) : (
                        <span className="text-dp-text-dim italic">Local Only</span>
                      )}
                    </td>
                    <td className="px-5 py-3">
                      <div className="flex items-center gap-2">
                        <span className={`w-2 h-2 rounded-full pulse-glow ${decoy.state === "running" ? "bg-dp-teal" : "bg-dp-red"}`} />
                        <span className={`font-mono text-[11px] ${decoy.state === "running" ? "text-dp-teal" : "text-dp-red"}`}>
                          {decoy.state.toUpperCase()}
                        </span>
                      </div>
                    </td>
                    <td className="px-5 py-3 text-right">
                      <div className="flex items-center justify-end gap-3">
                        <button
                          onClick={() => handleInspect(decoy.container_id)}
                          className={`text-dp-text-dim hover:text-dp-amber transition-colors ${expandedDecoy === decoy.container_id ? 'text-dp-amber' : ''}`}
                          title="Inspect Decoy"
                        >
                          <Info className="w-4 h-4" />
                        </button>
                        {decoy.state === "running" ? (
                          <>
                            <button
                              onClick={() => stopDecoy(decoy.container_id)}
                              className="text-dp-text-dim hover:text-dp-red transition-colors"
                              title="Stop Decoy"
                            >
                              <Square className="w-4 h-4" />
                            </button>
                            <button
                              onClick={() => restartDecoy(decoy.container_id)}
                              className="text-dp-text-dim hover:text-dp-amber transition-colors"
                              title="Restart Decoy"
                            >
                              <RotateCw className="w-4 h-4" />
                            </button>
                          </>
                        ) : (
                          <button
                            onClick={() => startDecoy(decoy.container_id)}
                            className="text-dp-text-dim hover:text-dp-teal transition-colors"
                            title="Start Decoy"
                          >
                            <Play className="w-4 h-4" />
                          </button>
                        )}
                        <button
                          onClick={() => terminateDecoy(decoy.container_id)}
                          className="text-dp-text-dim hover:text-dp-red transition-colors"
                          title="Terminate Decoy"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            
            {/* Expanded Details Panel */}
            {expandedDecoy && (
              <div className="bg-dp-bg/50 border-t border-dp-line p-5 font-mono text-[11px]">
                <div className="flex items-center justify-between mb-4">
                  <div className="text-[12px] font-semibold text-dp-text flex items-center gap-2">
                    <Info className="w-4 h-4 text-dp-amber" /> Container Inspector
                  </div>
                  <button onClick={() => setExpandedDecoy(null)} className="text-dp-text-dim hover:text-dp-text">
                    <X className="w-4 h-4" />
                  </button>
                </div>
                
                {isLoadingDetails ? (
                  <div className="text-dp-text-faint animate-pulse">Querying Docker Daemon...</div>
                ) : decoyDetails ? (
                  <div className="space-y-6">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      <div className="space-y-1">
                        <div className="text-dp-text-faint uppercase text-[9px] tracking-wider">Bridge IP Address</div>
                        <div className="text-dp-teal">{decoyDetails.ip_address || 'N/A'}</div>
                      </div>
                      <div className="space-y-1">
                        <div className="text-dp-text-faint uppercase text-[9px] tracking-wider">Network</div>
                        <div className="text-dp-text">{decoyDetails.network_name || 'N/A'}</div>
                      </div>
                      <div className="space-y-1">
                        <div className="text-dp-text-faint uppercase text-[9px] tracking-wider">Gateway</div>
                        <div className="text-dp-text">{decoyDetails.gateway || 'N/A'}</div>
                      </div>
                      <div className="space-y-1">
                        <div className="text-dp-text-faint uppercase text-[9px] tracking-wider">Port Bindings</div>
                        <div className="text-dp-text">
                          {decoyDetails.ports && decoyDetails.ports.length > 0 
                            ? decoyDetails.ports.join(', ') 
                            : 'None'}
                        </div>
                      </div>
                    </div>
                    
                    {/* Tunnel info if available */}
                    {decoys.find(d => d.container_id === expandedDecoy)?.tunnel_provider && (
                      <div className="bg-dp-bg/30 border border-dp-line p-3 mt-4 flex justify-between items-center">
                        <div>
                          <div className="text-dp-text-faint uppercase text-[9px] tracking-wider mb-1">Tunnel Provider</div>
                          <div className="text-dp-text font-semibold capitalize">{decoys.find(d => d.container_id === expandedDecoy)?.tunnel_provider}</div>
                        </div>
                        <div className="text-right">
                          <div className="text-dp-text-faint uppercase text-[9px] tracking-wider mb-1">Public Endpoint</div>
                          <div className="text-dp-amber font-mono">
                            {decoys.find(d => d.container_id === expandedDecoy)?.tunnel_public_url || 'Provisioning...'}
                          </div>
                        </div>
                      </div>
                    )}
                    
                    <div className="pt-4 border-t border-dp-line-soft mt-4">
                      <div className="flex flex-col gap-3">
                        {/* Egress Airgap Test */}
                        <div className="flex items-center gap-4">
                          <button 
                            onClick={() => handleVerifyIsolation(expandedDecoy)}
                            disabled={isVerifying}
                            className="flex items-center gap-2 px-3 py-1.5 text-[11px] bg-dp-panel border border-dp-line hover:border-dp-amber transition-colors disabled:opacity-50"
                          >
                            <Shield className="w-3.5 h-3.5" />
                            {isVerifying ? 'Verifying...' : 'Test Egress Airgap'}
                          </button>
                          
                          {verificationResult && (
                            <div className={`text-[11px] font-semibold flex items-center gap-2 ${verificationResult.status === 'success' ? 'text-dp-teal' : 'text-dp-red'}`}>
                              {verificationResult.status === 'success' ? <CheckCircle2 className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />}
                              {verificationResult.message}
                            </div>
                          )}
                        </div>

                        {/* PCAP Capture */}
                        <div className="flex items-center gap-4">
                          <div className="relative">
                            <select 
                              value={pcapDuration}
                              onChange={(e) => setPcapDuration(parseInt(e.target.value))}
                              disabled={isCapturing}
                              className="bg-dp-panel border border-dp-line px-2 py-1.5 pr-7 text-[11px] text-dp-text outline-none focus:border-dp-amber appearance-none"
                            >
                              <option value={15}>15s</option>
                              <option value={30}>30s</option>
                              <option value={60}>1 min</option>
                              <option value={300}>5 min</option>
                            </select>
                            <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3 h-3 text-dp-text-faint pointer-events-none" />
                          </div>
                          
                          <button 
                            onClick={() => handleCapturePcap(expandedDecoy)}
                            disabled={isCapturing}
                            className="flex items-center gap-2 px-3 py-1.5 text-[11px] bg-dp-panel border border-dp-line hover:border-dp-amber transition-colors disabled:opacity-50"
                            title="Deploys a temporary sidecar to capture raw network traffic"
                          >
                            <Network className="w-3.5 h-3.5" />
                            {isCapturing ? `Capturing (${pcapDuration}s)...` : 'Capture PCAP Snapshot'}
                          </button>
                          
                          {captureResult && (
                            <div className={`text-[11px] font-semibold flex items-center gap-2 ${captureResult.status === 'success' ? 'text-dp-teal' : 'text-dp-red'}`}>
                              {captureResult.status === 'success' ? <CheckCircle2 className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />}
                              {captureResult.message}
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="text-dp-red">Failed to load container details.</div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
      {/* Network Manager Modal */}
      {isNetworkManagerOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-md p-4 transition-opacity animate-fade-in">
          <div className="glass-panel w-full max-w-lg shadow-2xl flex flex-col rounded-xl border border-dp-line overflow-hidden">
            <div className="flex items-center justify-between p-4 border-b border-dp-line glass-header">
              <div className="text-[13px] font-semibold text-dp-text uppercase tracking-wider flex items-center gap-2">
                <Network className="w-4 h-4 text-dp-amber" /> Network Manager
              </div>
              <button onClick={() => setIsNetworkManagerOpen(false)} className="text-dp-text-dim hover:text-dp-text transition-colors">
                <X className="w-4 h-4" />
              </button>
            </div>
            
            <div className="p-4 overflow-y-auto max-h-[60vh] space-y-2 bg-dp-bg/40">
              {networks.length === 0 ? (
                <div className="text-[12px] text-dp-text-faint italic py-4 text-center">
                  No managed networks found.
                </div>
              ) : (
                networks.map(net => (
                  <div key={net} className="flex items-center justify-between bg-dp-panel p-3 border border-dp-line">
                    <span className="font-mono text-[12px] text-dp-teal">{net}</span>
                    <button 
                      onClick={() => handleDeleteNetwork(net)}
                      disabled={isDeletingNetwork === net}
                      className="text-dp-text-dim hover:text-dp-red disabled:opacity-50 transition-colors"
                      title="Delete Network (will fail if in use)"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                ))
              )}
              
              <div className="mt-4 p-3 bg-dp-panel-raised border border-dp-line-soft text-[11px] text-dp-text-faint leading-relaxed">
                <span className="text-dp-amber font-semibold block mb-1">Note:</span>
                Docker will automatically reject the deletion if the network is currently attached to any running or stopped containers.
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
