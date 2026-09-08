import { BookOpen, Shield, Terminal, CheckCircle2, AlertTriangle, Cpu, Globe, Crosshair, Lock } from 'lucide-react';

export function Guide() {
  return (
    <div className="flex-1 overflow-auto p-8 flex flex-col gap-10 bg-dp-bg">
      {/* Header */}
      <div className="border-b border-dp-line-soft pb-6">
        <h1 className="text-2xl font-bold text-dp-text flex items-center gap-3">
          <BookOpen className="w-6 h-6 text-dp-amber" /> DecoyOps: Comprehensive Operator Guide
        </h1>
        <p className="text-[13px] text-dp-text-faint mt-2 max-w-3xl leading-relaxed">
          Welcome to the DecoyOps documentation. This extensive guide covers everything from the theoretical basics of honeypots to advanced deployment architectures, incident response, and threat intelligence configuration. 
        </p>
      </div>

      <div className="max-w-4xl space-y-12">
        
        {/* Section 1: Introduction to Honeypots */}
        <section className="space-y-4">
          <h2 className="text-lg font-semibold text-dp-text flex items-center gap-2 border-l-4 border-dp-amber pl-3">
            <Shield className="w-5 h-5 text-dp-amber" /> 1. Understanding Honeypots & DecoyOps Architecture
          </h2>
          <div className="text-[13px] text-dp-text-dim space-y-3 leading-relaxed bg-dp-panel border border-dp-line p-5">
            <p>
              A <strong>honeypot</strong> is a decoy system deployed alongside production infrastructure. It serves no legitimate business purpose, meaning <em>any</em> interaction with it is by definition unauthorized and highly suspicious. 
            </p>
            <p>
              <strong>DecoyOps</strong> automates the deployment of containerized honeypots using Docker. Rather than manually configuring virtual machines, DecoyOps spins up lightweight, purpose-built Docker containers that emulate vulnerable services (like SSH, FTP, or Industrial Control Systems).
            </p>
            <div className="mt-4 p-4 border border-dp-teal-dim bg-dp-teal/5">
              <h3 className="font-semibold text-dp-teal mb-2 flex items-center gap-2"><Lock className="w-4 h-4"/> Zero-Trust Airgap (HC#3)</h3>
              <p className="text-dp-teal/80 text-[12px]">
                By default, every decoy deployed by DecoyOps is placed on its own isolated Docker bridge network. On supported Linux hosts, DecoyOps dynamically injects strict <code>nftables</code> egress rules that <strong>drop all outbound traffic</strong> from the honeypot subnet. Attackers can connect <em>in</em>, but they cannot pivot <em>out</em> to your internal LAN.
              </p>
            </div>
          </div>
        </section>

        {/* Section 2: Deployment Guide */}
        <section className="space-y-4">
          <h2 className="text-lg font-semibold text-dp-text flex items-center gap-2 border-l-4 border-dp-amber pl-3">
            <Cpu className="w-5 h-5 text-dp-amber" /> 2. Deploying & Managing the Fleet
          </h2>
          <div className="text-[13px] text-dp-text-dim space-y-4 leading-relaxed bg-dp-panel border border-dp-line p-5">
            <p>
              The <strong>Deploy Decoy</strong> tab is where you configure and launch your honeypots. The deployment wizard consists of three phases:
            </p>
            
            <h3 className="font-semibold text-dp-text mt-4">A. Template Selection</h3>
            <p>DecoyOps comes with built-in templates optimized for threat capture:</p>
            <ul className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-2">
              <li className="bg-dp-bg border border-dp-line-soft p-3">
                <span className="font-semibold text-dp-amber block mb-1">Cowrie</span>
                A medium-to-high interaction SSH and Telnet honeypot designed to log brute force attacks and the shell interaction performed by the attacker.
              </li>
              <li className="bg-dp-bg border border-dp-line-soft p-3">
                <span className="font-semibold text-dp-amber block mb-1">Dionaea</span>
                A "nepenthes" successor designed to trap malware exploiting vulnerabilities exposed by services to networks (SMB, HTTP, FTP).
              </li>
              <li className="bg-dp-bg border border-dp-line-soft p-3">
                <span className="font-semibold text-dp-amber block mb-1">Conpot</span>
                An ICS/SCADA honeypot designed to simulate industrial control systems (like Siemens S7).
              </li>
              <li className="bg-dp-bg border border-dp-line-soft p-3">
                <span className="font-semibold text-dp-amber block mb-1">Custom Container</span>
                Allows you to specify any arbitrary Docker image (e.g., <code>nginx:latest</code> or <code>myrepo/custom-decoy:v2</code>) and bind custom ports.
              </li>
            </ul>

            <h3 className="font-semibold text-dp-text mt-6">B. Network Configuration & Port Mapping</h3>
            <ul className="list-disc pl-5 space-y-2 text-dp-text-faint">
              <li><strong>Port Mapping (Host:Container):</strong> E.g., <code>2222:2222</code> means traffic hitting port 2222 on your physical machine is routed to port 2222 inside the isolated container. <em>(Note: Mapping to standard ports like 22 or 80 increases the Realism Score).</em></li>
              <li><strong>Bridge Subnet CIDR:</strong> The isolated internal IP range for the decoy (default: <code>172.20.0.0/16</code>).</li>
              <li><strong>Auto-Restart Policy:</strong> If enabled, Docker will automatically restart the container using an exponential backoff if it crashes (useful for brittle honeypots).</li>
            </ul>

            <h3 className="font-semibold text-dp-text mt-6 flex items-center gap-2"><AlertTriangle className="w-4 h-4 text-dp-red"/> C. Advanced Unmanaged Networks</h3>
            <p className="text-[12px]">
              If you check the "Use unmanaged network" box during Step 2, you are explicitly bypassing the DecoyOps firewall. The application will <strong>not</strong> apply egress-deny rules. You should only use this if you have manually segmented your physical network at the hardware switch or hypervisor level.
            </p>
          </div>
        </section>

        {/* Section 3: Testing Methodology */}
        <section className="space-y-4">
          <h2 className="text-lg font-semibold text-dp-text flex items-center gap-2 border-l-4 border-dp-amber pl-3">
            <Crosshair className="w-5 h-5 text-dp-amber" /> 3. Validating & Attacking Your Honeypot
          </h2>
          <div className="text-[13px] text-dp-text-dim space-y-3 leading-relaxed bg-dp-panel border border-dp-line p-5">
            <p>
              Once a decoy is active in the Fleet table, you must validate that it is reachable and properly logging telemetry. You do not need to use the internal <code>172.x.x.x</code> bridge IP to test it.
            </p>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
              <div className="bg-dp-bg border border-dp-line-soft p-4">
                <h4 className="font-semibold text-dp-text mb-2 text-[12px] uppercase tracking-wider">Method A: Localhost Testing</h4>
                <p className="text-[12px] mb-3">Run this from the same machine running DecoyOps.</p>
                <div className="font-mono text-[10.5px] bg-[#0d0d0d] p-3 text-dp-text-dim">
                  <span className="text-dp-teal"># Assuming Cowrie mapped to 2222</span><br/>
                  ssh root@127.0.0.1 -p 2222<br/>
                  <br/>
                  <span className="text-dp-teal"># Assuming Dionaea mapped to 445</span><br/>
                  smbclient -L //127.0.0.1 -U guest
                </div>
              </div>

              <div className="bg-dp-bg border border-dp-line-soft p-4">
                <h4 className="font-semibold text-dp-text mb-2 text-[12px] uppercase tracking-wider">Method B: LAN / VM Testing</h4>
                <p className="text-[12px] mb-3">Run this from a separate Kali Linux VM or laptop on the same network.</p>
                <div className="font-mono text-[10.5px] bg-[#0d0d0d] p-3 text-dp-text-dim">
                  <span className="text-dp-teal"># Find your host machine's IP (e.g. 192.168.1.50)</span><br/>
                  <span className="text-dp-teal"># Run an Nmap service scan</span><br/>
                  nmap -sV -p 2222 192.168.1.50<br/>
                  <br/>
                  <span className="text-dp-teal"># Attempt SSH login</span><br/>
                  ssh admin@192.168.1.50 -p 2222
                </div>
              </div>
            </div>
            
            <p className="mt-4 text-[12px] text-dp-text-faint">
              <strong>Tip:</strong> You can click the <strong>Inspect (i)</strong> button on any running decoy in the Fleet table to reveal its exact Bridge IP, Network Name, and live port bindings.
            </p>
          </div>
        </section>

        {/* Section 4: Telemetry & Threat Intel */}
        <section className="space-y-4">
          <h2 className="text-lg font-semibold text-dp-text flex items-center gap-2 border-l-4 border-dp-amber pl-3">
            <Globe className="w-5 h-5 text-dp-amber" /> 4. Telemetry, Threat Map, & Quarantine
          </h2>
          <div className="text-[13px] text-dp-text-dim space-y-3 leading-relaxed bg-dp-panel border border-dp-line p-5">
            <p>
              As attackers interact with your decoys, telemetry flows instantly into the <strong>Command Center</strong>.
            </p>
            <ul className="list-disc pl-5 space-y-2 text-dp-text-faint">
              <li>
                <strong>Live Threat Map (Deck.gl):</strong> Visualizes the geographic origin of incoming attacks. <em>Important:</em> For IPs to be plotted on the map, you must configure the MaxMind GeoLite2 database in the Settings tab. Otherwise, attacks will appear in the feed but won't be mapped.
              </li>
              <li>
                <strong>Trend Dashboard (24H/7D):</strong> Histograms and leaderboards showing attack frequency, top targeted ports (vectors), and the most aggressive source IPs.
              </li>
              <li>
                <strong>Realism Score:</strong> A metric (0-100) indicating how believable a decoy is. Deploying a custom image on a non-standard port (like 2222) lowers the score. Deploying Cowrie on port 22 yields a high score.
              </li>
            </ul>

            <h3 className="font-semibold text-dp-text mt-6">Quarantine & Incident Response</h3>
            <p>
              If a decoy like Dionaea or Cowrie captures a file (e.g., an attacker attempts to download a malicious bash script via <code>wget</code> inside the honeypot), DecoyOps intercepts the file transfer.
            </p>
            <div className="bg-dp-bg/50 border border-dp-line-soft p-4 mt-2 text-[12px]">
              The file is immediately saved to the host, <strong>its execution permissions are stripped (chmod 000)</strong>, and it is appended with an <code>.isolated</code> suffix. This guarantees the malware cannot be accidentally executed on your host machine.
            </div>
            <p className="mt-2">
              In the <strong>Quarantine</strong> tab, you can view the SHA-256 hash of these captured payloads. By configuring a VirusTotal API key in Settings, you can click to query VirusTotal and determine exactly what malware family attempted to infect your honeypot.
            </p>
          </div>
        </section>

        {/* Section 5: Configuration */}
        <section className="space-y-4">
          <h2 className="text-lg font-semibold text-dp-text flex items-center gap-2 border-l-4 border-dp-amber pl-3">
            <Terminal className="w-5 h-5 text-dp-amber" /> 5. Initial Configuration Checklist
          </h2>
          <div className="text-[13px] text-dp-text-dim space-y-3 leading-relaxed bg-dp-panel border border-dp-line p-5">
            <p>To get the most out of DecoyOps, ensure you configure the following in the <strong>Settings</strong> tab:</p>
            <ol className="list-decimal pl-5 space-y-3 text-dp-text-faint mt-2">
              <li>
                <strong>MaxMind GeoLite2:</strong> Required for the Live Threat Map. Create a free MaxMind account, generate a license key, and input it to enable IP-to-Geolocation mapping.
              </li>
              <li>
                <strong>VirusTotal API Key:</strong> Required for the Quarantine tab. Create a free VirusTotal account and paste the API key to enable instant malware hash lookups.
              </li>
              <li>
                <strong>AbuseIPDB API Key:</strong> Required for Threat Intel. Allows you to check if attacking IPs have been reported by other security researchers globally.
              </li>
            </ol>
            <div className="mt-4 text-[12px] flex items-center gap-2 text-dp-amber">
              <CheckCircle2 className="w-4 h-4"/> <em>All API keys are securely stored in your operating system's native keychain (ADR-003) and are never logged or stored in plain text.</em>
            </div>
          </div>
        </section>
        {/* Section 6: Best Practices & Strategy */}
        <section className="space-y-4">
          <h2 className="text-lg font-semibold text-dp-text flex items-center gap-2 border-l-4 border-dp-amber pl-3">
            <Shield className="w-5 h-5 text-dp-amber" /> 6. Best Practices & Operational Strategy
          </h2>
          <div className="text-[13px] text-dp-text-dim space-y-6 leading-relaxed bg-dp-panel border border-dp-line p-5">
            
            <div className="space-y-2">
              <h3 className="font-semibold text-dp-text">A. Monitor and Analyze Activity</h3>
              <ul className="list-disc pl-5 space-y-1 text-dp-text-faint">
                <li><strong>Log Files:</strong> Review the raw logs (bind-mounted in the `data/logs/` directory on your host) for deep details about attempted attacks.</li>
                <li><strong>Packet Captures:</strong> For advanced analysis, you can attach tools like Wireshark or <code>tcpdump</code> to the virtual bridge interface created by DecoyOps to analyze raw network traffic entering the honeypot.</li>
                <li><strong>Behavior Analysis:</strong> Use the 24H and 7D views in the Command Center to identify patterns in attacker behavior (e.g., automated botnets scanning sequentially vs. targeted manual exploitation).</li>
              </ul>
            </div>

            <div className="space-y-2">
              <h3 className="font-semibold text-dp-text">B. Mitigate Risks</h3>
              <ul className="list-disc pl-5 space-y-1 text-dp-text-faint">
                <li><strong>Isolation Verification:</strong> Always ensure the honeypot cannot be used as a launchpad for further attacks. DecoyOps handles this automatically via the <code>nftables</code> egress-deny feature, but you should routinely verify it (e.g., attempt to ping <code>8.8.8.8</code> from inside the container).</li>
                <li><strong>Regular Updates:</strong> Keep the honeypot container software updated (by redeploying with the <code>:latest</code> tag) to address vulnerabilities that might allow container escapes.</li>
                <li><strong>Access Controls:</strong> Restrict who can physically access this machine or view the DecoyOps dashboard, as the telemetry data itself can be sensitive.</li>
              </ul>
            </div>

            <div className="space-y-2">
              <h3 className="font-semibold text-dp-text">C. Leverage Insights</h3>
              <p className="text-dp-text-faint">The data collected by DecoyOps is only useful if it informs your broader security strategy:</p>
              <ul className="list-disc pl-5 space-y-1 text-dp-text-faint">
                <li><strong>Update Defenses:</strong> Extract aggressive IP addresses from the Command Center and block them at your edge firewall or IDS/IPS.</li>
                <li><strong>Educate your team:</strong> Review quarantined payloads and TTY sessions to train junior analysts on emerging threat tactics.</li>
                <li><strong>Contribute:</strong> By querying VirusTotal and AbuseIPDB, you inherently contribute anonymized data points that assist global threat intelligence platforms.</li>
              </ul>
            </div>

          </div>
        </section>

      </div>
    </div>
  );
}
