import { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { FileWarning, FileCode2, Search, Shield } from 'lucide-react';

interface CapturedFile {
  id: number;
  session_id: number;
  container_id: string;
  sha256: string;
  original_name: string | null;
  file_size: number | null;
  isolated_path: string;
  vt_status: string | null;
  vt_result_json: string | null;
  operator_upload_consent: boolean;
  captured_at: string;
}

function detectFileType(hexDump: string): string {
  if (!hexDump || hexDump.length < 8) return "Unknown";
  const magic = hexDump.substring(0, 8).toLowerCase();
  if (magic.startsWith("4d5a")) return "PE Executable (Windows)";
  if (magic.startsWith("7f454c46")) return "ELF Binary (Linux)";
  if (magic.startsWith("cafebabe")) return "Java Class / Mach-O Fat";
  if (magic.startsWith("504b0304")) return "ZIP / JAR / APK Archive";
  if (magic.startsWith("1f8b")) return "GZIP Compressed";
  if (magic.startsWith("25504446")) return "%PDF Document";
  if (magic.startsWith("d0cf11e0")) return "MS Office (OLE2)";
  if (magic.startsWith("89504e47")) return "PNG Image";
  if (magic.startsWith("23212f")) return "Shell Script (#!/)";
  return "Unknown binary";
}

export function Quarantine() {
  const [files, setFiles] = useState<CapturedFile[]>([]);
  const [selectedFile, setSelectedFile] = useState<CapturedFile | null>(null);
  const [hexDump, setHexDump] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [vtLoading, setVtLoading] = useState(false);
  const [vtResult, setVtResult] = useState<string | null>(null);

  useEffect(() => {
    fetchQuarantine();
    const id = setInterval(fetchQuarantine, 5000);
    return () => clearInterval(id);
  }, []);

  const fetchQuarantine = async () => {
    try {
      const data = await invoke<CapturedFile[]>('get_quarantined_files');
      setFiles(data);
    } catch (e) {
      console.error(e);
    }
  };

  const handleSelectFile = async (file: CapturedFile) => {
    setSelectedFile(file);
    setHexDump(null);
    setVtResult(null);
    setIsLoading(true);
    try {
      const hex = await invoke<string>('read_quarantine_hex', { filePath: file.isolated_path });
      setHexDump(hex);
    } catch (e) {
      setHexDump(null);
    }
    setIsLoading(false);
  };

  const handleVtLookup = async () => {
    if (!selectedFile) return;
    setVtLoading(true);
    try {
      const result = await invoke<string>('enrich_hash', { hash: selectedFile.sha256 });
      setVtResult(result);
    } catch (e: any) {
      setVtResult(`Lookup failed: ${e}`);
    }
    setVtLoading(false);
  };

  const formatHex = (raw: string): string => {
    if (!raw) return "";
    const bytes = raw.match(/.{1,2}/g) || [];
    const lines: string[] = [];
    for (let i = 0; i < bytes.length; i += 16) {
      const offset = i.toString(16).padStart(8, "0");
      const hexPart = bytes.slice(i, i + 16).join(" ");
      const asciiPart = bytes.slice(i, i + 16).map((b) => {
        const code = parseInt(b, 16);
        return code >= 32 && code < 127 ? String.fromCharCode(code) : ".";
      }).join("");
      lines.push(`${offset}  ${hexPart.padEnd(47)}  |${asciiPart}|`);
    }
    return lines.join("\n");
  };

  return (
    <div className="flex-1 min-h-0 overflow-hidden flex flex-col bg-transparent">
      {/* Header */}
      <div className="px-6 py-4 border-b border-dp-line-soft">
        <h1 className="text-xl font-semibold text-dp-text">Forensic Inspector</h1>
        <p className="text-[12px] text-dp-text-faint mt-1">Safely inspect quarantined malware payloads intercepted by decoys. All files are chmod 000 with .isolated suffix.</p>
      </div>

      <div className="flex-1 min-h-0 overflow-hidden grid grid-cols-[1fr_380px] p-5 gap-5">
        {/* File List */}
        <div className="glass-panel flex flex-col overflow-auto rounded-xl">
          <div className="flex items-center gap-2 px-5 py-3 border-b border-dp-line-soft glass-header rounded-t-xl">
            <FileWarning className="w-4 h-4 text-dp-red pulse-glow" />
            <span className="text-[13px] font-semibold text-dp-text tracking-wide uppercase">Isolated Payloads</span>
            <span className="ml-auto font-mono text-[11px] text-dp-text-faint">{files.length} file{files.length !== 1 ? "s" : ""}</span>
          </div>
          {files.length === 0 ? (
            <div className="flex items-center justify-center h-64">
              <div className="text-center space-y-1">
                <div className="text-[12px] text-dp-text-faint">No payloads intercepted</div>
                <div className="text-[11px] text-dp-text-faint">Deploy a decoy to start capturing malware</div>
              </div>
            </div>
          ) : (
            <table className="w-full text-[12px]">
              <thead>
                <tr className="border-b border-dp-line-soft">
                  <th className="h-8 px-5 text-left font-medium text-dp-text-faint uppercase text-[10px] tracking-wider">Captured</th>
                  <th className="h-8 px-5 text-left font-medium text-dp-text-faint uppercase text-[10px] tracking-wider">SHA-256</th>
                  <th className="h-8 px-5 text-left font-medium text-dp-text-faint uppercase text-[10px] tracking-wider">Size</th>
                  <th className="h-8 px-5 text-left font-medium text-dp-text-faint uppercase text-[10px] tracking-wider">VT</th>
                </tr>
              </thead>
              <tbody>
                {files.map(file => (
                  <tr
                    key={file.id}
                    onClick={() => handleSelectFile(file)}
                    className={`border-b border-dp-line-soft cursor-pointer transition-colors ${
                      selectedFile?.id === file.id ? "bg-dp-panel-raised" : "hover:bg-dp-teal/5"
                    }`}
                  >
                    <td className="px-5 py-2.5 font-mono text-[10.5px] text-dp-text-dim">{new Date(file.captured_at).toLocaleString()}</td>
                    <td className="px-5 py-2.5 font-mono text-[10.5px] text-dp-text-dim" title={file.sha256}>{file.sha256.substring(0, 16)}…</td>
                    <td className="px-5 py-2.5 font-mono text-[10.5px] text-dp-text-dim">{file.file_size ? `${(file.file_size / 1024).toFixed(1)} KB` : "—"}</td>
                    <td className="px-5 py-2.5">
                      <span className={`font-mono text-[9px] px-1.5 py-0.5 border ${
                        file.vt_status === "clean" ? "border-dp-teal-dim text-dp-teal" :
                        file.vt_status === "malicious" ? "border-dp-red-dim text-dp-red" :
                        "border-dp-line text-dp-text-faint"
                      }`}>
                        {(file.vt_status ?? "PENDING").toUpperCase()}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Inspection Panel */}
        <div className="glass-panel flex flex-col overflow-hidden rounded-xl">
          {selectedFile ? (
            <>
              <div className="px-5 py-3.5 border-b border-dp-line-soft bg-dp-red/5 glass-header rounded-t-xl">
                <div className="flex items-center gap-2">
                  <FileCode2 className="w-4 h-4 text-dp-red" />
                  <span className="text-[13px] font-semibold text-dp-red tracking-wide uppercase">Payload Analysis</span>
                </div>
              </div>
              <div className="flex-1 overflow-y-auto px-5 py-4 space-y-4">
                <div>
                  <div className="text-[10px] text-dp-text-faint uppercase tracking-wider mb-1">SHA-256 Hash</div>
                  <div className="font-mono text-[10.5px] text-dp-text break-all bg-dp-bg p-2 border border-dp-line">{selectedFile.sha256}</div>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <div className="text-[10px] text-dp-text-faint uppercase tracking-wider mb-1">Original Name</div>
                    <div className="font-mono text-[11px] text-dp-text">{selectedFile.original_name || "N/A"}</div>
                  </div>
                  <div>
                    <div className="text-[10px] text-dp-text-faint uppercase tracking-wider mb-1">File Type</div>
                    <div className="font-mono text-[11px] text-dp-text">{hexDump ? detectFileType(hexDump) : "—"}</div>
                  </div>
                </div>
                <div>
                  <div className="flex justify-between items-center mb-1">
                    <div className="text-[10px] text-dp-text-faint uppercase tracking-wider">Hex Preview (Read-Only)</div>
                    <div className="font-mono text-[9px] text-dp-teal">chmod 000 · .isolated</div>
                  </div>
                  <div className="bg-dp-bg border border-dp-line p-2 h-48 overflow-y-auto">
                    {isLoading ? (
                      <div className="font-mono text-[10px] text-dp-text-faint animate-pulse">Reading bytes…</div>
                    ) : (
                      <pre className="font-mono text-[9.5px] text-dp-text-dim leading-relaxed whitespace-pre">
                        {hexDump ? formatHex(hexDump) : "No data"}
                      </pre>
                    )}
                  </div>
                </div>
                <div className="border-t border-dp-line-soft pt-4 space-y-2">
                  <button
                    onClick={handleVtLookup}
                    disabled={vtLoading}
                    className="w-full flex items-center justify-center gap-2 px-4 py-2 text-[12px] font-medium border border-dp-amber-dim bg-dp-amber/5 text-dp-amber hover:bg-dp-amber/10 transition-colors disabled:opacity-30"
                  >
                    <Shield className="w-3.5 h-3.5" />
                    {vtLoading ? "Querying VirusTotal…" : "Threat Score (VirusTotal)"}
                  </button>
                  <div className="text-[10px] text-dp-text-faint text-center">Hash-only lookup. No file upload (HC#2).</div>
                  {vtResult && (
                    <div className="bg-dp-bg border border-dp-line p-2 font-mono text-[10px] text-dp-text-dim max-h-32 overflow-y-auto">
                      {vtResult}
                    </div>
                  )}
                </div>
              </div>
            </>
          ) : (
            <div className="flex items-center justify-center h-full">
              <div className="text-center space-y-2">
                <Search className="w-6 h-6 text-dp-text-faint mx-auto" />
                <div className="text-[12px] text-dp-text-faint">Select a payload to inspect</div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
