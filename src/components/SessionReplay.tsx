import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { X, Terminal } from "lucide-react";

interface SessionReplayProps {
  logPath: string;
  onClose: () => void;
}

export function SessionReplay({ logPath, onClose }: SessionReplayProps) {
  const [content, setContent] = useState<string>("Loading TTY log...");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchLog = async () => {
      try {
        const rawContent = await invoke<string>("read_tty_log", { logPath });
        setContent(rawContent);
      } catch (err: any) {
        console.error("Failed to read log:", err);
        setError(err.toString());
      }
    };
    fetchLog();
  }, [logPath]);

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-8">
      <div className="w-full max-w-4xl h-[80vh] flex flex-col bg-dp-panel border border-dp-line shadow-2xl rounded">
        
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-3 border-b border-dp-line-soft shrink-0">
          <div className="flex items-center gap-3">
            <Terminal className="w-4 h-4 text-dp-amber" />
            <div>
              <div className="text-[13px] font-semibold text-dp-text">Session Replay (Untrusted Input)</div>
              <div className="text-[11px] font-mono text-dp-text-faint truncate max-w-lg mt-0.5">
                {logPath}
              </div>
            </div>
          </div>
          <button 
            onClick={onClose}
            className="p-1.5 text-dp-text-dim hover:text-dp-text hover:bg-dp-panel-raised rounded transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Terminal Body */}
        <div className="flex-1 overflow-auto bg-[#0C0C0C] p-4 text-[#CCCCCC] font-mono text-[12px] leading-relaxed">
          {error ? (
            <div className="text-dp-red">Error: {error}</div>
          ) : (
            // Security: Rendering as plain text without parsing escape sequences
            <pre className="whitespace-pre-wrap break-all">{content}</pre>
          )}
        </div>
        
        {/* Footer */}
        <div className="px-5 py-2.5 border-t border-dp-line-soft bg-dp-panel-raised shrink-0 flex justify-between items-center">
          <div className="text-[10px] text-dp-text-faint font-mono">
            RAW HEX / TEXT MODE (Escape Sequences Disabled)
          </div>
          <button 
            onClick={onClose}
            className="text-[11px] font-medium text-dp-text hover:text-white px-4 py-1.5 border border-dp-line hover:border-dp-line-soft rounded bg-dp-panel transition-colors"
          >
            Close Viewer
          </button>
        </div>

      </div>
    </div>
  );
}
