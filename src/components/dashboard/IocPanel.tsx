import React from 'react';
import { ShieldAlert, Globe, Link as LinkIcon, Cpu, Maximize2, Minimize2 } from 'lucide-react';
import { IocRow } from '../../lib/useDecoyOps';

interface IocPanelProps {
  iocs: IocRow[];
  isMaximized?: boolean;
  onToggleMaximize?: () => void;
}

export const IocPanel: React.FC<IocPanelProps> = ({ iocs, isMaximized, onToggleMaximize }) => {
  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <div className="flex flex-col h-full bg-transparent">
      <div className="flex items-center justify-between px-5 py-3.5 border-b border-dp-line-soft glass-header shrink-0">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-dp-amber" />
          <div>
            <div className="text-[13px] font-semibold tracking-wide text-dp-text uppercase">
              Indicators of Compromise
            </div>
            <div className="text-[11px] text-dp-text-faint mt-0.5">
              Live extracted IPs and URLs
            </div>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <div className="text-[10px] uppercase font-mono text-dp-text-faint bg-dp-line/30 px-2 py-0.5 rounded border border-dp-line-soft">
            Auto-Feed
          </div>
          {onToggleMaximize && (
            <button 
              onClick={onToggleMaximize}
              className="text-dp-text-dim hover:text-dp-text transition-colors p-1"
              title={isMaximized ? "Minimize Panel" : "Maximize Panel"}
            >
              {isMaximized ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
            </button>
          )}
        </div>
      </div>
      <div className="flex-1 overflow-y-auto custom-scrollbar bg-dp-bg/30">
        {iocs.length === 0 ? (
          <div className="flex items-center justify-center h-full">
            <div className="text-center space-y-2">
              <Cpu className="w-6 h-6 text-dp-text-faint opacity-50 mx-auto" />
              <div className="font-mono text-[11px] text-dp-text-faint">No IoCs extracted yet</div>
            </div>
          </div>
        ) : (
          <div className="divide-y divide-dp-line-soft">
            {iocs.map((ioc) => (
              <div
                key={ioc.id}
                className="flex items-center justify-between px-5 py-3 hover:bg-dp-teal/5 transition-colors group"
              >
                <div className="flex items-center gap-3 overflow-hidden">
                  <div className="shrink-0">
                    {ioc.ioc_type === 'URL' ? (
                      <LinkIcon className="w-4 h-4 text-dp-amber" />
                    ) : (
                      <Globe className="w-4 h-4 text-dp-teal" />
                    )}
                  </div>
                  <div className="flex flex-col overflow-hidden">
                    <span className="text-[11.5px] font-mono text-dp-text truncate">
                      {ioc.ioc_value}
                    </span>
                    <span className="text-[10px] font-mono text-dp-text-faint flex gap-2 pt-0.5">
                      <span>{ioc.ioc_type}</span>
                      <span>·</span>
                      <span>{ioc.container_id.substring(0, 8)}</span>
                    </span>
                  </div>
                </div>
                <button
                  onClick={() => handleCopy(ioc.ioc_value)}
                  className="opacity-0 group-hover:opacity-100 transition-opacity text-[10px] font-mono text-dp-text-dim hover:text-dp-text bg-dp-panel-raised border border-dp-line px-2 py-1 rounded"
                >
                  COPY
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
