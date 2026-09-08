import { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { ShieldAlert, CheckCircle, XCircle } from 'lucide-react';

export interface DependenciesStatus {
  docker: boolean;
  ngrok: boolean;
  frpc: boolean;
}

export function DependencyCheckModal({ onReady, setDeps }: { onReady: () => void, setDeps: (deps: DependenciesStatus) => void }) {
  const [status, setStatus] = useState<DependenciesStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const check = async () => {
    setLoading(true);
    try {
      const res: DependenciesStatus = await invoke('check_dependencies');
      setStatus(res);
      setDeps(res);
      if (res.docker) {
        onReady();
      }
    } catch (e: any) {
      setError(e.toString());
    }
    setLoading(false);
  };

  useEffect(() => {
    check();
  }, []);

  if (loading) {
    return (
      <div className="fixed inset-0 bg-dp-bg/95 backdrop-blur-md z-[100] flex items-center justify-center">
        <div className="text-center space-y-4">
          <div className="w-8 h-8 border-2 border-dp-teal border-t-transparent rounded-full animate-spin mx-auto" />
          <div className="font-mono text-[12px] text-dp-text-faint tracking-widest uppercase">Checking System Dependencies...</div>
        </div>
      </div>
    );
  }

  if (status && status.docker) {
    return null; // Don't render anything if Docker is available
  }

  return (
    <div className="fixed inset-0 bg-dp-bg/95 backdrop-blur-md z-[100] flex items-center justify-center">
      <div className="glass-panel w-[400px] rounded-xl overflow-hidden shadow-2xl shadow-black/50 border border-dp-red/30">
        <div className="bg-dp-red/10 border-b border-dp-red/20 px-5 py-4 flex items-center gap-3">
          <ShieldAlert className="w-5 h-5 text-dp-red" />
          <div>
            <h2 className="text-[14px] font-semibold text-dp-red">Missing Critical Dependency</h2>
            <p className="text-[11px] text-dp-text-faint">DecoyOps cannot launch</p>
          </div>
        </div>
        
        <div className="p-5 space-y-4">
          <p className="text-[12px] text-dp-text-dim leading-relaxed">
            DecoyOps uses Docker to strictly isolate honeypot containers and enforce egress-deny networking rules. 
            Your system must have Docker installed and running.
          </p>
          
          <div className="bg-dp-bg border border-dp-line rounded-lg p-3 space-y-2">
            <div className="flex items-center justify-between text-[12px]">
              <span className="text-dp-text font-mono">Docker Engine</span>
              {status?.docker ? (
                <CheckCircle className="w-4 h-4 text-dp-teal" />
              ) : (
                <XCircle className="w-4 h-4 text-dp-red" />
              )}
            </div>
            <div className="flex items-center justify-between text-[12px]">
              <span className="text-dp-text font-mono">Ngrok</span>
              {status?.ngrok ? (
                <CheckCircle className="w-4 h-4 text-dp-teal" />
              ) : (
                <XCircle className="w-4 h-4 text-dp-text-faint" />
              )}
            </div>
            <div className="flex items-center justify-between text-[12px]">
              <span className="text-dp-text font-mono">FRP Client</span>
              {status?.frpc ? (
                <CheckCircle className="w-4 h-4 text-dp-teal" />
              ) : (
                <XCircle className="w-4 h-4 text-dp-text-faint" />
              )}
            </div>
          </div>
          
          {error && (
            <div className="text-[10px] text-dp-red font-mono bg-dp-red/5 p-2 rounded border border-dp-red/10 break-all">
              {error}
            </div>
          )}
          
          <div className="flex justify-end pt-2">
            <button
              onClick={check}
              className="px-4 py-2 bg-dp-line hover:bg-dp-line-soft text-dp-text text-[12px] rounded transition-colors font-medium"
            >
              Check Again
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
