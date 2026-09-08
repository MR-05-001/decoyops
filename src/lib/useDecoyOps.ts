import { useState, useEffect, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';

export interface DecoyStatus {
  container_id: string;
  name: string;
  state: string;
  realism_score?: number;
  tunnel_public_url?: string | null;
  tunnel_provider?: string | null;
}

export interface EventRow {
  id: number;
  session_id: number;
  container_id: string;
  event_type: string;
  source_ip: string | null;
  attack_vector: string | null;
  raw_data: string | null;
  timestamp: string;
  geo_lat?: number;
  geo_lon?: number;
  mitre_ttp?: string;
  tty_log_path?: string;
}

export interface DashboardCounters {
  active_decoys: number;
  active_sessions: number;
  unique_actors: number;
  payloads_captured: number;
  total_events: number;
}

export interface DeployResult {
  container_id: string;
}

export interface IocRow {
  id: number;
  session_id: number | null;
  container_id: string;
  ioc_type: string;
  ioc_value: string;
  extracted_at: string;
}

export function useDecoyOps() {
  const [counters, setCounters] = useState<DashboardCounters | null>(null);
  const [decoys, setDecoys] = useState<DecoyStatus[]>([]);
  const [incidentFeed, setIncidentFeed] = useState<EventRow[]>([]);
  const [iocs, setIocs] = useState<IocRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [networks, setNetworks] = useState<string[]>([]);
  const [frpRunning, setFrpRunning] = useState(false);

  const fetchTelemetry = useCallback(async () => {
    try {
      const [newCounters, newDecoys, newFeed, newIocs] = await Promise.all([
        invoke<DashboardCounters>('get_dashboard_counters'),
        invoke<DecoyStatus[]>('get_fleet_telemetry'),
        invoke<EventRow[]>('get_incident_feed', { limit: 50 }),
        invoke<IocRow[]>('get_extracted_iocs', { limit: 20 }),
      ]);
      setCounters(newCounters);
      setDecoys(newDecoys);
      setIncidentFeed(newFeed);
      setIocs(newIocs);
      
      // Ping docker to verify true health (will throw if docker is down)
      await invoke('check_docker');
      
      // Also fetch networks
      try {
        const netList = await invoke<string[]>('get_docker_networks');
        setNetworks(netList);
      } catch(e) {
        // non-fatal, might just not have any managed networks yet
      }

      // Fetch FRP status
      try {
        const frpStatus = await invoke<boolean>('get_frp_status');
        setFrpRunning(frpStatus);
      } catch(e) {
        setFrpRunning(false);
      }

      setError(null);
    } catch (err: any) {
      console.error('Failed to fetch telemetry or ping docker:', err);
      setError(err.toString());
    }
  }, []);

  useEffect(() => {
    // Initial fetch
    fetchTelemetry();

    let isSubscribed = true;
    let timeoutId: number;

    const poll = async () => {
      const isAutoRefreshEnabled = localStorage.getItem('app_autorefresh') !== 'false';
      if (isAutoRefreshEnabled) {
        await fetchTelemetry();
      }
      
      const intervalMs = parseInt(localStorage.getItem('app_poll_interval') || '3000', 10);
      if (isSubscribed) {
        timeoutId = window.setTimeout(poll, intervalMs);
      }
    };

    timeoutId = window.setTimeout(poll, parseInt(localStorage.getItem('app_poll_interval') || '3000', 10));

    return () => {
      isSubscribed = false;
      clearTimeout(timeoutId);
    };
  }, [fetchTelemetry]);

  const deployDecoy = useCallback(async (name: string, templateType: string, portMapping: string, autoRestart: boolean, networkName?: string, isUnmanaged?: boolean, tunnelProvider?: string | null) => {
    try {
      const result = await invoke<DeployResult>('deploy_decoy', { 
        name, templateType, portMapping, autoRestart, 
        networkName: networkName || null, 
        isUnmanaged: !!isUnmanaged,
        tunnelProvider: tunnelProvider || null
      });
      // Wait a moment for the backend async DB writer to commit the insert
      await new Promise(r => setTimeout(r, 500));
      await fetchTelemetry();
      return result;
    } catch (err: any) {
      setError(err.toString());
      throw err;
    }
  }, [fetchTelemetry]);

  const terminateDecoy = async (containerId: string) => {
    try {
      await invoke('terminate_decoy', { containerId });
      fetchTelemetry();
    } catch (err: any) {
      throw new Error(err.toString());
    }
  };

  const startDecoy = async (containerId: string) => {
    try {
      await invoke('start_decoy', { containerId });
      fetchTelemetry();
    } catch (err: any) {
      throw new Error(err.toString());
    }
  };

  const stopDecoy = async (containerId: string) => {
    try {
      await invoke('stop_decoy', { containerId });
      fetchTelemetry();
    } catch (err: any) {
      throw new Error(err.toString());
    }
  };

  const restartDecoy = async (containerId: string) => {
    try {
      await invoke('restart_decoy', { containerId });
      fetchTelemetry();
    } catch (err: any) {
      throw new Error(err.toString());
    }
  };

  return {
    counters,
    decoys,
    incidentFeed,
    iocs,
    error,
    networks,
    frpRunning,
    deployDecoy,
    startDecoy,
    stopDecoy,
    restartDecoy,
    terminateDecoy,
    fetchTelemetry,
    refresh: fetchTelemetry,
  };
}
