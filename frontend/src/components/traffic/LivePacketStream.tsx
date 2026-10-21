// components/traffic/LivePacketStream.tsx — Real-time live packet stream & physical NIC flow analyzer.

import React, { useState, useEffect, useRef } from 'react';
import { api } from '../../services/api';
import { useToast } from '../../context/ToastContext';
import { SeverityBadge } from '../common/SeverityBadge';
import { Badge } from '../common/Badge';
import type { DetectionResult, LiveSnifferStatus } from '../../types';
import {
  Play,
  Pause,
  StepForward,
  Trash2,
  Activity,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Wifi,
  Radio,
  Sliders,
  ShieldAlert,
  Network,
  Cpu,
  Globe,
} from 'lucide-react';

const SCENARIOS = [
  { value: '', label: 'Mixed Real-World Flow' },
  { value: 'normal', label: 'Normal Clean Packets (HTTP/TLS/DNS)' },
  { value: 'dos', label: 'Ingress SYN / UDP Flood (Corrupted Rate)' },
  { value: 'portscan', label: 'Stealth Recon Scan (Probing Frames)' },
  { value: 'exfiltration', label: 'Data Exfiltration (Abnormal Egress Payload)' },
  { value: 'theft', label: 'Data Theft Spike (High Ingress Ratio)' },
];

export const LivePacketStream: React.FC = () => {
  const { addToast } = useToast();

  // Mode: 'NIC' (Physical Network Interface) vs 'SYNTHETIC' (Simulation Engine)
  const [captureMode, setCaptureMode] = useState<'NIC' | 'SYNTHETIC'>('NIC');
  const [liveStatus, setLiveStatus] = useState<LiveSnifferStatus | null>(null);
  const [selectedIp, setSelectedIp] = useState<string>('');

  const [isStreaming, setIsStreaming] = useState<boolean>(false);
  const [intervalSec, setIntervalSec] = useState<number>(1.0);
  const [scenario, setScenario] = useState<string>('');
  const [packets, setPackets] = useState<DetectionResult[]>([]);
  const [selectedPacket, setSelectedPacket] = useState<DetectionResult | null>(null);
  const [autoScroll, setAutoScroll] = useState<boolean>(true);

  // Aggregated live stream telemetry
  const [stats, setStats] = useState({
    total: 0,
    clean: 0,
    corrupted: 0,
    anomalies: 0,
    latencies: [] as number[],
  });

  const eventSourceRef = useRef<EventSource | null>(null);
  const tableBottomRef = useRef<HTMLDivElement | null>(null);

  // Fetch live NIC status
  const fetchLiveStatus = async () => {
    try {
      const data = await api.getLiveStatus(selectedIp || undefined);
      setLiveStatus(data);
      if (!selectedIp && data.interfaces && data.interfaces.length > 0) {
        setSelectedIp(data.active_ip || data.interfaces[0].ip);
      }
    } catch (err) {
      console.error('Failed to get live sniffer status', err);
    }
  };

  useEffect(() => {
    fetchLiveStatus();
  }, [selectedIp]);

  // Auto-scroll to latest packet if enabled
  useEffect(() => {
    if (autoScroll && tableBottomRef.current) {
      tableBottomRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [packets, autoScroll]);

  const handleNewPacket = (packet: DetectionResult) => {
    // Filter out initial handshake message if structured as info
    if ((packet as any).type === 'connection') {
      return;
    }

    setPackets((prev) => {
      const updated = [...prev, packet];
      if (updated.length > 150) {
        return updated.slice(updated.length - 150);
      }
      return updated;
    });

    setStats((prev) => {
      const isCorrupt = packet.is_corrupted || packet.violation_rule !== null;
      const isAnom = packet.status === 'INTRUSION';
      const newLatencies = [...prev.latencies.slice(-19), packet.latency_ms || 1.2];

      return {
        total: prev.total + 1,
        clean: prev.clean + (isCorrupt ? 0 : 1),
        corrupted: prev.corrupted + (isCorrupt ? 1 : 0),
        anomalies: prev.anomalies + (isAnom ? 1 : 0),
        latencies: newLatencies,
      };
    });

    // Auto select first packet if none selected
    setSelectedPacket((curr) => curr || packet);
  };

  // Start or stop streaming SSE based on active mode
  useEffect(() => {
    if (!isStreaming) {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
      return;
    }

    const streamUrl =
      captureMode === 'NIC'
        ? api.getLiveStreamUrl(selectedIp || undefined)
        : api.getPacketStreamUrl(intervalSec, scenario || undefined);

    const es = new EventSource(streamUrl);
    eventSourceRef.current = es;

    es.onopen = () => {
      // Connected
    };

    es.onmessage = (event) => {
      try {
        const data: DetectionResult = JSON.parse(event.data);
        handleNewPacket(data);
      } catch (err) {
        console.error('Failed to parse SSE packet frame', err);
      }
    };

    es.onerror = () => {
      addToast(
        'info',
        'Stream Reconnecting',
        'Packet stream connection reset. Re-establishing link...'
      );
    };

    return () => {
      es.close();
      eventSourceRef.current = null;
    };
  }, [isStreaming, captureMode, selectedIp, intervalSec, scenario]);

  // Single step injection (Synthetic mode only)
  const handleSingleStep = async () => {
    try {
      const packet = await api.simulatePacket(scenario || undefined);
      handleNewPacket(packet);
      addToast(
        packet.is_corrupted ? 'warning' : 'success',
        'Frame Injected',
        `Captured ${packet.protocol || 'IP'} frame [${packet.packet_id || 'pkt-0'}]. Status: ${packet.status}`
      );
    } catch {
      addToast(
        'error',
        'Injection Failed',
        'Could not inject simulation frame. Ensure backend service is reachable.'
      );
    }
  };

  const handleClear = () => {
    setPackets([]);
    setSelectedPacket(null);
    setStats({
      total: 0,
      clean: 0,
      corrupted: 0,
      anomalies: 0,
      latencies: [],
    });
    addToast(
      'info',
      'Buffer Cleared',
      'Packet telemetry buffer and real-time metrics have been reset.'
    );
  };

  const avgLatency =
    stats.latencies.length > 0
      ? (stats.latencies.reduce((a, b) => a + b, 0) / stats.latencies.length).toFixed(2)
      : '0.00';

  const corruptionRate =
    stats.total > 0 ? ((stats.corrupted / stats.total) * 100).toFixed(1) : '0.0';

  return (
    <div className="space-y-4">
      {/* Mode Selector Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-soc-surface border border-soc-border rounded-lg p-3">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold text-soc-text uppercase tracking-wider">
            Packet Ingestion Source:
          </span>
          <div className="inline-flex rounded-md shadow-sm">
            <button
              onClick={() => {
                setIsStreaming(false);
                setCaptureMode('NIC');
              }}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-l-md border transition-colors ${
                captureMode === 'NIC'
                  ? 'bg-soc-primary text-white border-soc-primary'
                  : 'bg-soc-bg border-soc-border text-soc-text-secondary hover:text-soc-text'
              }`}
            >
              <Network className="w-3.5 h-3.5" />
              Physical NIC (Live Device Wire)
            </button>
            <button
              onClick={() => {
                setIsStreaming(false);
                setCaptureMode('SYNTHETIC');
              }}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-r-md border-t border-b border-r transition-colors ${
                captureMode === 'SYNTHETIC'
                  ? 'bg-soc-primary text-white border-soc-primary'
                  : 'bg-soc-bg border-soc-border text-soc-text-secondary hover:text-soc-text'
              }`}
            >
              <Cpu className="w-3.5 h-3.5" />
              Synthetic Stimulation (Lab Profiles)
            </button>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs">
          {captureMode === 'NIC' ? (
            <span className="inline-flex items-center gap-1.5 text-emerald-400 font-medium">
              <CheckCircle2 className="w-3.5 h-3.5" />
              {liveStatus?.mode_label || 'Live Host Socket Telemetry'} ({liveStatus?.active_ip || selectedIp || 'Active'})
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 text-sky-400 font-medium">
              <Cpu className="w-3.5 h-3.5" />
              Synthetic Attack Lab Active
            </span>
          )}
        </div>
      </div>

      {/* Optional Elevation Tip (Non-blocking) */}
      {captureMode === 'NIC' && liveStatus && !liveStatus.is_raw && (
        <div className="bg-sky-950/20 border border-sky-600/30 rounded-lg p-3 text-xs space-y-2">
          <div className="flex items-center justify-between">
            <span className="font-semibold text-sky-300 flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4 text-sky-400" />
              Physical NIC Socket Monitor Active (Zero Admin Mode)
            </span>
            <Badge variant="success">READY TO SNIFF</Badge>
          </div>
          <p className="text-soc-text-secondary">
            Ready to track real physical network traffic (Google searches, browser requests, DNS, background sessions) with <strong>zero third-party software</strong>.
            Click <strong className="text-emerald-400">Start NIC Sniffing</strong> below to begin.
          </p>
        </div>
      )}

      {/* Main Control Deck */}
      <div className="bg-soc-surface border border-soc-border rounded-lg p-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="relative flex h-3 w-3">
                {isStreaming && (
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                )}
                <span
                  className={`relative inline-flex rounded-full h-3 w-3 ${
                    isStreaming ? 'bg-emerald-500' : 'bg-soc-text-secondary/40'
                  }`}
                ></span>
              </span>
              <h2 className="text-base font-semibold text-soc-text flex items-center gap-2">
                {captureMode === 'NIC'
                  ? 'Real-Time Physical NIC Packet Sniffing & Flow Analysis'
                  : 'Live Synthetic Stimulation & Corruption Lab'}
              </h2>
              <Badge variant={isStreaming ? 'success' : 'neutral'}>
                {isStreaming ? 'STREAMING ACTIVE' : 'IDLE / PAUSED'}
              </Badge>
            </div>
            <p className="text-xs text-soc-text-secondary mt-1">
              {captureMode === 'NIC'
                ? 'Intercepting live packets transmitted & received across your physical network adapter (Google searches, web browsing, background flows) and testing RFC compliance & anomaly scores.'
                : 'Synthetic packet arrival engine verifying flow conformance against Deterministic SOC Rules and Isolation Forest Anomaly Scoring.'}
            </p>
          </div>

          {/* Action Buttons */}
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => setIsStreaming(!isStreaming)}
              className={`flex items-center gap-2 px-3 py-1.5 rounded text-xs font-semibold shadow-sm transition-all ${
                isStreaming
                  ? 'bg-amber-600/20 text-amber-400 border border-amber-500/40 hover:bg-amber-600/30'
                  : 'bg-emerald-600 text-white hover:bg-emerald-500'
              }`}
            >
              {isStreaming ? (
                <>
                  <Pause className="w-3.5 h-3.5" />
                  Pause Capture
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-current" />
                  {captureMode === 'NIC' ? 'Start NIC Sniffing' : 'Start Simulation'}
                </>
              )}
            </button>

            {captureMode === 'SYNTHETIC' && (
              <button
                onClick={handleSingleStep}
                disabled={isStreaming}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium bg-soc-elevated border border-soc-border text-soc-text hover:bg-soc-border disabled:opacity-40"
                title="Inject one synthetic packet frame"
              >
                <StepForward className="w-3.5 h-3.5" />
                Step (1 Frame)
              </button>
            )}

            <button
              onClick={handleClear}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium bg-soc-elevated border border-soc-border text-soc-text-secondary hover:text-rose-400 hover:border-rose-500/40 transition-colors"
              title="Clear captured packets from view"
            >
              <Trash2 className="w-3.5 h-3.5" />
              Clear
            </button>
          </div>
        </div>

        {/* Configuration Row */}
        <div className="mt-4 pt-3 border-t border-soc-border/60 grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
          {captureMode === 'NIC' ? (
            <div>
              <label className="text-soc-text-secondary font-medium block mb-1">
                Active Network Interface (NIC IP)
              </label>
              <select
                value={selectedIp}
                onChange={(e) => setSelectedIp(e.target.value)}
                disabled={isStreaming}
                className="w-full bg-soc-bg border border-soc-border rounded px-2.5 py-1 text-soc-text focus:outline-none focus:border-soc-primary text-xs"
              >
                {liveStatus?.interfaces?.map((iface) => (
                  <option key={iface.ip} value={iface.ip}>
                    {iface.name}
                  </option>
                ))}
              </select>
            </div>
          ) : (
            <div>
              <label className="text-soc-text-secondary font-medium block mb-1">
                Traffic Stimulation Profile
              </label>
              <select
                value={scenario}
                onChange={(e) => setScenario(e.target.value)}
                className="w-full bg-soc-bg border border-soc-border rounded px-2.5 py-1 text-soc-text focus:outline-none focus:border-soc-primary text-xs"
              >
                {SCENARIOS.map((sc) => (
                  <option key={sc.value} value={sc.value}>
                    {sc.label}
                  </option>
                ))}
              </select>
            </div>
          )}

          {captureMode === 'SYNTHETIC' ? (
            <div>
              <label className="text-soc-text-secondary font-medium block mb-1">
                Emission Frequency (Interval)
              </label>
              <div className="flex items-center gap-2">
                {[
                  { label: 'Hyper (0.4s)', val: 0.4 },
                  { label: 'Normal (1.0s)', val: 1.0 },
                  { label: 'Relaxed (2.0s)', val: 2.0 },
                ].map((speed) => (
                  <button
                    key={speed.val}
                    onClick={() => setIntervalSec(speed.val)}
                    className={`flex-1 py-1 px-2 rounded border text-center transition-colors ${
                      intervalSec === speed.val
                        ? 'bg-soc-primary/20 border-soc-primary text-soc-primary font-semibold'
                        : 'bg-soc-bg border-soc-border text-soc-text-secondary hover:text-soc-text'
                    }`}
                  >
                    {speed.label}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            <div>
              <label className="text-soc-text-secondary font-medium block mb-1">
                Flow Session Aggregation Window
              </label>
              <div className="py-1 px-2.5 bg-soc-bg border border-soc-border rounded text-soc-text-secondary text-xs flex items-center justify-between">
                <span>Sliding Window: <strong>2.0s Inactivity / 5.0s Max</strong></span>
                <span className="text-emerald-400 font-mono text-[11px]">ACTIVE</span>
              </div>
            </div>
          )}

          <div className="flex items-end justify-between md:justify-end gap-3">
            <label className="flex items-center gap-2 cursor-pointer text-soc-text-secondary hover:text-soc-text py-1">
              <input
                type="checkbox"
                checked={autoScroll}
                onChange={(e) => setAutoScroll(e.target.checked)}
                className="rounded border-soc-border bg-soc-bg text-soc-primary focus:ring-0"
              />
              Auto-scroll feed
            </label>
            <div className="text-right text-[11px] text-soc-text-secondary font-mono">
              Buffer: {packets.length}/150 frames
            </div>
          </div>
        </div>
      </div>

      {/* Telemetry Metrics Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        <div className="bg-soc-surface border border-soc-border rounded-lg p-3">
          <div className="text-[11px] text-soc-text-secondary font-medium uppercase tracking-wider flex items-center justify-between">
            Total Captured
            <Radio className="w-3.5 h-3.5 text-sky-400" />
          </div>
          <div className="text-xl font-bold font-mono text-soc-text mt-1">{stats.total}</div>
          <div className="text-[10px] text-soc-text-secondary mt-0.5">
            {captureMode === 'NIC' ? 'Live network flows' : 'Stimulated flows'}
          </div>
        </div>

        <div className="bg-soc-surface border border-soc-border rounded-lg p-3">
          <div className="text-[11px] text-emerald-400 font-medium uppercase tracking-wider flex items-center justify-between">
            Rule Compliant
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="text-xl font-bold font-mono text-emerald-400 mt-1">{stats.clean}</div>
          <div className="text-[10px] text-soc-text-secondary mt-0.5">
            {stats.total > 0 ? ((stats.clean / stats.total) * 100).toFixed(0) : '100'}% safe payload
          </div>
        </div>

        <div className="bg-soc-surface border border-soc-border rounded-lg p-3">
          <div className="text-[11px] text-rose-400 font-medium uppercase tracking-wider flex items-center justify-between">
            Rule Violations / Corrupt
            <XCircle className="w-3.5 h-3.5 text-rose-400" />
          </div>
          <div className="text-xl font-bold font-mono text-rose-400 mt-1">{stats.corrupted}</div>
          <div className="text-[10px] text-rose-400/80 mt-0.5">{corruptionRate}% corruption rate</div>
        </div>

        <div className="bg-soc-surface border border-soc-border rounded-lg p-3">
          <div className="text-[11px] text-amber-400 font-medium uppercase tracking-wider flex items-center justify-between">
            Anomalies Detected
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="text-xl font-bold font-mono text-amber-400 mt-1">{stats.anomalies}</div>
          <div className="text-[10px] text-soc-text-secondary mt-0.5">Flagged for alert</div>
        </div>

        <div className="bg-soc-surface border border-soc-border rounded-lg p-3 col-span-2 sm:col-span-1">
          <div className="text-[11px] text-soc-text-secondary font-medium uppercase tracking-wider flex items-center justify-between">
            Engine Latency
            <Activity className="w-3.5 h-3.5 text-indigo-400" />
          </div>
          <div className="text-xl font-bold font-mono text-indigo-300 mt-1">{avgLatency} ms</div>
          <div className="text-[10px] text-soc-text-secondary mt-0.5">Per-frame pipeline</div>
        </div>
      </div>

      {/* Main Split View: Stream Table & Deep Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left Column: Live Packet Log */}
        <div className="lg:col-span-8 bg-soc-surface border border-soc-border rounded-lg flex flex-col h-[520px] overflow-hidden">
          <div className="p-3 border-b border-soc-border bg-soc-elevated/40 flex items-center justify-between">
            <span className="text-xs font-semibold text-soc-text flex items-center gap-1.5">
              <Wifi className="w-3.5 h-3.5 text-soc-primary" />
              {captureMode === 'NIC' ? 'Live Network Adapter Ingress/Egress Wire' : 'Simulated Traffic Ingress Wire'}
            </span>
            <span className="text-[11px] text-soc-text-secondary">
              Click any row to inspect RFC compliance & decision pipeline
            </span>
          </div>

          <div className="flex-1 overflow-auto p-0 text-xs font-mono">
            {packets.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-soc-text-secondary space-y-2">
                <Radio className="w-8 h-8 opacity-40 animate-pulse" />
                <p className="text-sm font-sans font-medium text-soc-text">No traffic currently buffered in stream.</p>
                {captureMode === 'NIC' ? (
                  <p className="text-xs text-soc-text-secondary/70 max-w-sm text-center font-sans">
                    Click <span className="text-emerald-400 font-semibold">Start NIC Sniffing</span>. Then open any website (e.g. Google) in your browser to see real live packets flow here.
                  </p>
                ) : (
                  <p className="text-xs text-soc-text-secondary/70 font-sans">
                    Click <span className="text-emerald-400 font-semibold">Start Live Stream</span> or{' '}
                    <span className="text-soc-primary font-semibold">Step (1 Frame)</span> to begin stimulation.
                  </p>
                )}
              </div>
            ) : (
              <table className="w-full text-left border-collapse">
                <thead className="sticky top-0 bg-soc-surface border-b border-soc-border text-[11px] text-soc-text-secondary uppercase">
                  <tr>
                    <th className="py-2 px-3">Flow ID</th>
                    <th className="py-2 px-2">Proto</th>
                    <th className="py-2 px-2">Source</th>
                    <th className="py-2 px-2">Destination</th>
                    <th className="py-2 px-2">Flags</th>
                    <th className="py-2 px-2">Integrity / Rule Status</th>
                    <th className="py-2 px-2 text-right">Verdict</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-soc-border/40">
                  {packets.map((pkt) => {
                    const isSelected = selectedPacket?.packet_id === pkt.packet_id;
                    const isCorrupted = pkt.is_corrupted || pkt.violation_rule !== null;

                    return (
                      <tr
                        key={pkt.packet_id || `${pkt.timestamp}-${Math.random()}`}
                        onClick={() => setSelectedPacket(pkt)}
                        className={`cursor-pointer transition-colors ${
                          isSelected
                            ? 'bg-soc-primary/15 hover:bg-soc-primary/20'
                            : isCorrupted
                            ? 'hover:bg-rose-950/20'
                            : 'hover:bg-soc-elevated/50'
                        }`}
                      >
                        <td className="py-1.5 px-3 font-semibold text-soc-text flex items-center gap-1.5">
                          <span
                            className={`w-1.5 h-1.5 rounded-full ${
                              isCorrupted ? 'bg-rose-500' : 'bg-emerald-400'
                            }`}
                          />
                          {pkt.packet_id || 'pkt-stream'}
                        </td>
                        <td className="py-1.5 px-2">
                          <span className="px-1.5 py-0.5 rounded text-[10px] bg-soc-elevated text-sky-300 border border-soc-border">
                            {pkt.protocol || 'TCP'}
                          </span>
                        </td>
                        <td className="py-1.5 px-2 text-soc-text-secondary truncate max-w-[130px]" title={`${pkt.src_ip}:${pkt.src_port}`}>
                          {pkt.src_ip || '192.168.1.10'}:{pkt.src_port || 443}
                        </td>
                        <td className="py-1.5 px-2 text-soc-text-secondary truncate max-w-[130px]" title={`${pkt.dst_ip}:${pkt.dst_port}`}>
                          {pkt.dst_ip || '10.0.0.1'}:{pkt.dst_port || 80}
                        </td>
                        <td className="py-1.5 px-2">
                          <span className="text-[10px] text-amber-300 font-mono">
                            {pkt.flags && pkt.flags.length > 0 ? pkt.flags.join(',') : 'ACK'}
                          </span>
                        </td>
                        <td className="py-1.5 px-2">
                          {isCorrupted ? (
                            <span className="inline-flex items-center gap-1 text-[11px] text-rose-400 font-medium">
                              <XCircle className="w-3 h-3 text-rose-400 flex-shrink-0" />
                              <span className="truncate max-w-[140px]" title={pkt.violation_rule || 'Corrupted Frame'}>
                                {pkt.violation_rule || 'Corrupted Flow'}
                              </span>
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400">
                              <CheckCircle2 className="w-3 h-3 text-emerald-400 flex-shrink-0" />
                              Rule Compliant
                            </span>
                          )}
                        </td>
                        <td className="py-1.5 px-2 text-right">
                          <SeverityBadge severity={pkt.severity} />
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
            <div ref={tableBottomRef} />
          </div>
        </div>

        {/* Right Column: Deep Packet & Rule Inspector */}
        <div className="lg:col-span-4 bg-soc-surface border border-soc-border rounded-lg flex flex-col h-[520px] overflow-hidden">
          <div className="p-3 border-b border-soc-border bg-soc-elevated/40 flex items-center justify-between">
            <span className="text-xs font-semibold text-soc-text flex items-center gap-1.5">
              <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
              Flow Integrity & Decision Inspector
            </span>
            {selectedPacket && (
              <span className="text-[10px] text-soc-text-secondary font-mono">
                {selectedPacket.packet_id}
              </span>
            )}
          </div>

          <div className="flex-1 overflow-auto p-4 space-y-4 text-xs">
            {selectedPacket ? (
              <>
                {/* Header Summary Card */}
                <div
                  className={`p-3 rounded-lg border ${
                    selectedPacket.is_corrupted || selectedPacket.violation_rule
                      ? 'bg-rose-950/20 border-rose-800/50'
                      : 'bg-emerald-950/20 border-emerald-800/50'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-soc-text">Flow Conformance</span>
                    <Badge
                      variant={
                        selectedPacket.is_corrupted || selectedPacket.violation_rule
                          ? 'critical'
                          : 'success'
                      }
                    >
                      {selectedPacket.is_corrupted || selectedPacket.violation_rule
                        ? 'CORRUPTED / VIOLATION'
                        : 'COMPLIANT'}
                    </Badge>
                  </div>
                  {selectedPacket.violation_rule ? (
                    <p className="mt-2 text-xs text-rose-300 font-mono">
                      Violates: {selectedPacket.violation_rule}
                    </p>
                  ) : (
                    <p className="mt-2 text-xs text-emerald-300">
                      Payload headers & byte ratios conform with baseline network specifications.
                    </p>
                  )}
                </div>

                {/* Network Header Tuple */}
                <div>
                  <h4 className="text-[11px] font-semibold text-soc-text-secondary uppercase tracking-wider mb-2 flex items-center gap-1.5">
                    <Globe className="w-3.5 h-3.5 text-sky-400" />
                    L3 / L4 Session Metadata
                  </h4>
                  <div className="grid grid-cols-2 gap-2 bg-soc-bg border border-soc-border p-2.5 rounded font-mono text-[11px]">
                    <div>
                      <span className="text-soc-text-secondary block text-[10px]">PROTOCOL</span>
                      <span className="text-sky-400 font-semibold">{selectedPacket.protocol || 'TCP'}</span>
                    </div>
                    <div>
                      <span className="text-soc-text-secondary block text-[10px]">PACKET SIZE</span>
                      <span className="text-soc-text">{selectedPacket.packet_size || selectedPacket.src_bytes + selectedPacket.dst_bytes} B</span>
                    </div>
                    <div>
                      <span className="text-soc-text-secondary block text-[10px]">SRC IP:PORT</span>
                      <span className="text-soc-text truncate block">
                        {selectedPacket.src_ip || '192.168.1.10'}:{selectedPacket.src_port || 443}
                      </span>
                    </div>
                    <div>
                      <span className="text-soc-text-secondary block text-[10px]">DST IP:PORT</span>
                      <span className="text-soc-text truncate block">
                        {selectedPacket.dst_ip || '10.0.0.1'}:{selectedPacket.dst_port || 80}
                      </span>
                    </div>
                    <div>
                      <span className="text-soc-text-secondary block text-[10px]">TCP FLAGS</span>
                      <span className="text-amber-400">
                        {selectedPacket.flags?.join(', ') || 'SYN, ACK'}
                      </span>
                    </div>
                    <div>
                      <span className="text-soc-text-secondary block text-[10px]">FLOW DURATION</span>
                      <span className="text-soc-text">{selectedPacket.duration.toFixed(3)}s</span>
                    </div>
                  </div>
                </div>

                {/* Byte Breakdown */}
                <div>
                  <h4 className="text-[11px] font-semibold text-soc-text-secondary uppercase tracking-wider mb-2">
                    Payload Telemetry & Ratio
                  </h4>
                  <div className="space-y-2">
                    <div>
                      <div className="flex justify-between text-[11px] text-soc-text-secondary mb-1">
                        <span>Source Payload (Outbound)</span>
                        <span className="font-mono text-soc-text">{selectedPacket.src_bytes.toLocaleString()} bytes</span>
                      </div>
                      <div className="h-1.5 w-full bg-soc-bg rounded-full overflow-hidden">
                        <div
                          className="h-full bg-indigo-500 rounded-full"
                          style={{
                            width: `${Math.min(
                              100,
                              (selectedPacket.src_bytes /
                                (selectedPacket.src_bytes + selectedPacket.dst_bytes || 1)) *
                                100
                            )}%`,
                          }}
                        />
                      </div>
                    </div>

                    <div>
                      <div className="flex justify-between text-[11px] text-soc-text-secondary mb-1">
                        <span>Destination Payload (Inbound)</span>
                        <span className="font-mono text-soc-text">{selectedPacket.dst_bytes.toLocaleString()} bytes</span>
                      </div>
                      <div className="h-1.5 w-full bg-soc-bg rounded-full overflow-hidden">
                        <div
                          className="h-full bg-purple-500 rounded-full"
                          style={{
                            width: `${Math.min(
                              100,
                              (selectedPacket.dst_bytes /
                                (selectedPacket.src_bytes + selectedPacket.dst_bytes || 1)) *
                                100
                            )}%`,
                          }}
                        />
                      </div>
                    </div>
                  </div>
                </div>

                {/* Pipeline Analysis */}
                <div>
                  <h4 className="text-[11px] font-semibold text-soc-text-secondary uppercase tracking-wider mb-2">
                    NEXUS Detection Verdict
                  </h4>
                  <div className="bg-soc-bg border border-soc-border p-2.5 rounded space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-soc-text-secondary">Method Applied</span>
                      <Badge variant="blue">{selectedPacket.detection_method}</Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-soc-text-secondary">Verdict Status</span>
                      <span
                        className={`font-semibold ${
                          selectedPacket.status === 'INTRUSION'
                            ? 'text-rose-400'
                            : 'text-emerald-400'
                        }`}
                      >
                        {selectedPacket.status}
                      </span>
                    </div>
                    {selectedPacket.anomaly_score !== undefined && (
                      <div className="flex items-center justify-between">
                        <span className="text-soc-text-secondary">iForest Anomaly Score</span>
                        <span className="font-mono text-amber-400">
                          {selectedPacket.anomaly_score.toFixed(4)}
                        </span>
                      </div>
                    )}
                    <div className="pt-2 border-t border-soc-border/60 text-soc-text-secondary text-[11px]">
                      {selectedPacket.message}
                    </div>
                  </div>
                </div>
              </>
            ) : (
              <div className="h-full flex flex-col items-center justify-center text-soc-text-secondary">
                <Sliders className="w-6 h-6 opacity-40 mb-2" />
                <p>Select a flow from the wirefeed to view its dissection.</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
