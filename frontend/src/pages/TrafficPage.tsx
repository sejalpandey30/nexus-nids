import { useState } from 'react';
import { TrafficInspector } from '../components/traffic/TrafficInspector';
import { SimulationConsole } from '../components/simulation/SimulationConsole';
import { LivePacketStream } from '../components/traffic/LivePacketStream';

type Tab = 'live_stream' | 'inspect' | 'simulate';

export default function TrafficPage() {
  const [tab, setTab] = useState<Tab>('live_stream');

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-lg font-semibold text-soc-text">Traffic Analysis & Live Stimulation</h1>
        <p className="text-sm text-soc-text-secondary mt-0.5">
          Real-time packet stream tracking, rule corruption analysis, flow inspection, and attack simulations
        </p>
      </div>

      {/* Tab bar */}
      <div className="flex border-b border-soc-border">
        {([
          { id: 'live_stream' as Tab, label: 'Live Packet Stream & Rule Integrity' },
          { id: 'inspect' as Tab, label: 'Flow Inspector' },
          { id: 'simulate' as Tab, label: 'Attack Simulation' },
        ] as const).map(({ id, label }) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
              tab === id
                ? 'border-soc-primary text-soc-primary'
                : 'border-transparent text-soc-text-secondary hover:text-soc-text'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === 'live_stream' && <LivePacketStream />}
      {tab === 'inspect' && <TrafficInspector />}
      {tab === 'simulate' && <SimulationConsole />}
    </div>
  );
}
