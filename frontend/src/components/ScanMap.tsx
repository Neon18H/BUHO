import React from 'react';
import RiskBadge from './RiskBadge';
import { Scan } from '../services/api';

interface ScanMapProps {
  scans: Scan[];
}

const severityToColor: Record<string, string> = {
  critical: '#ef4444',
  high: '#fb923c',
  medium: '#facc15',
  low: '#4ade80',
  informational: '#60a5fa'
};

const ScanMap: React.FC<ScanMapProps> = ({ scans }) => {
  const nodes = scans.map((scan, index) => {
    const severity = scan.findings[0]?.severity ?? 'informational';
    const color = severityToColor[severity] ?? severityToColor.informational;
    const angle = (index / Math.max(scans.length, 1)) * 2 * Math.PI;
    const radius = 140;
    const x = 200 + radius * Math.cos(angle);
    const y = 160 + radius * Math.sin(angle);
    return { id: scan.id, target: scan.target, severity, color, x, y };
  });

  return (
    <div className="card">
      <h3>Mapa de impacto</h3>
      <svg viewBox="0 0 400 320" style={{ width: '100%', height: '320px' }}>
        <defs>
          <radialGradient id="bg" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="rgba(59, 130, 246, 0.2)" />
            <stop offset="100%" stopColor="rgba(15, 23, 42, 0.8)" />
          </radialGradient>
        </defs>
        <rect x="0" y="0" width="400" height="320" fill="url(#bg)" rx="16" />
        {nodes.map((node) => (
          <g key={node.id}>
            <circle cx={node.x} cy={node.y} r={18} fill={node.color} opacity={0.85} />
            <text
              x={node.x}
              y={node.y + 32}
              textAnchor="middle"
              fontSize="10"
              fill="#cbd5f5"
            >
              {node.target.replace(/https?:\/\//, '')}
            </text>
          </g>
        ))}
      </svg>
      <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
        {scans.map((scan) => (
          <div key={scan.id} style={{ display: 'flex', flexDirection: 'column' }}>
            <strong>{scan.target}</strong>
            <RiskBadge level={scan.findings[0]?.severity ?? 'informational'} />
          </div>
        ))}
      </div>
    </div>
  );
};

export default ScanMap;
