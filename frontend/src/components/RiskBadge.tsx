import React from 'react';

interface RiskBadgeProps {
  level: string;
}

const severityToClass: Record<string, string> = {
  critical: 'badge badge-critical',
  high: 'badge badge-high',
  medium: 'badge badge-medium',
  low: 'badge badge-low',
  informational: 'badge badge-info'
};

export const RiskBadge: React.FC<RiskBadgeProps> = ({ level }) => {
  const normalized = level.toLowerCase();
  const className = severityToClass[normalized] ?? severityToClass.informational;
  return <span className={className}>{normalized}</span>;
};

export default RiskBadge;
