import React, { useMemo, useState } from 'react';
import RiskBadge from './RiskBadge';
import { Finding, Scan } from '../services/api';

interface FindingsTableProps {
  scans: Scan[];
}

const FindingsTable: React.FC<FindingsTableProps> = ({ scans }) => {
  const [selectedSeverity, setSelectedSeverity] = useState<string>('');

  const findings = useMemo(() => {
    return scans.flatMap((scan) =>
      scan.findings.map((finding) => ({
        ...finding,
        scanTarget: scan.target,
        scanStatus: scan.status
      }))
    );
  }, [scans]);

  const filtered = useMemo(() => {
    if (!selectedSeverity) return findings;
    return findings.filter((finding) => finding.severity === selectedSeverity);
  }, [findings, selectedSeverity]);

  const severities = Array.from(
    new Set(findings.map((finding) => finding.severity ?? 'informational'))
  );

  const renderRow = (finding: Finding & { scanTarget: string; scanStatus: string }) => (
    <tr key={finding.id}>
      <td>{finding.scanTarget}</td>
      <td>{finding.tool}</td>
      <td>
        <strong>{finding.title}</strong>
        <p style={{ margin: '0.25rem 0', opacity: 0.8 }}>
          {(finding.description ?? '').slice(0, 120)}...
        </p>
      </td>
      <td><RiskBadge level={finding.severity ?? 'informational'} /></td>
      <td>{finding.cve ?? 'Pendiente'}</td>
      <td style={{ maxWidth: '240px' }}>{finding.remediation ?? 'Generando...'}</td>
    </tr>
  );

  return (
    <div className="card">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h3>Hallazgos</h3>
        <select
          value={selectedSeverity}
          onChange={(event) => setSelectedSeverity(event.target.value)}
          style={{ padding: '0.5rem 0.75rem', borderRadius: '8px', border: '1px solid #1e293b' }}
        >
          <option value="">Todas las criticidades</option>
          {severities.map((severity) => (
            <option key={severity} value={severity}>
              {severity}
            </option>
          ))}
        </select>
      </div>
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: '1rem' }}>
          <thead>
            <tr style={{ textAlign: 'left', borderBottom: '1px solid rgba(148, 163, 184, 0.2)' }}>
              <th>Sitio</th>
              <th>Herramienta</th>
              <th>Detalle</th>
              <th>Severidad</th>
              <th>CVE</th>
              <th>Remediación</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length ? (
              filtered.map((finding) => renderRow(finding as any))
            ) : (
              <tr>
                <td colSpan={6} style={{ textAlign: 'center', padding: '1rem' }}>
                  No hay hallazgos para la selección actual.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default FindingsTable;
