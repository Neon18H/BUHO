import React, { useMemo } from 'react';
import { Scan } from '../services/api';
import RiskBadge from './RiskBadge';

interface AssetsOverviewProps {
  scans: Scan[];
}

interface AssetSummary {
  target: string;
  findings: number;
  worstSeverity: string;
  cves: string[];
  remediations: string[];
}

const severityOrder = ['critical', 'high', 'medium', 'low', 'informational'];

const AssetsOverview: React.FC<AssetsOverviewProps> = ({ scans }) => {
  const assets = useMemo<AssetSummary[]>(() => {
    const map = new Map<string, AssetSummary>();

    scans.forEach((scan) => {
      const summary = map.get(scan.target) ?? {
        target: scan.target,
        findings: 0,
        worstSeverity: 'informational',
        cves: [],
        remediations: []
      };

      scan.findings.forEach((finding) => {
        summary.findings += 1;
        const severity = finding.severity ?? 'informational';
        if (
          severityOrder.indexOf(severity) <=
          severityOrder.indexOf(summary.worstSeverity)
        ) {
          summary.worstSeverity = severity;
        }
        if (finding.cve && !summary.cves.includes(finding.cve)) {
          summary.cves.push(finding.cve);
        }
        if (finding.remediation) {
          summary.remediations.push(finding.remediation);
        }
      });

      map.set(scan.target, summary);
    });

    return Array.from(map.values());
  }, [scans]);

  if (!assets.length) {
    return (
      <div className="card">
        <h3>Inventario de objetivos</h3>
        <p style={{ opacity: 0.8 }}>
          Cuando existan escaneos registrados verás aquí los activos analizados con su
          nivel de riesgo, CVE asociadas y acciones recomendadas.
        </p>
      </div>
    );
  }

  return (
    <div className="card">
      <h3>Inventario de objetivos</h3>
      <div className="asset-table-wrapper">
        <table className="asset-table">
          <thead>
            <tr>
              <th>Objetivo</th>
              <th>Hallazgos</th>
              <th>Criticidad</th>
              <th>CVE Asociadas</th>
              <th>Remediaciones sugeridas</th>
            </tr>
          </thead>
          <tbody>
            {assets.map((asset) => (
              <tr key={asset.target}>
                <td>{asset.target}</td>
                <td>{asset.findings}</td>
                <td>
                  <RiskBadge level={asset.worstSeverity} />
                </td>
                <td>
                  {asset.cves.length ? asset.cves.join(', ') : 'Sin correlación'}
                </td>
                <td>
                  {asset.remediations.length ? (
                    <ul>
                      {asset.remediations.slice(0, 3).map((remediation, index) => (
                        <li key={index}>{remediation}</li>
                      ))}
                      {asset.remediations.length > 3 && <li>...</li>}
                    </ul>
                  ) : (
                    'Pendiente de recomendación'
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default AssetsOverview;
