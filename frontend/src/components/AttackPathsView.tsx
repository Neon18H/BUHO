import React, { useMemo } from 'react';
import { Scan } from '../services/api';
import RiskBadge from './RiskBadge';

interface AttackPathsViewProps {
  scans: Scan[];
}

const severityWeight: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  informational: 1
};

const AttackPathsView: React.FC<AttackPathsViewProps> = ({ scans }) => {
  const scenarios = useMemo(() => {
    return scans
      .map((scan) => {
        const ordered = [...scan.findings].sort((a, b) => {
          const left = severityWeight[a.severity ?? 'informational'] ?? 0;
          const right = severityWeight[b.severity ?? 'informational'] ?? 0;
          return right - left;
        });

        if (!ordered.length) {
          return null;
        }

        const topFindings = ordered.slice(0, 3);
        const attackNarrative = topFindings.map((finding, index) => {
          const vector = (finding.metadata?.['attack_vector'] as string) ?? 'remoto';
          const phase = ['Acceso inicial', 'Movimiento lateral', 'Impacto'][index] ?? 'Impacto';
          const cve = finding.cve ? ` (CVE: ${finding.cve})` : '';
          return `${phase}: ${finding.tool} detectó ${finding.title}${cve}. Vector ${vector}.`;
        });

        return {
          id: scan.id,
          target: scan.target,
          severity: ordered[0].severity ?? 'informational',
          narrative: attackNarrative,
        };
      })
      .filter((value): value is NonNullable<typeof value> => Boolean(value));
  }, [scans]);

  if (!scenarios.length) {
    return (
      <div className="card">
        <h3>Rutas de ataque</h3>
        <p style={{ opacity: 0.8 }}>
          Aún no hay hallazgos asociados a escaneos. Ejecuta un análisis para visualizar
          cómo un atacante podría encadenar vulnerabilidades.
        </p>
      </div>
    );
  }

  return (
    <div className="grid">
      {scenarios.map((scenario) => (
        <article key={scenario.id} className="card attack-card">
          <header className="attack-card-header">
            <div>
              <h3>{scenario.target}</h3>
              <p>Cadena de explotación propuesta</p>
            </div>
            <RiskBadge level={scenario.severity ?? 'informational'} />
          </header>
          <ol className="attack-steps">
            {scenario.narrative.map((step, index) => (
              <li key={index}>{step}</li>
            ))}
          </ol>
        </article>
      ))}
    </div>
  );
};

export default AttackPathsView;
