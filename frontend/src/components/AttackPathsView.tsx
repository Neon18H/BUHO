import React, { Fragment, useMemo } from 'react';
import { Scan } from '../services/api';
import RiskBadge from './RiskBadge';

interface AttackPathsViewProps {
  scans: Scan[];
}

interface AttackStep {
  phase: string;
  summary: string;
  vector: string;
  resource: string;
  severity: string;
}

const severityWeight: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  informational: 1
};

const attackPhases = ['Acceso inicial', 'Movimiento lateral', 'Impacto'];

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
        const attackNarrative: AttackStep[] = topFindings.map((finding, index) => {
          const vector = (finding.metadata?.['attack_vector'] as string) ?? 'remoto';
          const resource = (finding.metadata?.['technology'] as string) ?? 'activo desconocido';
          const phase = attackPhases[index] ?? attackPhases[attackPhases.length - 1];
          const cve = finding.cve ? ` (CVE: ${finding.cve})` : '';
          return {
            phase,
            summary: `${finding.tool} detectó ${finding.title}${cve}.`,
            vector,
            resource,
            severity: finding.severity ?? 'informational'
          };
        });

        return {
          id: scan.id,
          target: scan.target,
          severity: ordered[0].severity ?? 'informational',
          narrative: attackNarrative
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
          <div className="attack-path-diagram" role="list">
            {scenario.narrative.map((step, index) => (
              <Fragment key={`${scenario.id}-${index}`}>
                <div
                  role="listitem"
                  className={`attack-node severity-${step.severity ?? 'informational'}`}
                >
                  <div className="attack-node-badge">{index + 1}</div>
                  <div className="attack-node-body">
                    <h4>{step.phase}</h4>
                    <p>{step.summary}</p>
                    <span className="attack-node-meta">
                      Vector: <strong>{step.vector}</strong> · Recurso: <strong>{step.resource}</strong>
                    </span>
                  </div>
                </div>
                {index < scenario.narrative.length - 1 && (
                  <div className="attack-node-connector" aria-hidden="true">
                    <span />
                  </div>
                )}
              </Fragment>
            ))}
          </div>
        </article>
      ))}
    </div>
  );
};

export default AttackPathsView;
