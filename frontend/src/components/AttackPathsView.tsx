import React, { useMemo } from 'react';
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

        const accumulatedSeverity = topFindings.reduce((acc, finding) => {
          return acc + (severityWeight[finding.severity ?? 'informational'] ?? 1);
        }, 0);
        const normalizedScore = Math.min(
          100,
          Math.round(
            (accumulatedSeverity / Math.max(topFindings.length * severityWeight.critical, 1)) *
              100
          )
        );

        return {
          id: scan.id,
          target: scan.target,
          severity: ordered[0].severity ?? 'informational',
          narrative: attackNarrative,
          score: normalizedScore,
          findings: topFindings
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
            <div className="attack-card-summary">
              <div className="attack-score">
                <span>Exposición estimada</span>
                <strong>{scenario.score}%</strong>
              </div>
              <RiskBadge level={scenario.severity ?? 'informational'} />
            </div>
          </header>
          <p className="attack-card-subtitle">
            Secuencia priorizada de hallazgos con mayor probabilidad de explotación encadenada.
          </p>
          <ol className="attack-path" role="list">
            {scenario.narrative.map((step, index) => (
              <li
                key={`${scenario.id}-${index}`}
                className={`attack-step severity-${step.severity ?? 'informational'}`}
              >
                <div className="attack-step-marker">
                  <span className="attack-step-index">{index + 1}</span>
                  <span className="attack-step-phase">{step.phase}</span>
                </div>
                <div className="attack-step-body">
                  <p>{step.summary}</p>
                  <div className="attack-step-meta">
                    <span>Vector: <strong>{step.vector}</strong></span>
                    <span>Activo: <strong>{step.resource}</strong></span>
                  </div>
                </div>
              </li>
            ))}
          </ol>
        </article>
      ))}
    </div>
  );
};

export default AttackPathsView;
