import React, { useMemo } from 'react';
import type { Finding, Scan } from '../services/api';
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
  technique: string;
  weakness: string;
  impact: string;
  indicator?: string;
}

const severityWeight: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  informational: 1
};

const attackPhases = ['Acceso inicial', 'Movimiento lateral', 'Impacto'];

const cleanIndicator = (value: unknown): string | undefined => {
  if (typeof value !== 'string') {
    return undefined;
  }
  const trimmed = value.trim();
  if (!trimmed) {
    return undefined;
  }
  if (trimmed.length > 120) {
    return `${trimmed.slice(0, 117)}...`;
  }
  return trimmed;
};

const buildTechniqueProfile = (finding: Finding, resource: string) => {
  const vector = (finding.metadata?.['attack_vector'] as string) ?? 'remoto';
  const baseText = [
    finding.title,
    finding.description,
    (finding.metadata?.['classification'] as string) ?? '',
    (finding.metadata?.['reason'] as string) ?? ''
  ]
    .join(' ')
    .toLowerCase();

  const setProfile = (
    technique: string,
    tactic: string,
    impact: string
  ): { technique: string; impact: string } => ({
    technique: `${technique} (${tactic})`,
    impact
  });

  let profile = setProfile('Explotación de servicio expuesto', 'T1190', `comprometer ${resource}`);

  if (/sql|inyecci[óo]n/.test(baseText) || finding.tool === 'sqlmap') {
    profile = setProfile(
      'Inyección SQL',
      'T1190',
      'exfiltrar o manipular datos del motor de base de datos'
    );
  } else if (/xss|cross-site/.test(baseText)) {
    profile = setProfile(
      'Cross-Site Scripting',
      'T1059.007',
      'secuestrar sesiones de usuario o desplegar cargas maliciosas'
    );
  } else if (/cabecera|header|https|ssl|tls/.test(baseText) || finding.tool === 'nikto') {
    profile = setProfile(
      'Endurecimiento de superficie HTTP',
      'T1562',
      'degradar las defensas del canal web y habilitar ataques de intermediario'
    );
  } else if (/admin|backup|directory|listado|listing|expuesto/.test(baseText) || finding.tool === 'gobuster') {
    profile = setProfile(
      'Descubrimiento de recursos ocultos',
      'T1083',
      'acceder a paneles administrativos o archivos sensibles'
    );
  } else if (/csrf/.test(baseText)) {
    profile = setProfile(
      'Cross-Site Request Forgery',
      'T1190',
      'forzar acciones no autorizadas sobre cuentas válidas'
    );
  } else if (/default|config|exposici[óo]n|misconfig/.test(baseText)) {
    profile = setProfile(
      'Explotación de mala configuración',
      'T1046',
      `pivotar contra ${resource} debido a controles débiles`
    );
  }

  if (/credencial|password|contrase[ñn]a|login/.test(baseText)) {
    profile = setProfile(
      'Abuso de credenciales débiles',
      'T1110',
      'obtener acceso inicial a cuentas privilegiadas'
    );
  }

  if (/exposed|exposici[óo]n|surface|enum/.test(baseText) && finding.tool === 'wapiti') {
    profile = setProfile(
      'Enumeración avanzada de superficie',
      'T1595',
      `mapear rutas vulnerables dentro de ${resource}`
    );
  }

  const indicator =
    cleanIndicator(finding.evidence?.['indicator']) ??
    cleanIndicator(finding.evidence?.['parameter']) ??
    cleanIndicator(finding.evidence?.['path']) ??
    cleanIndicator(finding.evidence?.['url']) ??
    cleanIndicator(finding.evidence?.['message']) ??
    cleanIndicator(finding.evidence?.['references']) ??
    (finding.cve ?? undefined);

  const normalizedWeakness = (finding.title ?? 'Vulnerabilidad detectada').trim();
  const weakness = normalizedWeakness.replace(/\.+$/, '') || 'Vulnerabilidad detectada';

  return {
    technique: profile.technique,
    impact: profile.impact,
    vector,
    resource,
    indicator,
    weakness
  };
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
        const attackNarrative: AttackStep[] = topFindings.map((finding, index) => {
          const resource = (finding.metadata?.['technology'] as string) ?? 'activo desconocido';
          const phase = attackPhases[index] ?? attackPhases[attackPhases.length - 1];
          const profile = buildTechniqueProfile(finding, resource);
          return {
            phase,
            summary: `La técnica ${profile.technique} permite aprovechar ${profile.weakness} y derivar en ${profile.impact}.`,
            vector: profile.vector,
            resource: profile.resource,
            severity: finding.severity ?? 'informational',
            technique: profile.technique,
            weakness: profile.weakness,
            impact: profile.impact,
            indicator: profile.indicator
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
          <div className="attack-origin">
            <span className="attack-origin-icon" aria-hidden="true">
              🕵️
            </span>
            <div>
              <h4>Actor de amenaza</h4>
              <p>Encadena técnicas ofensivas para avanzar contra {scenario.target}.</p>
            </div>
          </div>
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
                  <div className="attack-step-technique">
                    <span className="technique-chip">{step.technique}</span>
                    <span className="weakness-label">{step.weakness}</span>
                  </div>
                  <p>{step.summary}</p>
                  <div className="attack-step-meta">
                    <span>Vector: <strong>{step.vector}</strong></span>
                    <span>Activo: <strong>{step.resource}</strong></span>
                    <span>Impacto: <strong>{step.impact}</strong></span>
                    {step.indicator ? (
                      <span>
                        Indicador: <strong>{step.indicator}</strong>
                      </span>
                    ) : null}
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
