import React from 'react';
import RiskBadge from './RiskBadge';
import { Scan } from '../services/api';

interface ScanListProps {
  scans: Scan[];
  onDelete: (scanId: string) => Promise<void>;
  deletingIds: Set<string>;
}

const statusLabel: Record<string, string> = {
  pending: 'Pendiente',
  running: 'En progreso',
  completed: 'Completado',
  failed: 'Fallido'
};

const severityRank: Record<string, number> = {
  informational: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
};

const resolvePrimarySeverity = (scan: Scan): string => {
  if (!scan.findings.length) {
    return 'informational';
  }
  return (
    [...scan.findings]
      .map((finding) => finding.severity ?? 'informational')
      .sort((left, right) => (severityRank[right] ?? 0) - (severityRank[left] ?? 0))[0] ??
    'informational'
  );
};

const ScanList: React.FC<ScanListProps> = ({ scans, onDelete, deletingIds }) => {
  const handleDelete = async (scan: Scan) => {
    const confirmation = window.confirm(
      `¿Eliminar el escaneo sobre ${scan.target}? Esta acción borrará todos los hallazgos asociados.`
    );
    if (!confirmation) {
      return;
    }

    try {
      await onDelete(scan.id);
    } catch (err) {
      console.error('Error al eliminar escaneo', err);
    }
  };

  return (
    <div className="card">
      <div className="scan-list-header">
        <div>
          <h3>Historial de escaneos</h3>
          <p>Gestiona ejecuciones previas y libera espacio eliminando escaneos obsoletos.</p>
        </div>
      </div>
      <div className="scan-table-wrapper">
        {scans.length ? (
          <table className="scan-table">
            <thead>
              <tr>
                <th>Sitio</th>
                <th>Estado</th>
                <th>Herramientas</th>
                <th>Hallazgos</th>
                <th>Máxima severidad</th>
                <th>Acciones</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => {
                const severity = resolvePrimarySeverity(scan);
                const isDeleting = deletingIds.has(scan.id);
                return (
                  <tr key={scan.id}>
                    <td>
                      <strong>{scan.target}</strong>
                      <span className="scan-table-meta">
                        Inició: {scan.started_at ? new Date(scan.started_at).toLocaleString() : '—'}
                      </span>
                    </td>
                    <td>
                      <span className={`scan-status status-${scan.status}`}>
                        {statusLabel[scan.status] ?? scan.status}
                      </span>
                    </td>
                    <td className="scan-tools">
                      {scan.requested_tools.map((tool) => (
                        <span key={`${scan.id}-${tool}`}>• {tool}</span>
                      ))}
                    </td>
                    <td>
                      <strong>{scan.findings.length}</strong>
                      <span className="scan-table-meta">
                        {scan.finished_at
                          ? `Finalizó: ${new Date(scan.finished_at).toLocaleString()}`
                          : 'Aún en ejecución'}
                      </span>
                    </td>
                    <td>
                      <RiskBadge level={severity} />
                    </td>
                    <td>
                      <button
                        type="button"
                        className="scan-delete-button"
                        onClick={() => handleDelete(scan)}
                        disabled={isDeleting}
                      >
                        {isDeleting ? 'Eliminando…' : 'Eliminar'}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        ) : (
          <div className="scan-table-empty">
            <p>No hay ejecuciones registradas. Lanza tu primer escaneo para poblar el tablero.</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default ScanList;
