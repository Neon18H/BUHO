import { useCallback, useEffect, useMemo, useState } from 'react';
import { AxiosError } from 'axios';
import {
  createScan as createScanRequest,
  deleteScan as deleteScanRequest,
  fetchScans,
  Scan
} from '../services/api';

type SeverityCount = Record<string, number>;

export interface DashboardData {
  scans: Scan[];
  isLoading: boolean;
  severityTally: SeverityCount;
  targets: string[];
  createScan: (target: string, tools: string[]) => Promise<Scan>;
  isCreating: boolean;
  error: string | null;
  deleteScan: (scanId: string) => Promise<void>;
  deletingIds: Set<string>;
}

const initialTally: SeverityCount = {
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  informational: 0
};

export const useScans = (): DashboardData => {
  const [scans, setScans] = useState<Scan[]>([]);
  const [isLoading, setLoading] = useState<boolean>(false);
  const [isCreating, setCreating] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [deletingIds, setDeletingIds] = useState<Set<string>>(() => new Set());

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      try {
        const data = await fetchScans();
        setScans(data);
      } catch (error) {
        console.error('Error cargando escaneos', error);
      } finally {
        setLoading(false);
      }
    };
    load();
  }, []);

  const severityTally = useMemo(() => {
    return scans.reduce<SeverityCount>((acc, scan) => {
      scan.findings.forEach((finding) => {
        const key = finding.severity ?? 'informational';
        acc[key] = (acc[key] ?? 0) + 1;
      });
      return acc;
    }, { ...initialTally });
  }, [scans]);

  const createScan = useCallback(
    async (target: string, tools: string[]) => {
      setCreating(true);
      setError(null);
      try {
        const newScan = await createScanRequest({ target, tools });
        setScans((prev) => [newScan, ...prev]);
        return newScan;
      } catch (err) {
        let message = 'No se pudo iniciar el escaneo.';
        if (err instanceof AxiosError) {
          message = err.response?.data?.detail ?? err.message;
        }
        setError(message);
        throw err;
      } finally {
        setCreating(false);
      }
    },
    []
  );

  const targets = useMemo(() => scans.map((scan) => scan.target), [scans]);

  const deleteScan = useCallback(async (scanId: string) => {
    setError(null);
    setDeletingIds((prev) => {
      const next = new Set(prev);
      next.add(scanId);
      return next;
    });

    try {
      await deleteScanRequest(scanId);
      setScans((prev) => prev.filter((scan) => scan.id !== scanId));
    } catch (err) {
      if (err instanceof AxiosError) {
        setError(err.response?.data?.detail ?? err.message);
      } else {
        setError('No se pudo eliminar el escaneo.');
      }
      throw err;
    } finally {
      setDeletingIds((prev) => {
        const next = new Set(prev);
        next.delete(scanId);
        return next;
      });
    }
  }, []);

  return {
    scans,
    isLoading,
    severityTally,
    targets,
    createScan,
    isCreating,
    error,
    deleteScan,
    deletingIds
  };
};
