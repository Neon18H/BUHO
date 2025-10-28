import { useCallback, useEffect, useMemo, useState } from 'react';
import { AxiosError } from 'axios';
import { createScan as createScanRequest, fetchScans, Scan } from '../services/api';

type SeverityCount = Record<string, number>;

export interface DashboardData {
  scans: Scan[];
  isLoading: boolean;
  severityTally: SeverityCount;
  targets: string[];
  createScan: (target: string, tools: string[]) => Promise<Scan>;
  isCreating: boolean;
  error: string | null;
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

  return { scans, isLoading, severityTally, targets, createScan, isCreating, error };
};
