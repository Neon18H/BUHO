import { useEffect, useMemo, useState } from 'react';
import { fetchScans, Scan } from '../services/api';

type SeverityCount = Record<string, number>;

export interface DashboardData {
  scans: Scan[];
  isLoading: boolean;
  severityTally: SeverityCount;
  targets: string[];
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

  const targets = useMemo(() => scans.map((scan) => scan.target), [scans]);

  return { scans, isLoading, severityTally, targets };
};
