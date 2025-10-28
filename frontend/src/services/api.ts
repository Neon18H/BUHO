import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL ?? 'http://localhost:8000'
});

export interface Finding {
  id: string;
  tool: string;
  title: string;
  severity: string;
  cve?: string | null;
  remediation?: string | null;
  exploitation?: string | null;
  description: string;
  evidence: Record<string, unknown>;
  metadata: Record<string, unknown>;
}

export interface Scan {
  id: string;
  target: string;
  status: string;
  requested_tools: string[];
  started_at?: string;
  finished_at?: string;
  findings: Finding[];
}

export interface CreateScanPayload {
  target: string;
  tools: string[];
}

export const fetchScans = async (): Promise<Scan[]> => {
  const response = await api.get<Scan[]>('/scans');
  return response.data;
};

export const createScan = async (payload: CreateScanPayload): Promise<Scan> => {
  const response = await api.post<Scan>('/scans', payload);
  return response.data;
};

export default api;
