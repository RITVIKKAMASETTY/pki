// API service layer

const BASE = '/api';

export async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options?.headers },
    ...options,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`API ${res.status}: ${text}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  // Dashboard
  dashboard: () => apiFetch<DashboardStats>('/dashboard'),

  // Certificates
  certificates: (type?: string) =>
    apiFetch<Certificate[]>(`/certificates${type ? `?cert_type=${type}` : ''}`),
  certificate: (id: number) => apiFetch<CertificateDetail>(`/certificates/${id}`),
  chain: (id: number) => apiFetch<ChainResult>(`/certificates/${id}/chain`),
  analysis: (id: number) => apiFetch<AnalysisResult>(`/certificates/${id}/analysis`),
  deleteCert: (id: number) =>
    apiFetch(`/certificates/${id}`, { method: 'DELETE' }),
  uploadCerts: (files: File[]) => {
    const fd = new FormData();
    files.forEach(f => fd.append('files', f));
    return fetch(`${BASE}/certificates/upload`, { method: 'POST', body: fd }).then(r => r.json());
  },

  // Graph
  graph: () => apiFetch<GraphData>('/graph'),

  // AI
  aiAnalyze: (id: number) => apiFetch<AIAnalysis>(`/ai/analyze/${id}`, { method: 'POST' }),
  chat: (messages: ChatMessage[], context?: Record<string, unknown>) =>
    apiFetch<{ reply: string }>('/ai/chat', {
      method: 'POST',
      body: JSON.stringify({ messages, certificate_context: context }),
    }),

  // Services
  services: () => apiFetch<AIService[]>('/services'),
};

// Types
export interface DashboardStats {
  total: number;
  trusted: number;
  warning: number;
  critical: number;
  expired: number;
  expiring_soon: number;
  by_ca: { ca: string; count: number }[];
  by_status: { status: string; count: number }[];
  expiry_timeline: { month: string; count: number }[];
  risk_distribution: { risk: string; count: number }[];
}

export interface Certificate {
  id: number;
  filename: string;
  subject_cn: string;
  issuer_cn: string;
  certificate_type: 'root' | 'intermediate' | 'leaf';
  valid_from: string;
  valid_until: string;
  days_remaining: number;
  is_expired: boolean;
  public_key_algorithm: string;
  public_key_size: number;
  signature_algorithm: string;
  is_ca: boolean;
  overall_risk: string;
  fingerprint_sha256: string;
}

export interface CertificateDetail extends Certificate {
  subject: string;
  issuer: string;
  serial_number: string;
  version: number;
  path_length: number | null;
  key_usage: string[];
  extended_key_usage: string[];
  subject_alternative_names: string[];
  authority_key_identifier: string | null;
  subject_key_identifier: string | null;
  fingerprint_sha1: string;
}

export interface ChainLink {
  subject_cn: string;
  issuer_cn: string;
  certificate_type: string;
  is_valid: boolean;
}

export interface ChainResult {
  status: string;
  chain: ChainLink[];
  issues: string[];
  validated_at: string;
}

export interface Finding {
  id: number;
  severity: string;
  finding_type: string;
  description: string;
  recommendation: string;
}

export interface AnalysisResult {
  certificate_cn: string;
  overall_risk: string;
  findings: Finding[];
  chain: { status: string; issues: string[] } | null;
}

export interface AIAnalysis {
  certificate_cn: string;
  summary: string;
  security_risks: string;
  risk_impact: string;
  remediation: string;
  full_text: string;
}

export interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface GraphNode {
  id: string;
  type: string;
  data: {
    label: string;
    certType: string;
    risk: string;
    expired: boolean;
    daysRemaining: number;
    color: string;
    certId: number;
  };
  position: { x: number; y: number };
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  animated: boolean;
  style: { stroke: string; strokeWidth: number };
}

export interface AIService {
  id: number;
  service_name: string;
  domain: string;
  status: string;
  certificate: {
    id: number;
    subject_cn: string;
    days_remaining: number;
    is_expired: boolean;
  } | null;
}

export function riskColor(risk: string): string {
  const map: Record<string, string> = {
    TRUSTED: 'var(--trusted)',
    LOW: 'var(--trusted)',
    INFO: 'var(--info)',
    MEDIUM: 'var(--warning)',
    HIGH: 'var(--high)',
    CRITICAL: 'var(--critical)',
  };
  return map[risk] ?? 'var(--text-muted)';
}

export function riskIcon(risk: string): string {
  const map: Record<string, string> = {
    TRUSTED: '✓',
    LOW: '✓',
    INFO: 'ℹ',
    MEDIUM: '⚠',
    HIGH: '⚠',
    CRITICAL: '✕',
  };
  return map[risk] ?? '?';
}
