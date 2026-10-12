export type Gate = {
  stage: string;
  status: string;
  artifact?: string | null;
  detail?: string;
};

export type Vulnerability = {
  id: string;
  tool: string;
  severity: string;
  title: string;
  file?: string;
  line?: number;
  status?: string;
  ai_score?: number;
  ai_label?: string;
  cve?: string;
};

export type DashboardSummary = {
  generated_at: string | null;
  pipeline: { id?: string; ref?: string; sha?: string; url?: string };
  gates: Gate[];
  ai: { fp_reduction_pct?: number; filtered_fps?: number; total?: number };
  cloud: { app_url?: string; environment?: string; ecs_cluster?: string };
  vulnerabilities: Vulnerability[];
  counts: { total: number; by_tool: Record<string, number>; by_severity: Record<string, number> };
};

const base = import.meta.env.VITE_API_URL ?? "";

async function get<T>(path: string): Promise<T> {
  const r = await fetch(`${base}${path}`);
  if (!r.ok) throw new Error(`${path} → ${r.status}`);
  return r.json();
}

export const fetchSummary = () => get<DashboardSummary>("/api/pipeline/status");
export const fetchRemediation = () =>
  get<{ semgrep_before: number; semgrep_after_ai: number; reduction_pct: number }>(
    "/api/remediation/summary"
  );
export const fetchExplain = (id: string) => get<unknown>(`/api/vulnerabilities/${id}/explain`);
