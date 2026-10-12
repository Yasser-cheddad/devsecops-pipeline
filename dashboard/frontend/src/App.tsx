import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  DashboardSummary,
  fetchExplain,
  fetchRemediation,
  fetchSummary,
  Vulnerability,
} from "./api";

const gateColor: Record<string, string> = {
  passed: "bg-emerald-600",
  failed: "bg-red-600",
  skipped: "bg-slate-600",
};

function GateCards({ gates }: { gates: DashboardSummary["gates"] }) {
  return (
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
      {gates.map((g) => (
        <div key={g.stage} className="rounded-lg border border-slate-700 bg-slate-900 p-4">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-slate-300">{g.stage}</span>
            <span
              className={`rounded px-2 py-0.5 text-xs uppercase text-white ${gateColor[g.status] ?? "bg-slate-500"}`}
            >
              {g.status}
            </span>
          </div>
          {g.detail ? <p className="mt-2 text-xs text-slate-400">{g.detail}</p> : null}
        </div>
      ))}
    </div>
  );
}

function VulnTable({
  items,
  onExplain,
}: {
  items: Vulnerability[];
  onExplain: (id: string) => void;
}) {
  const [tool, setTool] = useState("");
  const [severity, setSeverity] = useState("");

  const filtered = useMemo(() => {
    return items.filter((v) => {
      if (tool && v.tool !== tool) return false;
      if (severity && v.severity.toUpperCase() !== severity.toUpperCase()) return false;
      return true;
    });
  }, [items, tool, severity]);

  const tools = [...new Set(items.map((v) => v.tool))];

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-2">
        <select
          className="rounded border border-slate-600 bg-slate-800 px-2 py-1 text-sm"
          value={tool}
          onChange={(e) => setTool(e.target.value)}
        >
          <option value="">Tous les outils</option>
          {tools.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
        <select
          className="rounded border border-slate-600 bg-slate-800 px-2 py-1 text-sm"
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
        >
          <option value="">Toutes sévérités</option>
          {["CRITICAL", "ERROR", "HIGH", "WARNING", "MEDIUM", "LOW"].map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </div>
      <div className="overflow-x-auto rounded-lg border border-slate-700">
        <table className="min-w-full text-left text-sm">
          <thead className="bg-slate-800 text-slate-300">
            <tr>
              <th className="px-3 py-2">Outil</th>
              <th className="px-3 py-2">Sévérité</th>
              <th className="px-3 py-2">Titre</th>
              <th className="px-3 py-2">IA</th>
              <th className="px-3 py-2"></th>
            </tr>
          </thead>
          <tbody>
            {filtered.slice(0, 100).map((v) => (
              <tr key={v.id} className="border-t border-slate-800">
                <td className="px-3 py-2">{v.tool}</td>
                <td className="px-3 py-2">{v.severity}</td>
                <td className="max-w-md truncate px-3 py-2" title={v.title}>
                  {v.title}
                </td>
                <td className="px-3 py-2">
                  {v.ai_score != null ? (
                    <span className="text-cyan-400">
                      {v.ai_label} ({v.ai_score})
                    </span>
                  ) : (
                    "—"
                  )}
                </td>
                <td className="px-3 py-2">
                  <button
                    type="button"
                    className="rounded bg-indigo-600 px-2 py-1 text-xs hover:bg-indigo-500"
                    onClick={() => onExplain(v.id)}
                  >
                    Explain
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="text-xs text-slate-500">{filtered.length} résultat(s)</p>
    </div>
  );
}

export default function App() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [remediation, setRemediation] = useState<{
    semgrep_before: number;
    semgrep_after_ai: number;
    reduction_pct: number;
  } | null>(null);
  const [explain, setExplain] = useState<unknown>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setError(null);
      const [s, r] = await Promise.all([fetchSummary(), fetchRemediation()]);
      setSummary(s);
      setRemediation(r);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Erreur chargement");
    }
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  }, [load]);

  const chartData = remediation
    ? [
        { name: "Avant IA", count: remediation.semgrep_before },
        { name: "Après IA", count: remediation.semgrep_after_ai },
      ]
    : [];

  const onExplain = async (id: string) => {
    try {
      const data = await fetchExplain(id);
      setExplain(data);
    } catch {
      setExplain({ error: "Appelez /classify sur ce finding avant Explain (cache SHAP)." });
    }
  };

  return (
    <div className="min-h-screen p-6">
      <header className="mb-8 border-b border-slate-800 pb-4">
        <h1 className="text-2xl font-bold text-white">DevSecOps Dashboard</h1>
        <p className="text-sm text-slate-400">
          Pipeline {summary?.pipeline?.sha ?? "—"} ·{" "}
          {summary?.generated_at ? new Date(summary.generated_at).toLocaleString("fr-FR") : "—"}
        </p>
        {summary?.pipeline?.url ? (
          <a className="text-sm text-cyan-400 hover:underline" href={summary.pipeline.url}>
            Voir le pipeline GitLab
          </a>
        ) : null}
      </header>

      {error ? (
        <div className="mb-4 rounded border border-amber-700 bg-amber-950/50 p-3 text-amber-200">
          {error} — Lancez le backend avec des rapports dans <code>reports/</code>.
        </div>
      ) : null}

      <section className="mb-8">
        <h2 className="mb-3 text-lg font-semibold">Security gates</h2>
        <GateCards gates={summary?.gates ?? []} />
      </section>

      <section className="mb-8 grid gap-6 lg:grid-cols-2">
        <div className="rounded-lg border border-slate-700 bg-slate-900 p-4">
          <h2 className="mb-3 text-lg font-semibold">IA – filtrage faux positifs</h2>
          <p className="text-3xl font-bold text-cyan-400">
            {summary?.ai?.fp_reduction_pct ?? 0}%
          </p>
          <p className="text-sm text-slate-400">
            {summary?.ai?.filtered_fps ?? 0} alertes filtrées sur {summary?.ai?.total ?? 0}
          </p>
        </div>
        <div className="rounded-lg border border-slate-700 bg-slate-900 p-4">
          <h2 className="mb-3 text-lg font-semibold">Cloud AWS</h2>
          <ul className="space-y-1 text-sm text-slate-300">
            <li>Environnement : {summary?.cloud?.environment ?? "—"}</li>
            <li>Cluster ECS : {summary?.cloud?.ecs_cluster ?? "—"}</li>
            <li>
              URL déployée :{" "}
              {summary?.cloud?.app_url ? (
                <a className="text-cyan-400 hover:underline" href={summary.cloud.app_url}>
                  {summary.cloud.app_url}
                </a>
              ) : (
                "—"
              )}
            </li>
          </ul>
        </div>
      </section>

      <section className="mb-8 rounded-lg border border-slate-700 bg-slate-900 p-4">
        <h2 className="mb-3 text-lg font-semibold">Remédiation (avant / après IA)</h2>
        <div className="h-48">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="name" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" />
              <Tooltip />
              <Bar dataKey="count" fill="#6366f1" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </section>

      <section className="mb-8">
        <h2 className="mb-3 text-lg font-semibold">Vulnérabilités</h2>
        <VulnTable items={summary?.vulnerabilities ?? []} onExplain={onExplain} />
      </section>

      {explain ? (
        <section className="rounded-lg border border-indigo-700 bg-slate-900 p-4">
          <h2 className="mb-2 text-lg font-semibold">Explication SHAP</h2>
          <pre className="overflow-auto text-xs text-slate-300">
            {JSON.stringify(explain, null, 2)}
          </pre>
        </section>
      ) : null}
    </div>
  );
}
