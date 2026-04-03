import { notFound } from "next/navigation";
import { getScan } from "@/lib/kv";
import type { Grade } from "@beacon/types";
import Link from "next/link";

export const dynamic = "force-dynamic";

interface ComparisonReport {
  domain: string;
  overallGrade: Grade | null;
  categories: Array<{ category: string; grade: Grade }>;
  summary: { critical: number; high: number; medium: number; low: number; info: number; total: number } | null;
  error?: string;
}

interface Comparison {
  id: string;
  timestamp: string;
  industry: string;
  domains: string[];
  reports: ComparisonReport[];
  ranking: Array<{ rank: number; domain: string; grade: Grade }>;
}

const GRADE_COLORS: Record<string, string> = {
  A: "var(--grade-a)",
  B: "var(--grade-b)",
  C: "var(--grade-c)",
  D: "var(--grade-d)",
  F: "var(--grade-f)",
};

const CATEGORY_LABELS: Record<string, string> = {
  tls: "Encryption",
  headers: "Headers",
  dns: "Email Auth",
  paths: "Exposed Files",
  "third-party": "Third-Party",
  forms: "Forms",
  cookies: "Cookies",
};

export default async function ComparePage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const data = await getScan(`cmp:${id}`);
  if (!data) notFound();

  const comparison = data as unknown as Comparison;
  const validReports = comparison.reports.filter((r) => r.overallGrade);

  return (
    <main className="min-h-screen">
      <div className="mx-auto max-w-4xl px-5 py-12 sm:py-16">
        {/* header */}
        <div className="mb-10">
          <Link href="/" className="ff-mono text-xs text-[var(--fg-dim)] hover:text-[var(--accent)] transition-colors">
            &larr; beacon
          </Link>
          <h1 className="mt-4 text-2xl font-bold tracking-tight sm:text-3xl">
            Security comparison
          </h1>
          <p className="mt-2 text-sm text-[var(--fg-muted)]">
            {comparison.domains.length} sites compared &middot; {new Date(comparison.timestamp).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" })} &middot; {comparison.industry} profile
          </p>
        </div>

        {/* ranking */}
        <div className="mb-10">
          <h2 className="text-xs text-[var(--fg-dim)] tracking-wider uppercase mb-4">
            Ranking
          </h2>
          <div className="space-y-2">
            {comparison.ranking.map((entry) => (
              <div
                key={entry.domain}
                className="flex items-center gap-4 rounded-lg border border-[var(--border)] px-4 py-3"
              >
                <span className="ff-mono text-lg font-bold w-8 text-center" style={{ color: GRADE_COLORS[entry.grade] }}>
                  {entry.rank}
                </span>
                <div className="flex-1 min-w-0">
                  <span className="text-sm font-medium text-[var(--fg)] truncate block">
                    {entry.domain}
                  </span>
                </div>
                <span
                  className="ff-mono text-2xl font-bold"
                  style={{ color: GRADE_COLORS[entry.grade] }}
                >
                  {entry.grade}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* category comparison table */}
        {validReports.length >= 2 && (
          <div className="mb-10">
            <h2 className="text-xs text-[var(--fg-dim)] tracking-wider uppercase mb-4">
              By category
            </h2>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[var(--border)]">
                    <th className="text-left py-3 pr-4 text-xs text-[var(--fg-dim)] font-normal">
                      Category
                    </th>
                    {validReports.map((r) => (
                      <th key={r.domain} className="text-center py-3 px-3 text-xs text-[var(--fg-dim)] font-normal truncate max-w-[120px]">
                        {r.domain}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(CATEGORY_LABELS).map(([cat, label]) => (
                    <tr key={cat} className="border-b border-[var(--border)]/50">
                      <td className="py-2.5 pr-4 text-[var(--fg-muted)]">{label}</td>
                      {validReports.map((r) => {
                        const catReport = r.categories.find((c) => c.category === cat);
                        const grade = catReport?.grade ?? "—";
                        return (
                          <td key={r.domain} className="text-center py-2.5 px-3">
                            <span
                              className="ff-mono font-bold text-base"
                              style={{ color: GRADE_COLORS[grade] ?? "var(--fg-dim)" }}
                            >
                              {grade}
                            </span>
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                  {/* overall row */}
                  <tr className="border-t-2 border-[var(--border)]">
                    <td className="py-3 pr-4 font-medium text-[var(--fg)]">Overall</td>
                    {validReports.map((r) => (
                      <td key={r.domain} className="text-center py-3 px-3">
                        <span
                          className="ff-mono font-bold text-xl"
                          style={{ color: GRADE_COLORS[r.overallGrade ?? "F"] }}
                        >
                          {r.overallGrade}
                        </span>
                      </td>
                    ))}
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* findings summary */}
        <div className="mb-10">
          <h2 className="text-xs text-[var(--fg-dim)] tracking-wider uppercase mb-4">
            Findings
          </h2>
          <div className="grid gap-3" style={{ gridTemplateColumns: `repeat(${validReports.length}, 1fr)` }}>
            {validReports.map((r) => (
              <div
                key={r.domain}
                className="rounded-lg border border-[var(--border)] p-4"
              >
                <div className="flex items-baseline justify-between mb-3">
                  <span className="text-xs text-[var(--fg-muted)] truncate">{r.domain}</span>
                  <span
                    className="ff-mono text-lg font-bold ml-2"
                    style={{ color: GRADE_COLORS[r.overallGrade ?? "F"] }}
                  >
                    {r.overallGrade}
                  </span>
                </div>
                {r.summary && (
                  <div className="space-y-1 text-xs">
                    {r.summary.critical > 0 && (
                      <div className="flex justify-between">
                        <span className="text-[var(--sev-critical)]">Critical</span>
                        <span className="ff-mono text-[var(--sev-critical)]">{r.summary.critical}</span>
                      </div>
                    )}
                    {r.summary.high > 0 && (
                      <div className="flex justify-between">
                        <span className="text-[var(--sev-high)]">High</span>
                        <span className="ff-mono text-[var(--sev-high)]">{r.summary.high}</span>
                      </div>
                    )}
                    {r.summary.medium > 0 && (
                      <div className="flex justify-between">
                        <span className="text-[var(--sev-medium)]">Medium</span>
                        <span className="ff-mono text-[var(--sev-medium)]">{r.summary.medium}</span>
                      </div>
                    )}
                    {r.summary.low > 0 && (
                      <div className="flex justify-between">
                        <span className="text-[var(--fg-muted)]">Low</span>
                        <span className="ff-mono text-[var(--fg-muted)]">{r.summary.low}</span>
                      </div>
                    )}
                    <div className="flex justify-between pt-1 border-t border-[var(--border)]/50">
                      <span className="text-[var(--fg-dim)]">Total</span>
                      <span className="ff-mono text-[var(--fg-dim)]">{r.summary.total}</span>
                    </div>
                  </div>
                )}
                {/* link to full report */}
                <Link
                  href={`/scan/${id}-${r.domain.replace(/\./g, "-")}`}
                  className="mt-3 block text-xs text-[var(--accent)] hover:underline"
                >
                  View full report &rarr;
                </Link>
              </div>
            ))}
          </div>
        </div>

        {/* failed scans */}
        {comparison.reports.some((r) => r.error) && (
          <div className="mb-10">
            <h2 className="text-xs text-[var(--fg-dim)] tracking-wider uppercase mb-3">
              Failed
            </h2>
            {comparison.reports
              .filter((r) => r.error)
              .map((r) => (
                <div key={r.domain} className="text-sm text-[var(--fg-muted)]">
                  {r.domain}: {r.error}
                </div>
              ))}
          </div>
        )}

        {/* footer */}
        <div className="pt-8 border-t border-[var(--border)]">
          <p className="text-xs text-[var(--fg-dim)]">
            All scans use the same methodology — passive analysis of publicly visible
            configuration. No authentication bypass or active exploitation.
            Grades are based on documented security standards and mapped to real breach precedents.
          </p>
          <div className="mt-4 flex gap-4">
            <Link href="/" className="text-xs text-[var(--accent)] hover:underline">
              New comparison
            </Link>
            <Link href="/" className="text-xs text-[var(--fg-dim)] hover:text-[var(--fg-muted)]">
              Single scan
            </Link>
          </div>
        </div>
      </div>
    </main>
  );
}
