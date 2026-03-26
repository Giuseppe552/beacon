import { notFound } from "next/navigation";
import { getScan } from "@/lib/kv";
import type { ScanReport, Finding, Grade, Severity } from "@beacon/types";
import { GRADE_EXPLANATIONS, SEVERITY_EXPLANATIONS } from "@beacon/grade";
import ShareActions from "@/components/report/ShareActions";

export const dynamic = "force-dynamic";

export default async function ScanPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  let report: ScanReport | null = null;
  try {
    report = await getScan(id);
  } catch (err) {
    console.error("[beacon] getScan error:", err);
  }
  if (!report) notFound();

  return (
    <main className="min-h-screen">
      <div className="mx-auto max-w-3xl px-5 py-12 sm:py-16">
        <GradeHero report={report} />
        <Verdict grade={report.overallGrade} />
        <SummaryBar report={report} />
        <PriorityFix report={report} />
        <SeverityLegend report={report} />
        <CategoryBreakdown report={report} />
        <FindingsList report={report} />
        {report.thirdPartyDomains.length > 0 && (
          <ThirdPartySection domains={report.thirdPartyDomains} />
        )}
        <ShareActions id={id} domain={report.domain} />
        <Footer report={report} />
      </div>
    </main>
  );
}

/* ── Grade Hero ────────────────────────────────────── */

const GRADE_COLORS: Record<Grade, string> = {
  A: "var(--grade-a)",
  B: "var(--grade-b)",
  C: "var(--grade-c)",
  D: "var(--grade-d)",
  F: "var(--grade-f)",
};

function GradeHero({ report }: { report: ScanReport }) {
  const color = GRADE_COLORS[report.overallGrade];
  return (
    <div className="mb-8">
      <div className="flex items-center gap-5">
        <div
          className="flex items-center justify-center w-20 h-20 rounded-xl text-4xl font-bold ff-mono"
          style={{
            background: `color-mix(in srgb, ${color} 15%, transparent)`,
            color,
            border: `1px solid color-mix(in srgb, ${color} 30%, transparent)`,
          }}
        >
          {report.overallGrade}
        </div>
        <div>
          <h1 className="ff-mono text-xl font-bold text-[var(--fg)]">
            {report.domain}
          </h1>
          <p className="mt-1 text-xs text-[var(--fg-dim)] ff-mono">
            {report.timestamp.split("T")[0]} · {(report.durationMs / 1000).toFixed(1)}s
          </p>
        </div>
      </div>
    </div>
  );
}

/* ── Verdict ───────────────────────────────────────── */

function Verdict({ grade }: { grade: Grade }) {
  const ex = GRADE_EXPLANATIONS[grade];
  return (
    <div className="mb-8 rounded-lg border border-[var(--border)] bg-[var(--bg-subtle)] p-5">
      <div
        className="ff-mono text-xs font-medium tracking-wider uppercase mb-2"
        style={{ color: GRADE_COLORS[grade] }}
      >
        {ex.label}
      </div>
      <p className="text-sm text-[var(--fg-secondary)] leading-relaxed">
        {ex.meaning}
      </p>
      <p className="mt-3 text-sm text-[var(--fg-muted)] leading-relaxed">
        {ex.action}
      </p>
    </div>
  );
}

/* ── Summary Bar ───────────────────────────────────── */

const SEV_COLORS: Record<Severity, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  info: "var(--sev-info)",
};

function SummaryBar({ report }: { report: ScanReport }) {
  const counts: [Severity, number][] = [
    ["critical", report.summary.critical],
    ["high", report.summary.high],
    ["medium", report.summary.medium],
    ["low", report.summary.low],
    ["info", report.summary.info],
  ];

  return (
    <div className="mb-8 flex flex-wrap gap-2">
      {counts
        .filter(([, n]) => n > 0)
        .map(([sev, n]) => (
          <span
            key={sev}
            className="inline-flex items-center gap-1.5 rounded border px-2.5 py-1 ff-mono text-xs"
            style={{
              color: SEV_COLORS[sev],
              borderColor: `color-mix(in srgb, ${SEV_COLORS[sev]} 30%, transparent)`,
              background: `color-mix(in srgb, ${SEV_COLORS[sev]} 8%, transparent)`,
            }}
          >
            {n} {sev}
          </span>
        ))}
      <span className="inline-flex items-center px-2.5 py-1 text-xs text-[var(--fg-dim)]">
        {report.summary.total} total
      </span>
    </div>
  );
}

/* ── Priority Fix ──────────────────────────────────── */

function PriorityFix({ report }: { report: ScanReport }) {
  const criticals = report.findings.filter((f) => f.severity === "critical");
  const highs = report.findings.filter((f) => f.severity === "high");
  const priority = criticals[0] ?? highs[0];
  if (!priority) return null;

  const color = SEV_COLORS[priority.severity];

  return (
    <div
      className="mb-8 rounded-lg border p-5"
      style={{
        borderColor: `color-mix(in srgb, ${color} 30%, transparent)`,
        background: `color-mix(in srgb, ${color} 5%, transparent)`,
      }}
    >
      <div className="ff-mono text-xs font-medium tracking-wider uppercase mb-3" style={{ color }}>
        Fix this first
      </div>
      <h3 className="text-base font-medium text-[var(--fg)]">{priority.title}</h3>
      <p className="mt-2 text-sm text-[var(--fg-secondary)] leading-relaxed">
        {priority.risk}
      </p>
      {priority.remediation && (
        <p className="mt-3 text-sm text-[var(--grade-a)] ff-mono">
          → {priority.remediation}
        </p>
      )}
      {priority.precedent && (
        <PrecedentCard precedent={priority.precedent} />
      )}
    </div>
  );
}

/* ── Severity Legend ────────────────────────────────── */

function SeverityLegend({ report }: { report: ScanReport }) {
  const active = new Set(report.findings.map((f) => f.severity));
  const order: Severity[] = ["critical", "high", "medium", "low", "info"];

  return (
    <div className="mb-8">
      <h2 className="ff-mono text-xs text-[var(--fg-dim)] tracking-wider uppercase mb-3">
        Severity levels
      </h2>
      <div className="space-y-1.5">
        {order
          .filter((s) => active.has(s))
          .map((sev) => {
            const ex = SEVERITY_EXPLANATIONS[sev];
            return (
              <div key={sev} className="flex gap-3 text-xs">
                <span
                  className="ff-mono font-medium shrink-0 w-16 text-right"
                  style={{ color: SEV_COLORS[sev] }}
                >
                  {ex.label}
                </span>
                <span className="text-[var(--fg-muted)]">{ex.meaning}</span>
              </div>
            );
          })}
      </div>
    </div>
  );
}

/* ── Category Breakdown ────────────────────────────── */

function CategoryBreakdown({ report }: { report: ScanReport }) {
  return (
    <div className="mb-8">
      <h2 className="ff-mono text-xs text-[var(--fg-dim)] tracking-wider uppercase mb-3">
        Category breakdown
      </h2>
      <div className="space-y-1">
        {report.categories.map((cat) => {
          const color = GRADE_COLORS[cat.grade];
          const filled = { A: 5, B: 4, C: 3, D: 2, F: 1 }[cat.grade];
          const label = cat.category
            .replace(/-/g, " ")
            .replace(/\b\w/g, (c) => c.toUpperCase());
          const n = cat.findings.length;

          return (
            <div
              key={cat.category}
              className="flex items-center gap-3 rounded border border-[var(--border)] bg-[var(--surface)] px-3 py-2"
            >
              <span className="ff-mono text-sm font-bold w-5" style={{ color }}>
                {cat.grade}
              </span>
              <div className="flex gap-0.5">
                {Array.from({ length: 5 }).map((_, i) => (
                  <div
                    key={i}
                    className="w-2.5 h-3 rounded-sm"
                    style={{
                      background: i < filled ? color : "var(--surface)",
                      opacity: i < filled ? 1 : 0.3,
                    }}
                  />
                ))}
              </div>
              <span className="text-sm text-[var(--fg)] flex-1">{label}</span>
              <span className="ff-mono text-xs text-[var(--fg-dim)]">
                {n === 0 ? "clean" : `${n} finding${n > 1 ? "s" : ""}`}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ── Findings List ─────────────────────────────────── */

function FindingsList({ report }: { report: ScanReport }) {
  const order: Severity[] = ["critical", "high", "medium", "low", "info"];

  return (
    <div className="mb-8 space-y-6">
      {order.map((sev) => {
        const findings = report.findings.filter((f) => f.severity === sev);
        if (findings.length === 0) return null;

        return (
          <div key={sev}>
            <h2
              className="ff-mono text-xs font-medium tracking-wider uppercase mb-3"
              style={{ color: SEV_COLORS[sev] }}
            >
              {sev}
            </h2>
            <div className="space-y-3">
              {findings.map((f) => (
                <FindingCard key={f.id} finding={f} />
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function FindingCard({ finding: f }: { finding: Finding }) {
  const color = SEV_COLORS[f.severity];

  return (
    <div className="rounded-lg border border-[var(--border)] bg-[var(--bg-subtle)] p-4">
      <div className="flex items-start gap-3">
        <span
          className="mt-0.5 w-1.5 h-1.5 rounded-full shrink-0"
          style={{ background: color }}
        />
        <div className="flex-1 min-w-0">
          <h3 className="text-sm font-medium text-[var(--fg)]">{f.title}</h3>
          <p className="mt-1 text-xs text-[var(--fg-dim)] ff-mono">{f.detail}</p>
          <p className="mt-2 text-sm text-[var(--fg-secondary)] leading-relaxed">
            {f.risk}
          </p>

          {f.remediation && (
            <p className="mt-2 text-xs text-[var(--grade-a)] ff-mono">
              → {f.remediation}
            </p>
          )}

          {f.precedent && <PrecedentCard precedent={f.precedent} />}
        </div>
      </div>
    </div>
  );
}

/* ── Precedent Card ────────────────────────────────── */

function PrecedentCard({ precedent }: { precedent: NonNullable<Finding["precedent"]> }) {
  return (
    <div className="mt-3 rounded border border-[var(--border)] bg-[var(--surface)] p-3">
      <div className="ff-mono text-xs text-[var(--fg-dim)] mb-1">
        Real incident
      </div>
      <div className="text-sm font-medium text-[var(--fg)]">
        {precedent.name}
      </div>
      <p className="mt-1 text-xs text-[var(--fg-muted)] leading-relaxed">
        {precedent.summary}
      </p>
      {precedent.impact && (
        <p className="mt-1 text-xs text-[var(--fg-secondary)] italic">
          {precedent.impact}
        </p>
      )}
      {precedent.quote && (
        <p className="mt-2 text-xs text-[var(--sev-high)] italic leading-relaxed">
          &ldquo;{precedent.quote}&rdquo;
        </p>
      )}
      {precedent.source && (
        <a
          href={precedent.source}
          target="_blank"
          rel="noreferrer"
          className="mt-2 inline-block text-xs text-[var(--fg-dim)] hover:text-[var(--fg-muted)] transition-colors ff-mono underline decoration-[var(--border)]"
        >
          Source ↗
        </a>
      )}
    </div>
  );
}

/* ── Third-Party Domains ───────────────────────────── */

function ThirdPartySection({ domains }: { domains: string[] }) {
  return (
    <div className="mb-8">
      <h2 className="ff-mono text-xs text-[var(--fg-dim)] tracking-wider uppercase mb-3">
        Data sent to {domains.length} external domain{domains.length > 1 ? "s" : ""}
      </h2>
      <div className="rounded-lg border border-[var(--border)] bg-[var(--bg-subtle)] p-4">
        <div className="flex flex-wrap gap-2">
          {domains.map((d) => (
            <span
              key={d}
              className="ff-mono text-xs text-[var(--fg-muted)] border border-[var(--border)] rounded px-2 py-0.5"
            >
              {d}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

/* ── Footer ────────────────────────────────────────── */

function Footer({ report }: { report: ScanReport }) {
  return (
    <div className="border-t border-[var(--border)] pt-6 mt-8 text-center">
      <a
        href={`/?domain=${encodeURIComponent(report.domain)}`}
        className="inline-flex items-center gap-2 rounded border border-[var(--accent)]/30 bg-[var(--accent)]/10 px-5 py-2 ff-mono text-xs font-medium text-[var(--accent)] transition-all hover:bg-[var(--accent)]/20 hover:border-[var(--accent)]/50"
      >
        Scan again
      </a>
      <p className="mt-4 text-xs text-[var(--fg-dim)]">
        beacon v0.2.0 ·{" "}
        <a
          href="https://giuseppegiona.com/projects/beacon"
          className="hover:text-[var(--fg-muted)] transition-colors"
        >
          giuseppegiona.com
        </a>
      </p>
    </div>
  );
}
