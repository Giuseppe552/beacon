import type { CategoryResult, Finding, ScanReport, Scanner, Severity } from "./types.js";
import { buildContext } from "./context.js";
import { computeGrade } from "./grade.js";
import { tlsScanner } from "./scanners/tls.js";
import { headersScanner } from "./scanners/headers.js";
import { dnsScanner } from "./scanners/dns.js";
import { pathsScanner } from "./scanners/paths.js";
import { thirdPartyScanner, extractThirdPartyDomains } from "./scanners/third-party.js";
import { formsScanner } from "./scanners/forms.js";
import { cookiesScanner } from "./scanners/cookies.js";
import { type Industry, INDUSTRY_PROFILES } from "./industry.js";

const ALL_SCANNERS: Scanner[] = [
  tlsScanner,
  headersScanner,
  dnsScanner,
  pathsScanner,
  thirdPartyScanner,
  formsScanner,
  cookiesScanner,
];

export type ScanProgress = {
  phase: "context" | "scanner";
  label: string;
  current: number;
  total: number;
};

export type ScanOptions = {
  /** Print progress to stderr. */
  verbose?: boolean;
  /** Called when scan progress changes. */
  onProgress?: (p: ScanProgress) => void;
  /** Industry context — adjusts severity, risk text, and precedent selection. */
  industry?: Industry;
};

/** Severity ordering for bump comparisons. */
const SEV_ORDER: Record<Severity, number> = {
  info: 0, low: 1, medium: 2, high: 3, critical: 4,
};

/**
 * Apply industry context to findings:
 * - Bump severity where the industry profile demands it
 * - Append industry-specific risk text
 * - Prefer industry-relevant precedents
 */
function applyIndustryContext(findings: Finding[], industry: Industry): Finding[] {
  const profile = INDUSTRY_PROFILES[industry];
  if (!profile || industry === "general") return findings;

  return findings.map((f) => {
    const bump = profile.severityBumps[f.id];
    const suffix = profile.riskSuffix[f.id];

    // Check prefix matches too (e.g., "cookies-insecure-session-id" → "cookies-insecure")
    const prefixBump = !bump
      ? Object.entries(profile.severityBumps).find(([k]) => f.id.startsWith(k))?.[1]
      : undefined;
    const prefixSuffix = !suffix
      ? Object.entries(profile.riskSuffix).find(([k]) => f.id.startsWith(k))?.[1]
      : undefined;

    const effectiveBump = bump ?? prefixBump;
    const effectiveSuffix = suffix ?? prefixSuffix;

    let newSeverity = f.severity;
    if (effectiveBump && SEV_ORDER[effectiveBump] > SEV_ORDER[f.severity]) {
      newSeverity = effectiveBump;
    }

    let newRisk = f.risk;
    if (effectiveSuffix) {
      newRisk = f.risk + " " + effectiveSuffix;
    }

    if (newSeverity === f.severity && newRisk === f.risk) return f;

    return { ...f, severity: newSeverity, risk: newRisk };
  });
}

/** Run all scanners against a domain and produce a report. */
export async function scan(domain: string, opts: ScanOptions = {}): Promise<ScanReport> {
  const t0 = performance.now();
  const log = opts.verbose
    ? (msg: string) => process.stderr.write(`  ${msg}\n`)
    : () => {};

  const progress = opts.onProgress ?? (() => {});
  const industry = opts.industry ?? "general";

  log(`building context for ${domain}...`);
  if (industry !== "general") log(`industry context: ${industry}`);
  progress({ phase: "context", label: "Connecting", current: 0, total: ALL_SCANNERS.length });
  const ctx = await buildContext(domain);
  ctx.industry = industry;
  log(`fetched ${ctx.url} (${ctx.statusCode}), ${ctx.html.length} bytes`);

  // Run all scanners concurrently — they share ctx but don't depend on each other
  progress({ phase: "scanner", label: "Scanning", current: 0, total: ALL_SCANNERS.length });

  const results = await Promise.all(
    ALL_SCANNERS.map(async (scanner, si) => {
      log(`running ${scanner.name}...`);
      const st = performance.now();
      let findings: Finding[];
      try {
        findings = await scanner.scan(ctx);
      } catch (err) {
        findings = [
          {
            id: `error-${scanner.category}`,
            category: scanner.category,
            severity: "info",
            title: `${scanner.name} scanner error`,
            detail: err instanceof Error ? err.message : "Unknown error",
            risk: "This scanner could not complete. Results may be incomplete.",
          },
        ];
      }

      findings = applyIndustryContext(findings, industry);
      const durationMs = Math.round(performance.now() - st);
      log(`  ${scanner.name}: ${findings.length} findings (${durationMs}ms)`);
      progress({ phase: "scanner", label: scanner.name, current: si + 1, total: ALL_SCANNERS.length });

      return { scanner, findings, durationMs };
    }),
  );

  const allFindings: Finding[] = [];
  const categories: CategoryResult[] = [];

  for (const { scanner, findings, durationMs } of results) {
    categories.push({
      category: scanner.category,
      grade: computeGrade(findings),
      findings,
      durationMs,
    });
    allFindings.push(...findings);
  }

  const summary = {
    critical: allFindings.filter((f) => f.severity === "critical").length,
    high: allFindings.filter((f) => f.severity === "high").length,
    medium: allFindings.filter((f) => f.severity === "medium").length,
    low: allFindings.filter((f) => f.severity === "low").length,
    info: allFindings.filter((f) => f.severity === "info").length,
    total: allFindings.length,
  };

  const thirdPartyDomains = extractThirdPartyDomains(ctx);

  return {
    domain,
    url: ctx.url,
    timestamp: new Date().toISOString(),
    durationMs: Math.round(performance.now() - t0),
    overallGrade: computeGrade(allFindings),
    categories,
    findings: allFindings,
    thirdPartyDomains,
    summary,
  };
}
