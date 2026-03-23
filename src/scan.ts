import type { CategoryResult, Finding, ScanCategory, ScanReport, Scanner } from "./types.js";
import { buildContext } from "./context.js";
import { computeGrade } from "./grade.js";
import { tlsScanner } from "./scanners/tls.js";
import { headersScanner } from "./scanners/headers.js";
import { dnsScanner } from "./scanners/dns.js";
import { pathsScanner } from "./scanners/paths.js";
import { thirdPartyScanner, extractThirdPartyDomains } from "./scanners/third-party.js";
import { formsScanner } from "./scanners/forms.js";
import { cookiesScanner } from "./scanners/cookies.js";

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
};

/** Run all scanners against a domain and produce a report. */
export async function scan(domain: string, opts: ScanOptions = {}): Promise<ScanReport> {
  const t0 = performance.now();
  const log = opts.verbose
    ? (msg: string) => process.stderr.write(`  ${msg}\n`)
    : () => {};

  const progress = opts.onProgress ?? (() => {});

  log(`building context for ${domain}...`);
  progress({ phase: "context", label: "Connecting", current: 0, total: ALL_SCANNERS.length });
  const ctx = await buildContext(domain);
  log(`fetched ${ctx.url} (${ctx.statusCode}), ${ctx.html.length} bytes`);

  const allFindings: Finding[] = [];
  const categories: CategoryResult[] = [];

  for (let si = 0; si < ALL_SCANNERS.length; si++) {
    const scanner = ALL_SCANNERS[si];
    progress({ phase: "scanner", label: scanner.name, current: si + 1, total: ALL_SCANNERS.length });
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
    const durationMs = Math.round(performance.now() - st);

    categories.push({
      category: scanner.category,
      grade: computeGrade(findings),
      findings,
      durationMs,
    });
    allFindings.push(...findings);
    log(`  ${scanner.name}: ${findings.length} findings (${durationMs}ms)`);
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
