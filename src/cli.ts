#!/usr/bin/env node
import { scan, type ScanProgress } from "./scan.js";
import type { Finding, Grade, ScanReport, Severity } from "./types.js";
import { type Industry, INDUSTRY_PROFILES } from "./industry.js";
import { GRADE_EXPLANATIONS, SEVERITY_EXPLANATIONS } from "./grade.js";

// ── Colours ──────────────────────────────────────────────────────────

const R = "\x1b[0m";
const B = "\x1b[1m";
const D = "\x1b[2m";
const I = "\x1b[3m";
const RED = "\x1b[31m";
const GRN = "\x1b[32m";
const YEL = "\x1b[33m";
const CYN = "\x1b[36m";
const GRY = "\x1b[90m";
const BG_RED = "\x1b[41m\x1b[37m";
const BG_YEL = "\x1b[43m\x1b[30m";
const BG_GRN = "\x1b[42m\x1b[30m";

const SEV: Record<Severity, string> = {
  critical: BG_RED,
  high: RED,
  medium: YEL,
  low: CYN,
  info: GRY,
};

const GRADE_C: Record<Grade, string> = {
  A: BG_GRN,
  B: GRN,
  C: YEL,
  D: RED,
  F: BG_RED,
};

const GRADE_BG: Record<Grade, string> = {
  A: BG_GRN,
  B: BG_GRN,
  C: BG_YEL,
  D: BG_RED,
  F: BG_RED,
};

// ── Entry ────────────────────────────────────────────────────────────

function usage(): void {
  const w = process.stderr.write.bind(process.stderr);
  w(`\n${B}beacon${R} — business security surface scanner\n\n`);
  w(`${B}Usage:${R}\n`);
  w(`  beacon <domain>                          Scan and print report\n`);
  w(`  beacon <domain> --industry immigration   Scan with industry context\n`);
  w(`  beacon <domain> --json                   Output JSON\n`);
  w(`  beacon <domain> -v                       Verbose\n\n`);
  w(`${B}Industries:${R}  immigration, law, accounting, healthcare, general\n\n`);
  w(`${D}https://giuseppegiona.com/projects/beacon${R}\n\n`);
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    usage();
    process.exit(0);
  }

  const domain = args.find((a) => !a.startsWith("-"));
  if (!domain) {
    process.stderr.write("Error: provide a domain to scan.\n");
    process.exit(1);
  }

  const clean = domain.replace(/^https?:\/\//, "").replace(/\/.*$/, "").toLowerCase();
  const json = args.includes("--json");
  const verbose = args.includes("-v") || args.includes("--verbose");

  // Parse --industry flag
  const industryIdx = args.indexOf("--industry");
  const industryArg = industryIdx !== -1 ? args[industryIdx + 1] : undefined;
  const validIndustries = Object.keys(INDUSTRY_PROFILES) as Industry[];
  const industry: Industry = industryArg && validIndustries.includes(industryArg as Industry)
    ? (industryArg as Industry)
    : "general";

  if (industryArg && !validIndustries.includes(industryArg as Industry)) {
    process.stderr.write(`  ${YEL}Warning:${R} unknown industry "${industryArg}". Using general.\n`);
    process.stderr.write(`  ${D}Valid: ${validIndustries.join(", ")}${R}\n\n`);
  }

  // Banner
  const profile = INDUSTRY_PROFILES[industry];
  process.stderr.write(`\n  ${B}beacon${R}  ${D}v0.2.0${R}\n`);
  process.stderr.write(`  ${D}target${R}  ${B}${clean}${R}\n`);
  if (industry !== "general") {
    process.stderr.write(`  ${D}industry${R}  ${B}${profile.name}${R}\n`);
  }
  process.stderr.write(`\n`);

  // Spinner
  const spinner = json ? null : createSpinner();
  spinner?.start();

  try {
    const report = await scan(clean, {
      verbose,
      industry,
      onProgress: (p) => spinner?.update(p),
    });
    spinner?.stop();
    if (json) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      await render(report);
    }
    if (report.summary.critical > 0) process.exit(2);
    if (report.summary.high > 0) process.exit(1);
    process.exit(0);
  } catch (err) {
    spinner?.stop();
    process.stderr.write(`  ${BG_RED} FAILED ${R} ${err instanceof Error ? err.message : "Scan failed"}\n\n`);
    process.exit(1);
  }
}

// ── Renderer ─────────────────────────────────────────────────────────

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function render(r: ScanReport): Promise<void> {
  const o = console.log;
  const gc = GRADE_BG[r.overallGrade];

  // ── Grade block ──
  o(`  ${gc}${B}   ${r.overallGrade}   ${R}  ${B}${r.domain}${R}`);
  o();
  await wait(400);

  // ── Verdict ──
  renderVerdict(r);
  await wait(300);

  // ── Summary counts ──
  const counts: string[] = [];
  if (r.summary.critical) counts.push(`${SEV.critical} ${r.summary.critical} critical ${R}`);
  if (r.summary.high) counts.push(`${RED}${r.summary.high} high${R}`);
  if (r.summary.medium) counts.push(`${YEL}${r.summary.medium} medium${R}`);
  if (r.summary.low) counts.push(`${CYN}${r.summary.low} low${R}`);
  if (r.summary.info) counts.push(`${GRY}${r.summary.info} info${R}`);
  o(`  ${counts.join("  ·  ")}  ${D}(${r.summary.total} findings)${R}`);
  o();
  await wait(200);

  // ── Fix first ──
  renderPriority(r);
  await wait(300);

  // ── Category grades (each row paced) ──
  o(`  ${D}─── Category breakdown ───${R}`);
  o();
  for (const cat of r.categories) {
    const cg = GRADE_C[cat.grade];
    const bar = gradeBar(cat.grade);
    const label = formatCategory(cat.category).padEnd(20);
    const n = cat.findings.length;
    const countStr = n === 0 ? `${GRY}clean${R}` : `${n} finding${n > 1 ? "s" : ""}`;
    o(`  ${cg}${B}${cat.grade}${R}  ${bar}  ${label} ${D}${countStr}${R}`);
    await wait(60);
  }
  o();
  await wait(200);

  // ── Severity legend ──
  o(`  ${D}─── What the severity levels mean ───${R}`);
  o();
  const activeSevs = new Set(r.findings.map((f) => f.severity));
  const sevOrder: Severity[] = ["critical", "high", "medium", "low", "info"];
  for (const sev of sevOrder) {
    if (!activeSevs.has(sev)) continue;
    const ex = SEVERITY_EXPLANATIONS[sev];
    o(`  ${SEV[sev]}${B} ${ex.label} ${R}  ${D}${ex.meaning}${R}`);
  }
  o();
  await wait(200);

  // ── Findings (each finding paced) ──
  for (const sev of sevOrder) {
    const sf = r.findings.filter((f) => f.severity === sev);
    if (sf.length === 0) continue;

    o(`  ${SEV[sev]}${B} ${sev.toUpperCase()} ${R}`);
    o();
    await wait(120);

    for (const f of sf) {
      renderFinding(f);
      await wait(180);
    }
  }

  // ── Third-party domains ──
  if (r.thirdPartyDomains.length > 0) {
    o(`  ${D}─── Data sent to ${r.thirdPartyDomains.length} external domain${r.thirdPartyDomains.length > 1 ? "s" : ""} ───${R}`);
    o();
    for (const d of r.thirdPartyDomains) {
      o(`  ${D}·${R}  ${d}`);
    }
    o();
    await wait(150);
  }

  // ── Footer ──
  o(`  ${D}Scan completed in ${(r.durationMs / 1000).toFixed(1)}s · ${r.timestamp.split("T")[0]}${R}`);
  o(`  ${D}beacon v0.1.0 · giuseppegiona.com/projects/beacon${R}`);
  o();
}

function renderVerdict(r: ScanReport): void {
  const o = console.log;
  const g = r.overallGrade;
  const ex = GRADE_EXPLANATIONS[g];

  o(`  ${B}${ex.label}${R}`);
  o();
  // Wrap meaning text at ~75 chars
  wrapText(ex.meaning, 75).forEach((line) => o(`  ${I}${line}${R}`));
  o();
  wrapText(ex.action, 75).forEach((line) => o(`  ${line}`));
  o();
}

function wrapText(text: string, width: number): string[] {
  const words = text.split(" ");
  const lines: string[] = [];
  let line = "";
  for (const word of words) {
    if (line.length + word.length + 1 > width && line.length > 0) {
      lines.push(line);
      line = word;
    } else {
      line += (line ? " " : "") + word;
    }
  }
  if (line) lines.push(line);
  return lines;
}

function renderPriority(r: ScanReport): void {
  const o = console.log;
  const criticals = r.findings.filter((f) => f.severity === "critical");
  const highs = r.findings.filter((f) => f.severity === "high");
  const priority = criticals[0] ?? highs[0];
  if (!priority) return;

  o(`  ${D}─── Priority fix ───${R}`);
  o();
  o(`  ${SEV[priority.severity]}▸${R}  ${B}${priority.title}${R}`);
  if (priority.remediation) {
    o(`     ${priority.remediation}`);
  }
  if (priority.precedent) {
    o();
    o(`     ${D}Why this matters:${R}`);
    o(`     ${D}${priority.precedent.name}${R}`);
    // Show full impact, not truncated
    if (priority.precedent.impact) {
      o(`     ${D}${priority.precedent.impact}${R}`);
    }
    if (priority.precedent.source) {
      o(`     ${D}${priority.precedent.source}${R}`);
    }
  }
  o();
}

function renderFinding(f: Finding): void {
  const o = console.log;
  const sc = SEV[f.severity];

  o(`  ${sc}▸${R}  ${B}${f.title}${R}`);
  o(`     ${D}${f.detail}${R}`);
  o();
  // Risk gets full width, wrapped naturally by the terminal
  o(`     ${f.risk}`);

  if (f.precedent) {
    o();
    o(`     ${D}${f.precedent.name}${R}`);
    // Show the full summary — this is the value
    const words = f.precedent.summary.split(" ");
    let line = "     " + D;
    for (const word of words) {
      if (line.length + word.length > 90) {
        o(line);
        line = "     " + word;
      } else {
        line += (line.endsWith(D) ? "" : " ") + word;
      }
    }
    if (line.trim()) o(line + R);
    if (f.precedent.impact) {
      o(`     ${I}Impact: ${f.precedent.impact}${R}`);
    }
    if (f.precedent.quote) {
      o();
      o(`     ${I}"${f.precedent.quote}"${R}`);
    }
  }

  if (f.remediation) {
    o();
    o(`     ${GRN}→${R} ${f.remediation}`);
  }
  o();
  o(`  ${D}${"─".repeat(60)}${R}`);
  o();
}

function gradeBar(grade: Grade): string {
  const filled = { A: 5, B: 4, C: 3, D: 2, F: 1 }[grade];
  const c = GRADE_C[grade];
  return c + "█".repeat(filled) + R + D + "░".repeat(5 - filled) + R;
}

function formatCategory(cat: string): string {
  return cat.replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

// ── Spinner ──────────────────────────────────────────────────────────

const SPINNER_FRAMES = ["◜", "◠", "◝", "◞", "◡", "◟"];
const SPINNER_INTERVAL = 100;

function createSpinner() {
  let frame = 0;
  let timer: ReturnType<typeof setInterval> | null = null;
  let label = "Connecting";
  let progress = "";
  let elapsed = 0;
  const t0 = Date.now();

  function write() {
    elapsed = Math.floor((Date.now() - t0) / 1000);
    const f = SPINNER_FRAMES[frame % SPINNER_FRAMES.length];
    const line = `  ${CYN}${f}${R}  ${label}  ${D}${progress}${elapsed}s${R}`;
    // Clear line and write
    process.stderr.write(`\r\x1b[K${line}`);
    frame++;
  }

  return {
    start() {
      write();
      timer = setInterval(write, SPINNER_INTERVAL);
    },
    update(p: ScanProgress) {
      if (p.phase === "context") {
        label = "Connecting";
        progress = "";
      } else {
        label = p.label;
        progress = `${p.current}/${p.total}  `;
      }
    },
    stop() {
      if (timer) clearInterval(timer);
      // Clear the spinner line
      process.stderr.write(`\r\x1b[K`);
    },
  };
}

main();
