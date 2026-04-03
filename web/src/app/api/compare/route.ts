import { NextResponse } from "next/server";
import { resolve4 } from "node:dns/promises";
import { scan } from "@beacon/scan";
import { type Industry, INDUSTRY_PROFILES } from "@beacon/industry";
import { storeScan, checkRateLimit } from "@/lib/kv";
import { nanoid } from "nanoid";

export const runtime = "nodejs";
export const maxDuration = 60; // hobby plan limit

const VALID_INDUSTRIES = Object.keys(INDUSTRY_PROFILES) as Industry[];
const MAX_DOMAINS = 3; // 4 domains risks timeout on 60s hobby plan
const MIN_DOMAINS = 2;

const BLOCKED_DOMAINS = [
  "localhost", "0.0.0.0", "metadata.google.internal", "metadata.internal",
];

const BLOCKED_DOMAIN_PATTERNS = [
  /^127\.\d+\.\d+\.\d+$/, /^10\.\d+\.\d+\.\d+$/,
  /^172\.(1[6-9]|2\d|3[01])\./, /^192\.168\./,
  /^169\.254\./, /\.local$/, /\.internal$/, /\.localhost$/,
];

function isPrivateIp(ip: string): boolean {
  return (
    ip.startsWith("127.") || ip.startsWith("10.") || ip.startsWith("0.") ||
    ip.startsWith("169.254.") || ip.startsWith("192.168.") ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    ip === "::1" || ip.startsWith("fc00:") || ip.startsWith("fd") || ip.startsWith("fe80:")
  );
}

function cleanDomain(raw: string): string | null {
  let d = raw.trim().toLowerCase();
  d = d.replace(/^https?:\/\//, "");
  d = d.replace(/\/.*$/, "");
  d = d.replace(/^www\./, "");
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(d)) return null;
  if (BLOCKED_DOMAINS.includes(d)) return null;
  if (BLOCKED_DOMAIN_PATTERNS.some((p) => p.test(d))) return null;
  return d;
}

async function verifyPublicDns(domain: string): Promise<boolean> {
  try {
    const ips = await resolve4(domain);
    if (ips.length === 0) return false;
    return ips.every((ip) => !isPrivateIp(ip));
  } catch {
    return true;
  }
}

export async function POST(req: Request) {
  let body: { domains?: string[]; industry?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid request" }, { status: 400 });
  }

  const rawDomains = body.domains ?? [];
  if (!Array.isArray(rawDomains) || rawDomains.length < MIN_DOMAINS || rawDomains.length > MAX_DOMAINS) {
    return NextResponse.json(
      { error: `Provide ${MIN_DOMAINS}-${MAX_DOMAINS} domains to compare` },
      { status: 400 },
    );
  }

  // clean and validate all domains
  const domains: string[] = [];
  for (const raw of rawDomains) {
    if (typeof raw !== "string") {
      return NextResponse.json({ error: "Invalid domain" }, { status: 400 });
    }
    const cleaned = cleanDomain(raw);
    if (!cleaned) {
      return NextResponse.json({ error: `Invalid domain: ${raw}` }, { status: 400 });
    }
    const isPublic = await verifyPublicDns(cleaned);
    if (!isPublic) {
      return NextResponse.json({ error: `Invalid domain: ${raw}` }, { status: 400 });
    }
    domains.push(cleaned);
  }

  // deduplicate
  const unique = [...new Set(domains)];
  if (unique.length < MIN_DOMAINS) {
    return NextResponse.json({ error: "Provide at least 2 different domains" }, { status: 400 });
  }

  const industry: Industry = VALID_INDUSTRIES.includes(body.industry as Industry)
    ? (body.industry as Industry)
    : "general";

  // rate limit by IP: comparisons run 2-3 scans each, so 3 per hour
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";
  const ipAllowed = await checkRateLimit(`rl:cmp:${ip}`, 3, 3600);
  if (!ipAllowed) {
    return NextResponse.json(
      { error: "Too many comparisons. Try again in an hour." },
      { status: 429 },
    );
  }

  try {
    // 50s timeout — hobby plan kills at 60s, need margin for Redis storage
    const timeout = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error("timeout")), 50_000),
    );

    // scan all domains concurrently, race against timeout
    const results = await Promise.race([
      Promise.allSettled(unique.map((d) => scan(d, { industry }))),
      timeout,
    ]) as PromiseSettledResult<Awaited<ReturnType<typeof scan>>>[];

    const reports: Array<{ domain: string; report: ReturnType<typeof scan> extends Promise<infer R> ? R : never; error?: string }> = [];

    for (let i = 0; i < unique.length; i++) {
      const result = results[i];
      if (result.status === "fulfilled") {
        reports.push({ domain: unique[i], report: result.value });
      } else {
        reports.push({
          domain: unique[i],
          report: null as never,
          error: "Scan failed",
        });
      }
    }

    // sort by grade (A first, F last) for the ranking
    const gradeOrder = { A: 0, B: 1, C: 2, D: 3, F: 4 };
    const sorted = [...reports]
      .filter((r) => r.report)
      .sort((a, b) => {
        const ga = gradeOrder[a.report.overallGrade] ?? 5;
        const gb = gradeOrder[b.report.overallGrade] ?? 5;
        return ga - gb;
      });

    const comparison = {
      id: nanoid(10),
      timestamp: new Date().toISOString(),
      industry,
      domains: unique,
      reports: reports.map((r) => ({
        domain: r.domain,
        overallGrade: r.report?.overallGrade ?? null,
        categories: r.report?.categories.map((c) => ({
          category: c.category,
          grade: c.grade,
        })) ?? [],
        summary: r.report?.summary ?? null,
        error: r.error,
      })),
      ranking: sorted.map((r, i) => ({
        rank: i + 1,
        domain: r.domain,
        grade: r.report.overallGrade,
      })),
    };

    // store each individual report for drill-down
    for (const r of reports) {
      if (r.report) {
        const reportId = `${comparison.id}-${r.domain.replace(/\./g, "-")}`;
        await storeScan(reportId, r.report);
      }
    }

    // store the comparison itself
    await storeScan(`cmp:${comparison.id}`, comparison as never);

    return NextResponse.json(comparison);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error("[beacon] compare error:", msg);

    if (msg === "timeout") {
      return NextResponse.json(
        { error: "Comparison timed out. Try comparing fewer domains, or scan them individually." },
        { status: 504 },
      );
    }

    return NextResponse.json({ error: "Comparison failed" }, { status: 500 });
  }
}
