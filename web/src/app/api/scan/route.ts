import { NextResponse } from "next/server";
import { scan } from "@beacon/scan";
import { type Industry, INDUSTRY_PROFILES } from "@beacon/industry";
import { storeScan, checkRateLimit } from "@/lib/kv";
import { nanoid } from "nanoid";

export const runtime = "nodejs";
export const maxDuration = 30;

const VALID_INDUSTRIES = Object.keys(INDUSTRY_PROFILES) as Industry[];

/** Domains that resolve to internal/private infrastructure. */
const BLOCKED_DOMAINS = [
  "localhost",
  "0.0.0.0",
  "metadata.google.internal",
  "metadata.internal",
];

/** TLDs and patterns that indicate internal/test targets. */
const BLOCKED_PATTERNS = [
  /^127\.\d+\.\d+\.\d+$/,            // IPv4 loopback
  /^10\.\d+\.\d+\.\d+$/,             // RFC 1918
  /^172\.(1[6-9]|2\d|3[01])\./,      // RFC 1918
  /^192\.168\./,                       // RFC 1918
  /^169\.254\./,                       // link-local / cloud metadata
  /\.local$/,                          // mDNS
  /\.internal$/,                       // internal TLDs
  /\.localhost$/,                      // localhost TLD
];

function cleanDomain(raw: string): string | null {
  let d = raw.trim().toLowerCase();
  d = d.replace(/^https?:\/\//, "");
  d = d.replace(/\/.*$/, "");
  d = d.replace(/^www\./, "");
  // Must have at least one dot (rejects "localhost", bare hostnames)
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(d)) {
    return null;
  }
  // Block internal/private targets (SSRF prevention)
  if (BLOCKED_DOMAINS.includes(d)) return null;
  if (BLOCKED_PATTERNS.some((p) => p.test(d))) return null;
  return d;
}

export async function POST(req: Request) {
  let body: { domain?: string; industry?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid request body" }, { status: 400 });
  }

  const domain = cleanDomain(body.domain ?? "");
  if (!domain) {
    return NextResponse.json({ error: "Invalid domain" }, { status: 400 });
  }

  const industry: Industry = VALID_INDUSTRIES.includes(body.industry as Industry)
    ? (body.industry as Industry)
    : "general";

  // Rate limit by IP: 10 scans per hour
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";
  const ipAllowed = await checkRateLimit(`rl:ip:${ip}`, 10, 3600);
  if (!ipAllowed) {
    return NextResponse.json(
      { error: "Too many scans. Try again in an hour." },
      { status: 429 },
    );
  }

  // Rate limit by domain: 10 scans per hour
  const domainAllowed = await checkRateLimit(`rl:dom:${domain}`, 10, 3600);
  if (!domainAllowed) {
    return NextResponse.json(
      { error: "This domain has been scanned too many times recently. Try again later." },
      { status: 429 },
    );
  }

  try {
    const report = await scan(domain, { industry });
    const id = nanoid(10);
    await storeScan(id, report);

    return NextResponse.json({ id, report });
  } catch (err) {
    const msg = err instanceof Error ? err.message : "Scan failed";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
