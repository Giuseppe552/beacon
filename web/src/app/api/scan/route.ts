import { NextResponse } from "next/server";
import { resolve4 } from "node:dns/promises";
import { scan } from "@beacon/scan";
import { type Industry, INDUSTRY_PROFILES } from "@beacon/industry";
import { storeScan, checkRateLimit } from "@/lib/kv";
import { nanoid } from "nanoid";

export const runtime = "nodejs";
export const maxDuration = 60;

const VALID_INDUSTRIES = Object.keys(INDUSTRY_PROFILES) as Industry[];

/* ── SSRF Prevention ──────────────────────────────────────────────────
   Two layers:
   1. Domain-level blocklist (catches obvious names like localhost)
   2. DNS resolution check (catches evil.com → 127.0.0.1 rebinding)
   Both are needed because an attacker who reads this file will try to
   bypass one layer. The DNS check is the real defence.
   ──────────────────────────────────────────────────────────────────── */

const BLOCKED_DOMAINS = [
  "localhost",
  "0.0.0.0",
  "metadata.google.internal",
  "metadata.internal",
];

const BLOCKED_DOMAIN_PATTERNS = [
  /^127\.\d+\.\d+\.\d+$/,
  /^10\.\d+\.\d+\.\d+$/,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^169\.254\./,
  /\.local$/,
  /\.internal$/,
  /\.localhost$/,
];

/** Check if a resolved IP is private/internal. */
function isPrivateIp(ip: string): boolean {
  return (
    ip.startsWith("127.") ||
    ip.startsWith("10.") ||
    ip.startsWith("0.") ||
    ip.startsWith("169.254.") ||
    ip.startsWith("192.168.") ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    ip === "::1" ||
    ip.startsWith("fc00:") ||
    ip.startsWith("fd") ||
    ip.startsWith("fe80:")
  );
}

function cleanDomain(raw: string): string | null {
  let d = raw.trim().toLowerCase();
  d = d.replace(/^https?:\/\//, "");
  d = d.replace(/\/.*$/, "");
  d = d.replace(/^www\./, "");
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(d)) {
    return null;
  }
  if (BLOCKED_DOMAINS.includes(d)) return null;
  if (BLOCKED_DOMAIN_PATTERNS.some((p) => p.test(d))) return null;
  return d;
}

/** Resolve domain and verify all IPs are public. Catches DNS rebinding. */
async function verifyPublicDns(domain: string): Promise<boolean> {
  try {
    const ips = await resolve4(domain);
    if (ips.length === 0) return false;
    return ips.every((ip) => !isPrivateIp(ip));
  } catch {
    // DNS resolution failed — domain doesn't exist or no A records.
    // Let the scanner handle this gracefully (it has its own error handling).
    return true;
  }
}

export async function POST(req: Request) {
  let body: { domain?: string; industry?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid domain" }, { status: 400 });
  }

  const domain = cleanDomain(body.domain ?? "");
  if (!domain) {
    return NextResponse.json({ error: "Invalid domain" }, { status: 400 });
  }

  // DNS rebinding check — resolve the domain and verify IPs are public
  const isPublic = await verifyPublicDns(domain);
  if (!isPublic) {
    return NextResponse.json({ error: "Invalid domain" }, { status: 400 });
  }

  const industry: Industry = VALID_INDUSTRIES.includes(body.industry as Industry)
    ? (body.industry as Industry)
    : "general";

  // Rate limit by IP: 5 scans per hour (hobby plan, limited resources)
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";
  const ipAllowed = await checkRateLimit(`rl:ip:${ip}`, 5, 3600);
  if (!ipAllowed) {
    return NextResponse.json(
      { error: "Rate limit reached. This is a free tool on limited infrastructure — try again in an hour." },
      { status: 429 },
    );
  }

  // Rate limit by domain: 3 scans per hour (prevents using beacon to harass a target)
  const domainAllowed = await checkRateLimit(`rl:dom:${domain}`, 3, 3600);
  if (!domainAllowed) {
    return NextResponse.json(
      { error: "This domain has been scanned too many times recently. Try again later." },
      { status: 429 },
    );
  }

  try {
    // 50s timeout guard — hobby plan kills at 60s, leave margin for storage
    const timeout = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error("timeout")), 50_000),
    );
    const report = await Promise.race([scan(domain, { industry }), timeout]);
    const id = nanoid(10);
    await storeScan(id, report);

    return NextResponse.json({ id, report });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error("[beacon] scan error:", msg);

    if (msg === "timeout") {
      return NextResponse.json(
        { error: "Scan timed out. The target server may be slow to respond. Try again in a minute." },
        { status: 504 },
      );
    }

    return NextResponse.json({ error: "Scan failed" }, { status: 500 });
  }
}
