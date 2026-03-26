import type { ScanReport } from "@beacon/types";

const SCAN_TTL = 7 * 24 * 60 * 60; // 7 days

/** In-memory fallback when Redis isn't configured. */
const globalStore = globalThis as unknown as {
  __beaconMemoryStore?: Map<string, { data: string; expires: number }>;
};
if (!globalStore.__beaconMemoryStore) {
  globalStore.__beaconMemoryStore = new Map();
}
const memoryStore = globalStore.__beaconMemoryStore;

/**
 * Detect Redis config from env. Supports:
 * - UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN (direct)
 * - REDIS_URL (Vercel Marketplace provisioned — derive REST creds from it)
 */
function getRedisConfig(): { url: string; token: string } | null {
  if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
    return {
      url: process.env.UPSTASH_REDIS_REST_URL,
      token: process.env.UPSTASH_REDIS_REST_TOKEN,
    };
  }

  // Parse REDIS_URL: redis://default:TOKEN@HOST:PORT
  const redisUrl = process.env.REDIS_URL;
  if (redisUrl) {
    try {
      const parsed = new URL(redisUrl);
      const host = parsed.hostname;
      const token = parsed.password;
      if (host && token) {
        return {
          url: `https://${host}`,
          token,
        };
      }
    } catch {
      // Invalid URL format
    }
  }

  return null;
}

async function getRedis() {
  const config = getRedisConfig();
  if (!config) return null;
  const { Redis } = await import("@upstash/redis");
  return new Redis({ url: config.url, token: config.token });
}

export async function storeScan(id: string, report: ScanReport): Promise<void> {
  const redis = await getRedis();
  if (redis) {
    try {
      const json = JSON.stringify(report);
      await redis.set(`scan:${id}`, json, { ex: SCAN_TTL });
    } catch (err) {
      console.error("[kv] store error:", err);
    }
  } else {
    memoryStore.set(`scan:${id}`, {
      data: JSON.stringify(report),
      expires: Date.now() + SCAN_TTL * 1000,
    });
  }
}

export async function getScan(id: string): Promise<ScanReport | null> {
  const redis = await getRedis();
  if (redis) {
    try {
      const raw = await redis.get<string>(`scan:${id}`);
      if (!raw) return null;
      if (typeof raw === "string") return JSON.parse(raw);
      return raw as unknown as ScanReport;
    } catch (err) {
      console.error("[kv] get error:", err);
      return null;
    }
  }

  const entry = memoryStore.get(`scan:${id}`);
  if (!entry || entry.expires < Date.now()) {
    memoryStore.delete(`scan:${id}`);
    return null;
  }
  return JSON.parse(entry.data);
}

/** Rate limit by key. Returns true if allowed, false if over limit. */
export async function checkRateLimit(
  key: string,
  max: number,
  windowSeconds: number,
): Promise<boolean> {
  const redis = await getRedis();
  if (redis) {
    try {
      const current = await redis.incr(key);
      if (current === 1) {
        await redis.expire(key, windowSeconds);
      }
      return current <= max;
    } catch (err) {
      console.error("[kv] rate limit error:", err);
      return true;
    }
  }
  return true;
}
