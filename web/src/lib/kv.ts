import type { ScanReport } from "@beacon/types";

const SCAN_TTL = 7 * 24 * 60 * 60; // 7 days

/** In-memory fallback when Redis isn't configured. Persisted on globalThis so
 *  it survives module re-evaluation in dev (API route and page render share it). */
const globalStore = globalThis as unknown as {
  __beaconMemoryStore?: Map<string, { data: string; expires: number }>;
};
if (!globalStore.__beaconMemoryStore) {
  globalStore.__beaconMemoryStore = new Map();
}
const memoryStore = globalStore.__beaconMemoryStore;

function hasRedis(): boolean {
  return !!(process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN);
}

async function getRedis() {
  const { Redis } = await import("@upstash/redis");
  return Redis.fromEnv();
}

export async function storeScan(id: string, report: ScanReport): Promise<void> {
  const json = JSON.stringify(report);

  if (hasRedis()) {
    const redis = await getRedis();
    await redis.set(`scan:${id}`, json, { ex: SCAN_TTL });
  } else {
    memoryStore.set(`scan:${id}`, {
      data: json,
      expires: Date.now() + SCAN_TTL * 1000,
    });
  }
}

export async function getScan(id: string): Promise<ScanReport | null> {
  if (hasRedis()) {
    const redis = await getRedis();
    const raw = await redis.get<string>(`scan:${id}`);
    if (!raw) return null;
    return typeof raw === "string" ? JSON.parse(raw) : raw as unknown as ScanReport;
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
  if (hasRedis()) {
    const redis = await getRedis();
    const current = await redis.incr(key);
    if (current === 1) {
      await redis.expire(key, windowSeconds);
    }
    return current <= max;
  }

  // In-memory fallback — always allow in dev
  return true;
}
