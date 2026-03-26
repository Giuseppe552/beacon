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

function hasRedis(): boolean {
  return !!(process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN);
}

async function getRedis() {
  const { Redis } = await import("@upstash/redis");
  return Redis.fromEnv();
}

export async function storeScan(id: string, report: ScanReport): Promise<void> {
  if (hasRedis()) {
    try {
      const redis = await getRedis();
      const json = JSON.stringify(report);
      await redis.set(`scan:${id}`, json, { ex: SCAN_TTL });
      console.log(`[kv] stored scan:${id} (${json.length} bytes)`);
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
  if (hasRedis()) {
    try {
      const redis = await getRedis();
      const raw = await redis.get<string>(`scan:${id}`);
      console.log(`[kv] get scan:${id} → type=${typeof raw}, truthy=${!!raw}`);
      if (!raw) return null;
      // We store as JSON string, parse it back
      if (typeof raw === "string") return JSON.parse(raw);
      // Upstash may auto-deserialize — handle both cases
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
  if (hasRedis()) {
    try {
      const redis = await getRedis();
      const current = await redis.incr(key);
      if (current === 1) {
        await redis.expire(key, windowSeconds);
      }
      return current <= max;
    } catch (err) {
      console.error("[kv] rate limit error:", err);
      return true; // fail open
    }
  }

  return true;
}
